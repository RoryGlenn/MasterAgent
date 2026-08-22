"""Current-user Windows Credential Manager and DPAPI credential storage."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime.contracts import (
    AtomicPublicationRecoveryBackend,
    PlatformCapabilityUnavailable,
)
from master_agent.platform_runtime.windows.filesystem import (
    validate_windows_drive_path,
)

WINDOWS_CREDENTIAL_STORAGE_BACKEND_ID: Final = (
    "windows-credential-manager-current-user-dpapi"
)
WINDOWS_CREDENTIAL_MANAGER_PROVIDER: Final = "windows-credential-manager"
WINDOWS_DPAPI_PROVIDER: Final = "windows-dpapi"

MAX_WINDOWS_CREDENTIALS: Final = 64
MAX_WINDOWS_CREDENTIAL_NAME_BYTES: Final = 128
MAX_WINDOWS_CREDENTIAL_MANAGER_VALUE_BYTES: Final = 5 * 512
MAX_WINDOWS_DPAPI_PLAINTEXT_BYTES: Final = 1024 * 1024
MAX_WINDOWS_DPAPI_ENVELOPE_BYTES: Final = 2 * 1024 * 1024

_DPAPI_DOCUMENT_SCHEMA: Final = "master-agent/windows-dpapi-credentials@1"
_DPAPI_ENVELOPE_SCHEMA: Final = "master-agent/windows-dpapi-envelope@1"
_DPAPI_DESCRIPTION: Final = "MasterAgent current-user credential store"
_DPAPI_ENTROPY_DOMAIN: Final = b"master-agent-windows-dpapi-v1\0"
_CREDENTIAL_TARGET_PREFIX: Final = "MasterAgent/"
_CREDENTIAL_NAME = re.compile(r"[A-Z][A-Z0-9_]*\Z")

_CRED_TYPE_GENERIC: Final = 1
_CRED_PERSIST_LOCAL_MACHINE: Final = 2
_ERROR_NOT_FOUND: Final = 1168
_CRYPTPROTECT_UI_FORBIDDEN: Final = 0x1


class _FileTime(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class _CredentialW(ctypes.Structure):
    pass


_CredentialPointer = ctypes.POINTER(_CredentialW)
_BytePointer = ctypes.POINTER(ctypes.c_ubyte)

_CredentialW._fields_ = (
    ("flags", wintypes.DWORD),
    ("type", wintypes.DWORD),
    ("target_name", wintypes.LPWSTR),
    ("comment", wintypes.LPWSTR),
    ("last_written", _FileTime),
    ("credential_blob_size", wintypes.DWORD),
    ("credential_blob", _BytePointer),
    ("persist", wintypes.DWORD),
    ("attribute_count", wintypes.DWORD),
    ("attributes", ctypes.c_void_p),
    ("target_alias", wintypes.LPWSTR),
    ("user_name", wintypes.LPWSTR),
)


class _DataBlob(ctypes.Structure):
    _fields_ = (
        ("size", wintypes.DWORD),
        ("data", _BytePointer),
    )


class WindowsCredentialApi(Protocol):
    """Small injectable Win32 API used by the credential backend."""

    def probe(self) -> None:
        """Verify the required Win32 functions without touching credential state."""

    def credential_read(self, target: str) -> bytes | None:
        """Read one Generic current-user credential blob."""

    def credential_write(self, target: str, payload: bytes) -> None:
        """Write one Generic current-user credential blob."""

    def credential_delete(self, target: str) -> None:
        """Delete one Generic current-user credential when present."""

    def protect_data(self, payload: bytes, entropy: bytes) -> bytes:
        """Protect bytes with current-user DPAPI and UI disabled."""

    def unprotect_data(self, payload: bytes, entropy: bytes) -> bytes:
        """Unprotect bytes in the same current-user security context."""


class CtypesWindowsCredentialApi:
    """Direct bounded ctypes bindings for Cred* and CryptProtectData APIs."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise PlatformCapabilityUnavailable(
                "native Windows credential storage requires Windows"
            )
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise PlatformCapabilityUnavailable(
                "stdlib ctypes Win32 loading is unavailable"
            )
        try:
            self._advapi: Any = loader("advapi32", use_last_error=True)
            self._crypt: Any = loader("crypt32", use_last_error=True)
            self._kernel: Any = loader("kernel32", use_last_error=True)
            self._bind_functions()
        except (AttributeError, OSError) as error:
            raise PlatformCapabilityUnavailable(
                "required Windows credential APIs are unavailable"
            ) from error

    def _bind_functions(self) -> None:
        self._advapi.CredReadW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_CredentialPointer),
        )
        self._advapi.CredReadW.restype = wintypes.BOOL
        self._advapi.CredWriteW.argtypes = (
            ctypes.POINTER(_CredentialW),
            wintypes.DWORD,
        )
        self._advapi.CredWriteW.restype = wintypes.BOOL
        self._advapi.CredDeleteW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self._advapi.CredDeleteW.restype = wintypes.BOOL
        self._advapi.CredFree.argtypes = (ctypes.c_void_p,)
        self._advapi.CredFree.restype = None
        self._crypt.CryptProtectData.argtypes = (
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        )
        self._crypt.CryptProtectData.restype = wintypes.BOOL
        self._crypt.CryptUnprotectData.argtypes = (
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        )
        self._crypt.CryptUnprotectData.restype = wintypes.BOOL
        self._kernel.LocalFree.argtypes = (ctypes.c_void_p,)
        self._kernel.LocalFree.restype = ctypes.c_void_p

    def probe(self) -> None:
        """Verify every required function was bound."""

        for library, name in (
            (self._advapi, "CredReadW"),
            (self._advapi, "CredWriteW"),
            (self._advapi, "CredDeleteW"),
            (self._advapi, "CredFree"),
            (self._crypt, "CryptProtectData"),
            (self._crypt, "CryptUnprotectData"),
            (self._kernel, "LocalFree"),
        ):
            if getattr(library, name, None) is None:
                raise OSError("required native Windows credential API is unavailable")

    def credential_read(self, target: str) -> bytes | None:
        pointer = _CredentialPointer()
        if not self._advapi.CredReadW(
            target,
            _CRED_TYPE_GENERIC,
            0,
            ctypes.byref(pointer),
        ):
            error = _last_error()
            if error == _ERROR_NOT_FOUND:
                return None
            raise OSError(error, "Windows Credential Manager read failed")
        try:
            credential = pointer.contents
            size = int(credential.credential_blob_size)
            if size < 0 or size > MAX_WINDOWS_CREDENTIAL_MANAGER_VALUE_BYTES:
                raise ConfigurationError(
                    "Windows Credential Manager value exceeds its safety limit"
                )
            if size == 0:
                return b""
            if not credential.credential_blob:
                raise ConfigurationError(
                    "Windows Credential Manager returned an invalid value"
                )
            return ctypes.string_at(credential.credential_blob, size)
        finally:
            self._advapi.CredFree(pointer)

    def credential_write(self, target: str, payload: bytes) -> None:
        mutable = bytearray(payload)
        buffer = (ctypes.c_ubyte * len(mutable)).from_buffer(mutable)
        credential = _CredentialW()
        credential.type = _CRED_TYPE_GENERIC
        credential.target_name = target
        credential.credential_blob_size = len(mutable)
        credential.credential_blob = ctypes.cast(buffer, _BytePointer)
        credential.persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.user_name = "MasterAgent"
        try:
            if not self._advapi.CredWriteW(ctypes.byref(credential), 0):
                raise OSError(
                    _last_error(),
                    "Windows Credential Manager write failed",
                )
        finally:
            mutable[:] = b"\x00" * len(mutable)

    def credential_delete(self, target: str) -> None:
        if self._advapi.CredDeleteW(target, _CRED_TYPE_GENERIC, 0):
            return
        error = _last_error()
        if error != _ERROR_NOT_FOUND:
            raise OSError(error, "Windows Credential Manager delete failed")

    def protect_data(self, payload: bytes, entropy: bytes) -> bytes:
        source, source_buffer = _data_blob(payload)
        optional, optional_buffer = _data_blob(entropy)
        protected = _DataBlob()
        try:
            if not self._crypt.CryptProtectData(
                ctypes.byref(source),
                _DPAPI_DESCRIPTION,
                ctypes.byref(optional),
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(protected),
            ):
                raise OSError(_last_error(), "DPAPI protection failed")
            return _copy_local_blob(protected)
        finally:
            _zero_ctypes_buffer(source_buffer)
            _zero_ctypes_buffer(optional_buffer)
            _free_local_blob(self._kernel, protected, zero=False)

    def unprotect_data(self, payload: bytes, entropy: bytes) -> bytes:
        source, source_buffer = _data_blob(payload)
        optional, optional_buffer = _data_blob(entropy)
        plaintext = _DataBlob()
        description = wintypes.LPWSTR()
        try:
            if not self._crypt.CryptUnprotectData(
                ctypes.byref(source),
                ctypes.byref(description),
                ctypes.byref(optional),
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(plaintext),
            ):
                raise OSError(_last_error(), "DPAPI unprotect failed")
            if description.value != _DPAPI_DESCRIPTION:
                raise ConfigurationError("DPAPI credential description is invalid")
            return _copy_local_blob(plaintext)
        finally:
            _zero_ctypes_buffer(source_buffer)
            _zero_ctypes_buffer(optional_buffer)
            _free_local_blob(self._kernel, plaintext, zero=True)
            if description:
                self._kernel.LocalFree(ctypes.cast(description, ctypes.c_void_p))


class WindowsCredentialStorageBackend:
    """Native current-user credential storage with bounded exact-source APIs."""

    backend_id = WINDOWS_CREDENTIAL_STORAGE_BACKEND_ID

    def __init__(
        self,
        *,
        atomic: AtomicPublicationRecoveryBackend,
        api: WindowsCredentialApi | None = None,
    ) -> None:
        if not callable(getattr(atomic, "open_transaction", None)):
            raise TypeError("Windows credential atomic backend is invalid")
        self._atomic = atomic
        self._api = api if api is not None else CtypesWindowsCredentialApi()

    def load_credentials(
        self,
        *,
        provider: str,
        target: str,
        allowed_names: Sequence[str],
    ) -> Mapping[str, str]:
        names = _validate_credential_names(allowed_names, allow_empty=False)
        if provider == WINDOWS_CREDENTIAL_MANAGER_PROVIDER:
            namespace = _validate_credential_manager_target(target)
            values: dict[str, str] = {}
            for name in names:
                try:
                    payload = self._api.credential_read(
                        _credential_manager_entry(namespace, name)
                    )
                except (OSError, ConfigurationError) as error:
                    raise ConfigurationError(
                        "Windows Credential Manager source could not be read safely"
                    ) from error
                if payload is not None:
                    values[name] = _decode_credential_value(payload, name=name)
            return MappingProxyType(values)
        if provider == WINDOWS_DPAPI_PROVIDER:
            path = _validate_dpapi_target(target)
            return MappingProxyType(self._load_dpapi(path, allowed_names=names))
        raise ConfigurationError("configured credential provider is unsupported")

    def store_credentials(
        self,
        *,
        provider: str,
        target: str,
        credentials: Mapping[str, str],
    ) -> None:
        values = _validate_credential_values(credentials)
        if provider == WINDOWS_CREDENTIAL_MANAGER_PROVIDER:
            self._store_credential_manager(
                _validate_credential_manager_target(target), values
            )
            return
        if provider == WINDOWS_DPAPI_PROVIDER:
            self._store_dpapi(_validate_dpapi_target(target), values)
            return
        raise ConfigurationError("configured credential provider is unsupported")

    def remove_credentials(
        self,
        *,
        provider: str,
        target: str,
        credential_names: Sequence[str],
    ) -> None:
        names = _validate_credential_names(credential_names, allow_empty=False)
        if provider == WINDOWS_CREDENTIAL_MANAGER_PROVIDER:
            self._remove_credential_manager(
                _validate_credential_manager_target(target), names
            )
            return
        if provider == WINDOWS_DPAPI_PROVIDER:
            self._remove_dpapi(_validate_dpapi_target(target), names)
            return
        raise ConfigurationError("configured credential provider is unsupported")

    def _store_credential_manager(
        self,
        namespace: str,
        credentials: Mapping[str, str],
    ) -> None:
        for name, value in credentials.items():
            if len(value.encode("utf-8")) > MAX_WINDOWS_CREDENTIAL_MANAGER_VALUE_BYTES:
                raise ConfigurationError(
                    "Windows Credential Manager value exceeds its 2.5 KiB limit: "
                    + name
                )
        previous: dict[str, bytes | None] = {}
        completed: list[str] = []
        try:
            for name, value in credentials.items():
                entry = _credential_manager_entry(namespace, name)
                previous[name] = self._api.credential_read(entry)
                payload = value.encode("utf-8")
                self._api.credential_write(entry, payload)
                completed.append(name)
        except (OSError, ConfigurationError) as error:
            rollback_ok = self._rollback_credential_manager(
                namespace, previous, completed
            )
            message = "Windows Credential Manager update failed"
            if not rollback_ok:
                message += " and rollback was incomplete"
            raise ConfigurationError(message) from error

    def _remove_credential_manager(
        self,
        namespace: str,
        names: Sequence[str],
    ) -> None:
        previous: dict[str, bytes | None] = {}
        completed: list[str] = []
        try:
            for name in names:
                entry = _credential_manager_entry(namespace, name)
                previous[name] = self._api.credential_read(entry)
                self._api.credential_delete(entry)
                completed.append(name)
        except (OSError, ConfigurationError) as error:
            rollback_ok = self._rollback_credential_manager(
                namespace, previous, completed
            )
            message = "Windows Credential Manager removal failed"
            if not rollback_ok:
                message += " and rollback was incomplete"
            raise ConfigurationError(message) from error

    def _rollback_credential_manager(
        self,
        namespace: str,
        previous: Mapping[str, bytes | None],
        completed: Sequence[str],
    ) -> bool:
        ok = True
        for name in reversed(completed):
            try:
                payload = previous[name]
                entry = _credential_manager_entry(namespace, name)
                if payload is None:
                    self._api.credential_delete(entry)
                else:
                    self._api.credential_write(entry, payload)
            except OSError:
                ok = False
        return ok

    def _load_dpapi(
        self,
        path: Path,
        *,
        allowed_names: Sequence[str] | None,
    ) -> dict[str, str]:
        try:
            with self._atomic.open_transaction(
                path,
                max_bytes=MAX_WINDOWS_DPAPI_ENVELOPE_BYTES,
                create=False,
            ) as transaction:
                envelope = transaction.read_bytes()
        except (OSError, ConfigurationError) as error:
            raise ConfigurationError(
                "DPAPI credential store could not be opened safely"
            ) from error
        if envelope is None:
            raise ConfigurationError("DPAPI credential store does not exist")
        ciphertext = _decode_dpapi_envelope(envelope, path=path)
        try:
            plaintext = bytearray(
                self._api.unprotect_data(ciphertext, _dpapi_entropy(path))
            )
        except (OSError, ConfigurationError) as error:
            raise ConfigurationError(
                "DPAPI credential store could not be decrypted by this user"
            ) from error
        try:
            return _decode_dpapi_document(bytes(plaintext), allowed_names=allowed_names)
        finally:
            plaintext[:] = b"\x00" * len(plaintext)

    def _store_dpapi(self, path: Path, credentials: Mapping[str, str]) -> None:
        plaintext = bytearray(_encode_dpapi_document(credentials))
        try:
            try:
                ciphertext = self._api.protect_data(
                    bytes(plaintext), _dpapi_entropy(path)
                )
            except OSError as error:
                raise ConfigurationError(
                    "DPAPI credential store could not be protected"
                ) from error
        finally:
            plaintext[:] = b"\x00" * len(plaintext)
        envelope = _encode_dpapi_envelope(ciphertext, path=path)
        try:
            with self._atomic.open_transaction(
                path,
                max_bytes=MAX_WINDOWS_DPAPI_ENVELOPE_BYTES,
                create=True,
            ) as transaction:
                transaction.publish_bytes(envelope, expected=transaction.identity)
        except (OSError, ConfigurationError) as error:
            raise ConfigurationError(
                "DPAPI credential store could not be published safely"
            ) from error

    def _remove_dpapi(self, path: Path, names: Sequence[str]) -> None:
        try:
            with self._atomic.open_transaction(
                path,
                max_bytes=MAX_WINDOWS_DPAPI_ENVELOPE_BYTES,
                create=False,
            ) as transaction:
                envelope = transaction.read_bytes()
                if envelope is None or transaction.identity is None:
                    return
                ciphertext = _decode_dpapi_envelope(envelope, path=path)
                try:
                    plaintext = bytearray(
                        self._api.unprotect_data(ciphertext, _dpapi_entropy(path))
                    )
                except (OSError, ConfigurationError) as error:
                    raise ConfigurationError(
                        "DPAPI credential store could not be decrypted by this user"
                    ) from error
                try:
                    values = _decode_dpapi_document(
                        bytes(plaintext), allowed_names=None
                    )
                finally:
                    plaintext[:] = b"\x00" * len(plaintext)
                for name in names:
                    values.pop(name, None)
                if not values:
                    transaction.remove(expected=transaction.identity)
                    return
                replacement = bytearray(_encode_dpapi_document(values))
                try:
                    ciphertext = self._api.protect_data(
                        bytes(replacement), _dpapi_entropy(path)
                    )
                finally:
                    replacement[:] = b"\x00" * len(replacement)
                transaction.publish_bytes(
                    _encode_dpapi_envelope(ciphertext, path=path),
                    expected=transaction.identity,
                )
        except FileNotFoundError:
            return
        except (OSError, ConfigurationError) as error:
            if isinstance(error, ConfigurationError):
                raise
            raise ConfigurationError(
                "DPAPI credential store could not be removed safely"
            ) from error


def probe_windows_credential_storage_backend(
    *,
    atomic: AtomicPublicationRecoveryBackend,
    api: WindowsCredentialApi | None = None,
) -> WindowsCredentialApi:
    """Probe required Win32 functions without reading or creating a credential."""

    selected = api if api is not None else CtypesWindowsCredentialApi()
    selected.probe()
    WindowsCredentialStorageBackend(atomic=atomic, api=selected)
    return selected


def _data_blob(payload: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
    if not payload:
        raise ValueError("native Windows data blob must not be empty")
    buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    return _DataBlob(len(payload), ctypes.cast(buffer, _BytePointer)), buffer


def _copy_local_blob(blob: _DataBlob) -> bytes:
    size = int(blob.size)
    if size <= 0 or not blob.data:
        raise ConfigurationError("native Windows data protection returned no data")
    return ctypes.string_at(blob.data, size)


def _free_local_blob(
    kernel: Any,
    blob: _DataBlob,
    *,
    zero: bool,
) -> None:
    if not blob.data:
        return
    if zero and blob.size:
        ctypes.memset(blob.data, 0, int(blob.size))
    kernel.LocalFree(ctypes.cast(blob.data, ctypes.c_void_p))
    blob.data = _BytePointer()
    blob.size = 0


def _zero_ctypes_buffer(buffer: ctypes.Array[ctypes.c_ubyte]) -> None:
    ctypes.memset(buffer, 0, ctypes.sizeof(buffer))


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        return 0
    return int(getter())


def _validate_credential_names(
    names: Sequence[str],
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    selected = tuple(names)
    if not selected and not allow_empty:
        raise ConfigurationError("credential name selection must not be empty")
    if len(selected) > MAX_WINDOWS_CREDENTIALS:
        raise ConfigurationError("credential name selection exceeds its limit")
    if len(set(selected)) != len(selected):
        raise ConfigurationError("credential name selection contains duplicates")
    for name in selected:
        if (
            not isinstance(name, str)
            or not _CREDENTIAL_NAME.fullmatch(name)
            or len(name.encode("ascii")) > MAX_WINDOWS_CREDENTIAL_NAME_BYTES
        ):
            raise ConfigurationError("credential name selection is invalid")
    return tuple(sorted(selected))


def _validate_credential_values(
    values: Mapping[str, str],
) -> Mapping[str, str]:
    names = _validate_credential_names(tuple(values), allow_empty=False)
    result: dict[str, str] = {}
    for name in names:
        value = values[name]
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ConfigurationError(
                "credential value must be a non-empty NUL-free string: " + name
            )
        if len(value.encode("utf-8")) > MAX_WINDOWS_DPAPI_PLAINTEXT_BYTES:
            raise ConfigurationError(
                "credential value exceeds its safety limit: " + name
            )
        result[name] = value
    encoded = _encode_dpapi_document(result)
    if len(encoded) > MAX_WINDOWS_DPAPI_PLAINTEXT_BYTES:
        raise ConfigurationError("credential document exceeds its 1 MiB limit")
    return MappingProxyType(result)


def _validate_credential_manager_target(value: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value.startswith(_CREDENTIAL_TARGET_PREFIX)
        or value.endswith("/")
        or not value.isprintable()
        or "\x00" in value
        or len(value.encode("utf-8")) > 512
    ):
        raise ConfigurationError(
            "Windows Credential Manager target must be a bounded MasterAgent namespace"
        )
    return value


def _credential_manager_entry(namespace: str, name: str) -> str:
    return f"{namespace}/{name}"


def _validate_dpapi_target(value: str) -> Path:
    if not isinstance(value, str) or value != value.strip() or "\x00" in value:
        raise ConfigurationError("Windows DPAPI target path is invalid")
    try:
        selected = validate_windows_drive_path(Path(value))
    except (OSError, ValueError, ConfigurationError) as error:
        raise ConfigurationError("Windows DPAPI target path is unsafe") from error
    if not selected.components:
        raise ConfigurationError("Windows DPAPI target must identify a file")
    return Path(selected.canonical)


def _decode_credential_value(payload: bytes, *, name: str) -> str:
    if not payload:
        raise ConfigurationError("Windows Credential Manager value is empty: " + name)
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConfigurationError(
            "Windows Credential Manager value is not valid UTF-8: " + name
        ) from error
    if "\x00" in value:
        raise ConfigurationError(
            "Windows Credential Manager value contains a prohibited NUL: " + name
        )
    return value


def _dpapi_entropy(path: Path) -> bytes:
    canonical = str(path).encode("utf-16-le")
    return hashlib.sha256(_DPAPI_ENTROPY_DOMAIN + canonical).digest()


def _encode_dpapi_document(credentials: Mapping[str, str]) -> bytes:
    payload = (
        json.dumps(
            {
                "credentials": dict(credentials),
                "schema": _DPAPI_DOCUMENT_SCHEMA,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    if len(payload) > MAX_WINDOWS_DPAPI_PLAINTEXT_BYTES:
        raise ConfigurationError("credential document exceeds its 1 MiB limit")
    return payload


def _decode_dpapi_document(
    payload: bytes,
    *,
    allowed_names: Sequence[str] | None,
) -> dict[str, str]:
    if (
        not payload
        or len(payload) > MAX_WINDOWS_DPAPI_PLAINTEXT_BYTES
        or not payload.endswith(b"\n")
    ):
        raise ConfigurationError("DPAPI credential document is malformed")
    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("DPAPI credential document is malformed") from error
    if not isinstance(raw, dict) or set(raw) != {"credentials", "schema"}:
        raise ConfigurationError("DPAPI credential document is malformed")
    if raw["schema"] != _DPAPI_DOCUMENT_SCHEMA:
        raise ConfigurationError("DPAPI credential document schema is unsupported")
    values = raw["credentials"]
    if not isinstance(values, Mapping):
        raise ConfigurationError("DPAPI credential document is malformed")
    validated = dict(_validate_credential_values(values))
    if allowed_names is not None:
        allowed = frozenset(allowed_names)
        if set(validated) - allowed:
            raise ConfigurationError(
                "DPAPI credential document contains an undeclared credential name"
            )
        validated = {name: validated[name] for name in sorted(allowed & set(validated))}
    return validated


def _encode_dpapi_envelope(ciphertext: bytes, *, path: Path) -> bytes:
    if not ciphertext or len(ciphertext) > MAX_WINDOWS_DPAPI_ENVELOPE_BYTES:
        raise ConfigurationError("DPAPI ciphertext exceeds its safety limit")
    payload = (
        json.dumps(
            {
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "entropy_sha256": hashlib.sha256(_dpapi_entropy(path)).hexdigest(),
                "provider": WINDOWS_DPAPI_PROVIDER,
                "schema": _DPAPI_ENVELOPE_SCHEMA,
                "scope": "current-user",
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > MAX_WINDOWS_DPAPI_ENVELOPE_BYTES:
        raise ConfigurationError("DPAPI envelope exceeds its safety limit")
    return payload


def _decode_dpapi_envelope(payload: bytes, *, path: Path) -> bytes:
    if (
        not payload
        or len(payload) > MAX_WINDOWS_DPAPI_ENVELOPE_BYTES
        or not payload.endswith(b"\n")
    ):
        raise ConfigurationError("DPAPI credential envelope is malformed")
    try:
        raw = json.loads(payload.decode("ascii"), object_pairs_hook=_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("DPAPI credential envelope is malformed") from error
    expected_keys = {
        "ciphertext",
        "entropy_sha256",
        "provider",
        "schema",
        "scope",
    }
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        raise ConfigurationError("DPAPI credential envelope is malformed")
    if (
        raw["schema"] != _DPAPI_ENVELOPE_SCHEMA
        or raw["provider"] != WINDOWS_DPAPI_PROVIDER
        or raw["scope"] != "current-user"
        or raw["entropy_sha256"] != hashlib.sha256(_dpapi_entropy(path)).hexdigest()
        or not isinstance(raw["ciphertext"], str)
    ):
        raise ConfigurationError("DPAPI credential envelope identity is invalid")
    try:
        ciphertext = base64.b64decode(raw["ciphertext"], validate=True)
    except (ValueError, TypeError) as error:
        raise ConfigurationError("DPAPI credential envelope is malformed") from error
    if not ciphertext or len(ciphertext) > MAX_WINDOWS_DPAPI_ENVELOPE_BYTES:
        raise ConfigurationError("DPAPI ciphertext exceeds its safety limit")
    return ciphertext


def _without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("credential document contains a duplicate key")
        result[key] = value
    return result
