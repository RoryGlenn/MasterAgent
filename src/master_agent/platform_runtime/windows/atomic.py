"""Native Windows protected-file publication and deterministic recovery."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime.contracts import (
    AtomicStateIdentity,
    FilesystemObjectKind,
    LockMode,
    PlatformObjectIdentity,
)
from master_agent.platform_runtime.windows.filesystem import (
    CreatedWindowsFile,
    PinnedWindowsPath,
    WindowsObjectIdentity,
    WindowsObjectKind,
    WindowsPathSecurityError,
    WindowsSecureFilesystemBackend,
    validate_windows_drive_path,
)
from master_agent.platform_runtime.windows.locking import (
    WindowsCrossProcessLockingBackend,
)

WINDOWS_ATOMIC_BACKEND_ID = "windows-handle-atomic-state"
MAX_WINDOWS_ATOMIC_STATE_BYTES = 64 * 1024 * 1024

_LEDGER_SCHEMA: Final = "master-agent/windows-atomic-ledger@1"
_MAX_LEDGER_BYTES: Final = 64 * 1024
_INTEGRITY_DOMAIN: Final = b"master-agent-windows-atomic-ledger-v1\0"


class WindowsAtomicStateIndeterminate(ConfigurationError):
    """A recorded Windows mutation cannot be reconciled to old or new state."""


@dataclass(frozen=True, slots=True)
class _WindowsStateSnapshot:
    payload: bytes
    identity: AtomicStateIdentity
    native_identity: WindowsObjectIdentity


@dataclass(frozen=True, slots=True)
class _LedgerSnapshot:
    payload: bytes
    native_identity: WindowsObjectIdentity
    state: _LedgerState


@dataclass(frozen=True, slots=True)
class _LedgerState:
    committed: AtomicStateIdentity | None
    operation: str | None = None
    pending_old: AtomicStateIdentity | None = None
    pending_new: AtomicStateIdentity | None = None

    def __post_init__(self) -> None:
        if self.operation is None:
            if self.pending_old is not None or self.pending_new is not None:
                raise ValueError("Windows atomic ledger pending state is incomplete")
            return
        if self.operation == "replace":
            if self.pending_new is None or self.pending_old != self.committed:
                raise ValueError("Windows atomic ledger replacement is inconsistent")
            return
        if self.operation == "remove":
            if self.pending_old is None or self.pending_new is not None:
                raise ValueError("Windows atomic ledger removal is inconsistent")
            if self.pending_old != self.committed:
                raise ValueError("Windows atomic ledger removal is inconsistent")
            return
        raise ValueError("Windows atomic ledger operation is invalid")


class WindowsAtomicPublicationRecoveryBackend:
    """Handle-relative, ledger-recovered private file transactions on Windows."""

    backend_id = WINDOWS_ATOMIC_BACKEND_ID

    def __init__(
        self,
        *,
        filesystem: WindowsSecureFilesystemBackend,
        locking: WindowsCrossProcessLockingBackend,
    ) -> None:
        if not isinstance(filesystem, WindowsSecureFilesystemBackend):
            raise TypeError("Windows atomic filesystem backend is invalid")
        if not isinstance(locking, WindowsCrossProcessLockingBackend):
            raise TypeError("Windows atomic locking backend is invalid")
        self._filesystem = filesystem
        self._locking = locking

    @property
    def filesystem(self) -> WindowsSecureFilesystemBackend:
        """Return the exact filesystem backend bound into this service."""

        return self._filesystem

    def ensure_private_directory(self, path: Path) -> Path:
        """Create missing descendants beneath the deepest private existing parent."""

        selected = validate_windows_drive_path(path)
        if not selected.components:
            raise WindowsPathSecurityError(
                "Windows atomic state directory cannot be a drive root"
            )
        missing: list[str] = []
        current = selected
        pinned: PinnedWindowsPath | None = None
        while current.components:
            try:
                pinned = self._filesystem.pin_directory(
                    current.canonical,
                    require_private=True,
                )
                break
            except FileNotFoundError:
                missing.append(current.components[-1])
                current = type(current)(
                    drive=current.drive,
                    components=current.components[:-1],
                )
        if pinned is None:
            raise WindowsPathSecurityError(
                "Windows atomic state requires an existing private parent"
            )
        try:
            for component in reversed(missing):
                with pinned.create_private_directory(component) as created:
                    created.validate()
                next_path = Path(str(pinned.path).rstrip("\\") + "\\" + component)
                following = self._filesystem.pin_directory(
                    next_path,
                    require_private=True,
                )
                pinned.flush_directory()
                pinned.close()
                pinned = following
            pinned.validate()
            pinned.flush_directory()
            return Path(pinned.path)
        finally:
            pinned.close()

    def open_transaction(
        self,
        path: Path,
        *,
        max_bytes: int,
        create: bool,
    ) -> WindowsAtomicStateTransaction:
        """Return an unentered target-specific native transaction."""

        return WindowsAtomicStateTransaction(
            backend=self,
            path=path,
            max_bytes=max_bytes,
            create=create,
        )


class WindowsAtomicStateTransaction:
    """One lock-held, recovered Windows state-file transaction."""

    def __init__(
        self,
        *,
        backend: WindowsAtomicPublicationRecoveryBackend,
        path: Path,
        max_bytes: int,
        create: bool,
    ) -> None:
        _validate_limit(max_bytes)
        selected = validate_windows_drive_path(path)
        if not selected.components:
            raise WindowsPathSecurityError(
                "Windows atomic state path must identify a file"
            )
        self._backend = backend
        self._selected = selected
        self._path = Path(selected.canonical)
        parent_selected = type(selected)(
            drive=selected.drive,
            components=selected.components[:-1],
        )
        self._parent_path = Path(parent_selected.canonical)
        self._max_bytes = max_bytes
        self._create = bool(create)
        target_hash = hashlib.sha256(
            selected.components[-1].encode("utf-16-le")
        ).hexdigest()[:32]
        self._lock_name = f".master-agent-{target_hash}.lock"
        self._ledger_name = f".master-agent-{target_hash}.ledger"
        self._parent: PinnedWindowsPath | None = None
        self._lock_pin: PinnedWindowsPath | None = None
        self._lock_handle: Any | None = None
        self._identity: AtomicStateIdentity | None = None
        self._snapshot: _WindowsStateSnapshot | None = None
        self._ledger: _LedgerSnapshot | None = None
        self._entered = False
        self._closed = False
        self._thread_lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def identity(self) -> AtomicStateIdentity | None:
        with self._thread_lock:
            self._require_entered()
            return self._identity

    def __enter__(self) -> Self:
        with self._thread_lock:
            if self._entered or self._closed:
                raise RuntimeError("Windows atomic transaction cannot be re-entered")
            if self._create:
                self._backend.ensure_private_directory(self._parent_path)
            parent = self._backend.filesystem.pin_directory(
                self._parent_path,
                require_private=True,
            )
            lock_pin: PinnedWindowsPath | None = None
            lock_handle: Any | None = None
            acquired = False
            try:
                lock_pin = self._open_lock(parent)
                lock_handle = lock_pin.duplicate_target_handle()
                self._backend._locking.acquire_handle(
                    lock_handle.value,
                    mode=LockMode.EXCLUSIVE,
                )
                acquired = True
                parent.validate()
                lock_pin.validate()
                self._parent = parent
                self._lock_pin = lock_pin
                self._lock_handle = lock_handle
                self._entered = True
                self._snapshot = self._read_target(missing_ok=True)
                self._ledger = self._read_ledger(missing_ok=True)
                self._recover()
                self._identity = (
                    None if self._snapshot is None else self._snapshot.identity
                )
                return self
            except BaseException:
                self._entered = False
                self._parent = None
                self._lock_pin = None
                self._lock_handle = None
                if acquired and lock_handle is not None:
                    try:
                        self._backend._locking.release_handle(lock_handle.value)
                    except OSError:
                        pass
                if lock_handle is not None:
                    lock_handle.close()
                if lock_pin is not None:
                    lock_pin.close()
                parent.close()
                raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        """Release the native lock and every retained handle exactly once."""

        with self._thread_lock:
            if self._closed:
                return
            handle = self._lock_handle
            lock_pin = self._lock_pin
            parent = self._parent
            self._lock_handle = None
            self._lock_pin = None
            self._parent = None
            self._entered = False
            self._closed = True
        if handle is not None:
            try:
                self._backend._locking.release_handle(handle.value)
            except OSError:
                pass
            handle.close()
        if lock_pin is not None:
            lock_pin.close()
        if parent is not None:
            parent.close()

    def read_bytes(self) -> bytes | None:
        """Return the exact recovered generation after a fresh revalidation."""

        with self._thread_lock:
            self._require_entered()
            observed = self._read_target(missing_ok=True)
            if _snapshot_identity(observed) != self._identity:
                raise ConfigurationError("Windows atomic state generation changed")
            self._snapshot = observed
            return None if observed is None else observed.payload

    def publish_bytes(
        self,
        payload: bytes,
        *,
        expected: AtomicStateIdentity | None,
    ) -> AtomicStateIdentity:
        """Prepare, replace, verify, and commit one bounded generation."""

        with self._thread_lock:
            parent = self._require_entered()
            if not isinstance(payload, bytes):
                raise TypeError("Windows atomic state payload must be bytes")
            if len(payload) > self._max_bytes:
                raise ConfigurationError(
                    "Windows atomic state payload exceeds its safety limit"
                )
            observed = self._read_target(missing_ok=True)
            if (
                expected != self._identity
                or _snapshot_identity(observed) != expected
                or _snapshot_identity(self._snapshot) != expected
            ):
                raise ConfigurationError(
                    "Windows atomic state generation changed before publication"
                )
            temporary_name = f".master-agent-tmp-{secrets.token_hex(16)}"
            created: CreatedWindowsFile | None = None
            prepared = False
            try:
                created = parent.create_private_file(
                    temporary_name,
                    max_bytes=self._max_bytes,
                )
                created.write_bytes(payload)
                new_identity = _atomic_identity(
                    created.identity,
                    payload,
                )
                prepared_state = _LedgerState(
                    committed=expected,
                    operation="replace",
                    pending_old=expected,
                    pending_new=new_identity,
                )
                self._ledger = self._replace_ledger(
                    expected=self._ledger,
                    state=prepared_state,
                )
                prepared = True
                parent.validate()
                current = self._read_target(missing_ok=True)
                if _snapshot_identity(current) != expected:
                    raise ConfigurationError(
                        "Windows atomic state changed during publication"
                    )
                expected_native = None if current is None else current.native_identity
                published_native = created.replace_into(
                    parent,
                    self._selected.components[-1],
                    expected_identity=expected_native,
                )
                created.publish()
                published = self._read_target(missing_ok=False)
                if (
                    published is None
                    or published.native_identity != published_native
                    or published.identity != new_identity
                    or published.payload != payload
                ):
                    raise WindowsAtomicStateIndeterminate(
                        "Windows atomic replacement could not be verified"
                    )
                self._ledger = self._replace_ledger(
                    expected=self._ledger,
                    state=_LedgerState(committed=new_identity),
                )
                self._snapshot = published
                self._identity = new_identity
                return new_identity
            except BaseException:
                if prepared:
                    # A fresh transaction must reconcile the exact public old/new
                    # generation before any further mutation.
                    self._snapshot = None
                    self._identity = None
                raise
            finally:
                if created is not None:
                    created.close()

    def remove(self, *, expected: AtomicStateIdentity) -> bool:
        """Record and remove only the exact retained public generation."""

        with self._thread_lock:
            parent = self._require_entered()
            observed = self._read_target(missing_ok=True)
            if (
                self._identity != expected
                or observed is None
                or observed.identity != expected
            ):
                raise ConfigurationError(
                    "Windows atomic state generation changed before removal"
                )
            self._ledger = self._replace_ledger(
                expected=self._ledger,
                state=_LedgerState(
                    committed=expected,
                    operation="remove",
                    pending_old=expected,
                ),
            )
            try:
                with parent.pin_child(
                    self._selected.components[-1],
                    kind=WindowsObjectKind.FILE,
                    require_private=True,
                ) as target:
                    if target.identity != observed.native_identity:
                        raise ConfigurationError(
                            "Windows atomic state identity changed before removal"
                        )
                    target.delete_exact()
                parent.flush_directory()
                if self._read_target(missing_ok=True) is not None:
                    raise WindowsAtomicStateIndeterminate(
                        "Windows atomic state removal is indeterminate"
                    )
                self._ledger = self._replace_ledger(
                    expected=self._ledger,
                    state=_LedgerState(committed=None),
                )
                self._snapshot = None
                self._identity = None
                return True
            except BaseException:
                self._snapshot = None
                self._identity = None
                raise

    def _open_lock(self, parent: PinnedWindowsPath) -> PinnedWindowsPath:
        try:
            lock = parent.pin_child(
                self._lock_name,
                kind=WindowsObjectKind.FILE,
                require_private=True,
            )
        except FileNotFoundError:
            if not self._create:
                raise ConfigurationError(
                    "Windows atomic state has no trusted transaction lock"
                ) from None
            try:
                parent.publish_private_file(
                    self._lock_name,
                    b"",
                    max_bytes=0,
                )
                parent.flush_directory()
            except FileExistsError:
                pass
            lock = parent.pin_child(
                self._lock_name,
                kind=WindowsObjectKind.FILE,
                require_private=True,
            )
        if lock.read_bytes(0) != b"":
            lock.close()
            raise ConfigurationError(
                "Windows atomic state transaction lock must remain content-free"
            )
        return lock

    def _read_target(self, *, missing_ok: bool) -> _WindowsStateSnapshot | None:
        parent = self._require_entered()
        try:
            child = parent.pin_child(
                self._selected.components[-1],
                kind=WindowsObjectKind.FILE,
                require_private=True,
            )
        except FileNotFoundError:
            if missing_ok:
                return None
            raise ConfigurationError(
                "Windows atomic state file does not exist"
            ) from None
        with child:
            payload = child.read_bytes(self._max_bytes)
            child.validate()
            return _WindowsStateSnapshot(
                payload=payload,
                identity=_atomic_identity(child.identity, payload),
                native_identity=child.identity,
            )

    def _read_ledger(self, *, missing_ok: bool) -> _LedgerSnapshot | None:
        parent = self._require_entered()
        try:
            child = parent.pin_child(
                self._ledger_name,
                kind=WindowsObjectKind.FILE,
                require_private=True,
            )
        except FileNotFoundError:
            if missing_ok:
                return None
            raise ConfigurationError(
                "Windows atomic state has no trusted recovery ledger"
            ) from None
        with child:
            payload = child.read_bytes(_MAX_LEDGER_BYTES)
            child.validate()
            return _LedgerSnapshot(
                payload=payload,
                native_identity=child.identity,
                state=_parse_ledger(payload),
            )

    def _replace_ledger(
        self,
        *,
        expected: _LedgerSnapshot | None,
        state: _LedgerState,
    ) -> _LedgerSnapshot:
        parent = self._require_entered()
        payload = _format_ledger(state)
        observed = self._read_ledger(missing_ok=True)
        if not _ledger_matches(observed, expected):
            raise ConfigurationError(
                "Windows atomic recovery ledger changed before publication"
            )
        temporary_name = f".master-agent-ledger-{secrets.token_hex(16)}"
        with parent.create_private_file(
            temporary_name,
            max_bytes=_MAX_LEDGER_BYTES,
        ) as created:
            created.write_bytes(payload)
            expected_native = created.replace_into(
                parent,
                self._ledger_name,
                expected_identity=(
                    None if expected is None else expected.native_identity
                ),
            )
            created.publish()
        published = self._read_ledger(missing_ok=False)
        if (
            published is None
            or published.native_identity != expected_native
            or published.payload != payload
            or published.state != state
        ):
            raise WindowsAtomicStateIndeterminate(
                "Windows atomic recovery ledger publication is indeterminate"
            )
        return published

    def _recover(self) -> None:
        current = self._snapshot
        ledger = self._ledger
        if ledger is None:
            if current is None:
                return
            if not self._create:
                raise ConfigurationError(
                    "Windows atomic state has no trusted recovery ledger"
                )
            self._ledger = self._replace_ledger(
                expected=None,
                state=_LedgerState(committed=current.identity),
            )
            return
        state = ledger.state
        current_identity = _snapshot_identity(current)
        if state.operation == "replace":
            if current_identity == state.pending_new:
                resolved = state.pending_new
            elif current_identity == state.pending_old:
                resolved = state.pending_old
            else:
                raise WindowsAtomicStateIndeterminate(
                    "Windows atomic replacement does not match its recorded generations"
                )
            self._ledger = self._replace_ledger(
                expected=ledger,
                state=_LedgerState(committed=resolved),
            )
            state = self._ledger.state
        elif state.operation == "remove":
            if current_identity is None:
                resolved = None
            elif current_identity == state.pending_old:
                resolved = state.pending_old
            else:
                raise WindowsAtomicStateIndeterminate(
                    "Windows atomic removal does not match its recorded generation"
                )
            self._ledger = self._replace_ledger(
                expected=ledger,
                state=_LedgerState(committed=resolved),
            )
            state = self._ledger.state
        if current_identity != state.committed:
            raise WindowsAtomicStateIndeterminate(
                "Windows atomic state differs from its committed generation"
            )

    def _require_entered(self) -> PinnedWindowsPath:
        if not self._entered or self._closed or self._parent is None:
            raise RuntimeError("Windows atomic state transaction is not entered")
        self._parent.validate()
        if self._lock_pin is None or self._lock_handle is None:
            raise RuntimeError("Windows atomic state transaction lock is missing")
        self._lock_pin.validate()
        return self._parent


def _atomic_identity(
    native: WindowsObjectIdentity,
    payload: bytes,
) -> AtomicStateIdentity:
    if native.kind is not WindowsObjectKind.FILE:
        raise WindowsPathSecurityError("Windows atomic state is not a regular file")
    return AtomicStateIdentity(
        object_identity=PlatformObjectIdentity.from_windows(
            kind=FilesystemObjectKind.FILE,
            volume_serial=native.volume_serial_hex,
            file_id=native.file_id_hex,
            owner_sid=native.owner_sid,
            dacl_sha256=native.dacl_sha256,
            trust_policy_sha256=native.trust_policy_sha256,
        ),
        content_sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def _snapshot_identity(
    value: _WindowsStateSnapshot | None,
) -> AtomicStateIdentity | None:
    return None if value is None else value.identity


def _identity_to_dict(value: AtomicStateIdentity | None) -> object:
    if value is None:
        return None
    return {
        "object_identity": value.object_identity.to_dict(),
        "content_sha256": value.content_sha256,
        "size": value.size,
    }


def _identity_from_dict(value: object) -> AtomicStateIdentity | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "object_identity",
        "content_sha256",
        "size",
    }:
        raise ConfigurationError("Windows atomic recovery ledger is malformed")
    try:
        object_value = value["object_identity"]
        if not isinstance(object_value, Mapping):
            raise TypeError("object identity is not a mapping")
        return AtomicStateIdentity(
            object_identity=PlatformObjectIdentity.from_dict(object_value),
            content_sha256=str(value["content_sha256"]),
            size=value["size"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigurationError(
            "Windows atomic recovery ledger is malformed"
        ) from error


def _format_ledger(state: _LedgerState) -> bytes:
    body = {
        "committed": _identity_to_dict(state.committed),
        "operation": state.operation,
        "pending_new": _identity_to_dict(state.pending_new),
        "pending_old": _identity_to_dict(state.pending_old),
        "schema": _LEDGER_SCHEMA,
    }
    canonical = json.dumps(
        body,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    document = {
        **body,
        "integrity_sha256": hashlib.sha256(_INTEGRITY_DOMAIN + canonical).hexdigest(),
    }
    payload = (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > _MAX_LEDGER_BYTES:
        raise ConfigurationError("Windows atomic recovery ledger exceeds its limit")
    return payload


def _parse_ledger(payload: bytes) -> _LedgerState:
    if not payload or len(payload) > _MAX_LEDGER_BYTES or not payload.endswith(b"\n"):
        raise ConfigurationError("Windows atomic recovery ledger is torn")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigurationError(
            "Windows atomic recovery ledger is malformed"
        ) from error
    expected_keys = {
        "committed",
        "integrity_sha256",
        "operation",
        "pending_new",
        "pending_old",
        "schema",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ConfigurationError("Windows atomic recovery ledger is malformed")
    integrity = value.pop("integrity_sha256")
    if value.get("schema") != _LEDGER_SCHEMA or not isinstance(integrity, str):
        raise ConfigurationError("Windows atomic recovery ledger is malformed")
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    expected = hashlib.sha256(_INTEGRITY_DOMAIN + canonical).hexdigest()
    if not secrets.compare_digest(integrity, expected):
        raise ConfigurationError(
            "Windows atomic recovery ledger integrity check failed"
        )
    operation = value["operation"]
    if operation is not None and not isinstance(operation, str):
        raise ConfigurationError("Windows atomic recovery ledger is malformed")
    try:
        return _LedgerState(
            committed=_identity_from_dict(value["committed"]),
            operation=operation,
            pending_old=_identity_from_dict(value["pending_old"]),
            pending_new=_identity_from_dict(value["pending_new"]),
        )
    except ValueError as error:
        raise ConfigurationError(
            "Windows atomic recovery ledger is inconsistent"
        ) from error


def _ledger_matches(
    observed: _LedgerSnapshot | None,
    expected: _LedgerSnapshot | None,
) -> bool:
    if observed is None or expected is None:
        return observed is expected
    return (
        observed.native_identity == expected.native_identity
        and observed.payload == expected.payload
        and observed.state == expected.state
    )


def _validate_limit(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("Windows atomic state byte limit must be an integer")
    if not 0 <= value <= MAX_WINDOWS_ATOMIC_STATE_BYTES:
        raise ValueError(
            "Windows atomic state byte limit must be between 0 and "
            f"{MAX_WINDOWS_ATOMIC_STATE_BYTES}"
        )


def probe_windows_atomic_backend(
    *,
    filesystem: WindowsSecureFilesystemBackend,
    locking: WindowsCrossProcessLockingBackend,
) -> None:
    """Validate the dependency types without touching a caller namespace."""

    WindowsAtomicPublicationRecoveryBackend(
        filesystem=filesystem,
        locking=locking,
    )
