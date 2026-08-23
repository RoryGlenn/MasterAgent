"""Native Windows secure-filesystem policy and handle-pinned paths.

This module is intentionally importable on every Python platform.  The Win32
adapter is imported only when a native operation is selected, which keeps
package inspection and configuration-only diagnostics platform neutral.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import cmp_to_key
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime.contracts import PlatformCapabilityUnavailable

WINDOWS_FILESYSTEM_BACKEND_ID = "windows-handle-acl-filesystem"
MAX_PINNED_READ_BYTES = 64 * 1024 * 1024

# Attribute values are stable Win32 ABI constants.  Cloud placeholders are
# rejected even when pinned because reading them can cause provider I/O.
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_PINNED = 0x00080000
FILE_ATTRIBUTE_UNPINNED = 0x00100000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
UNSAFE_WINDOWS_FILE_ATTRIBUTES = (
    FILE_ATTRIBUTE_REPARSE_POINT
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_PINNED
    | FILE_ATTRIBUTE_UNPINNED
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

INHERIT_ONLY_ACE = 0x08

_SUPPORTED_WINDOWS_ALLOW_ACE_TYPES = frozenset({0x00, 0x05})
_UNSUPPORTED_WINDOWS_ALLOW_ACE_TYPES = frozenset({0x04, 0x09, 0x0B})
_KNOWN_WINDOWS_NON_ALLOW_ACE_TYPES = frozenset(
    {
        0x01,
        0x02,
        0x03,
        0x06,
        0x07,
        0x08,
        0x0A,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
    }
)

# File/directory mutations plus standard and generic deletion/ACL ownership
# rights.  READ_CONTROL and SYNCHRONIZE are deliberately not classified as
# writes.  MAXIMUM_ALLOWED is rejected because it is not an exact fixed grant.
WINDOWS_DANGEROUS_WRITE_MASK = (
    0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000040  # FILE_DELETE_CHILD
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x02000000  # MAXIMUM_ALLOWED
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)

LOCAL_SYSTEM_SID = "S-1-5-18"
BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"
OWNER_RIGHTS_SID = "S-1-3-4"
TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_CONTEXTUAL_SECURITY_SIDS = frozenset(
    {
        "S-1-3-0",  # CREATOR OWNER
        "S-1-3-1",  # CREATOR GROUP
        "S-1-3-2",  # CREATOR OWNER SERVER
        "S-1-3-3",  # CREATOR GROUP SERVER
        OWNER_RIGHTS_SID,
    }
)

# On retained directories, these two object-specific rights permit creating an
# unrelated child but cannot replace, rename, delete, or mutate the selected
# descendant.  They remain forbidden on the selected target/mutable root.
WINDOWS_ANCESTOR_CHILD_CREATE_MASK = 0x00000002 | 0x00000004

_SID_PATTERN = re.compile(r"S-([0-9]+)-([0-9]+)((?:-[0-9]+)+)", re.ASCII)
_DRIVE_PATH_PATTERN = re.compile(r"([A-Za-z]):[\\/](.*)", re.DOTALL)
_RESERVED_BASENAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        "CLOCK$",
        *(f"COM{suffix}" for suffix in "123456789¹²³"),
        *(f"LPT{suffix}" for suffix in "123456789¹²³"),
    }
)
_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"|?*')
_MAX_WINDOWS_PATH_UTF16_UNITS = 32_767
_MAX_WINDOWS_COMPONENT_UTF16_UNITS = 255
_MAX_DUPLICATE_DESCRIPTOR = 65_535


class WindowsPathSecurityError(ConfigurationError):
    """A Windows path failed a native identity or access-control invariant."""


class WindowsObjectKind(StrEnum):
    """Exact native object kind admitted by a pinned path."""

    FILE = "file"
    DIRECTORY = "directory"


class WindowsDaclPolicy(StrEnum):
    """Context-sensitive ACL policy for one retained handle."""

    ANCESTOR = "ancestor"
    TARGET_PUBLIC = "target-public"
    TARGET_PRIVATE = "target-private"


@dataclass(frozen=True, slots=True)
class ValidatedWindowsPath:
    """Strict absolute drive path safe to pass through the Win32 namespace."""

    drive: str
    components: tuple[str, ...]

    @property
    def root(self) -> str:
        """Return the canonical drive root."""

        return f"{self.drive}:\\"

    @property
    def canonical(self) -> str:
        """Return the ordinary canonical DOS path."""

        if not self.components:
            return self.root
        return self.root + "\\".join(self.components)

    @property
    def extended(self) -> str:
        """Return the validated extended-length Win32 spelling."""

        return "\\\\?\\" + self.canonical

    def prefixes(self) -> tuple[str, ...]:
        """Return the root and each descendant prefix in lexical order."""

        values = [self.root]
        for index in range(1, len(self.components) + 1):
            values.append(self.root + "\\".join(self.components[:index]))
        return tuple(values)


@dataclass(frozen=True, slots=True)
class WindowsAccessAllowedAce:
    """One parsed access-allowed ACE used by the pure DACL evaluator."""

    sid: str
    access_mask: int
    flags: int = 0
    ace_type: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "sid", canonicalize_windows_sid(self.sid))
        if isinstance(self.access_mask, bool) or not isinstance(self.access_mask, int):
            raise TypeError("Windows ACE access mask must be an integer")
        if not 0 <= self.access_mask <= 0xFFFFFFFF:
            raise ValueError("Windows ACE access mask is out of range")
        if isinstance(self.flags, bool) or not isinstance(self.flags, int):
            raise TypeError("Windows ACE flags must be an integer")
        if not 0 <= self.flags <= 0xFF:
            raise ValueError("Windows ACE flags are out of range")
        if isinstance(self.ace_type, bool) or not isinstance(self.ace_type, int):
            raise TypeError("Windows ACE type must be an integer")
        if not 0 <= self.ace_type <= 0xFF:
            raise ValueError("Windows ACE type is out of range")


@dataclass(frozen=True, slots=True)
class WindowsDacl:
    """Exact self-relative DACL bytes plus parsed access-allowed entries."""

    raw: bytes | None
    valid: bool
    allow_aces: tuple[WindowsAccessAllowedAce, ...]

    def __post_init__(self) -> None:
        if self.raw is not None and not isinstance(self.raw, bytes):
            raise TypeError("Windows DACL bytes are invalid")
        if not isinstance(self.valid, bool):
            raise TypeError("Windows DACL validity must be a boolean")
        if not isinstance(self.allow_aces, tuple):
            raise TypeError("Windows DACL ACE collection must be a tuple")
        if any(
            not isinstance(item, WindowsAccessAllowedAce) for item in self.allow_aces
        ):
            raise TypeError("Windows DACL contains an invalid ACE")


@dataclass(frozen=True, slots=True)
class WindowsDaclEvaluation:
    """Secret-free result from exact Windows DACL admission."""

    trusted: bool
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.trusted == (self.reason is not None):
            raise ValueError("Windows DACL evaluation result is inconsistent")


@dataclass(frozen=True, slots=True)
class NativeWindowsVolume:
    """Native volume facts returned by the lazy Win32 adapter."""

    drive_type: int
    serial_number: int
    filesystem: str
    maximum_component_length: int
    filesystem_flags: int

    def __post_init__(self) -> None:
        integer_values = (
            self.drive_type,
            self.serial_number,
            self.maximum_component_length,
            self.filesystem_flags,
        )
        if any(
            isinstance(item, bool) or not isinstance(item, int)
            for item in integer_values
        ):
            raise TypeError("Windows volume information is invalid")
        if not self.filesystem or self.filesystem != self.filesystem.strip():
            raise ValueError("Windows volume filesystem identity is invalid")


@dataclass(frozen=True, slots=True)
class NativeWindowsFileSnapshot:
    """Handle-derived file facts with a stable 128-bit identifier."""

    attributes: int
    is_directory: bool
    size: int
    volume_serial_number: int
    file_id: bytes

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("Windows file size is invalid")
        if not isinstance(self.file_id, bytes):
            raise TypeError("Windows file identifier must be bytes")
        if len(self.file_id) != 16:
            raise ValueError("Windows file identifier must contain 128 bits")


@dataclass(frozen=True, slots=True)
class NativeWindowsSecurity:
    """Owner and DACL facts returned by the lazy Win32 adapter."""

    owner_sid: str
    dacl: WindowsDacl
    dacl_protected: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "owner_sid", canonicalize_windows_sid(self.owner_sid))
        if not isinstance(self.dacl_protected, bool):
            raise TypeError("Windows DACL protection flag must be a boolean")


@dataclass(frozen=True, slots=True)
class WindowsObjectIdentity:
    """Stable handle identity and security fingerprint for revalidation."""

    volume_serial_number: int
    file_id: bytes
    owner_sid: str
    dacl_sha256: str
    trust_policy_sha256: str
    kind: WindowsObjectKind

    def __post_init__(self) -> None:
        if isinstance(self.volume_serial_number, bool) or not isinstance(
            self.volume_serial_number, int
        ):
            raise TypeError("Windows volume serial number must be an integer")
        if not 0 <= self.volume_serial_number <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Windows volume serial number is out of range")
        if not isinstance(self.file_id, bytes):
            raise TypeError("Windows file identifier must be bytes")
        if len(self.file_id) != 16:
            raise ValueError("Windows file identifier must contain 128 bits")
        object.__setattr__(self, "owner_sid", canonicalize_windows_sid(self.owner_sid))
        if not re.fullmatch(r"[0-9a-f]{64}", self.dacl_sha256):
            raise ValueError("Windows DACL digest is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.trust_policy_sha256):
            raise ValueError("Windows trust-policy digest is invalid")
        if not isinstance(self.kind, WindowsObjectKind):
            raise TypeError("Windows object kind is invalid")

    @property
    def volume_serial_hex(self) -> str:
        """Return the fixed-width volume serial for structured conversion."""

        return f"{self.volume_serial_number:016x}"

    @property
    def file_id_hex(self) -> str:
        """Return the 128-bit file identifier as lowercase hexadecimal."""

        return self.file_id.hex()

    def to_dict(self) -> dict[str, object]:
        """Return JSON-ready identity values without dropping native precision."""

        return {
            "volume_serial_number": self.volume_serial_number,
            "volume_serial_hex": self.volume_serial_hex,
            "file_id_hex": self.file_id_hex,
            "owner_sid": self.owner_sid,
            "dacl_sha256": self.dacl_sha256,
            "trust_policy_sha256": self.trust_policy_sha256,
            "kind": str(self.kind),
        }


# Retain the narrower issue-#98-era name for callers that adopted an early
# review branch while making the object-kind-aware identity canonical.
WindowsFileIdentity = WindowsObjectIdentity


class _WindowsFilesystemApi(Protocol):
    """Minimum native adapter used by the handle-pinned implementation."""

    def current_user_sid(self) -> str: ...

    def current_token_is_member(self, sid: str) -> bool: ...

    def volume_information(self, root: str) -> NativeWindowsVolume: ...

    def open_path(
        self,
        path: str,
        *,
        directory: bool,
        readable: bool,
        writable: bool = False,
        replacement_handoff: bool = False,
        deletable: bool = False,
    ) -> int: ...

    def close_handle(self, handle: int) -> None: ...

    def duplicate_handle(self, handle: int) -> int: ...

    def file_snapshot(self, handle: int) -> NativeWindowsFileSnapshot: ...

    def file_security(self, handle: int) -> NativeWindowsSecurity: ...

    def directory_is_case_sensitive(self, handle: int) -> bool: ...

    def final_path(self, handle: int) -> str: ...

    def directory_names(self, path: str) -> Sequence[str]: ...

    def compare_ordinal_ignore_case(self, left: str, right: str) -> int: ...

    def rewind_file(self, handle: int) -> None: ...

    def read_file(self, handle: int, maximum_bytes: int) -> bytes: ...

    def create_private_file(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int: ...

    def create_private_directory(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int: ...

    def write_file(self, handle: int, payload: bytes) -> int: ...

    def flush_file(self, handle: int) -> None: ...

    def flush_directory(self, handle: int) -> None: ...

    def replace_file(
        self,
        source_handle: int,
        parent_handle: int,
        destination_name: str,
        *,
        replace_existing: bool,
    ) -> None: ...

    def set_delete_on_close(self, handle: int, *, enabled: bool) -> None: ...


def canonicalize_windows_sid(value: str) -> str:
    """Validate and canonicalize a textual Windows SID without native calls."""

    if not isinstance(value, str):
        raise TypeError("Windows SID must be text")
    match = _SID_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("Windows SID is invalid")
    revision = int(match.group(1), 10)
    authority = int(match.group(2), 10)
    subauthorities = tuple(int(item, 10) for item in match.group(3)[1:].split("-"))
    if revision != 1 or not 0 <= authority < (1 << 48):
        raise ValueError("Windows SID is invalid")
    if not 1 <= len(subauthorities) <= 15 or any(
        item < 0 or item > 0xFFFFFFFF for item in subauthorities
    ):
        raise ValueError("Windows SID is invalid")
    return (
        "S-1-" + str(authority) + "-" + "-".join(str(item) for item in subauthorities)
    )


def _canonicalize_trusted_principal_sids(values: Iterable[str]) -> tuple[str, ...]:
    """Normalize configured principals and reject contextual SID aliases."""

    normalized = tuple(canonicalize_windows_sid(item) for item in values)
    if _CONTEXTUAL_SECURITY_SIDS.intersection(normalized):
        raise ValueError(
            "Windows contextual SID aliases cannot be configured as trusted principals"
        )
    return normalized


def validate_windows_drive_path(path: str | os.PathLike[str]) -> ValidatedWindowsPath:
    """Reject alternate namespaces and return one strict absolute drive path."""

    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise TypeError("Windows secure path must be text")
    if not raw or "\x00" in raw:
        raise WindowsPathSecurityError("Windows secure path has unsafe syntax")
    try:
        encoded = raw.encode("utf-16-le", errors="strict")
    except UnicodeEncodeError as exc:
        raise WindowsPathSecurityError("Windows secure path has unsafe syntax") from exc
    if len(encoded) // 2 > _MAX_WINDOWS_PATH_UTF16_UNITS:
        raise WindowsPathSecurityError("Windows secure path exceeds the length limit")
    if raw.startswith(("\\\\", "\\?\\", "\\.\\", "\\??\\")):
        raise WindowsPathSecurityError(
            "Windows secure path must use an absolute local drive"
        )
    match = _DRIVE_PATH_PATTERN.fullmatch(raw)
    if match is None:
        raise WindowsPathSecurityError(
            "Windows secure path must use an absolute local drive"
        )
    drive = match.group(1).upper()
    tail = match.group(2).replace("/", "\\")
    if not tail:
        return ValidatedWindowsPath(drive=drive, components=())
    components = tuple(tail.split("\\"))
    if any(not component for component in components):
        raise WindowsPathSecurityError("Windows secure path has unsafe syntax")
    for component in components:
        _validate_windows_component(component)
    return ValidatedWindowsPath(drive=drive, components=components)


def evaluate_windows_dacl(
    *,
    owner_sid: str,
    dacl: WindowsDacl,
    trusted_sids: Iterable[str],
    require_private: bool | None = None,
    policy: WindowsDaclPolicy | str | None = None,
) -> WindowsDaclEvaluation:
    """Reject non-exact DACLs and untrusted write-capable allow entries."""

    if require_private is not None and not isinstance(require_private, bool):
        raise TypeError("Windows DACL privacy requirement must be a boolean or None")
    selected_policy = (
        _coerce_dacl_policy(policy)
        if policy is not None
        else (
            WindowsDaclPolicy.TARGET_PRIVATE
            if require_private is not False
            else WindowsDaclPolicy.TARGET_PUBLIC
        )
    )
    if require_private is not None:
        requested_policy = (
            WindowsDaclPolicy.TARGET_PRIVATE
            if require_private
            else WindowsDaclPolicy.TARGET_PUBLIC
        )
        if selected_policy is not requested_policy:
            raise ValueError("Windows DACL policy and privacy requirement disagree")
    try:
        owner = canonicalize_windows_sid(owner_sid)
        trusted = frozenset(canonicalize_windows_sid(item) for item in trusted_sids)
    except (TypeError, ValueError):
        return WindowsDaclEvaluation(False, "Windows DACL contains an invalid SID")
    if _CONTEXTUAL_SECURITY_SIDS.intersection(trusted):
        return WindowsDaclEvaluation(
            False,
            "Windows trust policy treats a contextual SID as a standalone principal",
        )
    if dacl.raw is None:
        return WindowsDaclEvaluation(False, "Windows DACL is NULL")
    if not dacl.valid:
        return WindowsDaclEvaluation(False, "Windows DACL is invalid")
    if owner not in trusted:
        return WindowsDaclEvaluation(False, "Windows file owner SID is not trusted")
    for ace in dacl.allow_aces:
        if ace.flags & INHERIT_ONLY_ACE:
            continue
        # OWNER RIGHTS is a well-known alias for the already-validated object
        # owner, not an independently authorized principal.  Windows and
        # CPython use it to express private 0o700-style owner access.  Any
        # owner change is still rejected above and during every revalidation.
        if ace.sid == OWNER_RIGHTS_SID and owner in trusted:
            continue
        if ace.sid in trusted:
            continue
        dangerous_mask = WINDOWS_DANGEROUS_WRITE_MASK
        if selected_policy is WindowsDaclPolicy.ANCESTOR:
            dangerous_mask &= ~WINDOWS_ANCESTOR_CHILD_CREATE_MASK
        if ace.access_mask & dangerous_mask:
            return WindowsDaclEvaluation(
                False,
                "Windows DACL grants write-capable access to an untrusted SID",
            )
        if selected_policy is WindowsDaclPolicy.TARGET_PRIVATE and ace.access_mask:
            return WindowsDaclEvaluation(
                False,
                "Windows private DACL grants access to an untrusted SID",
            )
    return WindowsDaclEvaluation(True)


def windows_trust_policy_sha256(
    trusted_sids: Iterable[str],
    *,
    policy: WindowsDaclPolicy | str,
) -> str:
    """Hash the exact SID set and ancestor/public/private admission mode."""

    selected_policy = _coerce_dacl_policy(policy)
    normalized = tuple(sorted(_canonicalize_trusted_principal_sids(trusted_sids)))
    payload = b"master-agent-windows-trust-v2\0"
    payload += selected_policy.value.encode("ascii") + b"\0"
    payload += b"\0".join(item.encode("ascii") for item in normalized)
    return hashlib.sha256(payload).hexdigest()


def parse_windows_ace_header(header: bytes) -> tuple[int, int, int]:
    """Parse and classify one exact four-byte ACE header without native calls."""

    if not isinstance(header, bytes):
        raise TypeError("Windows ACE header must be bytes")
    if len(header) != 4:
        raise WindowsPathSecurityError("Windows DACL contains an invalid ACE header")
    ace_type = header[0]
    flags = header[1]
    ace_size = int.from_bytes(header[2:4], "little")
    if ace_size < 8:
        raise WindowsPathSecurityError("Windows DACL contains an invalid ACE")
    if ace_type in _UNSUPPORTED_WINDOWS_ALLOW_ACE_TYPES:
        raise WindowsPathSecurityError(
            "Windows DACL contains an unsupported access-allowed ACE"
        )
    if (
        ace_type not in _SUPPORTED_WINDOWS_ALLOW_ACE_TYPES
        and ace_type not in _KNOWN_WINDOWS_NON_ALLOW_ACE_TYPES
    ):
        raise WindowsPathSecurityError("Windows DACL contains an unknown ACE type")
    return ace_type, flags, ace_size


def windows_ace_type_is_supported_allow(ace_type: int) -> bool:
    """Return whether an already-validated ACE type is an exact allow form."""

    if isinstance(ace_type, bool) or not isinstance(ace_type, int):
        raise TypeError("Windows ACE type must be an integer")
    if not 0 <= ace_type <= 0xFF:
        raise ValueError("Windows ACE type is out of range")
    return ace_type in _SUPPORTED_WINDOWS_ALLOW_ACE_TYPES


def windows_ace_sid_length(raw_ace: bytes, *, sid_offset: int) -> int:
    """Return a bounded SID length without reading beyond one copied ACE."""

    if not isinstance(raw_ace, bytes):
        raise TypeError("Windows ACE bytes must be bytes")
    if isinstance(sid_offset, bool) or not isinstance(sid_offset, int):
        raise TypeError("Windows ACE SID offset must be an integer")
    if sid_offset < 0 or sid_offset + 8 > len(raw_ace):
        raise WindowsPathSecurityError("Windows DACL contains a truncated SID")
    revision = raw_ace[sid_offset]
    subauthority_count = raw_ace[sid_offset + 1]
    if revision != 1 or subauthority_count > 15:
        raise WindowsPathSecurityError("Windows DACL contains an invalid SID")
    sid_length = 8 + 4 * subauthority_count
    if sid_offset + sid_length > len(raw_ace):
        raise WindowsPathSecurityError("Windows DACL contains a truncated SID")
    return sid_length


def windows_file_attributes_are_safe(attributes: int) -> bool:
    """Return whether file attributes avoid reparse, cloud, and offline state."""

    if isinstance(attributes, bool) or not isinstance(attributes, int):
        raise TypeError("Windows file attributes must be an integer")
    if not 0 <= attributes <= 0xFFFFFFFF:
        raise ValueError("Windows file attributes are out of range")
    return not bool(attributes & UNSAFE_WINDOWS_FILE_ATTRIBUTES)


def build_protected_windows_sddl(
    *,
    owner_sid: str,
    trusted_sids: Iterable[str],
) -> str:
    """Build the immutable protected full-control DACL used at file creation."""

    owner = canonicalize_windows_sid(owner_sid)
    trusted = frozenset(_canonicalize_trusted_principal_sids(trusted_sids))
    if owner not in trusted:
        raise ValueError("Windows file owner SID must be part of the trust policy")
    ordered = (owner, *sorted(trusted - {owner}))
    return "O:" + owner + "D:P" + "".join(f"(A;;FA;;;{sid})" for sid in ordered)


class WindowsHandle:
    """Owned Win32 handle with idempotent close and safe native duplication."""

    __slots__ = ("_api", "_closed", "_handle", "_lock")

    def __init__(self, api: _WindowsFilesystemApi, handle: int) -> None:
        if isinstance(handle, bool) or not isinstance(handle, int) or handle <= 0:
            raise ValueError("Windows handle is invalid")
        self._api = api
        self._handle = handle
        self._closed = False
        self._lock = threading.RLock()

    @property
    def value(self) -> int:
        """Return the live raw handle value for bounded backend operations."""

        with self._lock:
            if self._closed:
                raise ValueError("Windows handle is closed")
            return self._handle

    @property
    def closed(self) -> bool:
        """Return whether ownership has already been released."""

        with self._lock:
            return self._closed

    def duplicate(self) -> WindowsHandle:
        """Create an independently owned non-inheritable native handle."""

        with self._lock:
            return WindowsHandle(self._api, self._api.duplicate_handle(self.value))

    def close(self) -> None:
        """Close this owned handle exactly once."""

        with self._lock:
            if self._closed:
                return
            handle = self._handle
            self._closed = True
        self._api.close_handle(handle)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if hasattr(self, "_lock"):
            try:
                self.close()
            except OSError:
                return


class PinnedWindowsPath:
    """A target plus every retained ancestor handle and trusted identity."""

    __slots__ = (
        "_acl_policies",
        "_api",
        "_closed",
        "_handles",
        "_identities",
        "_is_directory",
        "_lock",
        "_path",
        "_require_private",
        "_sizes",
        "_trusted_sids",
    )

    def __init__(
        self,
        *,
        api: _WindowsFilesystemApi,
        path: ValidatedWindowsPath,
        handles: tuple[WindowsHandle, ...],
        identities: tuple[WindowsObjectIdentity, ...],
        sizes: tuple[int, ...],
        trusted_sids: frozenset[str],
        is_directory: bool,
        require_private: bool,
        acl_policies: tuple[WindowsDaclPolicy, ...],
    ) -> None:
        if (
            not handles
            or len(handles) != len(identities)
            or len(handles) != len(sizes)
            or len(handles) != len(acl_policies)
        ):
            raise ValueError("Windows pinned path handle chain is incomplete")
        final_policy = (
            WindowsDaclPolicy.TARGET_PRIVATE
            if require_private
            else WindowsDaclPolicy.TARGET_PUBLIC
        )
        if acl_policies[-1] is not final_policy or any(
            policy is not WindowsDaclPolicy.ANCESTOR for policy in acl_policies[:-1]
        ):
            raise ValueError("Windows pinned path ACL policy chain is inconsistent")
        self._api = api
        self._path = path
        self._handles = handles
        self._identities = identities
        self._sizes = sizes
        self._trusted_sids = trusted_sids
        self._is_directory = is_directory
        self._require_private = require_private
        self._acl_policies = acl_policies
        self._closed = False
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        """Return the validated canonical path spelling."""

        return Path(self._path.canonical)

    @property
    def identity(self) -> WindowsObjectIdentity:
        """Return the target's stable open-time identity."""

        return self._identities[-1]

    @property
    def ancestor_identities(self) -> tuple[WindowsObjectIdentity, ...]:
        """Return root-through-parent identities retained with the target."""

        return self._identities[:-1]

    @property
    def is_directory(self) -> bool:
        """Return whether the target was admitted as a directory."""

        return self._is_directory

    @property
    def size(self) -> int:
        """Return the revalidated target size captured from its native handle."""

        with self._lock:
            self._require_open()
            snapshots = self._revalidate_locked()
            return snapshots[-1].size

    @property
    def closed(self) -> bool:
        """Return whether the complete handle chain has been released."""

        with self._lock:
            return self._closed

    def duplicate_target_handle(self) -> WindowsHandle:
        """Return an independently owned duplicate of the pinned target."""

        with self._lock:
            self._require_open()
            self._revalidate_locked()
            return self._handles[-1].duplicate()

    def duplicate(self) -> PinnedWindowsPath:
        """Duplicate the complete retained handle chain and its binding."""

        with self._lock:
            self._require_open()
            self._revalidate_locked()
            duplicated: list[WindowsHandle] = []
            try:
                duplicated = [handle.duplicate() for handle in self._handles]
                result = PinnedWindowsPath(
                    api=self._api,
                    path=self._path,
                    handles=tuple(duplicated),
                    identities=self._identities,
                    sizes=self._sizes,
                    trusted_sids=self._trusted_sids,
                    is_directory=self._is_directory,
                    require_private=self._require_private,
                    acl_policies=self._acl_policies,
                )
                result.validate()
                return result
            except BaseException:
                for handle in reversed(duplicated):
                    try:
                        handle.close()
                    except OSError:
                        pass
                raise

    def revalidate(self) -> None:
        """Recheck every retained identity, DACL, and unsafe attribute."""

        with self._lock:
            self._require_open()
            self._revalidate_locked()

    def validate(self) -> None:
        """Compatibility spelling for complete native revalidation."""

        self.revalidate()

    def list_children(self) -> tuple[str, ...]:
        """Return a bounded, deterministic snapshot of immediate child names."""

        with self._lock:
            self._require_open()
            if not self._is_directory:
                raise NotADirectoryError("pinned Windows path is not a directory")
            self._revalidate_locked()
            names = tuple(
                sorted(
                    self._api.directory_names(self._path.canonical),
                    key=cmp_to_key(self._api.compare_ordinal_ignore_case),
                )
            )
            self._revalidate_locked()
            previous: str | None = None
            for name in names:
                _validate_windows_component(name)
                if (
                    previous is not None
                    and self._api.compare_ordinal_ignore_case(previous, name) == 0
                ):
                    raise WindowsPathSecurityError(
                        "Windows secure path contains a case-insensitive name collision"
                    )
                previous = name
            return names

    def pin_child(
        self,
        relative: str | os.PathLike[str],
        *,
        kind: WindowsObjectKind | str,
        require_private: bool = True,
        _replacement_handoff: bool = False,
    ) -> PinnedWindowsPath:
        """Pin one exact immediate child while retaining duplicated ancestors."""

        child_name = _validate_relative_child(relative)
        selected_kind = _coerce_object_kind(kind)
        if not isinstance(require_private, bool):
            raise TypeError("Windows path privacy requirement must be a boolean")
        if not isinstance(_replacement_handoff, bool):
            raise TypeError("Windows replacement handoff flag must be a boolean")
        with self._lock:
            self._require_open()
            if not self._is_directory:
                raise NotADirectoryError("pinned Windows path is not a directory")
            self._revalidate_locked()
            _require_exact_component(
                self._api,
                child_name,
                self._api.directory_names(self._path.canonical),
            )
            self._revalidate_locked()
            child_path = validate_windows_drive_path(
                self._path.canonical.rstrip("\\") + "\\" + child_name
            )
            duplicated: list[WindowsHandle] = []
            try:
                duplicated = [handle.duplicate() for handle in self._handles]
                child = WindowsHandle(
                    self._api,
                    self._api.open_path(
                        child_path.canonical,
                        directory=selected_kind is WindowsObjectKind.DIRECTORY,
                        readable=selected_kind is WindowsObjectKind.FILE,
                        writable=(
                            selected_kind is WindowsObjectKind.DIRECTORY
                            and require_private
                        ),
                        replacement_handoff=_replacement_handoff,
                        deletable=(
                            selected_kind is WindowsObjectKind.FILE
                            and require_private
                            and not _replacement_handoff
                        ),
                    ),
                )
                duplicated.append(child)
                identities: list[WindowsObjectIdentity] = []
                sizes: list[int] = []
                final_policy = (
                    WindowsDaclPolicy.TARGET_PRIVATE
                    if require_private
                    else WindowsDaclPolicy.TARGET_PUBLIC
                )
                acl_policies = (WindowsDaclPolicy.ANCESTOR,) * (len(duplicated) - 1) + (
                    final_policy,
                )
                for index, handle in enumerate(duplicated):
                    policy = acl_policies[index]
                    expected_directory = (
                        True
                        if index < len(duplicated) - 1
                        else selected_kind is WindowsObjectKind.DIRECTORY
                    )
                    snapshot, identity = _admit_open_handle(
                        self._api,
                        handle,
                        expected_path=child_path.prefixes()[index],
                        expected_directory=expected_directory,
                        expected_volume=self._identities[0].volume_serial_number,
                        trusted_sids=self._trusted_sids,
                        policy=policy,
                        trust_policy_sha256=windows_trust_policy_sha256(
                            self._trusted_sids,
                            policy=policy,
                        ),
                    )
                    identities.append(identity)
                    sizes.append(snapshot.size)
                result = PinnedWindowsPath(
                    api=self._api,
                    path=child_path,
                    handles=tuple(duplicated),
                    identities=tuple(identities),
                    sizes=tuple(sizes),
                    trusted_sids=self._trusted_sids,
                    is_directory=selected_kind is WindowsObjectKind.DIRECTORY,
                    require_private=require_private,
                    acl_policies=acl_policies,
                )
                result.validate()
                self._revalidate_locked()
                return result
            except BaseException:
                for handle in reversed(duplicated):
                    try:
                        handle.close()
                    except OSError:
                        pass
                raise

    def create_private_file(
        self,
        relative: str | os.PathLike[str],
        *,
        max_bytes: int,
    ) -> CreatedWindowsFile:
        """Exclusively create one protected regular file relative to this pin."""

        child_name = _validate_relative_child(relative)
        _validate_bounded_file_size(max_bytes)
        with self._lock:
            self._require_open()
            if not self._is_directory:
                raise NotADirectoryError("pinned Windows path is not a directory")
            if not self._require_private:
                raise WindowsPathSecurityError(
                    "private Windows file creation requires a private directory pin"
                )
            self._revalidate_locked()
            _require_component_absent(
                self._api,
                child_name,
                self._api.directory_names(self._path.canonical),
            )
            self._revalidate_locked()
            child_path = validate_windows_drive_path(
                self._path.canonical.rstrip("\\") + "\\" + child_name
            )
            duplicated: list[WindowsHandle] = []
            child: WindowsHandle | None = None
            try:
                duplicated = [handle.duplicate() for handle in self._handles]
                sddl = build_protected_windows_sddl(
                    owner_sid=self._api.current_user_sid(),
                    trusted_sids=self._trusted_sids,
                )
                child = WindowsHandle(
                    self._api,
                    self._api.create_private_file(
                        duplicated[-1].value,
                        child_name,
                        security_descriptor_sddl=sddl,
                    ),
                )
                duplicated.append(child)
                acl_policies = (WindowsDaclPolicy.ANCESTOR,) * (len(duplicated) - 1) + (
                    WindowsDaclPolicy.TARGET_PRIVATE,
                )
                identities: list[WindowsObjectIdentity] = []
                sizes: list[int] = []
                snapshot: NativeWindowsFileSnapshot | None = None
                for index, handle in enumerate(duplicated):
                    policy = acl_policies[index]
                    snapshot, identity = _admit_open_handle(
                        self._api,
                        handle,
                        expected_path=child_path.prefixes()[index],
                        expected_directory=index < len(duplicated) - 1,
                        expected_volume=self._identities[0].volume_serial_number,
                        trusted_sids=self._trusted_sids,
                        policy=policy,
                        trust_policy_sha256=windows_trust_policy_sha256(
                            self._trusted_sids,
                            policy=policy,
                        ),
                    )
                    identities.append(identity)
                    sizes.append(snapshot.size)
                if snapshot is None:  # pragma: no cover - child is always appended.
                    raise WindowsPathSecurityError(
                        "created Windows file handle chain is incomplete"
                    )
                if not self._api.file_security(child.value).dacl_protected:
                    raise WindowsPathSecurityError(
                        "created Windows file DACL is not protected"
                    )
                result = PinnedWindowsPath(
                    api=self._api,
                    path=child_path,
                    handles=tuple(duplicated),
                    identities=tuple(identities),
                    sizes=tuple(sizes),
                    trusted_sids=self._trusted_sids,
                    is_directory=False,
                    require_private=True,
                    acl_policies=acl_policies,
                )
                result.validate()
                self._revalidate_locked()
                return CreatedWindowsFile(result, max_bytes=max_bytes)
            except BaseException:
                cleanup_error: OSError | None = None
                if child is not None and not child.closed:
                    try:
                        self._api.set_delete_on_close(child.value, enabled=True)
                    except OSError as exc:
                        cleanup_error = exc
                for handle in reversed(duplicated):
                    try:
                        handle.close()
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                if cleanup_error is not None:
                    raise WindowsPathSecurityError(
                        "created Windows file cleanup failed"
                    ) from cleanup_error
                raise

    def create_private_directory(
        self,
        relative: str | os.PathLike[str],
    ) -> PinnedWindowsPath:
        """Exclusively create and retain one protected immediate directory."""

        child_name = _validate_relative_child(relative)
        with self._lock:
            self._require_open()
            if not self._is_directory:
                raise NotADirectoryError("pinned Windows path is not a directory")
            if not self._require_private:
                raise WindowsPathSecurityError(
                    "private Windows directory creation requires a private parent pin"
                )
            self._revalidate_locked()
            _require_component_absent(
                self._api,
                child_name,
                self._api.directory_names(self._path.canonical),
            )
            self._revalidate_locked()
            child_path = validate_windows_drive_path(
                self._path.canonical.rstrip("\\") + "\\" + child_name
            )
            duplicated: list[WindowsHandle] = []
            child: WindowsHandle | None = None
            try:
                duplicated = [handle.duplicate() for handle in self._handles]
                sddl = build_protected_windows_sddl(
                    owner_sid=self._api.current_user_sid(),
                    trusted_sids=self._trusted_sids,
                )
                child = WindowsHandle(
                    self._api,
                    self._api.create_private_directory(
                        duplicated[-1].value,
                        child_name,
                        security_descriptor_sddl=sddl,
                    ),
                )
                duplicated.append(child)
                acl_policies = (WindowsDaclPolicy.ANCESTOR,) * (len(duplicated) - 1) + (
                    WindowsDaclPolicy.TARGET_PRIVATE,
                )
                identities: list[WindowsObjectIdentity] = []
                sizes: list[int] = []
                for index, handle in enumerate(duplicated):
                    policy = acl_policies[index]
                    snapshot, identity = _admit_open_handle(
                        self._api,
                        handle,
                        expected_path=child_path.prefixes()[index],
                        expected_directory=True,
                        expected_volume=self._identities[0].volume_serial_number,
                        trusted_sids=self._trusted_sids,
                        policy=policy,
                        trust_policy_sha256=windows_trust_policy_sha256(
                            self._trusted_sids,
                            policy=policy,
                        ),
                    )
                    identities.append(identity)
                    sizes.append(snapshot.size)
                if not self._api.file_security(child.value).dacl_protected:
                    raise WindowsPathSecurityError(
                        "created Windows directory DACL is not protected"
                    )
                result = PinnedWindowsPath(
                    api=self._api,
                    path=child_path,
                    handles=tuple(duplicated),
                    identities=tuple(identities),
                    sizes=tuple(sizes),
                    trusted_sids=self._trusted_sids,
                    is_directory=True,
                    require_private=True,
                    acl_policies=acl_policies,
                )
                result.validate()
                self._revalidate_locked()
                return result
            except BaseException:
                cleanup_error: OSError | None = None
                if child is not None and not child.closed:
                    try:
                        self._api.set_delete_on_close(child.value, enabled=True)
                    except OSError as exc:
                        cleanup_error = exc
                for handle in reversed(duplicated):
                    try:
                        handle.close()
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                if cleanup_error is not None:
                    raise WindowsPathSecurityError(
                        "created Windows directory cleanup failed"
                    ) from cleanup_error
                raise

    def publish_private_file(
        self,
        relative: str | os.PathLike[str],
        payload: bytes,
        *,
        max_bytes: int,
    ) -> WindowsObjectIdentity:
        """Create, bounded-write, flush, read back, and retain one new file."""

        with self.create_private_file(relative, max_bytes=max_bytes) as created:
            created.write_bytes(payload)
            return created.publish()

    def read_bytes(self, max_bytes: int) -> bytes:
        """Read a pinned regular file under a strict caller-supplied bound."""

        if self._is_directory:
            raise IsADirectoryError("pinned Windows path is a directory")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise TypeError("pinned Windows read limit must be an integer")
        if not 0 <= max_bytes <= MAX_PINNED_READ_BYTES:
            raise ValueError(
                f"pinned Windows read limit must be between 0 and "
                f"{MAX_PINNED_READ_BYTES} bytes"
            )
        with self._lock:
            self._require_open()
            snapshots = self._revalidate_locked()
            expected_size = snapshots[-1].size
            if expected_size > max_bytes:
                raise WindowsPathSecurityError(
                    "pinned Windows file exceeds the bounded read limit"
                )
            target = self._handles[-1].value
            self._api.rewind_file(target)
            payload = bytearray()
            while len(payload) < expected_size:
                chunk = self._api.read_file(
                    target,
                    min(64 * 1024, expected_size - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            overflow = self._api.read_file(target, 1)
            after = self._revalidate_locked()
            if (
                overflow
                or len(payload) != expected_size
                or after[-1].size != expected_size
            ):
                raise WindowsPathSecurityError(
                    "pinned Windows file changed during the bounded read"
                )
            return bytes(payload)

    def flush_directory(self) -> None:
        """Flush an exact retained private directory and revalidate it."""

        with self._lock:
            self._require_open()
            if not self._is_directory:
                raise NotADirectoryError("pinned Windows path is not a directory")
            self._revalidate_locked()
            self._api.flush_directory(self._handles[-1].value)
            self._revalidate_locked()

    def delete_exact(self) -> None:
        """Mark this exact retained object for removal and release its handles."""

        with self._lock:
            self._require_open()
            self._revalidate_locked()
            if self._is_directory and self.list_children():
                raise WindowsPathSecurityError(
                    "nonempty Windows directory cannot be removed"
                )
            self._api.set_delete_on_close(self._handles[-1].value, enabled=True)
            self._revalidate_locked()
        self.close()

    def close(self) -> None:
        """Release the target and retained ancestors in reverse order."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            handles = tuple(reversed(self._handles))
        first_error: OSError | None = None
        for handle in handles:
            try:
                handle.close()
            except OSError as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if hasattr(self, "_lock"):
            try:
                self.close()
            except OSError:
                return

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("pinned Windows path is closed")

    def _revalidate_locked(self) -> tuple[NativeWindowsFileSnapshot, ...]:
        snapshots: list[NativeWindowsFileSnapshot] = []
        for handle, expected, policy in zip(
            self._handles,
            self._identities,
            self._acl_policies,
            strict=True,
        ):
            snapshot, observed = _capture_trusted_identity(
                self._api,
                handle.value,
                trusted_sids=self._trusted_sids,
                policy=policy,
                trust_policy_sha256=windows_trust_policy_sha256(
                    self._trusted_sids,
                    policy=policy,
                ),
            )
            if observed != expected:
                raise WindowsPathSecurityError(
                    "pinned Windows path identity or security changed"
                )
            if snapshot.is_directory and self._api.directory_is_case_sensitive(
                handle.value
            ):
                raise WindowsPathSecurityError(
                    "case-sensitive Windows directories are not supported"
                )
            snapshots.append(snapshot)
        return tuple(snapshots)


class CreatedWindowsFile:
    """One exclusive non-replacement file creation held until publish or cleanup."""

    __slots__ = (
        "_closed",
        "_lock",
        "_max_bytes",
        "_namespace_moved",
        "_pin",
        "_published",
        "_write_sha256",
        "_write_size",
    )

    def __init__(self, pin: PinnedWindowsPath, *, max_bytes: int) -> None:
        if pin.is_directory:
            raise ValueError("created Windows file pin identifies a directory")
        _validate_bounded_file_size(max_bytes)
        self._pin = pin
        self._max_bytes = max_bytes
        self._lock = threading.RLock()
        self._write_sha256: str | None = None
        self._write_size: int | None = None
        self._published = False
        self._namespace_moved = False
        self._closed = False

    @property
    def path(self) -> Path:
        """Return the validated created path."""

        return self._pin.path

    @property
    def identity(self) -> WindowsObjectIdentity:
        """Return the exact just-created handle identity."""

        return self._pin.identity

    @property
    def closed(self) -> bool:
        """Return whether the created-file transaction released its handles."""

        with self._lock:
            return self._closed

    @property
    def published(self) -> bool:
        """Return whether explicit verified publication retained the new name."""

        with self._lock:
            return self._published

    @property
    def namespace_moved(self) -> bool:
        """Return whether the prepared handle replaced a public destination."""

        with self._lock:
            return self._namespace_moved

    def validate(self) -> None:
        """Revalidate the complete retained chain and creation identity."""

        with self._lock:
            self._require_open()
            self._pin.validate()

    def write_bytes(self, payload: bytes) -> None:
        """Write, flush, and read back one bounded payload exactly once."""

        with self._lock:
            self._require_open()
            if not isinstance(payload, bytes):
                raise TypeError("created Windows file payload must be bytes")
            if self._write_size is not None:
                raise WindowsPathSecurityError(
                    "created Windows file payload has already been written"
                )
            if len(payload) > self._max_bytes:
                raise WindowsPathSecurityError(
                    "created Windows file exceeds the bounded write limit"
                )
            with self._pin._lock:
                self._pin.validate()
                target = self._pin._handles[-1].value
                self._pin._api.rewind_file(target)
                offset = 0
                while offset < len(payload):
                    written = self._pin._api.write_file(
                        target,
                        payload[offset : offset + 64 * 1024],
                    )
                    if written <= 0:
                        raise OSError("WriteFile made no forward progress")
                    offset += written
                self._pin._api.flush_file(target)
                snapshots = self._pin._revalidate_locked()
                if snapshots[-1].size != len(payload):
                    raise WindowsPathSecurityError(
                        "created Windows file size changed during the bounded write"
                    )
                readback = self._pin.read_bytes(self._max_bytes)
                if readback != payload:
                    raise WindowsPathSecurityError(
                        "created Windows file failed exact bounded readback"
                    )
                self._write_size = len(payload)
                self._write_sha256 = hashlib.sha256(payload).hexdigest()

    def read_bytes(self, max_bytes: int) -> bytes:
        """Read the just-created handle under a fresh caller bound."""

        with self._lock:
            self._require_open()
            return self._pin.read_bytes(max_bytes)

    def publish(self) -> WindowsObjectIdentity:
        """Retain the exact verified new file; this does not claim replacement."""

        with self._lock:
            self._require_open()
            if self._write_size is None or self._write_sha256 is None:
                raise WindowsPathSecurityError(
                    "created Windows file cannot publish before a verified write"
                )
            with self._pin._lock:
                self._pin.validate()
                observed = self._pin.read_bytes(self._max_bytes)
                if (
                    len(observed) != self._write_size
                    or hashlib.sha256(observed).hexdigest() != self._write_sha256
                ):
                    raise WindowsPathSecurityError(
                        "created Windows file changed before publication"
                    )
                if not self._namespace_moved:
                    self._pin._api.flush_file(self._pin._handles[-1].value)
                self._pin.validate()
                identity = self._pin.identity
                self._pin.close()
                self._published = True
                self._closed = True
                return identity

    def replace_into(
        self,
        parent: PinnedWindowsPath,
        relative: str | os.PathLike[str],
        *,
        expected_identity: WindowsObjectIdentity | None,
    ) -> WindowsObjectIdentity:
        """Atomically bind this prepared handle to one exact sibling name."""

        child_name = _validate_relative_child(relative)
        if expected_identity is not None and not isinstance(
            expected_identity,
            WindowsObjectIdentity,
        ):
            raise TypeError("expected Windows replacement identity is invalid")
        with self._lock, parent._lock:
            self._require_open()
            if self._namespace_moved:
                raise WindowsPathSecurityError(
                    "created Windows file has already moved in the namespace"
                )
            if self._write_size is None or self._write_sha256 is None:
                raise WindowsPathSecurityError(
                    "created Windows file cannot replace before a verified write"
                )
            if not parent.is_directory:
                raise NotADirectoryError("replacement parent is not a directory")
            parent._revalidate_locked()
            self._pin.validate()
            if not _same_windows_object_binding(
                self._pin._identities[-2],
                parent.identity,
            ) or self._pin._path.canonical.rsplit("\\", 1)[0] != (
                parent._path.canonical.rstrip("\\")
            ):
                raise WindowsPathSecurityError(
                    "prepared Windows file is not a child of the replacement parent"
                )
            observed: PinnedWindowsPath | None = None
            replaced: PinnedWindowsPath | None = None
            handoff: PinnedWindowsPath | None = None
            published: PinnedWindowsPath | None = None
            try:
                if expected_identity is None:
                    _require_component_absent(
                        parent._api,
                        child_name,
                        parent._api.directory_names(parent._path.canonical),
                    )
                else:
                    observed = parent.pin_child(
                        child_name,
                        kind=WindowsObjectKind.FILE,
                        require_private=True,
                    )
                    if observed.identity != expected_identity:
                        raise WindowsPathSecurityError(
                            "Windows replacement destination identity changed"
                        )
                    observed.validate()
                    replaced = parent.pin_child(
                        child_name,
                        kind=WindowsObjectKind.FILE,
                        require_private=True,
                        _replacement_handoff=True,
                    )
                    replaced.validate()
                    if replaced.identity != observed.identity:
                        raise WindowsPathSecurityError(
                            "Windows replacement destination identity changed"
                        )
                    observed.close()
                    observed = None
                parent._revalidate_locked()
                self._pin.validate()
                parent._api.replace_file(
                    self._pin._handles[-1].value,
                    parent._handles[-1].value,
                    child_name,
                    replace_existing=expected_identity is not None,
                )
                self._namespace_moved = True
                self._pin._path = validate_windows_drive_path(
                    parent._path.canonical.rstrip("\\") + "\\" + child_name
                )
                self._pin.validate()
                parent._api.flush_file(self._pin._handles[-1].value)
                parent.flush_directory()
                expected_published_identity = self._pin.identity
                handoff = parent.pin_child(
                    child_name,
                    kind=WindowsObjectKind.FILE,
                    require_private=True,
                    _replacement_handoff=True,
                )
                handoff.validate()
                if handoff.identity != expected_published_identity:
                    raise WindowsPathSecurityError(
                        "Windows replacement destination identity is indeterminate"
                    )
                self._pin.close()
                published = parent.pin_child(
                    child_name,
                    kind=WindowsObjectKind.FILE,
                    require_private=True,
                )
                published.validate()
                if published.identity != expected_published_identity:
                    raise WindowsPathSecurityError(
                        "Windows replacement destination identity is indeterminate"
                    )
                payload = published.read_bytes(self._max_bytes)
                if (
                    len(payload) != self._write_size
                    or hashlib.sha256(payload).hexdigest() != self._write_sha256
                ):
                    raise WindowsPathSecurityError(
                        "Windows replacement destination content is indeterminate"
                    )
                self._pin = published
                published = None
                return self._pin.identity
            finally:
                if published is not None:
                    published.close()
                if handoff is not None:
                    handoff.close()
                if replaced is not None:
                    replaced.close()
                if observed is not None:
                    observed.close()

    def cleanup(self) -> None:
        """Delete only the still-identical just-created file by its live handle."""

        with self._lock:
            self._require_open()
            if self._namespace_moved:
                raise WindowsPathSecurityError(
                    "moved Windows file requires explicit recovery"
                )
            try:
                self._pin.validate()
                self._pin._api.set_delete_on_close(
                    self._pin._handles[-1].value,
                    enabled=True,
                )
            finally:
                try:
                    self._pin.close()
                finally:
                    self._closed = True

    def close(self) -> None:
        """Clean up an unpublished file; published handles are already closed."""

        with self._lock:
            if self._closed:
                return
            if self._namespace_moved:
                self._pin.close()
                self._closed = True
                return
            self.cleanup()

    def __enter__(self) -> Self:
        with self._lock:
            self._require_open()
            return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if hasattr(self, "_closed") and not self._closed:
            try:
                self.cleanup()
            except (OSError, ConfigurationError, ValueError):
                return

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("created Windows file transaction is closed")


class WindowsSecureFilesystemBackend:
    """Windows 11 handle, file-ID, owner-SID, and DACL security backend."""

    backend_id = WINDOWS_FILESYSTEM_BACKEND_ID

    def __init__(
        self,
        *,
        additional_trusted_sids: tuple[str, ...] = (),
        trust_current_user: bool = True,
        _api: _WindowsFilesystemApi | None = None,
    ) -> None:
        if not isinstance(additional_trusted_sids, tuple):
            raise TypeError("additional trusted Windows SIDs must be a tuple")
        if not isinstance(trust_current_user, bool):
            raise TypeError("current-user Windows trust selection must be a boolean")
        normalized_additional_sids = _canonicalize_trusted_principal_sids(
            additional_trusted_sids
        )
        self._additional_trusted_sids = normalized_additional_sids
        self._trust_current_user = trust_current_user
        self._injected_api = _api
        self._api_lock = threading.Lock()
        self._selected_api: _WindowsFilesystemApi | None = None

    @property
    def additional_trusted_sids(self) -> tuple[str, ...]:
        """Return the explicit normalized trust extension supplied by policy."""

        return self._additional_trusted_sids

    @property
    def trust_current_user(self) -> bool:
        """Return whether this immutable policy admits the effective user."""

        return self._trust_current_user

    def for_organization_managed_configuration(
        self,
        trusted_writer_sids: tuple[str, ...],
    ) -> WindowsSecureFilesystemBackend:
        """Create a read-only managed-config policy on the same native API."""

        if not trusted_writer_sids:
            raise ValueError("managed Windows writer SID allowlist is empty")
        api = self._native_api()
        selected = WindowsSecureFilesystemBackend(
            additional_trusted_sids=trusted_writer_sids,
            trust_current_user=False,
            _api=api,
        )
        if any(
            api.current_token_is_member(sid)
            for sid in (
                LOCAL_SYSTEM_SID,
                BUILTIN_ADMINISTRATORS_SID,
                TRUSTED_INSTALLER_SID,
                *selected.additional_trusted_sids,
            )
        ):
            raise ValueError(
                "managed Windows writer policy includes the effective user token"
            )
        return selected

    def pin_directory(
        self,
        path: str | os.PathLike[str],
        *,
        require_private: bool = True,
        expected_identity: WindowsObjectIdentity | None = None,
    ) -> PinnedWindowsPath:
        """Open and retain a trusted root-through-directory handle chain."""

        return self._pin(
            path,
            target_is_directory=True,
            require_private=require_private,
            expected_identity=expected_identity,
        )

    def pin_file(
        self,
        path: str | os.PathLike[str],
        *,
        require_private: bool = True,
        expected_identity: WindowsObjectIdentity | None = None,
    ) -> PinnedWindowsPath:
        """Open and retain a trusted root-through-regular-file handle chain."""

        return self._pin(
            path,
            target_is_directory=False,
            require_private=require_private,
            expected_identity=expected_identity,
        )

    def read_restricted_file(
        self,
        path: str | os.PathLike[str],
        max_bytes: int,
        *,
        require_private: bool = True,
    ) -> tuple[Path, bytes, WindowsObjectIdentity]:
        """Pin, bounded-read, revalidate, and close one regular file."""

        with self.pin_file(path, require_private=require_private) as pinned:
            payload = pinned.read_bytes(max_bytes)
            return pinned.path, payload, pinned.identity

    def current_user_sid(self) -> str:
        """Return the canonical SID selected for this process token."""

        return canonicalize_windows_sid(self._native_api().current_user_sid())

    def duplicate_descriptor(
        self,
        descriptor: int,
        *,
        minimum_descriptor: int,
    ) -> int:
        """Duplicate one CRT descriptor as non-inheritable without replacement."""

        _require_windows_host()
        if isinstance(descriptor, bool) or not isinstance(descriptor, int):
            raise TypeError("Windows CRT descriptor must be an integer")
        if descriptor < 0:
            raise ValueError("Windows CRT descriptor is invalid")
        if isinstance(minimum_descriptor, bool) or not isinstance(
            minimum_descriptor, int
        ):
            raise TypeError("minimum Windows CRT descriptor must be an integer")
        if not 0 <= minimum_descriptor <= _MAX_DUPLICATE_DESCRIPTOR:
            raise ValueError("minimum Windows CRT descriptor is out of range")
        held: list[int] = []
        selected: int | None = None
        try:
            while selected is None:
                candidate = os.dup(descriptor)
                try:
                    os.set_inheritable(candidate, False)
                except OSError:
                    os.close(candidate)
                    raise
                if candidate >= minimum_descriptor:
                    selected = candidate
                else:
                    held.append(candidate)
            return selected
        except BaseException:
            if selected is not None:
                os.close(selected)
            raise
        finally:
            for candidate in held:
                os.close(candidate)

    def real_user_id(self) -> int:
        """Return a stable process-user token for legacy fail-closed callers."""

        return _sid_numeric_identity(self.current_user_sid())

    def effective_user_id(self) -> int:
        """Return the effective process-user token used by this backend."""

        return self.real_user_id()

    def group_is_private_to_owner(self, *, owner_id: int, group_id: int) -> bool:
        """Reject POSIX group semantics; Windows trust is evaluated by DACL."""

        del owner_id, group_id
        return False

    def _native_api(self) -> _WindowsFilesystemApi:
        with self._api_lock:
            if self._selected_api is None:
                if self._injected_api is not None:
                    self._selected_api = self._injected_api
                else:
                    _require_windows_host()
                    from master_agent.platform_runtime.windows.native import (
                        NativeWindowsApi,
                    )

                    self._selected_api = NativeWindowsApi()
            return self._selected_api

    def _trusted_sids(self, api: _WindowsFilesystemApi) -> frozenset[str]:
        current_user_sid = canonicalize_windows_sid(api.current_user_sid())
        selected = (
            LOCAL_SYSTEM_SID,
            BUILTIN_ADMINISTRATORS_SID,
            TRUSTED_INSTALLER_SID,
            *self._additional_trusted_sids,
        )
        if self._trust_current_user:
            selected = (current_user_sid, *selected)
        else:
            selected = tuple(sid for sid in selected if sid != current_user_sid)
        return frozenset(selected)

    def _pin(
        self,
        path: str | os.PathLike[str],
        *,
        target_is_directory: bool,
        require_private: bool,
        expected_identity: WindowsObjectIdentity | None,
    ) -> PinnedWindowsPath:
        if not isinstance(require_private, bool):
            raise TypeError("Windows path privacy requirement must be a boolean")
        if expected_identity is not None and not isinstance(
            expected_identity, WindowsObjectIdentity
        ):
            raise TypeError("expected Windows identity is invalid")
        selected = validate_windows_drive_path(path)
        if not target_is_directory and not selected.components:
            raise WindowsPathSecurityError(
                "Windows secure file path must identify a file"
            )
        api = self._native_api()
        volume = api.volume_information(selected.root)
        _validate_volume(volume, selected)
        trusted_sids = self._trusted_sids(api)
        handles: list[WindowsHandle] = []
        identities: list[WindowsFileIdentity] = []
        acl_policies: list[WindowsDaclPolicy] = []
        sizes: list[int] = []
        prefixes = selected.prefixes()
        try:
            root_policy = (
                (
                    WindowsDaclPolicy.TARGET_PRIVATE
                    if require_private
                    else WindowsDaclPolicy.TARGET_PUBLIC
                )
                if not selected.components
                else WindowsDaclPolicy.ANCESTOR
            )
            root_handle = WindowsHandle(
                api,
                api.open_path(
                    selected.root,
                    directory=True,
                    readable=False,
                    writable=(
                        target_is_directory
                        and require_private
                        and not selected.components
                    ),
                ),
            )
            handles.append(root_handle)
            root_snapshot, root_identity = _admit_open_handle(
                api,
                root_handle,
                expected_path=selected.root,
                expected_directory=True,
                expected_volume=None,
                trusted_sids=trusted_sids,
                policy=root_policy,
                trust_policy_sha256=windows_trust_policy_sha256(
                    trusted_sids,
                    policy=root_policy,
                ),
            )
            identities.append(root_identity)
            acl_policies.append(root_policy)
            sizes.append(root_snapshot.size)
            expected_volume = root_snapshot.volume_serial_number

            for index, component in enumerate(selected.components, start=1):
                parent = handles[-1]
                parent_identity = identities[-1]
                _assert_handle_identity(
                    api,
                    parent,
                    parent_identity,
                    trusted_sids=trusted_sids,
                    policy=acl_policies[-1],
                )
                names = api.directory_names(prefixes[index - 1])
                _require_exact_component(api, component, names)
                _assert_handle_identity(
                    api,
                    parent,
                    parent_identity,
                    trusted_sids=trusted_sids,
                    policy=acl_policies[-1],
                )
                is_target = index == len(selected.components)
                expected_directory = not is_target or target_is_directory
                child_policy = (
                    (
                        WindowsDaclPolicy.TARGET_PRIVATE
                        if require_private
                        else WindowsDaclPolicy.TARGET_PUBLIC
                    )
                    if is_target
                    else WindowsDaclPolicy.ANCESTOR
                )
                child = WindowsHandle(
                    api,
                    api.open_path(
                        prefixes[index],
                        directory=expected_directory,
                        readable=is_target and not target_is_directory,
                        writable=(
                            is_target and target_is_directory and require_private
                        ),
                    ),
                )
                handles.append(child)
                child_snapshot, child_identity = _admit_open_handle(
                    api,
                    child,
                    expected_path=prefixes[index],
                    expected_directory=expected_directory,
                    expected_volume=expected_volume,
                    trusted_sids=trusted_sids,
                    policy=child_policy,
                    trust_policy_sha256=windows_trust_policy_sha256(
                        trusted_sids,
                        policy=child_policy,
                    ),
                )
                identities.append(child_identity)
                acl_policies.append(child_policy)
                sizes.append(child_snapshot.size)
                _assert_handle_identity(
                    api,
                    parent,
                    parent_identity,
                    trusted_sids=trusted_sids,
                    policy=acl_policies[-2],
                )

            pinned = PinnedWindowsPath(
                api=api,
                path=selected,
                handles=tuple(handles),
                identities=tuple(identities),
                sizes=tuple(sizes),
                trusted_sids=trusted_sids,
                is_directory=target_is_directory,
                require_private=require_private,
                acl_policies=tuple(acl_policies),
            )
            pinned.revalidate()
            if expected_identity is not None and pinned.identity != expected_identity:
                raise WindowsPathSecurityError(
                    "pinned Windows path did not match the expected identity"
                )
            return pinned
        except BaseException:
            for handle in reversed(handles):
                try:
                    handle.close()
                except OSError:
                    pass
            raise


def _validate_windows_component(component: str) -> None:
    if component in {".", ".."} or component.endswith((".", " ")):
        raise WindowsPathSecurityError("Windows secure path has an unsafe component")
    if any(ord(character) < 32 for character in component) or any(
        character in _FORBIDDEN_COMPONENT_CHARACTERS for character in component
    ):
        raise WindowsPathSecurityError("Windows secure path has an unsafe component")
    if len(component.encode("utf-16-le")) // 2 > _MAX_WINDOWS_COMPONENT_UTF16_UNITS:
        raise WindowsPathSecurityError(
            "Windows secure path component exceeds the length limit"
        )
    basename = component.split(".", 1)[0].rstrip(" .").upper()
    if basename in _RESERVED_BASENAMES:
        raise WindowsPathSecurityError(
            "Windows secure path contains a reserved device name"
        )


def _validate_relative_child(path: str | os.PathLike[str]) -> str:
    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise TypeError("Windows child name must be text")
    if not raw or "\\" in raw or "/" in raw or ":" in raw or "\x00" in raw:
        raise WindowsPathSecurityError(
            "Windows child path must contain exactly one relative component"
        )
    _validate_windows_component(raw)
    return raw


def _coerce_object_kind(value: WindowsObjectKind | str) -> WindowsObjectKind:
    if isinstance(value, WindowsObjectKind):
        return value
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("Windows object kind is invalid")
    try:
        return WindowsObjectKind(value)
    except ValueError as exc:
        raise ValueError("Windows object kind is invalid") from exc


def _coerce_dacl_policy(value: WindowsDaclPolicy | str) -> WindowsDaclPolicy:
    if isinstance(value, WindowsDaclPolicy):
        return value
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("Windows DACL policy is invalid")
    try:
        return WindowsDaclPolicy(value)
    except ValueError as exc:
        raise ValueError("Windows DACL policy is invalid") from exc


def _validate_volume(
    volume: NativeWindowsVolume,
    path: ValidatedWindowsPath,
) -> None:
    if volume.drive_type != 3:  # DRIVE_FIXED
        raise WindowsPathSecurityError("Windows secure path volume is not fixed")
    if volume.filesystem.casefold() not in {"ntfs", "refs"}:
        raise WindowsPathSecurityError(
            "Windows secure path filesystem is not NTFS or ReFS"
        )
    if not volume.filesystem_flags & 0x00000008:  # FILE_PERSISTENT_ACLS
        raise WindowsPathSecurityError(
            "Windows secure path filesystem does not preserve ACLs"
        )
    maximum = min(volume.maximum_component_length, _MAX_WINDOWS_COMPONENT_UTF16_UNITS)
    if maximum <= 0 or any(
        len(component.encode("utf-16-le")) // 2 > maximum
        for component in path.components
    ):
        raise WindowsPathSecurityError(
            "Windows secure path component exceeds the volume limit"
        )


def _require_exact_component(
    api: _WindowsFilesystemApi,
    component: str,
    names: Sequence[str],
) -> None:
    matches = tuple(
        name for name in names if api.compare_ordinal_ignore_case(name, component) == 0
    )
    if not matches:
        raise FileNotFoundError("Windows secure path component does not exist")
    if len(matches) != 1:
        raise WindowsPathSecurityError(
            "Windows secure path contains a case-insensitive name collision"
        )
    if matches[0] != component:
        raise WindowsPathSecurityError(
            "Windows secure path component casing is not canonical"
        )


def _require_component_absent(
    api: _WindowsFilesystemApi,
    component: str,
    names: Sequence[str],
) -> None:
    if any(api.compare_ordinal_ignore_case(name, component) == 0 for name in names):
        raise FileExistsError("Windows child file already exists")


def _same_windows_object_binding(
    left: WindowsObjectIdentity,
    right: WindowsObjectIdentity,
) -> bool:
    """Compare one object/security binding independent of its policy role."""

    return (
        left.volume_serial_number == right.volume_serial_number
        and left.file_id == right.file_id
        and left.owner_sid == right.owner_sid
        and left.dacl_sha256 == right.dacl_sha256
        and left.kind is right.kind
    )


def _validate_bounded_file_size(max_bytes: int) -> None:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("Windows file byte limit must be an integer")
    if not 0 <= max_bytes <= MAX_PINNED_READ_BYTES:
        raise ValueError(
            f"Windows file byte limit must be between 0 and "
            f"{MAX_PINNED_READ_BYTES} bytes"
        )


def _capture_trusted_identity(
    api: _WindowsFilesystemApi,
    handle: int,
    *,
    trusted_sids: frozenset[str],
    policy: WindowsDaclPolicy,
    trust_policy_sha256: str,
) -> tuple[NativeWindowsFileSnapshot, WindowsObjectIdentity]:
    snapshot = api.file_snapshot(handle)
    if not windows_file_attributes_are_safe(snapshot.attributes):
        raise WindowsPathSecurityError(
            "Windows secure path uses reparse, cloud, or offline storage"
        )
    security = api.file_security(handle)
    evaluation = evaluate_windows_dacl(
        owner_sid=security.owner_sid,
        dacl=security.dacl,
        trusted_sids=trusted_sids,
        policy=policy,
    )
    if not evaluation.trusted:
        raise WindowsPathSecurityError(str(evaluation.reason))
    raw_dacl = security.dacl.raw
    if raw_dacl is None:  # pragma: no cover - rejected by the evaluator above.
        raise WindowsPathSecurityError("Windows DACL is NULL")
    identity = WindowsObjectIdentity(
        volume_serial_number=snapshot.volume_serial_number,
        file_id=snapshot.file_id,
        owner_sid=security.owner_sid,
        dacl_sha256=_dacl_digest(
            raw_dacl,
            protected=security.dacl_protected,
        ),
        trust_policy_sha256=trust_policy_sha256,
        kind=(
            WindowsObjectKind.DIRECTORY
            if snapshot.is_directory
            else WindowsObjectKind.FILE
        ),
    )
    return snapshot, identity


def _admit_open_handle(
    api: _WindowsFilesystemApi,
    handle: WindowsHandle,
    *,
    expected_path: str,
    expected_directory: bool,
    expected_volume: int | None,
    trusted_sids: frozenset[str],
    policy: WindowsDaclPolicy,
    trust_policy_sha256: str,
) -> tuple[NativeWindowsFileSnapshot, WindowsObjectIdentity]:
    snapshot, identity = _capture_trusted_identity(
        api,
        handle.value,
        trusted_sids=trusted_sids,
        policy=policy,
        trust_policy_sha256=trust_policy_sha256,
    )
    if snapshot.is_directory != expected_directory:
        label = "directory" if expected_directory else "regular file"
        raise WindowsPathSecurityError(f"Windows secure path target is not a {label}")
    if expected_volume is not None and snapshot.volume_serial_number != expected_volume:
        raise WindowsPathSecurityError("Windows secure path crossed a volume boundary")
    if snapshot.is_directory and api.directory_is_case_sensitive(handle.value):
        raise WindowsPathSecurityError(
            "case-sensitive Windows directories are not supported"
        )
    observed = validate_windows_drive_path(api.final_path(handle.value))
    expected = validate_windows_drive_path(expected_path)
    if api.compare_ordinal_ignore_case(observed.canonical, expected.canonical) != 0:
        raise WindowsPathSecurityError(
            "Windows secure path handle resolved to a different path"
        )
    return snapshot, identity


def _assert_handle_identity(
    api: _WindowsFilesystemApi,
    handle: WindowsHandle,
    expected: WindowsObjectIdentity,
    *,
    trusted_sids: frozenset[str],
    policy: WindowsDaclPolicy,
) -> None:
    snapshot, observed = _capture_trusted_identity(
        api,
        handle.value,
        trusted_sids=trusted_sids,
        policy=policy,
        trust_policy_sha256=windows_trust_policy_sha256(
            trusted_sids,
            policy=policy,
        ),
    )
    if observed != expected:
        raise WindowsPathSecurityError(
            "pinned Windows path identity or security changed"
        )
    if snapshot.is_directory and api.directory_is_case_sensitive(handle.value):
        raise WindowsPathSecurityError(
            "case-sensitive Windows directories are not supported"
        )


def _sid_numeric_identity(sid: str) -> int:
    digest = hashlib.sha256(sid.encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big") & 0x7FFFFFFFFFFFFFFF or 1


def _dacl_digest(raw: bytes, *, protected: bool) -> str:
    control = b"protected\0" if protected else b"inheritable\0"
    return hashlib.sha256(control + raw).hexdigest()


def _require_windows_host() -> None:
    if sys.platform != "win32":
        raise PlatformCapabilityUnavailable(
            "native Windows secure-filesystem operations require Windows"
        )


def probe_windows_filesystem_backend() -> None:
    """Fail closed unless every required stdlib-ctypes Win32 symbol loads."""

    _require_windows_host()
    from master_agent.platform_runtime.windows.native import NativeWindowsApi

    NativeWindowsApi()
