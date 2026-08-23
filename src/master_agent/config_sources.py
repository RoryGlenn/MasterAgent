"""Resolve explicit trusted or packaged configuration sources.

Target repositories are untrusted inputs.  In particular, merely changing the
current working directory must never change policy, connector destinations, or
credential references used by the runtime.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import io
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import IO, BinaryIO, Literal, overload

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime import (
    PlatformContract,
    get_secure_filesystem_backend,
    require_platform_contract,
)

_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_SID_PATTERN = re.compile(r"^S-[0-9]+(?:-[0-9]+){2,15}$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class OrganizationManagedFileTrust:
    """Externally supplied integrity and writer policy for managed config."""

    sha256: str
    posix_uids: tuple[int, ...] = ()
    posix_gids: tuple[int, ...] = ()
    windows_sids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ConfigurationError("managed configuration SHA-256 is invalid")
        for name, values in (
            ("POSIX UID", self.posix_uids),
            ("POSIX GID", self.posix_gids),
        ):
            if not isinstance(values, tuple) or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in values
            ):
                raise ConfigurationError(
                    f"managed configuration {name} allowlist is invalid"
                )
            if len(values) > 64 or len(values) != len(set(values)):
                raise ConfigurationError(
                    f"managed configuration {name} allowlist is too large or duplicated"
                )
        if not isinstance(self.windows_sids, tuple) or any(
            not isinstance(value, str) or _WINDOWS_SID_PATTERN.fullmatch(value) is None
            for value in self.windows_sids
        ):
            raise ConfigurationError(
                "managed configuration Windows SID allowlist is invalid"
            )
        canonical_sids = tuple(value.upper() for value in self.windows_sids)
        if len(canonical_sids) > 64 or len(canonical_sids) != len(set(canonical_sids)):
            raise ConfigurationError(
                "managed configuration Windows SID allowlist is too large or duplicated"
            )
        if not (self.posix_uids or canonical_sids):
            raise ConfigurationError(
                "managed configuration writer policy has no platform identity"
            )
        object.__setattr__(self, "posix_uids", tuple(sorted(self.posix_uids)))
        object.__setattr__(self, "posix_gids", tuple(sorted(self.posix_gids)))
        object.__setattr__(self, "windows_sids", tuple(sorted(canonical_sids)))


@dataclass(frozen=True, slots=True)
class ConfigSnapshot:
    """Immutable bytes captured from one trusted configuration source.

    Returning a snapshot instead of a reopenable path or package resource closes
    the check/use race between source validation, approval hashing, and the
    individual TOML loaders.
    """

    display_path: Path
    payload: bytes
    trust_class: str = "user-private"
    trust_reason: str = "owner-and-write-authority"

    @overload
    def open(self, mode: Literal["rb"]) -> BinaryIO: ...

    @overload
    def open(self, mode: str = "rb") -> BinaryIO: ...

    def open(self, mode: str = "rb") -> BinaryIO:
        """Return a fresh binary stream over the captured bytes."""

        if mode != "rb":
            raise ValueError("configuration snapshots support only binary reads")
        return io.BytesIO(self.payload)

    def __str__(self) -> str:
        return str(self.display_path)


type ConfigSource = Path | Traversable | ConfigSnapshot

_DEFAULT_CONFIG_FILES = frozenset(
    {
        "integrations.toml",
        "policy.toml",
        "sources_of_truth.toml",
        "weekly-status.toml",
        "communication-context.toml",
        "identities.toml",
        "retention.toml",
        "capabilities.toml",
        "governance.toml",
        "oauth.toml",
        "draft-package.toml",
        "dependency-licenses.toml",
        "recurring.toml",
        "organization-profile.toml",
    }
)


def snapshot_explicit_file(
    path: Path,
    *,
    organization_trust: OrganizationManagedFileTrust | None = None,
) -> ConfigSnapshot:
    """Capture one owner-controlled regular file as bounded immutable bytes."""

    return _trusted_explicit_file(path, organization_trust=organization_trust)


def resolve_config_source(
    explicit: Path | None,
    filename: str,
    *,
    organization_trust: OrganizationManagedFileTrust | None = None,
) -> ConfigSnapshot:
    """Resolve a configuration source into one bounded immutable snapshot.

    Resolution order is an explicit, permission-checked command-line path and
    then the package's safe fallback configuration.  The current working
    directory is deliberately never consulted.

    Parameters
    ----------
    explicit
        Explicit user-provided path, or ``None`` to use normal resolution.
    filename
        Approved default configuration filename.

    Returns
    -------
    ConfigSnapshot
        A bounded snapshot whose bytes remain identical across every parser and
        approval-hash read.

    Raises
    ------
    ConfigurationError
        If ``filename`` is not an approved packaged configuration resource or
        the packaged fallback is unavailable.
    """

    if explicit is not None:
        return _trusted_explicit_file(
            explicit,
            organization_trust=organization_trust,
        )
    if organization_trust is not None:
        raise ConfigurationError(
            "managed configuration trust requires an explicit local path"
        )
    if filename not in _DEFAULT_CONFIG_FILES:
        raise ConfigurationError(f"unsupported default configuration: {filename}")

    packaged = files("master_agent.defaults").joinpath(filename)
    if not packaged.is_file():
        raise ConfigurationError(
            f"packaged default configuration is unavailable: {filename}"
        )
    try:
        with packaged.open("rb") as handle:
            payload = _read_stream_bounded(
                handle,
                _MAX_CONFIG_BYTES,
                object_name="packaged default configuration",
            )
    except OSError as error:
        raise ConfigurationError(
            f"packaged default configuration could not be read: {filename}"
        ) from error
    return ConfigSnapshot(display_path=Path(str(packaged)), payload=payload)


def _trusted_explicit_file(
    path: Path,
    *,
    organization_trust: OrganizationManagedFileTrust | None,
) -> ConfigSnapshot:
    """Snapshot an explicit configuration file after local trust checks.

    The parent and file are opened by descriptor, their identities are checked
    before use, and the resulting bytes are detached from the filesystem path.
    Symlinks and group/other-writable objects are rejected. On POSIX, the
    invoking account must own both objects.
    """

    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if os.name == "nt":
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        backend = get_secure_filesystem_backend()
        if not isinstance(backend, WindowsSecureFilesystemBackend):
            raise ConfigurationError("native Windows secure filesystem is unavailable")
        if organization_trust is not None:
            if not organization_trust.windows_sids:
                raise ConfigurationError(
                    "managed configuration has no Windows writer SID policy"
                )
            try:
                backend = backend.for_organization_managed_configuration(
                    organization_trust.windows_sids
                )
            except (TypeError, ValueError) as error:
                raise ConfigurationError(
                    "managed configuration Windows writer policy is invalid"
                ) from error
        try:
            canonical, payload, _identity = backend.read_restricted_file(
                selected,
                _MAX_CONFIG_BYTES,
                require_private=False,
            )
        except FileNotFoundError as error:
            raise _configuration_not_found(selected, organization_trust) from error
        except (OSError, ValueError) as error:
            raise ConfigurationError(
                "explicit configuration could not be opened safely"
            ) from error
        _validate_managed_digest(payload, organization_trust)
        return ConfigSnapshot(
            display_path=canonical,
            payload=payload,
            trust_class=(
                "organization-managed"
                if organization_trust is not None
                else "user-private"
            ),
            trust_reason=(
                "content-and-writer-bound"
                if organization_trust is not None
                else "owner-and-write-authority"
            ),
        )
    try:
        requested_parent = Path(os.path.abspath(selected.parent))
        parent = requested_parent.resolve(strict=True)
        if parent != requested_parent:
            raise ConfigurationError(
                "explicit configuration parent must not traverse a symbolic link"
            )
        parent_before = parent.lstat()
    except FileNotFoundError as error:
        raise _configuration_not_found(selected, organization_trust) from error

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(parent, directory_flags)
    except OSError as error:
        raise ConfigurationError(
            "explicit configuration parent could not be opened safely"
        ) from error

    file_fd: int | None = None
    try:
        parent_open = os.fstat(directory_fd)
        _validate_trusted_metadata(
            parent_open,
            expected=parent_before,
            object_name="explicit configuration parent",
            expected_type=stat.S_ISDIR,
            organization_trust=organization_trust,
            access_name=".",
            access_directory_fd=directory_fd,
            object_fd=directory_fd,
        )
        try:
            file_before = os.stat(
                selected.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(file_before.st_mode) or not stat.S_ISREG(
                file_before.st_mode
            ):
                raise ConfigurationError(
                    "explicit configuration must be a regular non-symlink file"
                )
            file_fd = os.open(
                selected.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError as error:
            raise _configuration_not_found(selected, organization_trust) from error
        except OSError as error:
            raise ConfigurationError(
                "explicit configuration could not be opened safely"
            ) from error

        file_open = os.fstat(file_fd)
        _validate_trusted_metadata(
            file_open,
            expected=file_before,
            object_name="explicit configuration",
            expected_type=stat.S_ISREG,
            organization_trust=organization_trust,
            access_name=selected.name,
            access_directory_fd=directory_fd,
            object_fd=file_fd,
        )
        if file_open.st_size > _MAX_CONFIG_BYTES:
            raise ConfigurationError("explicit configuration exceeds the 4 MiB limit")
        payload = _read_bounded(file_fd, _MAX_CONFIG_BYTES)
        file_after = os.fstat(file_fd)
        public_after = os.stat(
            selected.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        parent_after = os.fstat(directory_fd)
        if _metadata_identity(file_open) != _metadata_identity(file_after) or (
            _metadata_identity(file_after) != _metadata_identity(public_after)
        ):
            raise ConfigurationError("explicit configuration changed during read")
        if _metadata_identity(parent_open) != _metadata_identity(parent_after):
            raise ConfigurationError(
                "explicit configuration parent changed during read"
            )
        _validate_managed_digest(payload, organization_trust)
        return ConfigSnapshot(
            display_path=selected,
            payload=payload,
            trust_class=(
                "organization-managed"
                if organization_trust is not None
                else "user-private"
            ),
            trust_reason=(
                "content-and-writer-bound"
                if organization_trust is not None
                else "owner-and-write-authority"
            ),
        )
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _configuration_not_found(
    selected: Path,
    organization_trust: OrganizationManagedFileTrust | None,
) -> ConfigurationError:
    """Keep managed-profile diagnostics free of administrator path metadata."""

    if organization_trust is not None:
        return ConfigurationError("organization-managed configuration was not found")
    return ConfigurationError(f"explicit configuration not found: {selected}")


def _validate_trusted_metadata(
    observed: os.stat_result,
    *,
    expected: os.stat_result,
    object_name: str,
    expected_type: Callable[[int], bool],
    organization_trust: OrganizationManagedFileTrust | None,
    access_name: str,
    access_directory_fd: int,
    object_fd: int,
) -> None:
    """Validate type, stable identity, ownership, and write permissions."""

    if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
        raise ConfigurationError(f"{object_name} changed while it was being opened")
    if not expected_type(observed.st_mode):
        raise ConfigurationError(f"{object_name} must be a regular non-symlink object")
    if os.name == "posix":
        if organization_trust is None:
            if observed.st_uid != os.geteuid():
                raise ConfigurationError(
                    f"{object_name} must be owned by the current user"
                )
            if stat.S_IMODE(observed.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                raise ConfigurationError(
                    f"{object_name} must not be group- or other-writable"
                )
            if _has_extended_posix_acl(object_fd):
                raise ConfigurationError(
                    f"{object_name} has write authority outside the user-private policy"
                )
            return
        _validate_organization_managed_posix_metadata(
            observed,
            object_name=object_name,
            trust=organization_trust,
            access_name=access_name,
            access_directory_fd=access_directory_fd,
            object_fd=object_fd,
        )


def _validate_organization_managed_posix_metadata(
    observed: os.stat_result,
    *,
    object_name: str,
    trust: OrganizationManagedFileTrust,
    access_name: str,
    access_directory_fd: int,
    object_fd: int,
) -> None:
    """Reject any managed POSIX object the effective user can modify."""

    mode = stat.S_IMODE(observed.st_mode)
    if not trust.posix_uids:
        raise ConfigurationError("managed configuration has no POSIX owner policy")
    effective_uid = os.geteuid()
    effective_groups = frozenset((os.getegid(), *os.getgroups()))
    if observed.st_uid == effective_uid or observed.st_uid not in trust.posix_uids:
        raise ConfigurationError(
            f"{object_name} owner is outside the managed writer policy"
        )
    if mode & stat.S_IWOTH:
        raise ConfigurationError(f"{object_name} is writable by an untrusted principal")
    if mode & stat.S_IWGRP:
        if observed.st_gid not in trust.posix_gids:
            raise ConfigurationError(
                f"{object_name} is writable by an untrusted principal"
            )
        if observed.st_gid in effective_groups:
            raise ConfigurationError(f"{object_name} is writable by the effective user")
    try:
        effective_user_can_write = os.access(
            access_name,
            os.W_OK,
            dir_fd=access_directory_fd,
            effective_ids=True,
            follow_symlinks=False,
        )
    except (NotImplementedError, OSError) as error:
        raise ConfigurationError(
            f"{object_name} effective write authority could not be verified"
        ) from error
    if effective_user_can_write:
        raise ConfigurationError(f"{object_name} is writable by the effective user")
    if _has_extended_posix_acl(object_fd):
        raise ConfigurationError(
            f"{object_name} has an extended ACL outside the managed writer policy"
        )


def _has_extended_posix_acl(descriptor: int) -> bool:
    """Detect named POSIX ACL entries without resolving the checked path again."""

    if sys.platform == "darwin":
        try:
            library = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
        except (AttributeError, OSError) as error:
            raise ConfigurationError(
                "managed configuration ACL could not be verified"
            ) from error
        library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        library.acl_get_fd_np.restype = ctypes.c_void_p
        library.acl_get_entry.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        library.acl_get_entry.restype = ctypes.c_int
        library.acl_free.argtypes = [ctypes.c_void_p]
        acl = library.acl_get_fd_np(descriptor, 0x100)  # ACL_TYPE_EXTENDED
        if not acl:
            observed_errno = ctypes.get_errno()
            if observed_errno in {errno.ENOENT, errno.EOPNOTSUPP}:
                return False
            raise ConfigurationError("managed configuration ACL could not be verified")
        try:
            entry = ctypes.c_void_p()
            result = library.acl_get_entry(acl, 0, ctypes.byref(entry))
            if result == 0:
                return True
            if ctypes.get_errno() == errno.EINVAL:
                return False
            raise ConfigurationError("managed configuration ACL could not be verified")
        finally:
            library.acl_free(acl)
    if sys.platform.startswith("linux"):
        library_name = ctypes.util.find_library("acl")
        if library_name is None:
            raise ConfigurationError("managed configuration ACL could not be verified")
        try:
            library = ctypes.CDLL(library_name, use_errno=True)
        except (AttributeError, OSError) as error:
            raise ConfigurationError(
                "managed configuration ACL could not be verified"
            ) from error
        library.acl_get_fd.argtypes = [ctypes.c_int]
        library.acl_get_fd.restype = ctypes.c_void_p
        library.acl_equiv_mode.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint),
        ]
        library.acl_equiv_mode.restype = ctypes.c_int
        library.acl_free.argtypes = [ctypes.c_void_p]
        acl = library.acl_get_fd(descriptor)
        if not acl:
            if ctypes.get_errno() == errno.EOPNOTSUPP:
                return False
            raise ConfigurationError("managed configuration ACL could not be verified")
        try:
            mode = ctypes.c_uint()
            result = library.acl_equiv_mode(acl, ctypes.byref(mode))
            if result in {0, 1}:
                return bool(result == 1)
            raise ConfigurationError("managed configuration ACL could not be verified")
        finally:
            library.acl_free(acl)
    raise ConfigurationError("managed configuration ACL could not be verified")


def _validate_managed_digest(
    payload: bytes,
    trust: OrganizationManagedFileTrust | None,
) -> None:
    if trust is not None and hashlib.sha256(payload).hexdigest() != trust.sha256:
        raise ConfigurationError("managed configuration content digest does not match")


def _metadata_identity(value: os.stat_result) -> tuple[int, ...]:
    """Return the retained POSIX metadata that must not drift during capture."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_bounded(descriptor: int, limit: int) -> bytes:
    """Read at most ``limit`` bytes from an already validated descriptor."""

    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise ConfigurationError("explicit configuration exceeds the 4 MiB limit")
    return payload


def _read_stream_bounded(
    stream: IO[bytes],
    limit: int,
    *,
    object_name: str,
) -> bytes:
    """Read one binary stream without allowing an unbounded package resource."""

    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise ConfigurationError(f"{object_name} exceeds the 4 MiB limit")
    return payload
