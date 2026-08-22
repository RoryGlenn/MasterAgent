"""Descriptor-bound POSIX atomic-file transactions used by common callers."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from master_agent.errors import ConfigurationError
from master_agent.platform_runtime.contracts import (
    AtomicStateIdentity,
    FilesystemObjectKind,
    LockMode,
    PlatformObjectIdentity,
)

_MAX_STATE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PosixAtomicPublicationRecoveryBackend:
    """Provide descriptor-bound publication while legacy callers keep their ledgers."""

    backend_id: str = "posix-atomic-publication"

    def ensure_private_directory(self, path: Path) -> Path:
        """Create and validate an owner-private directory without following leaves."""

        selected = Path(os.path.abspath(os.fspath(path)))
        try:
            selected.mkdir(parents=True, mode=0o700, exist_ok=True)
            descriptor = os.open(selected, _directory_flags())
        except OSError as error:
            raise ConfigurationError(
                "atomic state directory could not be created safely"
            ) from error
        try:
            value = os.fstat(descriptor)
            _validate_private_directory(value)
            public = selected.lstat()
            if (value.st_dev, value.st_ino) != (public.st_dev, public.st_ino):
                raise ConfigurationError("atomic state directory path was replaced")
            if stat.S_IMODE(value.st_mode) != 0o700:
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
            return selected
        finally:
            os.close(descriptor)

    def open_transaction(
        self,
        path: Path,
        *,
        max_bytes: int,
        create: bool,
    ) -> _PosixAtomicStateTransaction:
        """Return an unentered descriptor-bound transaction."""

        return _PosixAtomicStateTransaction(
            path,
            max_bytes=max_bytes,
            create=create,
            backend=self,
        )


class _PosixAtomicStateTransaction:
    """One stable-lock POSIX transaction for the common atomic-state surface."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int,
        create: bool,
        backend: PosixAtomicPublicationRecoveryBackend,
    ) -> None:
        _validate_limit(max_bytes)
        selected = Path(os.path.abspath(os.fspath(path)))
        if selected.name in {"", ".", ".."} or selected.parent == selected:
            raise ConfigurationError("atomic state path must name a file")
        self._path = selected
        self._max_bytes = max_bytes
        self._create = create
        self._backend = backend
        self._parent_descriptor: int | None = None
        self._lock_descriptor: int | None = None
        self._identity: AtomicStateIdentity | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def identity(self) -> AtomicStateIdentity | None:
        self._require_entered()
        return self._identity

    def __enter__(self) -> Self:
        if self._parent_descriptor is not None:
            raise RuntimeError("atomic state transaction is already entered")
        if self._create:
            self._backend.ensure_private_directory(self._path.parent)
        try:
            parent = os.open(self._path.parent, _directory_flags())
        except OSError as error:
            raise ConfigurationError("atomic state parent is unavailable") from error
        lock: int | None = None
        try:
            _validate_private_directory(os.fstat(parent))
            lock = _open_private_file(
                parent,
                f".{self._path.name}.master-agent.atomic.lock",
                create=self._create,
                content_free=True,
            )
            from master_agent.platform_runtime.factory import (
                get_cross_process_locking_backend,
            )

            get_cross_process_locking_backend().acquire(
                lock,
                mode=LockMode.EXCLUSIVE,
            )
            self._parent_descriptor = parent
            self._lock_descriptor = lock
            self._identity = self._read_identity(missing_ok=self._create)
            return self
        except BaseException:
            if lock is not None:
                os.close(lock)
            os.close(parent)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        lock = self._lock_descriptor
        parent = self._parent_descriptor
        self._lock_descriptor = None
        self._parent_descriptor = None
        if lock is not None:
            from master_agent.platform_runtime.factory import (
                get_cross_process_locking_backend,
            )

            try:
                get_cross_process_locking_backend().release(lock)
            except OSError:
                pass
            os.close(lock)
        if parent is not None:
            os.close(parent)

    def read_bytes(self) -> bytes | None:
        self._require_entered()
        identity, payload = self._read(missing_ok=True)
        if identity != self._identity:
            raise ConfigurationError("atomic state generation changed")
        return payload

    def publish_bytes(
        self,
        payload: bytes,
        *,
        expected: AtomicStateIdentity | None,
    ) -> AtomicStateIdentity:
        parent = self._require_entered()
        if not isinstance(payload, bytes):
            raise TypeError("atomic state payload must be bytes")
        if len(payload) > self._max_bytes:
            raise ConfigurationError("atomic state payload exceeds its safety limit")
        observed = self._read_identity(missing_ok=True)
        if observed != expected or self._identity != expected:
            raise ConfigurationError("atomic state generation changed before publish")
        temporary = f".{self._path.name}.tmp-{secrets.token_hex(16)}"
        descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
            0o600,
            dir_fd=parent,
        )
        replaced = False
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            if _read_all(descriptor, self._max_bytes) != payload:
                raise OSError("atomic state temporary verification failed")
            if self._read_identity(missing_ok=True) != expected:
                raise ConfigurationError(
                    "atomic state generation changed during publish"
                )
            os.replace(
                temporary,
                self._path.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
            replaced = True
            os.fsync(parent)
            identity, published = self._read(missing_ok=False)
            if identity is None or published != payload:
                raise ConfigurationError(
                    "atomic state replacement could not be verified"
                )
            self._identity = identity
            return identity
        finally:
            os.close(descriptor)
            if not replaced:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass

    def remove(self, *, expected: AtomicStateIdentity) -> bool:
        parent = self._require_entered()
        if (
            self._identity != expected
            or self._read_identity(missing_ok=True) != expected
        ):
            raise ConfigurationError("atomic state generation changed before removal")
        os.unlink(self._path.name, dir_fd=parent)
        os.fsync(parent)
        self._identity = None
        return True

    def _read_identity(self, *, missing_ok: bool) -> AtomicStateIdentity | None:
        identity, _ = self._read(missing_ok=missing_ok)
        return identity

    def _read(
        self,
        *,
        missing_ok: bool,
    ) -> tuple[AtomicStateIdentity | None, bytes | None]:
        parent = self._require_entered()
        try:
            descriptor = os.open(
                self._path.name,
                os.O_RDONLY | _no_follow_flag(),
                dir_fd=parent,
            )
        except FileNotFoundError:
            if missing_ok:
                return None, None
            raise ConfigurationError("atomic state file does not exist") from None
        try:
            before = os.fstat(descriptor)
            _validate_private_file(before)
            payload = _read_all(descriptor, self._max_bytes)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ) or len(payload) != after.st_size:
                raise ConfigurationError("atomic state changed while it was read")
            public = os.stat(
                self._path.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
            if (before.st_dev, before.st_ino) != (public.st_dev, public.st_ino):
                raise ConfigurationError("atomic state path was replaced")
            identity = AtomicStateIdentity(
                object_identity=PlatformObjectIdentity.from_posix(
                    kind=FilesystemObjectKind.FILE,
                    device=before.st_dev,
                    inode=before.st_ino,
                    owner=before.st_uid,
                    mode=stat.S_IMODE(before.st_mode),
                ),
                content_sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
            )
            return identity, payload
        finally:
            os.close(descriptor)

    def _require_entered(self) -> int:
        if self._parent_descriptor is None:
            raise RuntimeError("atomic state transaction is not entered")
        return self._parent_descriptor


def _open_private_file(
    parent: int,
    name: str,
    *,
    create: bool,
    content_free: bool,
) -> int:
    flags = os.O_RDWR | _no_follow_flag()
    try:
        descriptor = os.open(
            name,
            flags | (os.O_CREAT | os.O_EXCL if create else 0),
            0o600,
            dir_fd=parent,
        )
        created = create
    except FileExistsError:
        descriptor = os.open(name, flags, dir_fd=parent)
        created = False
    except FileNotFoundError as error:
        raise ConfigurationError("atomic state lock does not exist") from error
    try:
        _validate_private_file(os.fstat(descriptor))
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(parent)
        if content_free and os.fstat(descriptor).st_size:
            raise ConfigurationError("atomic state lock must remain content-free")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_private_directory(value: os.stat_result) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise ConfigurationError("atomic state parent must be a directory")
    if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) & 0o077:
        raise ConfigurationError("atomic state parent must be account-private")


def _validate_private_file(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != 0o600
    ):
        raise ConfigurationError("atomic state file must be account-private")


def _read_all(descriptor: int, max_bytes: int) -> bytes:
    size = os.fstat(descriptor).st_size
    if size > max_bytes:
        raise ConfigurationError("atomic state file exceeds its safety limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise OSError("atomic state file ended during a bounded read")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, payload: bytes) -> None:
    os.ftruncate(descriptor, 0)
    offset = 0
    while offset < len(payload):
        written = os.pwrite(descriptor, payload[offset:], offset)
        if written <= 0:
            raise OSError("atomic state write made no forward progress")
        offset += written
    os.ftruncate(descriptor, len(payload))


def _validate_limit(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("atomic state byte limit must be an integer")
    if not 0 <= value <= _MAX_STATE_BYTES:
        raise ValueError(
            f"atomic state byte limit must be between 0 and {_MAX_STATE_BYTES}"
        )


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    no_follow = _no_follow_flag()
    if not directory or not no_follow:
        raise ConfigurationError("descriptor-bound atomic state is unavailable")
    return os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)


def _no_follow_flag() -> int:
    value = getattr(os, "O_NOFOLLOW", 0)
    if not value:
        raise ConfigurationError("no-follow atomic state is unavailable")
    return value
