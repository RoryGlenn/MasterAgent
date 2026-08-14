"""Identity-pinned SQLite connections for trusted local runtime state."""

from __future__ import annotations

import os
import sqlite3
import stat
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from master_agent.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    """Stable filesystem properties that must not change after pinning."""

    device: int
    inode: int
    owner: int
    mode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _FileIdentity:
        """Capture identity and authorization-relevant metadata."""

        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
        )

    def matches(self, value: os.stat_result) -> bool:
        """Return whether a fresh stat still represents the pinned object."""

        return self == self.from_stat(value)


class PinnedSQLiteDatabase:
    """One persistent SQLite handle bound to a validated path identity.

    The persistent connection is important: validating a path and then opening a
    new SQLite connection on every operation would leave a rebinding window
    between those two steps. Once this object has connected and post-validated
    the path, later operations use only that already-open database handle. A
    per-operation identity check fails closed if the configured path no longer
    names the same database.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(os.path.abspath(os.fspath(path)))
        self._parent = self._path.parent
        self._lock = RLock()
        self._created = False

        parent_descriptor = _open_trusted_parent(self._parent, create=True)
        try:
            parent_stat = os.fstat(parent_descriptor)
            self._parent_identity = _validated_parent_identity(parent_stat)
            database_descriptor, self._created = _open_database_file(
                parent_descriptor,
                self._path.name,
            )
            try:
                database_stat = os.fstat(database_descriptor)
                self._database_identity = _validated_database_identity(database_stat)
            finally:
                os.close(database_descriptor)
        finally:
            os.close(parent_descriptor)

        try:
            self._validate_path_identity()
        except Exception:
            if self._created:
                self._remove_created_file()
            raise
        try:
            connection = sqlite3.connect(
                self._path.as_uri() + "?mode=rw",
                uri=True,
                timeout=30.0,
                check_same_thread=False,
            )
        except sqlite3.Error:
            if self._created:
                self._remove_created_file()
            raise
        try:
            # Post-validation happens before schema creation, migration, or any
            # other SQL write can occur through this handle.
            self._validate_path_identity()
            connection.execute("PRAGMA busy_timeout = 30000")
        except Exception:
            connection.close()
            if self._created:
                self._remove_created_file()
            raise
        self._connection = connection
        self._finalizer = weakref.finalize(
            self,
            _close_connection,
            connection,
            self._lock,
        )

    @property
    def created(self) -> bool:
        """Return whether this object securely created the database file."""

        return self._created

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield the pinned connection after revalidating its public path."""

        with self._lock:
            if not self._finalizer.alive:
                raise RuntimeError("SQLite state database is closed")
            self._validate_path_identity()
            try:
                yield self._connection
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def close(self, *, remove_created: bool = False) -> None:
        """Close the handle and optionally remove its securely-created file."""

        with self._lock:
            self._finalizer()
            if remove_created and self._created:
                self._remove_created_file()

    def _validate_path_identity(self) -> None:
        """Verify the parent and database path still name the pinned objects."""

        parent_descriptor = _open_trusted_parent(self._parent, create=False)
        try:
            parent_stat = os.fstat(parent_descriptor)
            _validated_parent_identity(parent_stat)
            if not self._parent_identity.matches(parent_stat):
                raise ConfigurationError(
                    "SQLite state database parent identity changed"
                )
            try:
                database_descriptor = os.open(
                    self._path.name,
                    os.O_RDWR | _no_follow_flag(),
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                raise ConfigurationError(
                    "SQLite state database must remain a regular no-follow file"
                ) from error
            try:
                database_stat = os.fstat(database_descriptor)
                _validated_database_identity(database_stat)
                if not self._database_identity.matches(database_stat):
                    raise ConfigurationError("SQLite state database identity changed")
                path_stat = os.stat(
                    self._path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if not self._database_identity.matches(path_stat):
                    raise ConfigurationError("SQLite state database path was replaced")
            finally:
                os.close(database_descriptor)
        finally:
            os.close(parent_descriptor)

    def _remove_created_file(self) -> None:
        """Remove only the exact file created by this object."""

        try:
            parent_descriptor = _open_trusted_parent(self._parent, create=False)
        except ConfigurationError:
            return
        try:
            if not self._parent_identity.matches(os.fstat(parent_descriptor)):
                return
            try:
                path_stat = os.stat(
                    self._path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            if self._database_identity.matches(path_stat):
                os.unlink(self._path.name, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)


def path_entry_exists(path: Path) -> bool:
    """Return whether a directory entry exists, including a broken symlink."""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _open_trusted_parent(path: Path, *, create: bool) -> int:
    """Open a current-user-owned directory that other accounts cannot modify."""

    if create:
        try:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as error:
            raise ConfigurationError(
                "SQLite state database parent could not be created safely"
            ) from error
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _directory_flag() | _no_follow_flag(),
        )
    except OSError as error:
        raise ConfigurationError(
            "SQLite state database parent must be a trusted no-follow directory"
        ) from error
    try:
        descriptor_stat = os.fstat(descriptor)
        path_stat = path.lstat()
        _validated_parent_identity(descriptor_stat)
        if (
            descriptor_stat.st_dev != path_stat.st_dev
            or descriptor_stat.st_ino != path_stat.st_ino
        ):
            raise ConfigurationError(
                "SQLite state database parent changed while it was opened"
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_database_file(parent_descriptor: int, name: str) -> tuple[int, bool]:
    """Create or open a database through the already-validated parent handle."""

    flags = os.O_RDWR | _no_follow_flag()
    created = False
    try:
        descriptor = os.open(
            name,
            flags | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise ConfigurationError(
                "SQLite state database must be a regular no-follow file"
            ) from error
    except OSError as error:
        raise ConfigurationError(
            "SQLite state database could not be created safely"
        ) from error
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode):
            raise ConfigurationError("SQLite state database must be a regular file")
        if value.st_uid != os.getuid():
            raise ConfigurationError(
                "SQLite state database must be owned by the current account"
            )
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        if created:
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise
    return descriptor, created


def _validated_parent_identity(value: os.stat_result) -> _FileIdentity:
    """Validate and capture a trusted state-directory identity."""

    if not stat.S_ISDIR(value.st_mode):
        raise ConfigurationError("SQLite state database parent must be a directory")
    if value.st_uid != os.getuid():
        raise ConfigurationError(
            "SQLite state database parent must be owned by the current account"
        )
    mode = stat.S_IMODE(value.st_mode)
    if mode & 0o022:
        raise ConfigurationError(
            "SQLite state database parent must not be group- or world-writable"
        )
    return _FileIdentity.from_stat(value)


def _validated_database_identity(value: os.stat_result) -> _FileIdentity:
    """Validate and capture a private regular database-file identity."""

    if not stat.S_ISREG(value.st_mode):
        raise ConfigurationError("SQLite state database must be a regular file")
    if value.st_uid != os.getuid():
        raise ConfigurationError(
            "SQLite state database must be owned by the current account"
        )
    if stat.S_IMODE(value.st_mode) != 0o600:
        raise ConfigurationError("SQLite state database permissions must remain 0600")
    return _FileIdentity.from_stat(value)


def _no_follow_flag() -> int:
    """Return the platform no-follow flag or fail closed."""

    value = getattr(os, "O_NOFOLLOW", 0)
    if not value:
        raise ConfigurationError("secure no-follow file opens are unavailable")
    return value


def _directory_flag() -> int:
    """Return the platform directory-only flag or fail closed."""

    value = getattr(os, "O_DIRECTORY", 0)
    if not value:
        raise ConfigurationError("secure directory-only opens are unavailable")
    return value


def _close_connection(connection: sqlite3.Connection, lock: RLock) -> None:
    """Close a connection under the same lock used for every operation."""

    with lock:
        connection.close()
