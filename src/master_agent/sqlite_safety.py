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

_SQLITE_CONNECT_LOCK = RLock()


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
        self._active_context = False
        self._poisoned = False

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
            except BaseException:
                os.close(database_descriptor)
                raise
        finally:
            os.close(parent_descriptor)

        connection: sqlite3.Connection | None = None
        try:
            self._validate_path_identity()
            connection, sqlite_descriptor = _connect_verified_database(
                self._path,
                self._database_identity,
                database_descriptor,
            )
            # Post-validation happens before schema creation, migration, or any
            # other SQL write can occur through this handle.
            self._validate_path_identity()
            connection.execute("PRAGMA busy_timeout = 30000")
        except BaseException:
            if connection is not None:
                _close_sqlite_connection(connection)
            try:
                os.close(database_descriptor)
            except OSError:
                pass
            if self._created:
                self._remove_created_file()
            raise
        self._database_descriptor = database_descriptor
        self._sqlite_descriptor = sqlite_descriptor
        self._connection = connection
        self._finalizer = weakref.finalize(
            self,
            _close_resources,
            connection,
            database_descriptor,
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
            if self._poisoned or not self._finalizer.alive:
                raise RuntimeError("SQLite state database is closed")
            if self._active_context:
                raise RuntimeError("nested SQLite state database contexts are unsafe")
            self._active_context = True
            try:
                self._validate_path_identity()
                self._validate_sqlite_descriptor()
                try:
                    yield self._connection
                except BaseException as error:
                    self._rollback_or_poison(error)
                    raise
                try:
                    # Revalidate after the caller's SQL and before the one
                    # commit point owned by this context manager.
                    self._validate_path_identity()
                    self._validate_sqlite_descriptor()
                    self._connection.commit()
                except BaseException as error:
                    self._rollback_or_poison(error)
                    raise
            finally:
                self._active_context = False

    def close(self, *, remove_created: bool = False) -> None:
        """Close the handle and optionally remove its securely-created file."""

        with self._lock:
            self._finalizer()
            if remove_created and self._created:
                self._remove_created_file()

    def _rollback_or_poison(self, original_error: BaseException) -> None:
        """Rollback a failed context, permanently closing on rollback failure."""

        try:
            self._connection.rollback()
        except BaseException as rollback_error:  # noqa: BLE001
            self._poisoned = True
            self._finalizer()
            original_error.add_note(
                "SQLite rollback failed; the state database connection was closed "
                f"({type(rollback_error).__name__})"
            )

    def _validate_sqlite_descriptor(self) -> None:
        """Verify SQLite still owns the descriptor proven at construction."""

        try:
            trusted_value = os.fstat(self._database_descriptor)
            sqlite_value = os.fstat(self._sqlite_descriptor)
        except OSError as error:
            self._poisoned = True
            self._finalizer()
            raise RuntimeError("SQLite state database descriptor was lost") from error
        try:
            _validated_database_identity(trusted_value)
            _validated_database_identity(sqlite_value)
        except ConfigurationError:
            self._poisoned = True
            self._finalizer()
            raise
        if not _same_regular_file(
            trusted_value, self._database_identity
        ) or not _same_regular_file(sqlite_value, self._database_identity):
            self._poisoned = True
            self._finalizer()
            raise RuntimeError("SQLite state database descriptor identity changed")

    def _validate_path_identity(self) -> None:
        """Verify the parent and database path still name the pinned objects."""

        with _SQLITE_CONNECT_LOCK:
            self._validate_path_identity_locked()

    def _validate_path_identity_locked(self) -> None:
        """Validate a path while no sibling state-db fd can be opened."""

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


def _connect_verified_database(
    path: Path,
    identity: _FileIdentity,
    trusted_descriptor: int,
) -> tuple[sqlite3.Connection, int]:
    """Connect and prove SQLite opened exactly the securely-pinned inode."""

    with _SQLITE_CONNECT_LOCK:
        before = _snapshot_live_descriptors()
        trusted_stat = before.get(trusted_descriptor)
        if trusted_stat is None or not _same_regular_file(trusted_stat, identity):
            raise ConfigurationError("trusted SQLite database descriptor was lost")
        connection: sqlite3.Connection | None = None
        try:
            # Do not execute SQL until the descriptor opened by sqlite3.connect
            # has been identified and matched to the independently pinned file.
            connection = sqlite3.connect(
                path.as_uri() + "?mode=rw",
                uri=True,
                timeout=30.0,
                check_same_thread=False,
            )
            after = _snapshot_live_descriptors()
            matching = [
                descriptor
                for descriptor, value in after.items()
                if _descriptor_is_new(descriptor, value, before)
                and _same_regular_file(value, identity)
            ]
            if len(matching) != 1:
                raise ConfigurationError(
                    "SQLite connection did not open exactly one pinned database "
                    "descriptor"
                )
            return connection, matching[0]
        except BaseException:
            if connection is not None:
                _close_sqlite_connection(connection)
            raise


def _snapshot_live_descriptors() -> dict[int, os.stat_result]:
    """Snapshot currently-live descriptors without retaining the scan handle."""

    descriptor_root = (
        Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
    )
    if not descriptor_root.is_dir():
        raise ConfigurationError("live file-descriptor inspection is unavailable")
    try:
        entries = os.listdir(descriptor_root)
    except OSError as error:
        raise ConfigurationError(
            "live file descriptors could not be inspected"
        ) from error
    snapshot: dict[int, os.stat_result] = {}
    for entry in entries:
        try:
            descriptor = int(entry)
            value = os.fstat(descriptor)
        except (OSError, ValueError):
            # The directory-enumeration descriptor is closed by os.listdir
            # before this loop, and concurrent unrelated closes fail closed if
            # they affect the pinned descriptor proof.
            continue
        snapshot[descriptor] = value
    return snapshot


def _descriptor_is_new(
    descriptor: int,
    value: os.stat_result,
    before: dict[int, os.stat_result],
) -> bool:
    """Return whether a descriptor number or its underlying object is new."""

    previous = before.get(descriptor)
    if previous is None:
        return True
    return (
        previous.st_dev != value.st_dev
        or previous.st_ino != value.st_ino
        or stat.S_IFMT(previous.st_mode) != stat.S_IFMT(value.st_mode)
    )


def _same_regular_file(value: os.stat_result, identity: _FileIdentity) -> bool:
    """Return whether a descriptor is a regular file with the pinned inode."""

    return (
        stat.S_ISREG(value.st_mode)
        and value.st_dev == identity.device
        and value.st_ino == identity.inode
    )


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

    with _SQLITE_CONNECT_LOCK:
        return _open_database_file_locked(parent_descriptor, name)


def _open_database_file_locked(parent_descriptor: int, name: str) -> tuple[int, bool]:
    """Open one state DB while descriptor snapshots are excluded."""

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
        if value.st_nlink != 1:
            raise ConfigurationError(
                "SQLite state database must have exactly one hard link"
            )
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
    if value.st_nlink != 1:
        raise ConfigurationError(
            "SQLite state database must have exactly one hard link"
        )
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


def _close_resources(
    connection: sqlite3.Connection,
    database_descriptor: int,
    lock: RLock,
) -> None:
    """Close SQLite and its independently retained trusted descriptor."""

    with lock:
        _close_sqlite_connection(connection)
        try:
            os.close(database_descriptor)
        except OSError:
            pass


def _close_sqlite_connection(connection: sqlite3.Connection) -> None:
    """Close SQLite without allowing cleanup failure to strand trusted fds."""

    try:
        connection.close()
    except BaseException as close_error:  # noqa: BLE001
        # Cleanup runs while propagating a more important construction,
        # transaction, or finalization failure.
        _ = close_error
