"""Race-safe SQLite snapshots for trusted local runtime state."""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError
from master_agent.platform_runtime import (
    AtomicPublicationRecoveryBackend,
    AtomicStateIdentity,
    LockMode,
    PlatformContract,
    get_atomic_publication_recovery_backend,
    get_cross_process_locking_backend,
    get_secure_filesystem_backend,
    require_persistent_state_platform,
    require_platform_contract,
)

_DIGEST_BYTES = 32
_DIGEST_HEX_LENGTH = _DIGEST_BYTES * 2
_LEDGER_SUFFIX = ".master-agent.lock"
_FLOCK_SUFFIX = ".master-agent.flock"
_MAX_LEDGER_BYTES = 8 * 1024 * 1024


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


@dataclass(frozen=True, slots=True)
class _Generation:
    """One validated on-disk SQLite generation."""

    content: bytes
    digest: str
    identity: _FileIdentity


@dataclass(frozen=True, slots=True)
class _GenerationRef:
    """Ledger-safe identity of one immutable database generation."""

    digest: str
    device: int
    inode: int

    @classmethod
    def from_generation(cls, generation: _Generation) -> _GenerationRef:
        """Build a ledger reference from one securely-opened generation."""

        return cls(
            digest=generation.digest,
            device=generation.identity.device,
            inode=generation.identity.inode,
        )


@dataclass(frozen=True, slots=True)
class _LedgerState:
    """Last durable generation and any interrupted replacement."""

    committed: _GenerationRef
    pending_old: _GenerationRef | None = None
    pending_new: _GenerationRef | None = None


@dataclass(frozen=True, slots=True)
class _LedgerGeneration:
    """One immutable, validated ledger snapshot."""

    content: bytes
    digest: str
    identity: _FileIdentity
    state: _LedgerState


class _PosixPinnedSQLiteDatabase:
    """SQLite state serialized through a pinned directory and stable lock.

    SQLite's standard Python API can open only pathnames, not an already
    validated file descriptor. Reopening the public path would reintroduce a
    substitution race. This class therefore executes SQL in memory and persists
    ordinary SQLite bytes as same-directory, fsynced, atomic generations.

    A retained parent-directory descriptor serializes independent instances.
    An atomically replaced ledger binds the approved database name to a content
    digest and makes the prepare/replace/commit crash windows deterministic on
    restart. Ledger files are only ever opened read-only; state transitions are
    written to fresh private files before publication.
    """

    def __init__(
        self,
        path: Path,
        *,
        parent_directory: PinnedDirectory | None = None,
        create: bool = True,
        initialize_existing: bool = True,
    ) -> None:
        self._parent_pin = (
            parent_directory.duplicate() if parent_directory is not None else None
        )
        try:
            self._path = _database_path(path, self._parent_pin)
        except BaseException:
            if self._parent_pin is not None:
                self._parent_pin.close()
            raise
        self._parent = self._path.parent
        self._name = self._path.name
        self._ledger_name = f".{self._name}{_LEDGER_SUFFIX}"
        self._lock_name = f".{self._name}{_FLOCK_SUFFIX}"
        self._lock = RLock()
        self._active_context = False
        self._poisoned = False
        self._created = False
        self._lock_created = False
        self._ledger_created = False

        try:
            parent_descriptor = (
                self._parent_pin.duplicate_fd()
                if self._parent_pin is not None
                else _open_trusted_parent(self._parent, create=create)
            )
        except BaseException:
            if self._parent_pin is not None:
                self._parent_pin.close()
            raise
        lock_descriptor: int | None = None
        lock_identity: _FileIdentity | None = None
        database_descriptor: int | None = None
        database_identity: _FileIdentity | None = None
        ledger_identity: _FileIdentity | None = None
        cleanup_generation_ref: _GenerationRef | None = None
        try:
            self._parent_identity = _validated_parent_identity(
                os.fstat(parent_descriptor)
            )
            with _file_lock(parent_descriptor, exclusive=True):
                lock_descriptor, self._lock_created = _open_flock_file(
                    parent_descriptor,
                    self._lock_name,
                    create=create,
                )
                lock_identity = _validated_state_file_identity(
                    os.fstat(lock_descriptor),
                    label="SQLite state transaction lock",
                )
                with _file_lock(lock_descriptor, exclusive=True):
                    _validate_flock_path(
                        parent_descriptor,
                        self._lock_name,
                        lock_descriptor,
                        lock_identity,
                    )
                    database_descriptor, self._created = _open_database_file(
                        parent_descriptor,
                        self._name,
                        create=create,
                    )
                    if create and not initialize_existing and not self._created:
                        raise ConfigurationError(
                            "SQLite state database namespace changed during "
                            "initialization"
                        )
                    database_identity = _validated_state_file_identity(
                        os.fstat(database_descriptor),
                        label="SQLite state database",
                    )
                    generation = _read_generation(database_descriptor)
                    _reject_sqlite_sidecars(parent_descriptor, self._name)
                    validation_connection = _memory_connection(generation.content)
                    _close_sqlite_connection(validation_connection)
                    ledger = _read_ledger_generation(
                        parent_descriptor,
                        self._ledger_name,
                        missing_ok=create and (initialize_existing or self._created),
                    )
                    ledger_created = ledger is None
                    self._ledger_created = ledger_created
                    reconciled = _reconcile_ledger(
                        parent_descriptor,
                        self._ledger_name,
                        _GenerationRef.from_generation(generation),
                        ledger,
                    )
                    ledger_identity = reconciled.identity
                    if self._created:
                        cleanup_generation_ref = _GenerationRef.from_generation(
                            generation
                        )
        except BaseException:
            ledger_publication_is_indeterminate = (
                self._ledger_created and ledger_identity is None
            )
            if (
                not ledger_publication_is_indeterminate
                and lock_descriptor is not None
                and lock_identity is not None
            ):
                try:
                    with (
                        _file_lock(parent_descriptor, exclusive=True),
                        _file_lock(lock_descriptor, exclusive=True),
                    ):
                        parent_stat = os.fstat(parent_descriptor)
                        if not self._parent_identity.matches(
                            parent_stat
                        ) or not self._parent_identity.matches(self._parent.lstat()):
                            raise ConfigurationError(
                                "SQLite state database parent path was replaced"
                            )
                        _validate_flock_path(
                            parent_descriptor,
                            self._lock_name,
                            lock_descriptor,
                            lock_identity,
                        )
                        removed = False
                        database_cleanup_complete = not self._created
                        if self._created:
                            database_cleanup_complete = _unlink_if_identity(
                                parent_descriptor,
                                self._name,
                                database_identity,
                            )
                            removed = database_cleanup_complete
                        if self._ledger_created and database_cleanup_complete:
                            removed = (
                                _unlink_if_identity(
                                    parent_descriptor,
                                    self._ledger_name,
                                    ledger_identity,
                                )
                                or removed
                            )
                        if self._lock_created and database_cleanup_complete:
                            removed = (
                                _unlink_if_identity(
                                    parent_descriptor,
                                    self._lock_name,
                                    lock_identity,
                                )
                                or removed
                            )
                        if removed:
                            os.fsync(parent_descriptor)
                except (ConfigurationError, OSError):
                    pass
            if database_descriptor is not None:
                descriptor_to_close = database_descriptor
                database_descriptor = None
                os.close(descriptor_to_close)
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            os.close(parent_descriptor)
            if self._parent_pin is not None:
                self._parent_pin.close()
            raise
        finally:
            if database_descriptor is not None:
                try:
                    os.close(database_descriptor)
                except OSError:
                    pass

        if lock_descriptor is None or lock_identity is None:
            raise RuntimeError("SQLite state transaction lock was not initialized")
        self._parent_descriptor = parent_descriptor
        self._lock_descriptor = lock_descriptor
        self._lock_identity = lock_identity
        self._cleanup_generation_ref = cleanup_generation_ref
        self._finalizer = weakref.finalize(
            self,
            _close_descriptors,
            parent_descriptor,
            lock_descriptor,
            self._lock,
            self._parent_pin,
        )

    @property
    def created(self) -> bool:
        """Return whether this object securely created the initial database."""

        return self._created

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield an isolated in-memory transaction over the latest generation."""

        with self._lock:
            if self._poisoned or not self._finalizer.alive:
                raise RuntimeError("SQLite state database is closed")
            if self._active_context:
                raise RuntimeError("nested SQLite state database contexts are unsafe")
            self._active_context = True
            connection: sqlite3.Connection | None = None
            try:
                with (
                    _file_lock(self._parent_descriptor, exclusive=True),
                    _file_lock(self._lock_descriptor, exclusive=True),
                ):
                    self._validate_fixed_paths()
                    generation = self._load_current_generation()
                    connection = _memory_connection(generation.content)
                    try:
                        yield connection
                    except BaseException as error:
                        self._rollback_memory_connection(connection, error)
                        raise
                    connection.commit()
                    updated = _serialize_connection(connection)
                    if _digest(updated) != generation.digest:
                        self._persist_generation(generation, updated)
            finally:
                if connection is not None:
                    _close_sqlite_connection(connection)
                self._active_context = False

    def close(self, *, remove_created: bool = False) -> None:
        """Close retained descriptors and optionally remove created state."""

        with self._lock:
            try:
                if (
                    remove_created
                    and self._created
                    and self._cleanup_generation_ref is not None
                    and self._finalizer.alive
                ):
                    with (
                        _file_lock(self._parent_descriptor, exclusive=True),
                        _file_lock(self._lock_descriptor, exclusive=True),
                    ):
                        try:
                            self._validate_fixed_paths()
                            generation = self._load_current_generation()
                        except (ConfigurationError, OSError):
                            pass
                        else:
                            current_ref = _GenerationRef.from_generation(generation)
                            ledger = _read_ledger_generation(
                                self._parent_descriptor,
                                self._ledger_name,
                                missing_ok=False,
                            )
                            removed = False
                            if (
                                ledger is not None
                                and current_ref == self._cleanup_generation_ref
                                and ledger.state
                                == _LedgerState(committed=self._cleanup_generation_ref)
                            ):
                                removed = _unlink_if_identity(
                                    self._parent_descriptor,
                                    self._name,
                                    generation.identity,
                                )
                                if removed and self._ledger_created:
                                    _unlink_if_identity(
                                        self._parent_descriptor,
                                        self._ledger_name,
                                        ledger.identity,
                                    )
                                if removed and self._lock_created:
                                    _unlink_if_identity(
                                        self._parent_descriptor,
                                        self._lock_name,
                                        self._lock_identity,
                                    )
                            if removed:
                                os.fsync(self._parent_descriptor)
            finally:
                self._finalizer()

    def _rollback_memory_connection(
        self,
        connection: sqlite3.Connection,
        original_error: BaseException,
    ) -> None:
        """Rollback an abandoned memory transaction or poison this instance."""

        try:
            connection.rollback()
        except BaseException as rollback_error:  # noqa: BLE001
            self._poisoned = True
            original_error.add_note(
                "SQLite rollback failed; the state database instance was poisoned "
                f"({type(rollback_error).__name__})"
            )

    def _validate_fixed_paths(self) -> None:
        """Verify the public parent still names the pinned directory."""

        parent_stat = os.fstat(self._parent_descriptor)
        _validated_parent_identity(parent_stat)
        if not self._parent_identity.matches(parent_stat):
            raise ConfigurationError("SQLite state database parent identity changed")
        if self._parent_pin is None:
            path_stat = self._parent.lstat()
            if not self._parent_identity.matches(path_stat):
                raise ConfigurationError(
                    "SQLite state database parent path was replaced"
                )
        else:
            self._parent_pin.validate()
        _validate_flock_path(
            self._parent_descriptor,
            self._lock_name,
            self._lock_descriptor,
            self._lock_identity,
        )

    def _load_current_generation(self) -> _Generation:
        """Read the approved generation and reconcile an interrupted replace."""

        _reject_sqlite_sidecars(self._parent_descriptor, self._name)
        descriptor, _ = _open_database_file(
            self._parent_descriptor,
            self._name,
            create=False,
        )
        try:
            generation = _read_generation(descriptor)
        finally:
            os.close(descriptor)
        ledger = _read_ledger_generation(
            self._parent_descriptor,
            self._ledger_name,
            missing_ok=False,
        )
        _reconcile_ledger(
            self._parent_descriptor,
            self._ledger_name,
            _GenerationRef.from_generation(generation),
            ledger,
        )
        return generation

    def _persist_generation(self, previous: _Generation, updated: bytes) -> None:
        """Atomically replace exactly the generation reviewed by this context."""

        updated_digest = _digest(updated)
        temp_name = f".{self._name}.tmp-{secrets.token_hex(16)}"
        temp_descriptor = os.open(
            temp_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
            0o600,
            dir_fd=self._parent_descriptor,
        )
        temp_identity: _FileIdentity | None = None
        replaced = False
        prepared = False
        try:
            temp_identity = _validated_state_file_identity(
                os.fstat(temp_descriptor),
                label="SQLite state temporary generation",
            )
            _write_descriptor(temp_descriptor, updated)
            os.fsync(temp_descriptor)
            if _digest(_read_descriptor(temp_descriptor)) != updated_digest:
                raise OSError("SQLite state temporary generation verification failed")

            self._validate_fixed_paths()
            current = self._read_generation_without_reconciliation()
            if current.digest != previous.digest or not current.identity.matches(
                os.stat(
                    self._name,
                    dir_fd=self._parent_descriptor,
                    follow_symlinks=False,
                )
            ):
                raise ConfigurationError(
                    "SQLite state database generation changed before commit"
                )
            previous_ref = _GenerationRef.from_generation(previous)
            updated_ref = _GenerationRef(
                digest=updated_digest,
                device=temp_identity.device,
                inode=temp_identity.inode,
            )
            ledger = _read_ledger_generation(
                self._parent_descriptor,
                self._ledger_name,
                missing_ok=False,
            )
            if ledger is None:
                raise ConfigurationError(
                    "SQLite state database has no trusted lock ledger"
                )
            if (
                ledger.state.pending_new is not None
                or ledger.state.committed != previous_ref
            ):
                raise ConfigurationError(
                    "SQLite state ledger changed before database commit"
                )

            prepared_ledger = _replace_ledger_generation(
                self._parent_descriptor,
                self._ledger_name,
                expected=ledger,
                state=_LedgerState(
                    committed=previous_ref,
                    pending_old=previous_ref,
                    pending_new=updated_ref,
                ),
            )
            prepared = True

            # Recheck after PREPARE. A swap after this check is atomically
            # replaced as a directory entry; no attacker-selected inode is
            # opened or written.
            current = self._read_generation_without_reconciliation()
            if current.digest != previous.digest:
                raise ConfigurationError(
                    "SQLite state database generation changed during commit"
                )
            os.replace(
                temp_name,
                self._name,
                src_dir_fd=self._parent_descriptor,
                dst_dir_fd=self._parent_descriptor,
            )
            replaced = True
            os.fsync(self._parent_descriptor)

            committed = self._read_generation_without_reconciliation()
            if _GenerationRef.from_generation(committed) != updated_ref:
                raise ConfigurationError(
                    "SQLite state database replacement could not be verified"
                )
            _replace_ledger_generation(
                self._parent_descriptor,
                self._ledger_name,
                expected=prepared_ledger,
                state=_LedgerState(committed=updated_ref),
            )
            if self._cleanup_generation_ref is not None:
                self._cleanup_generation_ref = updated_ref
        except BaseException:
            if prepared:
                # PREPARE may be durable or replacement may have occurred. A
                # fresh instance must reconcile exact old/new generations.
                self._poisoned = True
            raise
        finally:
            os.close(temp_descriptor)
            if not replaced and temp_identity is not None:
                _unlink_if_identity(
                    self._parent_descriptor,
                    temp_name,
                    temp_identity,
                )

    def _read_generation_without_reconciliation(self) -> _Generation:
        """Read the current path through the retained trusted directory."""

        descriptor, _ = _open_database_file(
            self._parent_descriptor,
            self._name,
            create=False,
        )
        try:
            return _read_generation(descriptor)
        finally:
            os.close(descriptor)


class _WindowsPinnedSQLiteDatabase:
    """Serialize in-memory SQLite generations through the Windows state backend."""

    def __init__(
        self,
        path: Path,
        *,
        atomic: AtomicPublicationRecoveryBackend,
        parent_directory: PinnedDirectory | None,
        create: bool = True,
        initialize_existing: bool = True,
    ) -> None:
        self._parent_pin = (
            parent_directory.duplicate() if parent_directory is not None else None
        )
        try:
            from master_agent.platform_runtime.windows.filesystem import (
                validate_windows_drive_path,
            )

            if self._parent_pin is None:
                self._path = Path(validate_windows_drive_path(path).canonical)
            elif path.parent == Path():
                self._path = Path(
                    str(self._parent_pin.path).rstrip("\\") + "\\" + path.name
                )
            else:
                selected = validate_windows_drive_path(path)
                parent = validate_windows_drive_path(self._parent_pin.path)
                if (
                    selected.components[:-1] != parent.components
                    or selected.drive != parent.drive
                ):
                    raise ConfigurationError(
                        "SQLite state database must be an immediate child of its "
                        "pinned parent"
                    )
                self._path = Path(selected.canonical)
            self._atomic = atomic
            self._lock = RLock()
            self._active_context = False
            self._closed = False
            self._created = False
            self._cleanup_identity: AtomicStateIdentity | None = None
            with atomic.open_transaction(
                self._path,
                max_bytes=_MAX_LEDGER_BYTES,
                create=create,
            ) as transaction:
                if transaction.identity is None:
                    if not create:
                        raise ConfigurationError("SQLite state database does not exist")
                    identity = transaction.publish_bytes(b"", expected=None)
                    self._created = True
                    self._cleanup_identity = identity
                else:
                    if create and not initialize_existing:
                        raise ConfigurationError(
                            "SQLite state database namespace changed during "
                            "initialization"
                        )
                    content = transaction.read_bytes()
                    if content is None:
                        raise ConfigurationError(
                            "SQLite state database disappeared during initialization"
                        )
                    validation = _memory_connection(content)
                    _close_sqlite_connection(validation)
        except BaseException:
            if self._parent_pin is not None:
                self._parent_pin.close()
            raise

    @property
    def created(self) -> bool:
        return self._created

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("SQLite state database is closed")
            if self._active_context:
                raise RuntimeError("nested SQLite state database contexts are unsafe")
            self._active_context = True
            connection: sqlite3.Connection | None = None
            try:
                with self._atomic.open_transaction(
                    self._path,
                    max_bytes=_MAX_LEDGER_BYTES,
                    create=False,
                ) as transaction:
                    content = transaction.read_bytes()
                    if content is None or transaction.identity is None:
                        raise ConfigurationError("SQLite state database does not exist")
                    generation = transaction.identity
                    connection = _memory_connection(content)
                    try:
                        yield connection
                    except BaseException as error:
                        try:
                            connection.rollback()
                        except BaseException as rollback_error:  # noqa: BLE001
                            error.add_note(
                                "SQLite rollback failed; the state transaction was "
                                f"abandoned ({type(rollback_error).__name__})"
                            )
                        raise
                    connection.commit()
                    updated = _serialize_connection(connection)
                    if _digest(updated) != generation.content_sha256:
                        published = transaction.publish_bytes(
                            updated,
                            expected=generation,
                        )
                        if self._cleanup_identity is not None:
                            self._cleanup_identity = published
            finally:
                if connection is not None:
                    _close_sqlite_connection(connection)
                self._active_context = False

    def close(self, *, remove_created: bool = False) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                if (
                    remove_created
                    and self._created
                    and self._cleanup_identity is not None
                ):
                    try:
                        with self._atomic.open_transaction(
                            self._path,
                            max_bytes=_MAX_LEDGER_BYTES,
                            create=False,
                        ) as transaction:
                            if transaction.identity == self._cleanup_identity:
                                transaction.remove(expected=self._cleanup_identity)
                    except (ConfigurationError, OSError):
                        pass
            finally:
                self._closed = True
                if self._parent_pin is not None:
                    self._parent_pin.close()


class PinnedSQLiteDatabase:
    """Select the certified native SQLite generation implementation."""

    def __init__(
        self,
        path: Path,
        *,
        parent_directory: PinnedDirectory | None = None,
        create: bool = True,
        initialize_existing: bool = True,
    ) -> None:
        require_persistent_state_platform()
        atomic = get_atomic_publication_recovery_backend()
        if atomic.backend_id == "windows-handle-atomic-state":
            self._implementation: (
                _PosixPinnedSQLiteDatabase | _WindowsPinnedSQLiteDatabase
            ) = _WindowsPinnedSQLiteDatabase(
                path,
                atomic=atomic,
                parent_directory=parent_directory,
                create=create,
                initialize_existing=initialize_existing,
            )
        else:
            self._implementation = _PosixPinnedSQLiteDatabase(
                path,
                parent_directory=parent_directory,
                create=create,
                initialize_existing=initialize_existing,
            )

    @property
    def created(self) -> bool:
        return self._implementation.created

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._implementation.connect() as connection:
            yield connection

    def close(self, *, remove_created: bool = False) -> None:
        self._implementation.close(remove_created=remove_created)


@contextmanager
def _posix_readonly_snapshot_connection(
    path: Path,
) -> Iterator[sqlite3.Connection]:
    """Open an existing stable POSIX generation without modifying it."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    parent = absolute.parent
    parent_descriptor = _open_trusted_parent(parent, create=False)
    parent_identity = _validated_parent_identity(os.fstat(parent_descriptor))
    lock_descriptor: int | None = None
    database_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        # Preserve a precise missing/unsafe database error without creating the
        # stable ledger. The generation used below is reopened under its lock.
        probe_descriptor, _ = _open_database_file(
            parent_descriptor,
            absolute.name,
            create=False,
            writable=False,
        )
        os.close(probe_descriptor)
        ledger_name = f".{absolute.name}{_LEDGER_SUFFIX}"
        lock_name = f".{absolute.name}{_FLOCK_SUFFIX}"
        try:
            lock_descriptor, _ = _open_flock_file(
                parent_descriptor,
                lock_name,
                create=False,
                writable=False,
            )
        except FileNotFoundError as error:
            raise ConfigurationError(
                "SQLite state database has no trusted transaction lock"
            ) from error
        lock_identity = _validated_state_file_identity(
            os.fstat(lock_descriptor),
            label="SQLite state transaction lock",
        )
        with (
            _file_lock(parent_descriptor, exclusive=False),
            _file_lock(lock_descriptor, exclusive=False),
        ):
            current_parent = os.fstat(parent_descriptor)
            if not parent_identity.matches(
                current_parent
            ) or not parent_identity.matches(parent.lstat()):
                raise ConfigurationError(
                    "SQLite state database parent path was replaced"
                )
            _validate_flock_path(
                parent_descriptor,
                lock_name,
                lock_descriptor,
                lock_identity,
            )
            database_descriptor, _ = _open_database_file(
                parent_descriptor,
                absolute.name,
                create=False,
                writable=False,
            )
            generation = _read_generation(database_descriptor)
            _reject_sqlite_sidecars(parent_descriptor, absolute.name)
            ledger = _read_ledger_generation(
                parent_descriptor,
                ledger_name,
                missing_ok=False,
            )
            if ledger is None:
                raise ConfigurationError(
                    "SQLite state database has no trusted lock ledger"
                )
            if ledger.state.pending_new is not None:
                raise ConfigurationError(
                    "SQLite state database has an interrupted replacement"
                )
            if ledger.state.committed != _GenerationRef.from_generation(generation):
                raise ConfigurationError(
                    "SQLite state database content identity changed"
                )
            connection = _memory_connection(generation.content)
            connection.execute("PRAGMA query_only = ON")
            yield connection
    finally:
        if connection is not None:
            _close_sqlite_connection(connection)
        if database_descriptor is not None:
            os.close(database_descriptor)
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        os.close(parent_descriptor)


@contextmanager
def readonly_snapshot_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """Open an existing stable native generation without modifying it."""

    require_persistent_state_platform()
    atomic = get_atomic_publication_recovery_backend()
    if atomic.backend_id != "windows-handle-atomic-state":
        with _posix_readonly_snapshot_connection(path) as connection:
            yield connection
        return
    with atomic.open_transaction(
        path,
        max_bytes=_MAX_LEDGER_BYTES,
        create=False,
    ) as transaction:
        content = transaction.read_bytes()
        if content is None:
            raise ConfigurationError("SQLite state database does not exist")
        connection = _memory_connection(content)
        try:
            connection.execute("PRAGMA query_only = ON")
            yield connection
        finally:
            _close_sqlite_connection(connection)


def path_entry_exists(path: Path) -> bool:
    """Return whether a directory entry exists, including a broken symlink."""

    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    require_platform_contract(PlatformContract.ATOMIC_PUBLICATION_RECOVERY)
    atomic = get_atomic_publication_recovery_backend()
    if atomic.backend_id == "windows-handle-atomic-state":
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        filesystem = get_secure_filesystem_backend()
        if not isinstance(filesystem, WindowsSecureFilesystemBackend):
            raise ConfigurationError("native Windows secure filesystem is unavailable")
        try:
            with filesystem.pin_file(path, require_private=True):
                return True
        except FileNotFoundError:
            return False
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


@contextmanager
def _file_lock(descriptor: int, *, exclusive: bool) -> Iterator[None]:
    """Hold an advisory whole-file lock across one snapshot transaction."""

    locking = get_cross_process_locking_backend()
    try:
        locking.acquire(
            descriptor,
            mode=LockMode.EXCLUSIVE if exclusive else LockMode.SHARED,
        )
    except OSError as error:
        raise ConfigurationError("SQLite state lock could not be acquired") from error
    try:
        yield
    finally:
        try:
            locking.release(descriptor)
        except OSError:
            pass


def _memory_connection(content: bytes) -> sqlite3.Connection:
    """Create an isolated connection from ordinary serialized SQLite bytes."""

    connection = sqlite3.connect(":memory:", check_same_thread=False)
    try:
        if content:
            connection.deserialize(content)
            row = connection.execute("PRAGMA quick_check").fetchone()
            if row is None or str(row[0]).casefold() != "ok":
                raise ConfigurationError("SQLite state database integrity check failed")
        connection.execute("PRAGMA temp_store = MEMORY")
        return connection
    except BaseException:
        _close_sqlite_connection(connection)
        raise


def _serialize_connection(connection: sqlite3.Connection) -> bytes:
    """Serialize a memory database, treating a schema-free database as empty."""

    try:
        return bytes(connection.serialize())
    except sqlite3.OperationalError as error:
        if "unable to serialize" in str(error).casefold():
            return b""
        raise


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
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _database_path(path: Path, parent: PinnedDirectory | None) -> Path:
    """Bind a database filename to an optional approved parent directory."""

    selected = Path(path)
    if parent is None:
        return Path(os.path.abspath(os.fspath(selected)))
    parent.validate()
    if selected.parent == Path():
        return parent.path / selected.name
    absolute = Path(os.path.abspath(os.fspath(selected)))
    if absolute.parent != parent.path:
        raise ConfigurationError(
            "SQLite state database must be an immediate child of its pinned parent"
        )
    return absolute


def _open_flock_file(
    parent_descriptor: int,
    name: str,
    *,
    create: bool = True,
    writable: bool = True,
) -> tuple[int, bool]:
    """Open or create the stable, content-free transaction lock."""

    flags = (os.O_RDWR if writable else os.O_RDONLY) | _no_follow_flag()
    created = False
    opened_identity: _FileIdentity | None = None
    if create:
        try:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    else:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        value = os.fstat(descriptor)
        opened_identity = _FileIdentity.from_stat(value)
        _validate_regular_owned_single_link(
            value,
            label="SQLite state transaction lock",
        )
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(parent_descriptor)
        elif stat.S_IMODE(value.st_mode) != 0o600:
            raise ConfigurationError(
                "SQLite state transaction lock permissions must remain 0600"
            )
        if os.fstat(descriptor).st_size != 0:
            raise ConfigurationError(
                "SQLite state transaction lock must remain content-free"
            )
    except BaseException:
        os.close(descriptor)
        if created:
            _unlink_if_identity(parent_descriptor, name, opened_identity)
        raise
    return descriptor, created


def _validate_flock_path(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    identity: _FileIdentity,
) -> None:
    """Prove the retained transaction lock still owns its public name."""

    descriptor_stat = os.fstat(descriptor)
    _validated_state_file_identity(
        descriptor_stat,
        label="SQLite state transaction lock",
    )
    if descriptor_stat.st_size != 0:
        raise ConfigurationError(
            "SQLite state transaction lock must remain content-free"
        )
    if not identity.matches(descriptor_stat):
        raise ConfigurationError(
            "SQLite state transaction lock descriptor identity changed"
        )
    try:
        public = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise ConfigurationError(
            "SQLite state transaction lock path was replaced"
        ) from error
    _validated_state_file_identity(public, label="SQLite state transaction lock")
    if not identity.matches(public):
        raise ConfigurationError("SQLite state transaction lock path was replaced")


def _open_ledger_file(parent_descriptor: int, name: str) -> int:
    """Open one existing ledger read-only without following aliases."""

    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _no_follow_flag(),
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "SQLite state ledger must be a regular no-follow file"
        ) from error
    try:
        _validated_state_file_identity(
            os.fstat(descriptor),
            label="SQLite state ledger",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_database_file(
    parent_descriptor: int,
    name: str,
    *,
    create: bool,
    writable: bool = True,
) -> tuple[int, bool]:
    """Open or securely create one approved SQLite generation."""

    flags = (os.O_RDWR if writable else os.O_RDONLY) | _no_follow_flag()
    created = False
    opened_identity: _FileIdentity | None = None
    if create:
        try:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    else:
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError as error:
            raise ConfigurationError("SQLite state database does not exist") from error
        except OSError as error:
            raise ConfigurationError(
                "SQLite state database must be a regular no-follow file"
            ) from error
    try:
        value = os.fstat(descriptor)
        opened_identity = _FileIdentity.from_stat(value)
        _validate_regular_owned_single_link(value, label="SQLite state database")
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(parent_descriptor)
        elif stat.S_IMODE(value.st_mode) != 0o600:
            raise ConfigurationError(
                "SQLite state database permissions must remain 0600"
            )
    except BaseException:
        os.close(descriptor)
        if created:
            _unlink_if_identity(parent_descriptor, name, opened_identity)
        raise
    return descriptor, created


def _read_generation(descriptor: int) -> _Generation:
    """Read one immutable snapshot from a validated open descriptor."""

    value = os.fstat(descriptor)
    identity = _validated_state_file_identity(
        value,
        label="SQLite state database",
    )
    content = _read_descriptor(descriptor)
    return _Generation(content=content, digest=_digest(content), identity=identity)


def _read_descriptor(descriptor: int, *, max_bytes: int | None = None) -> bytes:
    """Read all bytes without sharing or changing the descriptor offset."""

    size = os.fstat(descriptor).st_size
    if max_bytes is not None and size > max_bytes:
        raise ConfigurationError("SQLite state ledger exceeds its safety limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise OSError("SQLite state database ended during a locked read")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _write_descriptor(descriptor: int, content: bytes) -> None:
    """Replace one temporary descriptor's bytes before it becomes public."""

    os.ftruncate(descriptor, 0)
    offset = 0
    while offset < len(content):
        written = os.pwrite(descriptor, content[offset:], offset)
        if written <= 0:
            raise OSError("SQLite state temporary generation write stalled")
        offset += written
    os.ftruncate(descriptor, len(content))


def _digest(content: bytes) -> str:
    """Return the ledger identity for serialized SQLite bytes."""

    return hashlib.sha256(content).hexdigest()


def _read_ledger_generation(
    parent_descriptor: int,
    name: str,
    *,
    missing_ok: bool,
) -> _LedgerGeneration | None:
    """Read one complete ledger through a read-only, identity-checked handle."""

    try:
        descriptor = _open_ledger_file(parent_descriptor, name)
    except FileNotFoundError as error:
        if missing_ok:
            return None
        raise ConfigurationError(
            "SQLite state database has no trusted lock ledger"
        ) from error
    try:
        before = os.fstat(descriptor)
        identity = _validated_state_file_identity(
            before,
            label="SQLite state ledger",
        )
        if before.st_size > _MAX_LEDGER_BYTES:
            raise ConfigurationError("SQLite state ledger exceeds its safety limit")
        content = _read_descriptor(descriptor, max_bytes=_MAX_LEDGER_BYTES)
        after = os.fstat(descriptor)
        _validated_state_file_identity(after, label="SQLite state ledger")
        if not identity.matches(after) or after.st_size != len(content):
            raise ConfigurationError("SQLite state ledger changed while it was read")
        try:
            public = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ConfigurationError("SQLite state ledger path was replaced") from error
        _validated_state_file_identity(public, label="SQLite state ledger")
        if not identity.matches(public):
            raise ConfigurationError("SQLite state ledger path was replaced")
    finally:
        os.close(descriptor)
    if not content.endswith(b"\n"):
        raise ConfigurationError("SQLite state ledger has a torn tail")
    state = _parse_complete_ledger(content)
    return _LedgerGeneration(
        content=content,
        digest=_digest(content),
        identity=identity,
        state=state,
    )


def _parse_complete_ledger(raw: bytes) -> _LedgerState:
    """Parse one snapshot or a legacy append-only ledger."""

    committed: _GenerationRef | None = None
    pending_old: _GenerationRef | None = None
    pending_new: _GenerationRef | None = None
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ConfigurationError("SQLite state ledger is malformed") from error
    for line in lines:
        parts = line.split(" ")
        if len(parts) == 4 and parts[0] == "C":
            value = _parse_ref(parts[1:])
            if committed is None and pending_new is None:
                committed = value
            elif pending_new == value:
                committed = value
                pending_old = None
                pending_new = None
            else:
                raise ConfigurationError("SQLite state ledger commit is inconsistent")
        elif len(parts) == 7 and parts[0] == "P" and pending_new is None:
            old = _parse_ref(parts[1:4])
            new = _parse_ref(parts[4:7])
            if committed != old:
                raise ConfigurationError("SQLite state ledger prepare is inconsistent")
            pending_old = old
            pending_new = new
        elif len(parts) == 4 and parts[0] == "A":
            aborted = _parse_ref(parts[1:])
            if pending_old != aborted:
                raise ConfigurationError("SQLite state ledger abort is inconsistent")
            pending_old = None
            pending_new = None
        else:
            raise ConfigurationError("SQLite state ledger is malformed")
    if committed is None:
        raise ConfigurationError("SQLite state ledger is empty")
    return _LedgerState(
        committed=committed,
        pending_old=pending_old,
        pending_new=pending_new,
    )


def _format_ledger_state(state: _LedgerState) -> bytes:
    """Serialize one compact, complete ledger snapshot."""

    records = [f"C {_format_ref(state.committed)}\n"]
    if (state.pending_old is None) != (state.pending_new is None):
        raise ConfigurationError("SQLite state ledger pending state is incomplete")
    if state.pending_old is not None and state.pending_new is not None:
        if state.pending_old != state.committed:
            raise ConfigurationError("SQLite state ledger prepare is inconsistent")
        records.append(
            f"P {_format_ref(state.pending_old)} {_format_ref(state.pending_new)}\n"
        )
    return "".join(records).encode("ascii")


def _replace_ledger_generation(
    parent_descriptor: int,
    name: str,
    *,
    expected: _LedgerGeneration | None,
    state: _LedgerState,
) -> _LedgerGeneration:
    """Publish a complete ledger snapshot without mutating an opened ledger."""

    content = _format_ledger_state(state)
    temp_name = f".{name}.tmp-{secrets.token_hex(16)}"
    descriptor = os.open(
        temp_name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
        0o600,
        dir_fd=parent_descriptor,
    )
    temp_identity: _FileIdentity | None = None
    replaced = False
    try:
        os.fchmod(descriptor, 0o600)
        temp_identity = _validated_state_file_identity(
            os.fstat(descriptor),
            label="SQLite state temporary ledger",
        )
        _write_descriptor(descriptor, content)
        os.fsync(descriptor)
        if _read_descriptor(descriptor) != content:
            raise OSError("SQLite state temporary ledger verification failed")

        observed = _read_ledger_generation(
            parent_descriptor,
            name,
            missing_ok=True,
        )
        if expected is None:
            if observed is not None:
                raise ConfigurationError(
                    "SQLite state ledger appeared before publication"
                )
        elif (
            observed is None
            or observed.identity != expected.identity
            or observed.digest != expected.digest
            or observed.content != expected.content
        ):
            raise ConfigurationError("SQLite state ledger changed before publication")

        os.replace(
            temp_name,
            name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        replaced = True
        os.fsync(parent_descriptor)
        published = _read_ledger_generation(
            parent_descriptor,
            name,
            missing_ok=False,
        )
        if published is None:
            raise ConfigurationError(
                "SQLite state ledger disappeared after publication"
            )
        if published.identity != temp_identity or published.content != content:
            raise ConfigurationError(
                "SQLite state ledger replacement could not be verified"
            )
        return published
    finally:
        os.close(descriptor)
        if not replaced and temp_identity is not None:
            _unlink_if_identity(parent_descriptor, temp_name, temp_identity)


def _reconcile_ledger(
    parent_descriptor: int,
    name: str,
    current: _GenerationRef,
    ledger: _LedgerGeneration | None,
) -> _LedgerGeneration:
    """Resolve only the two outcomes of a prepared atomic replacement."""

    if ledger is None:
        return _replace_ledger_generation(
            parent_descriptor,
            name,
            expected=None,
            state=_LedgerState(committed=current),
        )
    state = ledger.state
    if state.pending_new is not None:
        if current == state.pending_new or current == state.pending_old:
            reconciled = _LedgerState(committed=current)
        else:
            raise ConfigurationError(
                "SQLite state database does not match either prepared generation"
            )
        ledger = _replace_ledger_generation(
            parent_descriptor,
            name,
            expected=ledger,
            state=reconciled,
        )
        state = ledger.state
    if state.committed != current:
        raise ConfigurationError("SQLite state database content identity changed")
    return ledger


def _is_digest(value: str) -> bool:
    """Return whether a ledger field is one lowercase SHA-256 digest."""

    return len(value) == _DIGEST_HEX_LENGTH and all(
        character in "0123456789abcdef" for character in value
    )


def _format_ref(reference: _GenerationRef) -> str:
    """Serialize one generation reference into three ASCII ledger fields."""

    return f"{reference.digest} {reference.device} {reference.inode}"


def _parse_ref(fields: list[str]) -> _GenerationRef:
    """Parse one strict generation reference from ledger fields."""

    if len(fields) != 3 or not _is_digest(fields[0]):
        raise ConfigurationError("SQLite state ledger reference is malformed")
    try:
        device = int(fields[1])
        inode = int(fields[2])
    except ValueError as error:
        raise ConfigurationError(
            "SQLite state ledger reference is malformed"
        ) from error
    if device < 0 or inode <= 0:
        raise ConfigurationError("SQLite state ledger reference is malformed")
    return _GenerationRef(digest=fields[0], device=device, inode=inode)


def _reject_sqlite_sidecars(parent_descriptor: int, name: str) -> None:
    """Fail closed rather than ignore a legacy hot journal or WAL."""

    for suffix in ("-journal", "-wal", "-shm"):
        try:
            os.stat(
                name + suffix,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        raise ConfigurationError(
            f"SQLite state database has an unsupported sidecar: {suffix}"
        )


def _validated_parent_identity(value: os.stat_result) -> _FileIdentity:
    """Validate and capture a trusted state-directory identity."""

    if not stat.S_ISDIR(value.st_mode):
        raise ConfigurationError("SQLite state database parent must be a directory")
    if value.st_uid != get_secure_filesystem_backend().real_user_id():
        raise ConfigurationError(
            "SQLite state database parent must be owned by the current account"
        )
    mode = stat.S_IMODE(value.st_mode)
    if mode & 0o022:
        raise ConfigurationError(
            "SQLite state database parent must not be group- or world-writable"
        )
    return _FileIdentity.from_stat(value)


def _validated_state_file_identity(
    value: os.stat_result,
    *,
    label: str,
) -> _FileIdentity:
    """Validate and capture one private regular state-file identity."""

    _validate_regular_owned_single_link(value, label=label)
    if stat.S_IMODE(value.st_mode) != 0o600:
        raise ConfigurationError(f"{label} permissions must remain 0600")
    return _FileIdentity.from_stat(value)


def _validate_regular_owned_single_link(
    value: os.stat_result,
    *,
    label: str,
) -> None:
    """Reject special files, aliases, and files controlled by another account."""

    if not stat.S_ISREG(value.st_mode):
        raise ConfigurationError(f"{label} must be a regular file")
    if value.st_nlink != 1:
        raise ConfigurationError(f"{label} must have exactly one hard link")
    if value.st_uid != get_secure_filesystem_backend().real_user_id():
        raise ConfigurationError(f"{label} must be owned by the current account")


def _unlink_if_identity(
    parent_descriptor: int,
    name: str,
    identity: _FileIdentity | None,
) -> bool:
    """Remove only an exact temporary or newly-created directory entry."""

    try:
        value = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if identity is None or not identity.matches(value):
        return False
    os.unlink(name, dir_fd=parent_descriptor)
    return True


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


def _close_descriptors(
    parent_descriptor: int,
    lock_descriptor: int,
    lock: RLock,
    parent_pin: PinnedDirectory | None,
) -> None:
    """Close stable descriptors under the same lock used for transactions."""

    with lock:
        for descriptor in (lock_descriptor, parent_descriptor):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if parent_pin is not None:
            parent_pin.close()


def _close_sqlite_connection(connection: sqlite3.Connection) -> None:
    """Close a disposable memory connection during every exit path."""

    try:
        connection.close()
    except BaseException as close_error:  # noqa: BLE001
        _ = close_error
