"""Focused pure and native tests for Windows atomic state transactions."""

from __future__ import annotations

import hashlib
import importlib
import threading
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from master_agent import (
    advisory_budget,
    approval_handoff,
    capsules,
    directory_safety,
    oauth,
    operating,
    retention,
    sqlite_safety,
)
from master_agent.advisory import AdvisoryRole
from master_agent.advisory_budget import AdvisoryBudgetStore
from master_agent.capsules import (
    CapsuleRole,
    CapsuleStore,
    create_quarantined_manifest,
)
from master_agent.connectors import drafts
from master_agent.connectors.drafts import write_artifact_bundle
from master_agent.errors import ConfigurationError, ConnectorError
from master_agent.oauth import AccessToken, write_token_file
from master_agent.platform_runtime import AtomicStateIdentity
from master_agent.platform_runtime.windows import (
    NativeWindowsFileSnapshot,
    NativeWindowsSecurity,
    NativeWindowsVolume,
    WindowsAtomicPublicationRecoveryBackend,
    WindowsAtomicStateIndeterminate,
    WindowsAtomicStateTransaction,
    WindowsCrossProcessLockingBackend,
    WindowsDacl,
    WindowsPathSecurityError,
    WindowsSecureFilesystemBackend,
)
from master_agent.retention import (
    PersistenceMode,
    RetentionConfig,
    RetentionRule,
    purge_expired_evidence,
    repair_orphaned_evidence,
    write_retained_text,
)
from master_agent.sqlite_safety import PinnedSQLiteDatabase
from master_agent.workflows import communication_context, weekly_status
from tests.windows_adversarial_evidence import adversarial_reasons

CURRENT_SID = "S-1-5-21-100-200-300-1001"
OTHER_SID = "S-1-5-21-100-200-300-1002"


@dataclass(slots=True)
class _Object:
    object_number: int
    is_directory: bool
    path: str | None
    content: bytes = b""
    protected: bool = True
    owner_sid: str = CURRENT_SID
    security_generation: int = 0


class _AtomicFilesystemApi:
    """In-memory Win32 namespace with handle-stable object identities."""

    def __init__(self) -> None:
        self._next_object = 1
        self._next_handle = 100
        self._objects: dict[int, _Object] = {}
        self._paths: dict[str, int] = {}
        self._handles: dict[int, int] = {}
        self._positions: dict[int, int] = {}
        self._closed: set[int] = set()
        self._delete_on_close: set[int] = set()
        self.created_sddl: list[str] = []
        self.flushes: list[str] = []
        self.open_modes: list[tuple[str, bool, bool]] = []
        self.fail_replace_before: str | None = None
        self.fail_flush_once: str | None = None
        self.race_destination_before_replace: tuple[str, bytes] | None = None
        self.race_directory_before_create: str | None = None
        self._add_directory("C:\\")
        self._add_directory(r"C:\Secure")

    def current_user_sid(self) -> str:
        return CURRENT_SID

    def volume_information(self, root: str) -> NativeWindowsVolume:
        if root != "C:\\":
            raise AssertionError(root)
        return NativeWindowsVolume(3, 0x123, "NTFS", 255, 0x8)

    def open_path(
        self,
        path: str,
        *,
        directory: bool,
        readable: bool,
        writable: bool = False,
        replacement_handoff: bool = False,
        deletable: bool = False,
    ) -> int:
        del readable, writable
        self.open_modes.append((path, replacement_handoff, deletable))
        selected = self._objects[self._lookup(path)]
        if selected.is_directory != directory:
            if selected.is_directory:
                raise IsADirectoryError(path)
            raise NotADirectoryError(path)
        return self._new_handle(selected.object_number)

    def close_handle(self, handle: int) -> None:
        selected = self._object_for_handle(handle)
        if handle in self._delete_on_close and selected.path is not None:
            current = self._paths.get(selected.path.casefold())
            if current == selected.object_number:
                self._paths.pop(selected.path.casefold(), None)
                selected.path = None
        self._closed.add(handle)

    def duplicate_handle(self, handle: int) -> int:
        selected = self._object_for_handle(handle)
        duplicate = self._new_handle(selected.object_number)
        self._positions[duplicate] = self._positions[handle]
        return duplicate

    def file_snapshot(self, handle: int) -> NativeWindowsFileSnapshot:
        selected = self._object_for_handle(handle)
        return NativeWindowsFileSnapshot(
            attributes=0,
            is_directory=selected.is_directory,
            size=0 if selected.is_directory else len(selected.content),
            volume_serial_number=0x123,
            file_id=selected.object_number.to_bytes(16, "little"),
        )

    def file_security(self, handle: int) -> NativeWindowsSecurity:
        selected = self._object_for_handle(handle)
        return NativeWindowsSecurity(
            owner_sid=selected.owner_sid,
            dacl=WindowsDacl(
                raw=(
                    f"acl:{selected.object_number}:{selected.security_generation}"
                ).encode("ascii"),
                valid=True,
                allow_aces=(),
            ),
            dacl_protected=selected.protected,
        )

    def directory_is_case_sensitive(self, handle: int) -> bool:
        self._object_for_handle(handle)
        return False

    def final_path(self, handle: int) -> str:
        selected = self._object_for_handle(handle)
        if selected.path is None:
            raise FileNotFoundError("object is no longer in the namespace")
        return selected.path

    def directory_names(self, path: str) -> tuple[str, ...]:
        selected = self._objects[self._lookup(path)]
        if not selected.is_directory:
            raise NotADirectoryError(path)
        prefix = path.rstrip("\\") + "\\"
        names: list[str] = []
        for object_number in self._paths.values():
            child = self._objects[object_number]
            if child.path is None or not child.path.casefold().startswith(
                prefix.casefold()
            ):
                continue
            remainder = child.path[len(prefix) :]
            if remainder and "\\" not in remainder:
                names.append(remainder)
        return tuple(names)

    @staticmethod
    def compare_ordinal_ignore_case(left: str, right: str) -> int:
        left_key = left.casefold()
        right_key = right.casefold()
        return (left_key > right_key) - (left_key < right_key)

    def rewind_file(self, handle: int) -> None:
        self._object_for_handle(handle)
        self._positions[handle] = 0

    def read_file(self, handle: int, maximum_bytes: int) -> bytes:
        selected = self._object_for_handle(handle)
        position = self._positions[handle]
        value = selected.content[position : position + maximum_bytes]
        self._positions[handle] += len(value)
        return value

    def create_private_file(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int:
        parent = self._object_for_handle(parent_handle)
        if not parent.is_directory or parent.path is None:
            raise NotADirectoryError(name)
        path = parent.path.rstrip("\\") + "\\" + name
        self._require_absent(path)
        selected = self._add_file(path, b"")
        self.created_sddl.append(security_descriptor_sddl)
        return self._new_handle(selected.object_number)

    def create_private_directory(
        self,
        parent_handle: int,
        name: str,
        *,
        security_descriptor_sddl: str,
    ) -> int:
        parent = self._object_for_handle(parent_handle)
        if not parent.is_directory or parent.path is None:
            raise NotADirectoryError(name)
        path = parent.path.rstrip("\\") + "\\" + name
        if (
            self.race_directory_before_create is not None
            and path.casefold() == self.race_directory_before_create.casefold()
        ):
            self.race_directory_before_create = None
            self._add_directory(path)
        self._require_absent(path)
        selected = self._add_directory(path)
        self.created_sddl.append(security_descriptor_sddl)
        return self._new_handle(selected.object_number)

    def write_file(self, handle: int, payload: bytes) -> int:
        selected = self._object_for_handle(handle)
        position = self._positions[handle]
        selected.content = (
            selected.content[:position]
            + payload
            + selected.content[position + len(payload) :]
        )
        self._positions[handle] += len(payload)
        return len(payload)

    def flush_file(self, handle: int) -> None:
        selected = self._object_for_handle(handle)
        path = selected.path or "<unlinked>"
        self.flushes.append(path)
        if (
            self.fail_flush_once is not None
            and path.casefold() == self.fail_flush_once.casefold()
        ):
            self.fail_flush_once = None
            raise OSError("injected post-replacement flush failure")

    def flush_directory(self, handle: int) -> None:
        selected = self._object_for_handle(handle)
        if not selected.is_directory:
            raise NotADirectoryError("flush target")
        self.flushes.append(selected.path or "<unlinked>")

    def replace_file(
        self,
        source_handle: int,
        parent_handle: int,
        destination_name: str,
        *,
        replace_existing: bool,
    ) -> None:
        source = self._object_for_handle(source_handle)
        parent = self._object_for_handle(parent_handle)
        if source.path is None or parent.path is None or not parent.is_directory:
            raise FileNotFoundError(destination_name)
        if (
            self.fail_replace_before is not None
            and destination_name.casefold() == self.fail_replace_before.casefold()
        ):
            self.fail_replace_before = None
            raise OSError("injected pre-replacement failure")
        destination = parent.path.rstrip("\\") + "\\" + destination_name
        raced = self.race_destination_before_replace
        if raced is not None and destination.casefold() == raced[0].casefold():
            self.race_destination_before_replace = None
            self._add_file(destination, raced[1])
        if not replace_existing and destination.casefold() in self._paths:
            raise FileExistsError(destination)
        previous_number = self._paths.pop(destination.casefold(), None)
        if previous_number is not None:
            self._objects[previous_number].path = None
        self._paths.pop(source.path.casefold(), None)
        source.path = destination
        self._paths[destination.casefold()] = source.object_number

    def set_delete_on_close(self, handle: int, *, enabled: bool) -> None:
        self._object_for_handle(handle)
        if enabled:
            self._delete_on_close.add(handle)
        else:
            self._delete_on_close.discard(handle)

    def replace_with_private_bytes(self, path: str, payload: bytes) -> None:
        previous = self._paths.pop(path.casefold(), None)
        if previous is not None:
            self._objects[previous].path = None
        self._add_file(path, payload)

    def broaden_dacl(self, path: str) -> None:
        self._objects[self._lookup(path)].owner_sid = OTHER_SID

    def public_bytes(self, path: str) -> bytes | None:
        try:
            selected = self._objects[self._lookup(path)]
        except FileNotFoundError:
            return None
        return selected.content

    def object_number_for_handle(self, handle: int) -> int:
        return self._object_for_handle(handle).object_number

    def _add_directory(self, path: str) -> _Object:
        return self._add_object(path, is_directory=True, payload=b"")

    def _add_file(self, path: str, payload: bytes) -> _Object:
        return self._add_object(path, is_directory=False, payload=payload)

    def _add_object(
        self,
        path: str,
        *,
        is_directory: bool,
        payload: bytes,
    ) -> _Object:
        selected = _Object(
            object_number=self._next_object,
            is_directory=is_directory,
            path=path,
            content=payload,
        )
        self._next_object += 1
        self._objects[selected.object_number] = selected
        self._paths[path.casefold()] = selected.object_number
        return selected

    def _new_handle(self, object_number: int) -> int:
        handle = self._next_handle
        self._next_handle += 1
        self._handles[handle] = object_number
        self._positions[handle] = 0
        return handle

    def _lookup(self, path: str) -> int:
        try:
            return self._paths[path.casefold()]
        except KeyError:
            raise FileNotFoundError(path) from None

    def _require_absent(self, path: str) -> None:
        if path.casefold() in self._paths:
            raise FileExistsError(path)

    def _object_for_handle(self, handle: int) -> _Object:
        if handle in self._closed or handle not in self._handles:
            raise OSError("invalid handle")
        return self._objects[self._handles[handle]]


class _AtomicLockApi:
    """Blocking object-identity locks for the in-memory native API."""

    def __init__(self, filesystem: _AtomicFilesystemApi) -> None:
        self._filesystem = filesystem
        self._guard = threading.Lock()
        self._locks: dict[int, threading.Lock] = {}
        self._held: dict[int, threading.Lock] = {}

    def acquire(
        self,
        descriptor: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None:
        del descriptor, exclusive, blocking
        return None

    def release(self, descriptor: int) -> None:
        del descriptor

    def acquire_handle(
        self,
        handle: int,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> int | None:
        del exclusive
        object_number = self._filesystem.object_number_for_handle(handle)
        with self._guard:
            selected = self._locks.setdefault(object_number, threading.Lock())
        if not selected.acquire(blocking=blocking):
            return 33
        with self._guard:
            self._held[handle] = selected
        return None

    def release_handle(self, handle: int) -> None:
        with self._guard:
            selected = self._held.pop(handle)
        selected.release()


def _backend() -> tuple[
    _AtomicFilesystemApi,
    WindowsAtomicPublicationRecoveryBackend,
]:
    api = _AtomicFilesystemApi()
    filesystem = WindowsSecureFilesystemBackend(_api=api)
    locking = WindowsCrossProcessLockingBackend(_api=_AtomicLockApi(api))
    return api, WindowsAtomicPublicationRecoveryBackend(
        filesystem=filesystem,
        locking=locking,
    )


class WindowsAtomicStateTests(unittest.TestCase):
    """Exercise state lifecycles, recovery, bounds, and race rejection."""

    def test_create_read_update_remove_and_private_creation(self) -> None:
        api, backend = _backend()
        path = Path("C:/Secure/state.json")
        with backend.open_transaction(path, max_bytes=32, create=True) as transaction:
            self.assertIsNone(transaction.read_bytes())
            first = transaction.publish_bytes(b"first", expected=None)
        with backend.open_transaction(path, max_bytes=32, create=False) as transaction:
            self.assertEqual(transaction.read_bytes(), b"first")
            second = transaction.publish_bytes(b"second", expected=first)
            self.assertNotEqual(second, first)
        with backend.open_transaction(path, max_bytes=32, create=False) as transaction:
            self.assertEqual(transaction.identity, second)
            self.assertTrue(transaction.remove(expected=second))
        self.assertIsNone(api.public_bytes(r"C:\Secure\state.json"))
        self.assertTrue(api.created_sddl)
        self.assertTrue(all("D:P" in value for value in api.created_sddl))
        self.assertTrue(api.flushes)
        handoffs = [
            (index, path, deletable)
            for index, (path, enabled, deletable) in enumerate(api.open_modes)
            if enabled
        ]
        self.assertTrue(handoffs)
        for index, path, deletable in handoffs:
            self.assertFalse(deletable)
            self.assertIn((path, False, True), api.open_modes[index + 1 :])

    def test_first_ledger_is_staged_before_its_public_name_exists(self) -> None:
        api, backend = _backend()
        path = Path("C:/Secure/state.json")
        target_hash = hashlib.sha256("state.json".encode("utf-16-le")).hexdigest()[:32]
        ledger_path = rf"C:\Secure\.master-agent-{target_hash}.ledger"
        api.fail_replace_before = ledger_path.rsplit("\\", 1)[-1]

        with (
            self.assertRaises(OSError),
            backend.open_transaction(path, max_bytes=32, create=True) as transaction,
        ):
            transaction.publish_bytes(b"first", expected=None)

        self.assertIsNone(api.public_bytes(ledger_path))
        self.assertIsNone(api.public_bytes(r"C:\Secure\state.json"))
        with backend.open_transaction(path, max_bytes=32, create=True) as transaction:
            transaction.publish_bytes(b"first", expected=None)
        self.assertIsNotNone(api.public_bytes(ledger_path))

    @adversarial_reasons("indeterminate_generation")
    def test_interrupted_prepare_and_replace_reconcile_old_or_new(self) -> None:
        api, backend = _backend()
        path = Path("C:/Secure/state.json")
        with backend.open_transaction(path, max_bytes=32, create=True) as transaction:
            old = transaction.publish_bytes(b"old", expected=None)

        api.fail_replace_before = "state.json"
        with (
            self.assertRaises(OSError),
            backend.open_transaction(path, max_bytes=32, create=False) as transaction,
        ):
            transaction.publish_bytes(b"new", expected=old)
        with backend.open_transaction(path, max_bytes=32, create=False) as recovered:
            self.assertEqual(recovered.read_bytes(), b"old")
            recovered_old = recovered.identity
        assert recovered_old is not None
        old = recovered_old

        api.fail_flush_once = r"C:\Secure\state.json"
        with (
            self.assertRaises(OSError),
            backend.open_transaction(path, max_bytes=32, create=False) as transaction,
        ):
            transaction.publish_bytes(b"new", expected=old)
        with backend.open_transaction(path, max_bytes=32, create=False) as recovered:
            self.assertEqual(recovered.read_bytes(), b"new")

    def test_substitution_acl_mutation_and_bounds_fail_closed(self) -> None:
        api, backend = _backend()
        path = Path("C:/Secure/state.json")
        with backend.open_transaction(path, max_bytes=8, create=True) as transaction:
            transaction.publish_bytes(b"trusted", expected=None)
        api.replace_with_private_bytes(r"C:\Secure\state.json", b"attacker")
        with (
            self.assertRaises(WindowsAtomicStateIndeterminate),
            backend.open_transaction(path, max_bytes=8, create=False),
        ):
            pass

        api, backend = _backend()
        with backend.open_transaction(path, max_bytes=8, create=True) as transaction:
            identity = transaction.publish_bytes(b"trusted", expected=None)
            with self.assertRaisesRegex(ConfigurationError, "safety limit"):
                transaction.publish_bytes(b"too-large", expected=identity)
        api.broaden_dacl(r"C:\Secure\state.json")
        with (
            self.assertRaises(WindowsPathSecurityError),
            backend.open_transaction(path, max_bytes=8, create=False),
        ):
            pass

    def test_create_only_publication_preserves_a_raced_destination(self) -> None:
        api, backend = _backend()
        path = Path("C:/Secure/state.json")
        api.race_destination_before_replace = (
            r"C:\Secure\state.json",
            b"peer",
        )

        with (
            self.assertRaises(FileExistsError),
            backend.open_transaction(path, max_bytes=8, create=True) as transaction,
        ):
            transaction.publish_bytes(b"ours", expected=None)

        self.assertEqual(api.public_bytes(r"C:\Secure\state.json"), b"peer")

    def test_concurrent_writers_serialize_on_the_native_handle(self) -> None:
        _api, backend = _backend()
        path = Path("C:/Secure/state.json")
        first = backend.open_transaction(path, max_bytes=32, create=True)
        first.__enter__()
        entered = threading.Event()
        completed = threading.Event()

        def writer() -> None:
            with backend.open_transaction(path, max_bytes=32, create=True):
                entered.set()
            completed.set()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        self.assertFalse(entered.wait(0.05))
        first.close()
        self.assertTrue(entered.wait(1.0))
        self.assertTrue(completed.wait(1.0))
        thread.join(timeout=1.0)
        self.assertFalse(thread.is_alive())

    def test_operating_run_directory_creation_rejects_a_raced_peer(self) -> None:
        api, backend = _backend()
        child = Path("C:/Secure/" + "a" * 32)
        real_ensure = backend.ensure_private_directory

        def race_after_legacy_absence_check(path: Path) -> Path:
            if str(path).replace("/", "\\") == str(child).replace("/", "\\"):
                api._add_directory("C:\\Secure\\" + "a" * 32)
            return real_ensure(path)

        api.race_directory_before_create = "C:\\Secure\\" + "a" * 32
        with (
            patch.object(
                backend,
                "ensure_private_directory",
                side_effect=race_after_legacy_absence_check,
            ),
            patch.object(
                operating,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                operating,
                "get_secure_filesystem_backend",
                return_value=backend.filesystem,
            ),
            self.assertRaises(FileExistsError),
        ):
            operating._create_private_child(Path("C:/Secure"), "a" * 32)

    def test_unicode_casefold_aliases_do_not_cross_pinned_parents(self) -> None:
        pinned = Mock()
        pinned.path = Path("C:/Stra\u00dfe")
        pinned.object_identity.platform = "windows"
        pinned.duplicate.return_value = pinned
        sibling = Path("C:/Strasse/state.sqlite3")

        with self.assertRaisesRegex(ConnectorError, "escaped the output root"):
            drafts._pinned_name(pinned, Path("C:/Strasse/artifact.json"))
        with self.assertRaisesRegex(
            ConfigurationError,
            "immediate child of its pinned parent",
        ):
            sqlite_safety._WindowsPinnedSQLiteDatabase(
                sibling,
                atomic=Mock(),
                parent_directory=pinned,
            )
        with self.assertRaisesRegex(
            ConfigurationError,
            "immediate child of its pinned parent",
        ):
            retention._windows_retained_child(
                pinned,
                Path("C:/Strasse/evidence.json"),
            )

    def test_sqlite_serializes_through_the_windows_backend(self) -> None:
        api, backend = _backend()
        path = Path("C:/Secure/audit.sqlite3")
        with (
            patch("master_agent.sqlite_safety.require_persistent_state_platform"),
            patch(
                "master_agent.sqlite_safety.get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            database = PinnedSQLiteDatabase(path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE events (value TEXT NOT NULL)")
                connection.execute("INSERT INTO events VALUES ('ok')")
            database.close()

            reopened = PinnedSQLiteDatabase(path)
            with reopened.connect() as connection:
                self.assertEqual(
                    connection.execute("SELECT value FROM events").fetchone(),
                    ("ok",),
                )
            reopened.close()
        self.assertIsNotNone(api.public_bytes(r"C:\Secure\audit.sqlite3"))

    def test_retention_write_purge_and_quarantine_use_native_state(self) -> None:
        api, backend = _backend()
        config = RetentionConfig(
            default=RetentionRule(
                pattern="*",
                ttl_hours=1,
                persistence=PersistenceMode.EXPLICIT_CONTENT,
            ),
            rules=(),
        )
        created = datetime(2026, 1, 1, tzinfo=UTC)

        def pinned_root(
            *_args: object,
            **_kwargs: object,
        ) -> directory_safety.PinnedDirectory:
            return directory_safety._WindowsPinnedDirectory(
                backend.filesystem.pin_directory(
                    r"C:\Secure",
                    require_private=True,
                ),
                require_private=True,
            )

        initial_pin = pinned_root()
        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            evidence, sidecar = write_retained_text(
                Path("C:/Secure/evidence.txt"),
                "retained",
                evidence_type="test/full",
                config=config,
                now=created,
                parent_directory=initial_pin,
            )
        initial_pin.close()
        self.assertEqual(evidence.name, "evidence.txt")
        self.assertEqual(sidecar.name, "evidence.txt.retention.json")
        self.assertEqual(
            api.public_bytes(r"C:\Secure\evidence.txt"),
            b"retained",
        )

        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                directory_safety.PinnedDirectory,
                "open",
                side_effect=pinned_root,
            ),
        ):
            preview = purge_expired_evidence(
                Path("C:/Secure"),
                now=created + timedelta(hours=2),
                dry_run=True,
            )
            self.assertEqual(preview.expired_manifests, 1)
            applied = purge_expired_evidence(
                Path("C:/Secure"),
                now=created + timedelta(hours=2),
                dry_run=False,
            )
            self.assertEqual(applied.expired_manifests, 1)
            self.assertEqual(len(applied.removed_files), 2)

            orphan_path = Path("C:/Secure/orphan.txt")
            with backend.open_transaction(
                orphan_path,
                max_bytes=32,
                create=True,
            ) as transaction:
                transaction.publish_bytes(b"orphan", expected=None)
            repaired = repair_orphaned_evidence(
                Path("C:/Secure"),
                dry_run=False,
            )
        self.assertEqual(len(repaired.orphaned_files), 1)
        self.assertEqual(len(repaired.quarantined_files), 1)
        self.assertIsNone(api.public_bytes(r"C:\Secure\orphan.txt"))

    def test_interrupted_retention_pair_and_quarantine_recover_as_units(self) -> None:
        api, backend = _backend()
        config = RetentionConfig(
            default=RetentionRule(
                pattern="*",
                ttl_hours=1,
                persistence=PersistenceMode.EXPLICIT_CONTENT,
            ),
            rules=(),
        )
        created = datetime(2026, 1, 1, tzinfo=UTC)

        def pinned_root(
            *_args: object,
            **_kwargs: object,
        ) -> directory_safety.PinnedDirectory:
            return directory_safety._WindowsPinnedDirectory(
                backend.filesystem.pin_directory(
                    r"C:\Secure",
                    require_private=True,
                ),
                require_private=True,
            )

        initial_pin = pinned_root()
        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            write_retained_text(
                Path("C:/Secure/evidence.txt"),
                "retained",
                evidence_type="test/full",
                config=config,
                now=created,
                parent_directory=initial_pin,
            )
        initial_pin.close()

        original_remove = WindowsAtomicStateTransaction.remove
        interrupted_pair = False

        def interrupt_pair_remove(
            transaction: WindowsAtomicStateTransaction,
            *,
            expected: AtomicStateIdentity,
        ) -> bool:
            nonlocal interrupted_pair
            if not interrupted_pair and str(transaction.path).casefold().endswith(
                "evidence.txt.retention.json"
            ):
                interrupted_pair = True
                raise OSError("injected pair interruption")
            return original_remove(transaction, expected=expected)

        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                directory_safety.PinnedDirectory,
                "open",
                side_effect=pinned_root,
            ),
            patch.object(
                WindowsAtomicStateTransaction,
                "remove",
                new=interrupt_pair_remove,
            ),
        ):
            interrupted = purge_expired_evidence(
                Path("C:/Secure"),
                now=created + timedelta(hours=2),
                dry_run=False,
            )
        self.assertTrue(interrupted.errors)
        self.assertIsNotNone(
            api.public_bytes(r"C:\Secure\.master-agent-retention.transaction")
        )

        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                directory_safety.PinnedDirectory,
                "open",
                side_effect=pinned_root,
            ),
        ):
            recovered_pair = purge_expired_evidence(
                Path("C:/Secure"),
                now=created + timedelta(hours=2),
                dry_run=False,
            )
        self.assertFalse(recovered_pair.errors)
        self.assertEqual(recovered_pair.expired_manifests, 1)
        self.assertEqual(len(recovered_pair.removed_files), 2)
        self.assertIsNone(api.public_bytes(r"C:\Secure\evidence.txt"))
        self.assertIsNone(api.public_bytes(r"C:\Secure\evidence.txt.retention.json"))

        orphan_path = Path("C:/Secure/orphan.txt")
        with backend.open_transaction(
            orphan_path,
            max_bytes=32,
            create=True,
        ) as transaction:
            transaction.publish_bytes(b"orphan", expected=None)
        interrupted_quarantine = False

        def interrupt_quarantine_remove(
            transaction: WindowsAtomicStateTransaction,
            *,
            expected: AtomicStateIdentity,
        ) -> bool:
            nonlocal interrupted_quarantine
            if not interrupted_quarantine and str(transaction.path).casefold().endswith(
                "orphan.txt"
            ):
                interrupted_quarantine = True
                raise OSError("injected quarantine interruption")
            return original_remove(transaction, expected=expected)

        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                directory_safety.PinnedDirectory,
                "open",
                side_effect=pinned_root,
            ),
            patch.object(
                WindowsAtomicStateTransaction,
                "remove",
                new=interrupt_quarantine_remove,
            ),
        ):
            interrupted_repair = repair_orphaned_evidence(
                Path("C:/Secure"),
                dry_run=False,
            )
        self.assertTrue(interrupted_repair.errors)
        self.assertIsNotNone(
            api.public_bytes(r"C:\Secure\.master-agent-retention.transaction")
        )

        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                directory_safety.PinnedDirectory,
                "open",
                side_effect=pinned_root,
            ),
        ):
            recovered_quarantine = repair_orphaned_evidence(
                Path("C:/Secure"),
                dry_run=False,
            )
        self.assertFalse(recovered_quarantine.errors)
        self.assertEqual(len(recovered_quarantine.quarantined_files), 1)
        self.assertIsNone(api.public_bytes(r"C:\Secure\orphan.txt"))
        self.assertIsNone(
            api.public_bytes(r"C:\Secure\.master-agent-retention.transaction")
        )

    def test_retained_reservation_holds_and_commits_native_targets(self) -> None:
        api, backend = _backend()
        pinned = directory_safety._WindowsPinnedDirectory(
            backend.filesystem.pin_directory(
                r"C:\Secure",
                require_private=True,
            ),
            require_private=True,
        )
        config = RetentionConfig(
            default=RetentionRule(
                pattern="*",
                ttl_hours=1,
                persistence=PersistenceMode.EXPLICIT_CONTENT,
            ),
            rules=(),
        )
        with (
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            retention.RetainedJSONReservation(
                Path("C:/Secure/reserved.json"),
                evidence_type="test/full",
                config=config,
                include_content=True,
                parent_directory=pinned,
            ) as reservation,
        ):
            evidence, sidecar = reservation.commit({"value": "retained"})
        pinned.close()
        self.assertTrue(str(evidence).endswith(r"\reserved.json"))
        self.assertTrue(str(sidecar).endswith(r"\reserved.json.retention.json"))
        self.assertIsNotNone(api.public_bytes(r"C:\Secure\reserved.json"))
        self.assertIsNotNone(
            api.public_bytes(r"C:\Secure\reserved.json.retention.json")
        )

    def test_capsule_artifacts_manifests_and_lock_use_native_state(self) -> None:
        _api, backend = _backend()
        helpers = importlib.import_module("tests.test_capability_capsules")
        authorities, trust = helpers._authorities()
        bundle = helpers._bundle()
        manifest = create_quarantined_manifest(
            bundle,
            authority=authorities[CapsuleRole.GENERATOR],
            environment="test",
            worker_sha256="a" * 64,
        )
        with (
            patch.object(capsules, "_require_capsule_store_platform"),
            patch.object(
                capsules,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                capsules,
                "get_secure_filesystem_backend",
                return_value=backend.filesystem,
            ),
        ):
            store = CapsuleStore(Path("C:/Secure/capsules"))
            installed = store.install(bundle, manifest, trust=trust)
            self.assertTrue(str(installed).endswith(".manifest.json"))
            self.assertEqual(
                store.load_bundle(
                    manifest.spec.capability_id,
                    manifest.spec.version,
                ).artifact_sha256,
                bundle.artifact_sha256,
            )
            self.assertEqual(
                store.manifests(
                    manifest.spec.capability_id,
                    manifest.spec.version,
                    trust=trust,
                ),
                (manifest,),
            )

    def test_advisory_key_and_budget_database_use_native_state(self) -> None:
        api, backend = _backend()
        state = Path("C:/Secure/advisory")
        repository = Path(__file__).resolve().parents[1]
        with (
            patch.object(advisory_budget, "_require_advisory_budget_platform"),
            patch.object(
                advisory_budget,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch("master_agent.sqlite_safety.require_persistent_state_platform"),
            patch(
                "master_agent.sqlite_safety.get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            with AdvisoryBudgetStore(state, repository) as store:
                first = store.reserve(
                    "goal",
                    AdvisoryRole.RESEARCH,
                    max_research_tasks=2,
                    max_plan_reviews=1,
                )
            with AdvisoryBudgetStore(state, repository) as reopened:
                second = reopened.reserve(
                    "goal",
                    AdvisoryRole.RESEARCH,
                    max_research_tasks=2,
                    max_plan_reviews=1,
                )
        self.assertTrue(first.allowed)
        self.assertEqual(second.research_attempts, 2)
        self.assertEqual(
            len(api.public_bytes(r"C:\Secure\advisory\.budget.hmac-key") or b""),
            32,
        )

    def test_draft_bundle_uses_create_only_native_publication(self) -> None:
        api, backend = _backend()
        pinned = directory_safety._WindowsPinnedDirectory(
            backend.filesystem.pin_directory(
                r"C:\Secure",
                require_private=True,
            ),
            require_private=True,
        )
        with patch.object(
            drafts,
            "get_atomic_publication_recovery_backend",
            return_value=backend,
        ):
            artifacts = write_artifact_bundle(
                pinned,
                (
                    (Path("C:/Secure/one.txt"), b"one", "text/plain"),
                    (Path("C:/Secure/two.txt"), b"two", "text/plain"),
                ),
            )
            with self.assertRaisesRegex(ConnectorError, "already exists"):
                write_artifact_bundle(
                    pinned,
                    ((Path("C:/Secure/one.txt"), b"new", "text/plain"),),
                )
        pinned.close()
        self.assertEqual(len(artifacts), 2)
        self.assertEqual(api.public_bytes(r"C:\Secure\one.txt"), b"one")
        self.assertEqual(api.public_bytes(r"C:\Secure\two.txt"), b"two")

    def test_registered_workflow_packages_use_native_artifact_state(self) -> None:
        api, backend = _backend()

        def pin_root(path: Path) -> directory_safety.PinnedDirectory:
            return directory_safety._WindowsPinnedDirectory(
                backend.filesystem.pin_directory(path, require_private=True),
                require_private=True,
            )

        weekly_helpers = importlib.import_module("tests.test_weekly_status")
        weekly_settings = weekly_status.WeeklyStatusSettings.from_toml(
            Path(__file__).resolve().parents[1] / "config/weekly-status.toml"
        )
        with (
            patch.object(weekly_status, "require_persistent_state_platform"),
            patch.object(
                weekly_status,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(weekly_status, "pin_directory", side_effect=pin_root),
            patch.object(drafts, "require_persistent_state_platform"),
            patch.object(
                drafts,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            weekly_artifacts = weekly_status.render_weekly_status_package(
                weekly_helpers._report(),
                weekly_settings,
                output_dir=Path("C:/Secure/weekly"),
            )
        self.assertTrue(str(weekly_artifacts.manifest_json).endswith("manifest.json"))
        self.assertIsNotNone(api.public_bytes(r"C:\Secure\weekly\weekly-status.pptx"))

        communication_helpers = importlib.import_module(
            "tests.test_communication_context"
        )
        repository = Path(__file__).resolve().parents[1]
        communication_settings = (
            communication_context.CommunicationContextSettings.from_toml(
                repository / "config/communication-context.toml"
            )
        )
        retention_config = RetentionConfig.from_toml(
            repository / "config/retention.toml"
        )
        with (
            patch.object(
                communication_context,
                "require_persistent_state_platform",
            ),
            patch.object(
                communication_context,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(
                communication_context,
                "pin_directory",
                side_effect=pin_root,
            ),
            patch.object(retention, "_require_retention_platform"),
            patch.object(
                retention,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
            patch.object(drafts, "require_persistent_state_platform"),
            patch.object(
                drafts,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            communication_artifacts = (
                communication_context.render_communication_context_package(
                    communication_helpers._report(),
                    communication_settings,
                    output_dir=Path("C:/Secure/communication"),
                    retention=retention_config,
                )
            )
        self.assertTrue(
            str(communication_artifacts.manifest_json).endswith("manifest.json")
        )
        self.assertIsNotNone(api.public_bytes(r"C:\Secure\communication\manifest.json"))

    def test_approval_token_and_profile_publications_use_native_state(self) -> None:
        api, backend = _backend()
        pinned = directory_safety._WindowsPinnedDirectory(
            backend.filesystem.pin_directory(
                r"C:\Secure",
                require_private=True,
            ),
            require_private=True,
        )
        with patch.object(
            approval_handoff,
            "get_atomic_publication_recovery_backend",
            return_value=backend,
        ):
            approval_handoff._publish_restricted_bytes(
                pinned,
                "approval.json",
                b'{"approved":true}\n',
                reuse_identical=False,
            )
            with self.assertRaisesRegex(ConfigurationError, "already exists"):
                approval_handoff._publish_restricted_bytes(
                    pinned,
                    "approval.json",
                    b'{"approved":false}\n',
                    reuse_identical=False,
                )
        pinned.close()

        with (
            patch.object(oauth, "require_persistent_state_platform"),
            patch.object(
                oauth,
                "get_atomic_publication_recovery_backend",
                return_value=backend,
            ),
        ):
            write_token_file(
                Path("C:/Secure/token.json"),
                AccessToken(
                    value="secret-token",
                    expires_at=datetime(2027, 1, 1, tzinfo=UTC),
                    scopes=("read",),
                ),
            )

        with patch.object(
            operating,
            "get_atomic_publication_recovery_backend",
            return_value=backend,
        ):
            self.assertTrue(
                operating._install_private_file(
                    Path("C:/Secure/profile.toml"),
                    b'[organization]\nname = "test"\n',
                )
            )
            self.assertFalse(
                operating._install_private_file(
                    Path("C:/Secure/profile.toml"),
                    b'[organization]\nname = "test"\n',
                )
            )
        self.assertEqual(
            api.public_bytes(r"C:\Secure\approval.json"),
            b'{"approved":true}\n',
        )
        self.assertIn(
            b"secret-token",
            api.public_bytes(r"C:\Secure\token.json") or b"",
        )
        self.assertEqual(
            api.public_bytes(r"C:\Secure\profile.toml"),
            b'[organization]\nname = "test"\n',
        )


if __name__ == "__main__":
    unittest.main()
