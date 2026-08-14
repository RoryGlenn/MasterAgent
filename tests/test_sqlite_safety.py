"""Adversarial tests for identity-pinned SQLite transaction handling."""

from __future__ import annotations

import os
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from master_agent import sqlite_safety
from master_agent.errors import ConfigurationError
from master_agent.sqlite_safety import PinnedSQLiteDatabase


class SQLiteSafetyTests(unittest.TestCase):
    """Exercise descriptor, hardlink, and transaction failure boundaries."""

    def test_keyboard_interrupt_is_rolled_back_before_a_later_commit(self) -> None:
        with TemporaryDirectory() as directory:
            database = PinnedSQLiteDatabase(Path(directory) / "state.sqlite3")
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")

            with self.assertRaises(KeyboardInterrupt), database.connect() as connection:
                connection.execute("INSERT INTO values_for_test VALUES (1)")
                raise KeyboardInterrupt

            with database.connect() as connection:
                connection.execute("INSERT INTO values_for_test VALUES (2)")
            with database.connect() as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test ORDER BY value"
                ).fetchall()

            self.assertEqual(rows, [(2,)])
            database.close()

    def test_nested_context_is_rejected_without_committing_outer_write(self) -> None:
        with TemporaryDirectory() as directory:
            database = PinnedSQLiteDatabase(Path(directory) / "state.sqlite3")
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")

            with (
                self.assertRaisesRegex(RuntimeError, "nested SQLite"),
                database.connect() as outer,
            ):
                outer.execute("INSERT INTO values_for_test VALUES (1)")
                with database.connect() as inner:
                    inner.execute("INSERT INTO values_for_test VALUES (2)")

            with database.connect() as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(rows, [])
            database.close()

    def test_hardlink_is_rejected_before_chmod_or_database_write(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sensitive.txt"
            database_path = root / "state.sqlite3"
            target.write_bytes(b"must-not-change")
            target.chmod(0o644)
            os.link(target, database_path)

            with self.assertRaisesRegex(ConfigurationError, "hard link"):
                PinnedSQLiteDatabase(database_path)

            self.assertEqual(target.read_bytes(), b"must-not-change")
            self.assertEqual(database_path.read_bytes(), b"must-not-change")
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            self.assertEqual(database_path.stat().st_mode & 0o777, 0o644)

    def test_new_hardlink_blocks_a_later_write(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            alias = root / "state-alias.sqlite3"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")

            with (
                self.assertRaisesRegex(ConfigurationError, "hard link"),
                database.connect() as connection,
            ):
                connection.execute("INSERT INTO values_for_test VALUES (1)")
                # Add the link after preflight so the pre-commit revalidation
                # must roll back SQL that has already run in this context.
                os.link(database_path, alias)

            alias.unlink()
            with database.connect() as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(rows, [])
            database.close()

    def test_removing_created_state_also_removes_its_ledger_for_retry(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")

            database.close(remove_created=True)

            self.assertFalse(database_path.exists())
            self.assertFalse(ledger_path.exists())
            self.assertFalse(lock_path.exists())
            replacement = PinnedSQLiteDatabase(database_path)
            with replacement.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            replacement.close()

    def test_cleanup_does_not_remove_a_generation_committed_by_a_peer(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            creator = PinnedSQLiteDatabase(database_path)
            with creator.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            peer = PinnedSQLiteDatabase(database_path)
            with peer.connect() as connection:
                connection.execute("INSERT INTO values_for_test VALUES (1)")
            paths = (database_path, ledger_path, lock_path)
            before = {
                path.name: (path.read_bytes(), path.stat().st_ino) for path in paths
            }

            creator.close(remove_created=True)

            after = {
                path.name: (path.read_bytes(), path.stat().st_ino) for path in paths
            }
            self.assertEqual(after, before)
            with peer.connect() as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(rows, [(1,)])
            peer.close()

    def test_read_only_peer_does_not_take_created_state_cleanup_ownership(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            creator = PinnedSQLiteDatabase(database_path)
            with creator.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            peer = PinnedSQLiteDatabase(database_path)
            with peer.connect() as connection:
                self.assertEqual(
                    connection.execute("SELECT * FROM values_for_test").fetchall(),
                    [],
                )

            creator.close(remove_created=True)

            self.assertFalse(database_path.exists())
            self.assertFalse(ledger_path.exists())
            self.assertFalse(lock_path.exists())
            peer.close()

    def test_cleanup_refuses_same_content_on_a_replacement_inode(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            replacement = root / "replacement.sqlite3"
            creator = PinnedSQLiteDatabase(database_path)
            with creator.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            original_content = database_path.read_bytes()
            original_inode = database_path.stat().st_ino
            replacement.write_bytes(original_content)
            replacement.chmod(0o600)
            replacement.replace(database_path)
            replacement_inode = database_path.stat().st_ino
            self.assertNotEqual(replacement_inode, original_inode)

            creator.close(remove_created=True)

            self.assertEqual(database_path.read_bytes(), original_content)
            self.assertEqual(database_path.stat().st_ino, replacement_inode)
            self.assertTrue(ledger_path.exists())
            self.assertTrue(lock_path.exists())

    def test_ledger_snapshots_remain_compact_and_lock_remains_content_free(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE counter (value INTEGER NOT NULL)")
                connection.execute("INSERT INTO counter VALUES (0)")
            for _ in range(100):
                with database.connect() as connection:
                    connection.execute("UPDATE counter SET value = value + 1")
            database.close()

            self.assertLess(ledger_path.stat().st_size, 512)
            self.assertEqual(lock_path.read_bytes(), b"")

    def test_last_moment_destination_swap_never_writes_attacker_inode(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            displaced = root / "trusted-old.sqlite3"
            attacker = root / "attacker.sqlite3"
            attacker_alias = root / "attacker-preserved.sqlite3"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            with closing(sqlite3.connect(attacker)) as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
                connection.execute("INSERT INTO values_for_test VALUES (99)")
                connection.commit()
            os.link(attacker, attacker_alias)
            real_replace = sqlite_safety.os.replace
            swapped = False

            def replace_after_destination_swap(
                source: str,
                destination: str,
                **kwargs: object,
            ) -> None:
                nonlocal swapped
                if destination != database_path.name or swapped:
                    real_replace(source, destination, **kwargs)  # type: ignore[arg-type]
                    return
                swapped = True
                database_path.rename(displaced)
                attacker.rename(database_path)
                real_replace(source, destination, **kwargs)  # type: ignore[arg-type]

            with (
                patch.object(
                    sqlite_safety.os,
                    "replace",
                    side_effect=replace_after_destination_swap,
                ),
                database.connect() as connection,
            ):
                connection.execute("INSERT INTO values_for_test VALUES (1)")

            with closing(sqlite3.connect(database_path)) as connection:
                committed = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            with closing(sqlite3.connect(attacker_alias)) as connection:
                attacker_rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            with closing(sqlite3.connect(displaced)) as connection:
                displaced_rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(committed, [(1,)])
            self.assertEqual(attacker_rows, [(99,)])
            self.assertEqual(displaced_rows, [])
            database.close()

    def test_interrupted_prepare_recovers_the_exact_old_generation(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "state.sqlite3"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")

            with (
                patch.object(
                    sqlite_safety.os,
                    "replace",
                    side_effect=OSError("simulated crash before replace"),
                ),
                self.assertRaisesRegex(OSError, "before replace"),
                database.connect() as connection,
            ):
                connection.execute("INSERT INTO values_for_test VALUES (1)")
            database.close()

            recovered = PinnedSQLiteDatabase(database_path)
            with recovered.connect() as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(rows, [])
            recovered.close()

    def test_interrupted_commit_recovers_the_exact_new_generation(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "state.sqlite3"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            real_replace = sqlite_safety._replace_ledger_generation
            prepared = False

            def fail_commit_record(
                parent_descriptor: int,
                name: str,
                *,
                expected: Any,
                state: Any,
            ) -> Any:
                nonlocal prepared
                if state.pending_new is not None:
                    prepared = True
                    return real_replace(
                        parent_descriptor,
                        name,
                        expected=expected,
                        state=state,
                    )
                if prepared:
                    raise OSError("simulated crash after replace")
                return real_replace(
                    parent_descriptor,
                    name,
                    expected=expected,
                    state=state,
                )

            with (
                patch.object(
                    sqlite_safety,
                    "_replace_ledger_generation",
                    side_effect=fail_commit_record,
                ),
                self.assertRaisesRegex(OSError, "after replace"),
                database.connect() as connection,
            ):
                connection.execute("INSERT INTO values_for_test VALUES (1)")
            database.close()

            recovered = PinnedSQLiteDatabase(database_path)
            with recovered.connect() as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(rows, [(1,)])
            recovered.close()

    def test_constructor_ledger_swap_never_writes_opened_victim(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            displaced_ledger = root / "trusted-ledger"
            victim = root / "victim.txt"
            database = PinnedSQLiteDatabase(database_path)
            database.close()
            victim.write_bytes(b"must-not-change")
            victim.chmod(0o600)
            victim_before = (victim.read_bytes(), victim.stat().st_mode & 0o777)
            real_open = sqlite_safety._open_ledger_file

            def open_swapped_ledger(parent_descriptor: int, name: str) -> int:
                ledger_path.rename(displaced_ledger)
                victim.rename(ledger_path)
                try:
                    return real_open(parent_descriptor, name)
                finally:
                    ledger_path.rename(victim)
                    displaced_ledger.rename(ledger_path)

            with (
                patch.object(
                    sqlite_safety,
                    "_open_ledger_file",
                    side_effect=open_swapped_ledger,
                ),
                self.assertRaisesRegex(ConfigurationError, "ledger path was replaced"),
            ):
                PinnedSQLiteDatabase(database_path)

            self.assertEqual(
                (victim.read_bytes(), victim.stat().st_mode & 0o777),
                victim_before,
            )

    def test_constructor_flock_swap_fails_before_state_mutation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            displaced_lock = root / "trusted-lock"
            victim = root / "victim.lock"
            database = PinnedSQLiteDatabase(database_path)
            database.close()
            victim.write_bytes(b"")
            victim.chmod(0o600)
            database_before = database_path.read_bytes()
            ledger_before = ledger_path.read_bytes()
            victim_before = (victim.read_bytes(), victim.stat().st_mode & 0o777)
            real_open = sqlite_safety._open_flock_file

            def open_swapped_lock(
                parent_descriptor: int,
                name: str,
                *,
                create: bool = True,
                writable: bool = True,
            ) -> tuple[int, bool]:
                lock_path.rename(displaced_lock)
                victim.rename(lock_path)
                try:
                    return real_open(
                        parent_descriptor,
                        name,
                        create=create,
                        writable=writable,
                    )
                finally:
                    lock_path.rename(victim)
                    displaced_lock.rename(lock_path)

            with (
                patch.object(
                    sqlite_safety,
                    "_open_flock_file",
                    side_effect=open_swapped_lock,
                ),
                self.assertRaisesRegex(ConfigurationError, "lock path was replaced"),
            ):
                PinnedSQLiteDatabase(database_path)

            self.assertEqual(database_path.read_bytes(), database_before)
            self.assertEqual(ledger_path.read_bytes(), ledger_before)
            self.assertEqual(
                (victim.read_bytes(), victim.stat().st_mode & 0o777),
                victim_before,
            )

    def test_constructor_database_swap_never_chmods_opened_victim(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            displaced_database = root / "trusted-database"
            victim = root / "victim.txt"
            database = PinnedSQLiteDatabase(database_path)
            database.close()
            victim.write_bytes(b"must-not-change")
            victim.chmod(0o644)
            victim_before = (victim.read_bytes(), victim.stat().st_mode & 0o777)
            real_open = sqlite_safety._open_database_file

            def open_swapped_database(
                parent_descriptor: int,
                name: str,
                *,
                create: bool,
                writable: bool = True,
            ) -> tuple[int, bool]:
                if not create:
                    return real_open(
                        parent_descriptor,
                        name,
                        create=create,
                        writable=writable,
                    )
                database_path.rename(displaced_database)
                victim.rename(database_path)
                try:
                    return real_open(
                        parent_descriptor,
                        name,
                        create=create,
                        writable=writable,
                    )
                finally:
                    database_path.rename(victim)
                    displaced_database.rename(database_path)

            with (
                patch.object(
                    sqlite_safety,
                    "_open_database_file",
                    side_effect=open_swapped_database,
                ),
                self.assertRaisesRegex(ConfigurationError, "permissions must remain"),
            ):
                PinnedSQLiteDatabase(database_path)

            self.assertEqual(
                (victim.read_bytes(), victim.stat().st_mode & 0o777),
                victim_before,
            )

    def test_indeterminate_initial_ledger_publication_remains_recoverable(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite3"
            ledger_path = root / ".state.sqlite3.master-agent.lock"
            lock_path = root / ".state.sqlite3.master-agent.flock"
            real_replace = sqlite_safety._replace_ledger_generation

            def publish_then_fail(
                parent_descriptor: int,
                name: str,
                *,
                expected: Any,
                state: Any,
            ) -> Any:
                _ = real_replace(
                    parent_descriptor,
                    name,
                    expected=expected,
                    state=state,
                )
                raise OSError("simulated lost publication acknowledgement")

            with (
                patch.object(
                    sqlite_safety,
                    "_replace_ledger_generation",
                    side_effect=publish_then_fail,
                ),
                self.assertRaisesRegex(OSError, "lost publication acknowledgement"),
            ):
                PinnedSQLiteDatabase(database_path)

            self.assertTrue(database_path.exists())
            self.assertTrue(ledger_path.exists())
            self.assertTrue(lock_path.exists())
            recovered = PinnedSQLiteDatabase(database_path)
            with recovered.connect() as connection:
                connection.execute("CREATE TABLE recovered (value INTEGER)")
            recovered.close()

    def test_rollback_failure_poison_closes_the_connection(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "state.sqlite3"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            real_connect = sqlite_safety.sqlite3.connect

            def rollback_failing_connect(
                *args: object,
                **kwargs: object,
            ) -> _RollbackFailingConnection:
                return _RollbackFailingConnection(real_connect(*args, **kwargs))

            with (
                patch.object(
                    sqlite_safety.sqlite3,
                    "connect",
                    side_effect=rollback_failing_connect,
                ),
                self.assertRaises(KeyboardInterrupt),
                database.connect() as connection,
            ):
                connection.execute("INSERT INTO values_for_test VALUES (1)")
                raise KeyboardInterrupt

            with self.assertRaisesRegex(RuntimeError, "closed"), database.connect():
                pass
            with closing(sqlite3.connect(database_path)) as connection:
                rows = connection.execute(
                    "SELECT value FROM values_for_test"
                ).fetchall()
            self.assertEqual(rows, [])


class _RollbackFailingConnection:
    """Delegate every operation except rollback to a real SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def rollback(self) -> None:
        """Simulate a connection whose rollback can no longer be trusted."""

        raise sqlite3.OperationalError("simulated rollback failure")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


if __name__ == "__main__":
    unittest.main()
