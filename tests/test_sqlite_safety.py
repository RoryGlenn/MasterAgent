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
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")

            database.close(remove_created=True)

            self.assertFalse(database_path.exists())
            self.assertFalse(ledger_path.exists())
            replacement = PinnedSQLiteDatabase(database_path)
            with replacement.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            replacement.close()

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

            def replace_after_destination_swap(
                source: str,
                destination: str,
                **kwargs: object,
            ) -> None:
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
            real_append = sqlite_safety._append_ledger_record
            prepared = False

            def fail_commit_record(descriptor: int, record: str) -> None:
                nonlocal prepared
                if record.startswith("P "):
                    prepared = True
                    real_append(descriptor, record)
                    return
                if prepared and record.startswith("C "):
                    raise OSError("simulated crash after replace")
                real_append(descriptor, record)

            with (
                patch.object(
                    sqlite_safety,
                    "_append_ledger_record",
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
