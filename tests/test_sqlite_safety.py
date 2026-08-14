"""Adversarial tests for identity-pinned SQLite transaction handling."""

from __future__ import annotations

import os
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

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

    def test_rollback_failure_poison_closes_the_connection(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "state.sqlite3"
            database = PinnedSQLiteDatabase(database_path)
            with database.connect() as connection:
                connection.execute("CREATE TABLE values_for_test (value INTEGER)")
            database._connection = _RollbackFailingConnection(database._connection)

            with self.assertRaises(KeyboardInterrupt), database.connect() as connection:
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
