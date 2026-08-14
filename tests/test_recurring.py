"""Tests for narrow registered recurring-workflow autonomy."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import textwrap
import threading
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from master_agent import sqlite_safety
from master_agent.errors import ConfigurationError
from master_agent.recurring import (
    ClaimStatus,
    RecurringConfig,
    RecurringRunner,
    RecurringRunResult,
    RecurringStateStore,
    validate_plan_scope,
    validate_recipients,
)


class RecurringWorkflowTests(unittest.TestCase):
    """Validate schedule calculation, durable state, and fixed scope."""

    def test_due_workflow_runs_once_for_scheduled_occurrence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "recurring.toml"
            config_path.write_text(_config_text(root), encoding="utf-8")
            config = RecurringConfig.from_toml(config_path)
            runner = RecurringRunner(config)
            now = datetime(2026, 8, 13, 20, 30, tzinfo=UTC)  # Thu 16:30 ET.
            calls: list[str] = []

            first = runner.run(
                "weekly",
                lambda workflow: _record_callback(workflow.name, calls),
                now=now,
            )
            second = runner.run(
                "weekly",
                lambda workflow: _record_callback(workflow.name, calls),
                now=now,
            )

            self.assertTrue(first.successful)
            self.assertEqual(calls, ["weekly"])
            self.assertTrue(second.summary["skipped"])

    def test_occurrence_claim_prevents_race_after_callback_unlocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "recurring.toml"
            config_path.write_text(_config_text(root), encoding="utf-8")
            config = RecurringConfig.from_toml(config_path)
            first_runner = RecurringRunner(config)
            second_runner = RecurringRunner(config)
            now = datetime(2026, 8, 13, 20, 30, tzinfo=UTC)
            callback_calls: list[str] = []
            callback_finished = threading.Event()
            allow_completion = threading.Event()
            first_results: list[RecurringRunResult] = []

            original_complete = first_runner._store.complete

            def delayed_complete(**kwargs: object) -> None:
                callback_finished.set()
                self.assertTrue(allow_completion.wait(timeout=5))
                original_complete(**kwargs)  # type: ignore[arg-type]

            first_runner._store.complete = delayed_complete  # type: ignore[method-assign]

            thread = threading.Thread(
                target=lambda: first_results.append(
                    first_runner.run(
                        "weekly",
                        lambda workflow: _record_callback(
                            workflow.name,
                            callback_calls,
                        ),
                        now=now,
                    )
                )
            )
            thread.start()
            self.assertTrue(callback_finished.wait(timeout=5))

            duplicate = second_runner.run(
                "weekly",
                lambda workflow: _record_callback(workflow.name, callback_calls),
                now=now,
            )
            allow_completion.set()
            thread.join(timeout=5)

            self.assertFalse(thread.is_alive())
            self.assertEqual(callback_calls, ["weekly"])
            self.assertTrue(duplicate.summary["skipped"])
            self.assertEqual(len(first_results), 1)
            with closing(sqlite3.connect(config.state_database)) as connection:
                rows = connection.execute(
                    "SELECT status FROM recurring_runs"
                ).fetchall()
            self.assertEqual(rows, [("succeeded",)])
            self.assertEqual(os.stat(config.state_database).st_mode & 0o777, 0o600)

    def test_failed_occurrence_is_not_automatically_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "recurring.toml"
            config_path.write_text(_config_text(root), encoding="utf-8")
            runner = RecurringRunner(RecurringConfig.from_toml(config_path))
            now = datetime(2026, 8, 13, 20, 30, tzinfo=UTC)
            calls = 0

            def fail_once(_: object) -> RecurringRunResult:
                nonlocal calls
                calls += 1
                raise RuntimeError("sensitive provider response")

            with self.assertRaisesRegex(RuntimeError, "sensitive provider"):
                runner.run("weekly", fail_once, now=now)
            second = runner.run("weekly", fail_once, now=now)

            self.assertEqual(calls, 1)
            self.assertTrue(second.summary["skipped"])
            raw = config_path.parent.joinpath("state.sqlite3").read_bytes()
            self.assertNotIn(b"sensitive provider response", raw)

    def test_expired_claim_requires_explicit_recovery_before_reclaim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "recurring.toml"
            config_path.write_text(_config_text(root), encoding="utf-8")
            config = RecurringConfig.from_toml(config_path)
            workflow = config.workflows["weekly"]
            now = datetime(2026, 8, 13, 20, 30, tzinfo=UTC)
            scheduled = workflow.schedule.scheduled_at_or_before(now)
            store = RecurringStateStore(
                config.state_database,
                lease_duration=timedelta(seconds=1),
            )
            self.assertTrue(
                store.claim(name="weekly", scheduled_at=scheduled, started_at=now)
            )

            store.expire_claims(now=now + timedelta(seconds=2))
            self.assertEqual(
                store.occurrence_status("weekly", scheduled),
                str(ClaimStatus.EXPIRED),
            )
            self.assertTrue(
                store.mark_recoverable(name="weekly", scheduled_at=scheduled)
            )

            runner = RecurringRunner(config)
            result = runner.run(
                "weekly",
                lambda item: RecurringRunResult(
                    successful=True,
                    summary={"workflow": item.name},
                ),
                now=now + timedelta(seconds=2),
                force=True,
            )

            self.assertTrue(result.successful)
            with closing(sqlite3.connect(config.state_database)) as connection:
                row = connection.execute(
                    "SELECT status, attempt_count FROM recurring_runs"
                ).fetchone()
            self.assertEqual(row, (str(ClaimStatus.SUCCEEDED), 2))

    def test_reclaimed_occurrence_rejects_stale_attempt_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            scheduled = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
            store = RecurringStateStore(
                database,
                lease_duration=timedelta(seconds=1),
            )
            stale_token = store.claim(
                name="weekly",
                scheduled_at=scheduled,
                started_at=scheduled,
            )
            self.assertIsNotNone(stale_token)
            self.assertEqual(
                store.expire_claims(now=scheduled + timedelta(seconds=2)),
                1,
            )
            self.assertTrue(
                store.mark_recoverable(name="weekly", scheduled_at=scheduled)
            )
            current_token = store.claim(
                name="weekly",
                scheduled_at=scheduled,
                started_at=scheduled + timedelta(seconds=2),
            )
            self.assertIsNotNone(current_token)
            self.assertNotEqual(stale_token, current_token)
            assert stale_token is not None
            assert current_token is not None

            self.assertFalse(
                store.renew(
                    name="weekly",
                    scheduled_at=scheduled,
                    claim_token=stale_token,
                    now=scheduled + timedelta(seconds=3),
                )
            )
            with self.assertRaisesRegex(
                ConfigurationError,
                "not actively claimed",
            ):
                store.complete(
                    name="weekly",
                    scheduled_at=scheduled,
                    claim_token=stale_token,
                    finished_at=scheduled + timedelta(seconds=3),
                    result=RecurringRunResult(
                        successful=True,
                        summary={"completed_by": "stale-attempt"},
                    ),
                )
            with self.assertRaisesRegex(
                ConfigurationError,
                "not actively claimed",
            ):
                store.fail(
                    name="weekly",
                    scheduled_at=scheduled,
                    claim_token=stale_token,
                    finished_at=scheduled + timedelta(seconds=3),
                    error=RuntimeError("stale attempt failed"),
                )

            store.complete(
                name="weekly",
                scheduled_at=scheduled,
                claim_token=current_token,
                finished_at=scheduled + timedelta(seconds=3),
                result=RecurringRunResult(
                    successful=True,
                    summary={"completed_by": "current-attempt"},
                ),
            )
            with closing(sqlite3.connect(database)) as connection:
                row = connection.execute(
                    "SELECT status, summary_json, claim_token FROM recurring_runs"
                ).fetchone()

        self.assertEqual(
            row,
            (
                str(ClaimStatus.SUCCEEDED),
                '{"completed_by":"current-attempt"}',
                None,
            ),
        )

    def test_concurrent_legacy_state_migration_precedes_attempt_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    CREATE TABLE recurring_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        workflow_name TEXT NOT NULL,
                        scheduled_at TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        finished_at TEXT NOT NULL,
                        successful INTEGER NOT NULL,
                        summary_json TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'succeeded',
                        lease_expires_at TEXT,
                        attempt_count INTEGER NOT NULL DEFAULT 1,
                        recovery_reason TEXT
                    )
                    """
                )
            stores: list[RecurringStateStore] = []
            errors: list[BaseException] = []
            barrier = threading.Barrier(8)

            def initialize_store() -> None:
                try:
                    barrier.wait(timeout=5)
                    stores.append(RecurringStateStore(database))
                except (
                    ConfigurationError,
                    OSError,
                    RuntimeError,
                    sqlite3.Error,
                ) as error:
                    errors.append(error)

            threads = [threading.Thread(target=initialize_store) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(len(stores), 8)
            scheduled = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
            store = stores[0]
            claim_token = store.claim(
                name="weekly",
                scheduled_at=scheduled,
                started_at=scheduled,
            )
            if claim_token is None:
                self.fail("migrated state did not return an attempt owner")
            with closing(sqlite3.connect(database)) as connection:
                columns = {
                    str(row[1])
                    for row in connection.execute("PRAGMA table_info(recurring_runs)")
                }
                stored_token = connection.execute(
                    "SELECT claim_token FROM recurring_runs"
                ).fetchone()

        self.assertIn("claim_token", columns)
        self.assertEqual(stored_token, (str(claim_token),))

    def test_post_construction_symlink_rebinding_rejects_claim_without_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            replacement = root / "replacement.sqlite3"
            displaced = root / "displaced.sqlite3"
            scheduled = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
            store = RecurringStateStore(database)
            replacement_store = RecurringStateStore(replacement)
            self.assertIsNotNone(
                store.claim(
                    name="original",
                    scheduled_at=scheduled,
                    started_at=scheduled,
                )
            )
            self.assertIsNotNone(
                replacement_store.claim(
                    name="replacement",
                    scheduled_at=scheduled,
                    started_at=scheduled,
                )
            )
            replacement_store.close()

            database.rename(displaced)
            database.symlink_to(replacement.name)

            with self.assertRaisesRegex(ConfigurationError, "no-follow"):
                store.claim(
                    name="must-not-be-redirected",
                    scheduled_at=scheduled + timedelta(days=7),
                    started_at=scheduled + timedelta(days=7),
                )

            self.assertEqual(_recurring_run_count(replacement), 1)
            self.assertEqual(_recurring_run_count(displaced), 1)
            store.close()

    def test_post_construction_regular_rebinding_rejects_claim_without_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            replacement = root / "replacement.sqlite3"
            displaced = root / "displaced.sqlite3"
            scheduled = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
            store = RecurringStateStore(database)
            replacement_store = RecurringStateStore(replacement)
            self.assertIsNotNone(
                store.claim(
                    name="original",
                    scheduled_at=scheduled,
                    started_at=scheduled,
                )
            )
            self.assertIsNotNone(
                replacement_store.claim(
                    name="replacement",
                    scheduled_at=scheduled,
                    started_at=scheduled,
                )
            )
            replacement_store.close()

            database.rename(displaced)
            replacement.rename(database)

            with self.assertRaisesRegex(ConfigurationError, "identity changed"):
                store.claim(
                    name="must-not-be-redirected",
                    scheduled_at=scheduled + timedelta(days=7),
                    started_at=scheduled + timedelta(days=7),
                )

            self.assertEqual(_recurring_run_count(database), 1)
            self.assertEqual(_recurring_run_count(displaced), 1)
            store.close()

    def test_constructor_swap_and_decoy_fd_cannot_redirect_schema_or_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            displaced = root / "displaced.sqlite3"
            attacker = root / "attacker.sqlite3"
            attacker.write_bytes(b"")
            attacker.chmod(0o600)
            store = RecurringStateStore(database)
            scheduled = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
            real_connect = sqlite_safety.sqlite3.connect
            decoy_descriptors: list[int] = []

            def connect_while_redirected(
                *args: object,
                **kwargs: object,
            ) -> sqlite3.Connection:
                database.rename(displaced)
                attacker.rename(database)
                try:
                    connection = real_connect(*args, **kwargs)
                finally:
                    database.rename(attacker)
                    displaced.rename(database)
                decoy_descriptors.append(os.open(database, os.O_RDWR | os.O_NOFOLLOW))
                return connection

            try:
                with patch.object(
                    sqlite_safety.sqlite3,
                    "connect",
                    side_effect=connect_while_redirected,
                ):
                    claim_token = store.claim(
                        name="must-not-be-redirected",
                        scheduled_at=scheduled,
                        started_at=scheduled,
                    )
                self.assertIsNotNone(claim_token)
                store.close()
                self.assertTrue(
                    all(os.fstat(descriptor).st_ino for descriptor in decoy_descriptors)
                )
            finally:
                for descriptor in decoy_descriptors:
                    os.close(descriptor)

            self.assertEqual(attacker.read_bytes(), b"")
            self.assertEqual(_recurring_run_count(database), 1)

    def test_scope_and_recipient_allowlists_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "recurring.toml"
            path.write_text(_config_text(root), encoding="utf-8")
            workflow = RecurringConfig.from_toml(path).workflows["weekly"]

            validate_plan_scope(("jira.issue.search",), workflow)
            validate_recipients(("rory@example.com",), workflow)
            with self.assertRaises(ConfigurationError):
                validate_plan_scope(("outlook.email.send",), workflow)
            with self.assertRaises(ConfigurationError):
                validate_recipients(("unknown@example.com",), workflow)

    def test_force_never_enables_a_disabled_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "recurring.toml"
            path.write_text(
                _config_text(root).replace("enabled = true", "enabled = false"),
                encoding="utf-8",
            )
            runner = RecurringRunner(RecurringConfig.from_toml(path))
            with self.assertRaises(ConfigurationError):
                runner.run(
                    "weekly",
                    lambda workflow: RecurringRunResult(
                        successful=True,
                        summary={"workflow": workflow.name},
                    ),
                    force=True,
                )

    def test_repository_safe_default_is_disabled(self) -> None:
        config = RecurringConfig.from_toml(Path("config/recurring.toml"))
        self.assertTrue(config.workflows)
        self.assertTrue(all(not item.enabled for item in config.workflows.values()))
        self.assertTrue(
            all(
                item.delivery_mode.value in {"local_only", "draft_only"}
                for item in config.workflows.values()
            )
        )


def _record_callback(name: str, calls: list[str]) -> RecurringRunResult:
    calls.append(name)
    return RecurringRunResult(successful=True, summary={"workflow": name})


def _recurring_run_count(database: Path) -> int:
    """Return the occurrence count without mutating the test database."""

    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute("SELECT COUNT(*) FROM recurring_runs").fetchone()
    assert row is not None
    return int(row[0])


def _config_text(root: Path) -> str:
    return textwrap.dedent(
        f"""
        [scheduler]
        state_database = "{root / "state.sqlite3"}"
        lock_dir = "{root / "locks"}"

        [workflows.weekly]
        enabled = true
        kind = "weekly_status_package"
        delivery_mode = "local_only"
        weekday = 3
        hour = 16
        minute = 0
        timezone = "America/New_York"
        max_lateness_minutes = 120
        output_dir = "{root / "out"}"
        integration_config = "{root / "integrations.toml"}"
        workflow_config = "{root / "workflow.toml"}"
        allowed_capabilities = ["jira.issue.search"]
        allowed_recipients = ["rory@example.com"]
        canonical_sources = ["jira://project"]
        """
    )


if __name__ == "__main__":
    unittest.main()
