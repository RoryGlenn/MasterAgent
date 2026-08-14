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
