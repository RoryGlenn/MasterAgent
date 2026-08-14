"""Tests for narrow registered recurring-workflow autonomy."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import tempfile
import textwrap
import unittest

from master_agent.errors import ConfigurationError
from master_agent.recurring import (
    RecurringConfig,
    RecurringRunResult,
    RecurringRunner,
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
        state_database = "{root / 'state.sqlite3'}"
        lock_dir = "{root / 'locks'}"

        [workflows.weekly]
        enabled = true
        kind = "weekly_status_package"
        delivery_mode = "local_only"
        weekday = 3
        hour = 16
        minute = 0
        timezone = "America/New_York"
        max_lateness_minutes = 120
        output_dir = "{root / 'out'}"
        integration_config = "{root / 'integrations.toml'}"
        workflow_config = "{root / 'workflow.toml'}"
        allowed_capabilities = ["jira.issue.search"]
        allowed_recipients = ["rory@example.com"]
        canonical_sources = ["jira://project"]
        """
    )


if __name__ == "__main__":
    unittest.main()
