"""End-to-end CLI tests for the v1 phase-complete surface."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
import unittest

from master_agent.cli import main


ROOT = Path(__file__).resolve().parents[1]


class VersionOneCliTests(unittest.TestCase):
    """Exercise phase entry points without live credentials."""

    def test_generated_sample_plan_applies_with_local_connectors(self) -> None:
        """The public sample plan should remain executable after connector upgrades."""

        with TemporaryDirectory() as raw:
            root = Path(raw)
            plan = root / "sample-plan.json"
            database = root / "audit.sqlite3"
            report = root / "report.json"
            original = Path.cwd()
            try:
                os.chdir(root)
                status, _stdout, stderr = _run_cli(
                    ["sample-plan", "--output", str(plan)]
                )
                self.assertEqual(status, 0, stderr)
                status, _stdout, stderr = _run_cli(
                    [
                        "run",
                        str(plan),
                        "--apply",
                        "--database",
                        str(database),
                        "--result-json",
                        str(report),
                    ]
                )
                self.assertEqual(status, 0, stderr)
            finally:
                os.chdir(original)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(payload["successful"])

    def test_readiness_and_draft_package_work_outside_repository(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            original = Path.cwd()
            try:
                os.chdir(root)
                status, stdout, stderr = _run_cli(
                    ["readiness", "--output", str(root / "readiness.json")]
                )
                self.assertEqual(status, 0, stderr)
                self.assertIn("ready: True", stdout)
                readiness = json.loads((root / "readiness.json").read_text())
                self.assertTrue(readiness["ready"])

                status, stdout, stderr = _run_cli(
                    [
                        "draft-package",
                        "--output-dir",
                        str(root / "drafts"),
                        "--database",
                        str(root / "audit.sqlite3"),
                    ]
                )
                self.assertEqual(status, 0, stderr)
                self.assertIn("successful: True", stdout)
            finally:
                os.chdir(original)

            expected = {
                "jira-update-draft.json",
                "confluence-update-draft.json",
                "stakeholder-email.eml",
                "team-message.md",
                "change-package.pptx",
                "source-change.patch",
                "manifest.json",
            }
            self.assertTrue(expected.issubset({item.name for item in (root / "drafts").iterdir()}))

    def test_force_does_not_enable_packaged_recurring_workflow(self) -> None:
        with TemporaryDirectory() as directory:
            original = Path.cwd()
            try:
                os.chdir(directory)
                status, _stdout, stderr = _run_cli(
                    ["recurring-run", "weekly_status", "--force"]
                )
            finally:
                os.chdir(original)
            self.assertEqual(status, 1)
            self.assertIn("workflow is disabled", stderr)

    def test_enabled_mock_recurring_workflow_generates_package_once(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "recurring.toml"
            config.write_text(
                textwrap.dedent(
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
                    max_lateness_minutes = 10080
                    output_dir = "{root / 'output'}"
                    integration_config = "{ROOT / 'config/integrations.toml'}"
                    workflow_config = "{ROOT / 'config/weekly-status.toml'}"
                    identity_config = "{ROOT / 'config/identities.toml'}"
                    retention_config = "{ROOT / 'config/retention.toml'}"
                    allowed_capabilities = [
                      "jira.issue.search",
                      "bitbucket.pull_request.search",
                      "confluence.page.read",
                    ]
                    allowed_recipients = []
                    canonical_sources = ["jira://project"]
                    """
                ).strip() + "\n",
                encoding="utf-8",
            )
            status, stdout, stderr = _run_cli(
                [
                    "recurring-run",
                    "weekly",
                    "--recurring",
                    str(config),
                    "--connector-mode",
                    "mock",
                    "--force",
                ]
            )
            self.assertEqual(status, 0, stderr)
            self.assertIn('"successful": true', stdout.lower())
            self.assertTrue((root / "output/manifest.json").is_file())
            self.assertTrue((root / "output/weekly-status.pptx").is_file())


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(argv)
    return status, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
