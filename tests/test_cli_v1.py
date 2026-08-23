"""End-to-end CLI tests for the v1 phase-complete surface."""

from __future__ import annotations

import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent.cli import main


class VersionOneCliTests(unittest.TestCase):
    """Exercise phase entry points without live credentials."""

    def test_generated_sample_plan_applies_with_local_connectors(self) -> None:
        """The public sample plan should remain executable after connector upgrades."""

        with TemporaryDirectory() as raw:
            root = Path(raw)
            plan = root / "sample-plan.json"
            bound_plan = root / "bound-sample-plan.json"
            state = root / "state"
            results = root / "results"
            database = state / "audit.sqlite3"
            report = results / "report.json"
            drafts = root / "drafts"
            for runtime_directory in (state, results, drafts):
                runtime_directory.mkdir(mode=0o700)
            original = Path.cwd()
            try:
                os.chdir(root)
                status, _stdout, stderr = _run_cli(
                    ["sample-plan", "--output", str(plan)]
                )
                self.assertEqual(status, 0, stderr)
                status, _stdout, stderr = _run_cli(
                    [
                        "bind-context",
                        str(plan),
                        "--connector-mode",
                        "mock",
                        "--database",
                        str(database),
                        "--result-json",
                        str(report),
                        "--draft-output-dir",
                        str(drafts),
                        "--output",
                        str(bound_plan),
                    ]
                )
                self.assertEqual(status, 0, stderr)
                status, _stdout, stderr = _run_cli(
                    [
                        "run",
                        str(bound_plan),
                        "--apply",
                        "--database",
                        str(database),
                        "--result-json",
                        str(report),
                        "--draft-output-dir",
                        str(drafts),
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
            (root / "drafts").mkdir(mode=0o700)
            original = Path.cwd()
            try:
                os.chdir(root)
                status, stdout, stderr = _run_cli(
                    ["readiness", "--output", str(root / "readiness.json")]
                )
                self.assertEqual(status, 0, stderr)
                self.assertIn("ready: True", stdout)
                self.assertIn(
                    "live connectors: 5 available, 0 credential-ready", stdout
                )
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
            self.assertTrue(
                expected.issubset({item.name for item in (root / "drafts").iterdir()})
            )

    def test_demo_runs_complete_safe_workflow_in_fresh_private_workspace(
        self,
    ) -> None:
        """One command should produce and verify a credential-free review package."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            checkout = root / "checkout"
            home.mkdir(mode=0o700)
            checkout.mkdir(mode=0o700)
            original = Path.cwd()
            try:
                os.chdir(checkout)
                with (
                    patch("master_agent.platform_paths.Path.home", return_value=home),
                    patch("master_agent.cli.build_live_registry") as live_registry,
                ):
                    status, stdout, stderr = _run_cli(["demo"])
            finally:
                os.chdir(original)

            product_root = home / ".master-agent" / "MasterAgent"
            workspaces = tuple(product_root.glob("demo-*"))
            self.assertEqual(len(workspaces), 1)
            workspace = workspaces[0].resolve()
            self.assertEqual(status, 0, stderr)
            self.assertIn("mode: safe local demonstration", stdout)
            self.assertIn(f"demo workspace: {workspace}", stdout)
            self.assertIn("mode: local generation", stdout)
            self.assertNotIn("mode: apply", stdout)
            self.assertIn("successful: True", stdout)
            self.assertIn("verified 8 audit events", stdout)
            live_registry.assert_not_called()
            self.assertFalse((checkout / ".master-agent").exists())
            self.assertTrue((workspace / "artifacts" / "manifest.json").is_file())
            self.assertTrue((workspace / "artifacts" / "change-package.pptx").is_file())
            self.assertTrue((workspace / "state" / "audit.sqlite3").is_file())
            self.assertEqual(product_root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)

    def test_draft_package_rejects_shared_audit_and_artifact_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch("master_agent.cli.resolve_config_source") as resolver,
                patch("master_agent.cli.AuditLog") as audit,
            ):
                status, _stdout, stderr = _run_cli(
                    [
                        "draft-package",
                        "--output-dir",
                        str(root),
                        "--database",
                        str(root / "audit.sqlite3"),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("directories must be distinct", stderr)
            resolver.assert_not_called()
            audit.assert_not_called()
            self.assertEqual(tuple(root.iterdir()), ())

    def test_draft_package_rejects_nonempty_output_before_config_or_audit(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "drafts"
            output.mkdir(mode=0o700)
            stale = output / "manifest.json"
            stale.write_bytes(b"peer-manifest")
            stale.chmod(0o600)
            with (
                patch("master_agent.cli.resolve_config_source") as resolver,
                patch("master_agent.cli.AuditLog") as audit,
            ):
                status, _stdout, stderr = _run_cli(
                    [
                        "draft-package",
                        "--output-dir",
                        str(output),
                        "--database",
                        str(root / "audit.sqlite3"),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("must be empty", stderr)
            resolver.assert_not_called()
            audit.assert_not_called()
            self.assertEqual(stale.read_bytes(), b"peer-manifest")

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
            self.assertIn("recurring-run execution is disabled", stderr)

    def test_citations_reports_when_result_contains_no_citations(self) -> None:
        """An empty successful lookup should be visible instead of printing nothing."""

        with TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            result.write_text("{}", encoding="utf-8")

            status, stdout, stderr = _run_cli(["citations", str(result)])

        self.assertEqual(status, 0, stderr)
        self.assertEqual(stdout, "no citations found\n")

    def test_unbound_execution_commands_fail_before_configs_clients_or_audit(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "untrusted.toml"
            commands = (
                [
                    "recurring-run",
                    "weekly",
                    "--recurring",
                    str(missing),
                    "--connector-mode",
                    "live",
                    "--force",
                ],
                [
                    "weekly-status",
                    "--integrations",
                    str(missing),
                    "--workflow",
                    str(missing),
                    "--output-dir",
                    str(root / "weekly"),
                    "--database",
                    str(root / "weekly-audit.sqlite3"),
                ],
                [
                    "communication-context",
                    "--integrations",
                    str(missing),
                    "--workflow",
                    str(missing),
                    "--identities",
                    str(missing),
                    "--retention",
                    str(missing),
                    "--output-dir",
                    str(root / "communication"),
                    "--database",
                    str(root / "communication-audit.sqlite3"),
                ],
            )
            for command in commands:
                with (
                    self.subTest(command=command[0]),
                    patch("master_agent.cli.resolve_config_source") as resolver,
                    patch("master_agent.cli.build_live_registry") as clients,
                    patch("master_agent.cli.AuditLog") as audit,
                ):
                    status, _stdout, stderr = _run_cli(command)
                    self.assertEqual(status, 1)
                    self.assertIn(f"{command[0]} execution is disabled", stderr)
                    resolver.assert_not_called()
                    clients.assert_not_called()
                    audit.assert_not_called()
            self.assertEqual(tuple(root.iterdir()), ())


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(argv)
    return status, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
