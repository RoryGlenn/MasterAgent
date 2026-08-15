"""Command-line safety and exit-status tests."""

from __future__ import annotations

import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from master_agent.cli import main
from master_agent.planners.static import build_weekly_status_plan
from tests.helpers import private_temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    """Verify CLI boundaries that protect live credentials and operators."""

    def test_live_mode_dry_run_does_not_require_credentials(self) -> None:
        """A policy-only dry run must not construct live connectors."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                __import__("json").dumps(
                    build_weekly_status_plan().to_dict(),
                    default=str,
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "run",
                        str(plan_path),
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(ROOT / "config/integrations.toml"),
                        "--database",
                        str(root / "audit.sqlite3"),
                        "--draft-output-dir",
                        str(root / "persistent/drafts"),
                        "--workspace-root",
                        str(root / "persistent/workspaces"),
                    ]
                )
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("mode: dry-run", stdout.getvalue())
            self.assertFalse((root / "audit.sqlite3").exists())
            self.assertFalse((root / "persistent").exists())

    def test_dry_run_cannot_persist_an_unbound_result(self) -> None:
        """Review mode must not write audit or result files outside a manifest."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                __import__("json").dumps(
                    build_weekly_status_plan().to_dict(),
                    default=str,
                ),
                encoding="utf-8",
            )
            stderr = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(stderr):
                status = main(
                    [
                        "run",
                        str(plan_path),
                        "--database",
                        str(root / "audit.sqlite3"),
                        "--result-json",
                        str(root / "result.json"),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("--result-json requires --apply", stderr.getvalue())
            self.assertFalse((root / "audit.sqlite3").exists())
            self.assertFalse((root / "result.json").exists())

    def test_discovery_returns_nonzero_for_enabled_missing_environment(self) -> None:
        """Enabled but unusable connectors should fail readiness checks."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            config = root / "integrations.toml"
            config.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "discover",
                        "--integrations",
                        str(config),
                        "--systems",
                        "jira",
                    ]
                )
            self.assertEqual(status, 2, stderr.getvalue())
            self.assertIn("missing_environment", stdout.getvalue())
            self.assertNotIn("secret", stdout.getvalue().lower())

    def test_packaged_defaults_allow_dry_run_outside_repository(self) -> None:
        """An installed package must not depend on the source-tree config path."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(
                __import__("json").dumps(
                    build_weekly_status_plan().to_dict(),
                    default=str,
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "run",
                            str(plan_path),
                            "--database",
                            str(root / "audit.sqlite3"),
                        ]
                    )
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("mode: dry-run", stdout.getvalue())

    def test_packaged_integrations_support_default_discovery(self) -> None:
        """Default discovery should use packaged disabled connector settings."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(["discover"])
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("disabled", stdout.getvalue())
            self.assertIn("jira", stdout.getvalue())

    def test_packaged_defaults_build_communication_plan_outside_repository(
        self,
    ) -> None:
        """Phase 2B planning must work from wheel-packaged safe defaults."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            output = root / "communication-plan.json"
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "communication-context-plan",
                            "--output",
                            str(output),
                        ]
                    )
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            payload = __import__("json").loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["actions"]), 4)
            self.assertTrue(
                all(action["risk"] == "read_only" for action in payload["actions"])
            )
            self.assertIn("plan fingerprint", stdout.getvalue())

    def test_packaged_identity_resolves_delegated_microsoft_user(self) -> None:
        """The default identity registry should resolve Rory to Graph ``me``."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            stdout = StringIO()
            stderr = StringIO()
            original = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "identity-resolve",
                            "Rory",
                            "--system",
                            "microsoft",
                        ]
                    )
            finally:
                os.chdir(original)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertIn("microsoft: me", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
