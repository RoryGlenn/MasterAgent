"""Command-level smoke tests for Phases 2C, 3, and 6."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from master_agent.cli import main
from tests.helpers import private_temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class PhaseCompletionCliTests(unittest.TestCase):
    """Exercise installed-facing commands without workplace credentials."""

    def test_readiness_reports_available_but_inactive_defaults(self) -> None:
        """Readiness should pass without credentials or opening a connection."""

        with private_temporary_directory() as directory:
            output = Path(directory) / "readiness.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["readiness", "--output", str(output)])
            self.assertEqual(status, 0, stderr.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["ready"])
            self.assertIn("available but inactive", " ".join(payload["warnings"]))
            connector_checks = [
                item
                for item in payload["checks"]
                if item["name"].startswith("connector:")
            ]
            self.assertEqual(len(connector_checks), 5)
            self.assertTrue(all(item["passed"] for item in connector_checks))
            self.assertTrue(
                all(not item["credential_ready"] for item in connector_checks)
            )

    def test_draft_package_command_generates_all_local_artifacts(self) -> None:
        """Phase 3 CLI should create a complete package without publishing."""

        with private_temporary_directory() as directory:
            root = Path(directory)
            output = root / "drafts"
            output.mkdir(mode=0o700)
            workflow = root / "draft-package.toml"
            workflow.write_bytes((ROOT / "config/draft-package.toml").read_bytes())
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "draft-package",
                        "--workflow",
                        str(workflow),
                        "--output-dir",
                        str(output),
                        "--database",
                        str(root / "audit.sqlite3"),
                    ]
                )
            self.assertEqual(status, 0, stderr.getvalue())
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["published"])
            self.assertEqual(len(manifest["artifacts"]), 6)
            self.assertTrue((output / "change-package.pptx").is_file())

    def test_recurring_status_uses_disabled_packaged_defaults(self) -> None:
        """Phase 6 defaults should register workflows without scheduling them."""

        with private_temporary_directory() as directory:
            output = Path(directory) / "status.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["recurring-status", "--output", str(output)])
            self.assertEqual(status, 0, stderr.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(payload["workflows"]), 2)
            self.assertTrue(all(not item["enabled"] for item in payload["workflows"]))

    def test_evidence_prune_apply_is_disabled_before_traversal(self) -> None:
        """Destructive recursive maintenance must remain non-routable."""

        with private_temporary_directory() as directory:
            missing = Path(directory) / "does-not-exist"
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = main(["evidence-prune", "--root", str(missing), "--apply"])

            self.assertEqual(status, 1)
            self.assertIn("pruning is disabled", stderr.getvalue())
            self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
