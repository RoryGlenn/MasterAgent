"""Command-level smoke tests for Phases 2C, 3, and 6."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from master_agent.cli import main


ROOT = Path(__file__).resolve().parents[1]


class PhaseCompletionCliTests(unittest.TestCase):
    """Exercise installed-facing commands without workplace credentials."""

    def test_readiness_reports_safe_unconnected_defaults(self) -> None:
        """Phase 2C readiness should pass while warning that nothing is connected."""

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "readiness.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["readiness", "--output", str(output)])
            self.assertEqual(status, 0, stderr.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["ready"])
            self.assertIn("not connected", " ".join(payload["warnings"]))

    def test_draft_package_command_generates_all_local_artifacts(self) -> None:
        """Phase 3 CLI should create a complete package without publishing."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "drafts"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "draft-package",
                        "--workflow",
                        str(ROOT / "config/draft-package.toml"),
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

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "status.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["recurring-status", "--output", str(output)])
            self.assertEqual(status, 0, stderr.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(payload["workflows"]), 2)
            self.assertTrue(
                all(not item["enabled"] for item in payload["workflows"])
            )


if __name__ == "__main__":
    unittest.main()
