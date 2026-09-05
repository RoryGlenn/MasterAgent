"""Exercise the installed-command contract without live accounts."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from masteragent.cli import main
from masteragent.settings import (
    configure_project,
    configure_provider,
    load_config,
    readiness,
)
from masteragent.state import TaskStore


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "state"

    def run_cli(self, *args: str) -> tuple[int, object]:
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = main(["--home", str(self.home), "--json", *args])
        return code, json.loads(output.getvalue())

    def test_demo_is_offline_and_leaves_default_home_untouched(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            code, result = self.run_cli("demo")
        self.assertEqual(code, 0)
        self.assertFalse(result["live_connections"])
        self.assertIn("DEMO-123", result["review"])
        self.assertFalse(self.home.exists())

    def test_setup_remembers_names_and_preserves_existing_projects(self) -> None:
        with patch.dict(
            os.environ,
            {"WORK_TOKEN": "sensitive-value", "WORK_EMAIL": "example@example.com"},
        ):
            code, _ = self.run_cli(
                "setup",
                "--provider",
                "jira",
                "--url",
                "https://example.atlassian.net",
                "--token-env",
                "WORK_TOKEN",
                "--username-env",
                "WORK_EMAIL",
            )
            self.assertEqual(code, 0)
            code, _ = self.run_cli(
                "setup",
                "--project",
                "APP",
                "--repository",
                str(self.home.parent),
                "--check-json",
                '["python","-m","unittest","discover"]',
            )
            self.assertEqual(code, 0)
            _, doctor = self.run_cli("doctor")
            self.assertEqual(doctor["providers"]["jira"]["status"], "configured")
            self.assertFalse(doctor["network_checked"])
        config_text = (self.home / "config.json").read_text()
        self.assertNotIn("sensitive-value", config_text)
        self.assertNotIn("example@example.com", config_text)
        config = load_config(self.home)
        self.assertEqual(config["jira"]["token_env"], "WORK_TOKEN")
        self.assertEqual(config["projects"]["APP"]["checks"][0][0], "python")

    def test_context_edits_survive_repeated_setup(self) -> None:
        self.run_cli("setup")
        context = self.home / "context.md"
        context.write_text("# My conventions\nKeep my edits.", encoding="utf-8")
        self.run_cli("setup")
        _, result = self.run_cli("context")
        self.assertIn("Keep my edits", result["content"])

    def test_invalid_setup_is_reported_without_partial_config_write(self) -> None:
        for arguments in (
            ("setup", "--url", "https://example.com"),
            ("setup", "--provider", "jira"),
            ("setup", "--project", "APP", "--check-json", '"not argv"'),
            ("setup", "--provider", "jira", "--url", "https://user:secret@example.com"),
        ):
            with self.subTest(arguments=arguments):
                code, result = self.run_cli(*arguments)
                self.assertEqual(code, 1)
                self.assertIn("error", result)
                self.assertFalse((self.home / "config.json").exists())

    def test_missing_provider_preserves_failed_review_and_returns_failure(self) -> None:
        code, result = self.run_cli("review", "APP-1")
        self.assertEqual(code, 1)
        self.assertIn("paused", result["error"])
        _, tasks = self.run_cli("tasks")
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["status"], "failed")
        self.assertEqual(tasks[0]["inputs"]["issue"], "APP-1")

    def test_status_draft_requires_no_connected_provider(self) -> None:
        code, result = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertFalse(result["result"]["sent"])
        self.assertIn("No tracked work", Path(result["result"]["artifact"]).read_text())

    def test_resolution_rejects_missing_result_fields(self) -> None:
        result_file = self.home.parent / "result.json"
        result_file.write_text("{}")
        with TaskStore(self.home / "tasks.sqlite3") as store:
            task = store.create("develop", {})
            store.begin_step(task, "git.push", is_write=True)
            store.fail_step(task, "git.push", "timeout", uncertain=True)
            store.fail(task, "timeout")
        code, _ = self.run_cli(
            "resolve", task, "git.push", "--result-file", str(result_file)
        )
        self.assertEqual(code, 1)
        with TaskStore(self.home / "tasks.sqlite3") as store:
            self.assertEqual(store.get(task)["steps"][0]["status"], "uncertain")

    def test_module_entrypoint_and_no_legacy_imports(self) -> None:
        root = Path(__file__).resolve().parents[1]
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from masteragent.cli import main; main(['--json','demo']); assert not any(k == 'master_agent' or k.startswith('master_agent.') for k in sys.modules)",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["demo"])

    def test_configuration_validates_targets_and_command_arguments(self) -> None:
        config = {"projects": {}}
        with self.assertRaises(ValueError):
            configure_project(config, "APP", checks=[[1]])
        with self.assertRaises(ValueError):
            configure_provider(
                config, "jira", "https://example.com", token_env="not an env variable"
            )
        with self.assertRaises(ValueError):
            configure_provider(config, "jira", "https://example.com?q=secret")
        configure_provider(config, "jira", "https://example.com/jira")
        self.assertEqual(config["jira"]["deployment"], "server")
        self.assertEqual(
            readiness(config)["providers"]["jira"]["status"], "missing_credentials"
        )


if __name__ == "__main__":
    unittest.main()
