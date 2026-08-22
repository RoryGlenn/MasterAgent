"""Regression tests for the repository-local first-run bootstrap."""

from __future__ import annotations

import os
import subprocess
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.bootstrap_agent import BootstrapError, _metadata_digest, _run, bootstrap


class AgentBootstrapTests(unittest.TestCase):
    """Keep first-run setup idempotent, local, and fail-closed."""

    def test_private_install_umask_is_scoped_to_the_child_command(self) -> None:
        observed: list[int] = []

        def fake_run(
            command: list[str],
            *,
            cwd: Path,
            check: bool,
        ) -> subprocess.CompletedProcess[bytes]:
            del cwd, check
            active = os.umask(0)
            os.umask(active)
            observed.append(active)
            return subprocess.CompletedProcess(command, 0)

        previous = os.umask(0o027)
        try:
            with (
                TemporaryDirectory() as directory,
                patch("scripts.bootstrap_agent.subprocess.run", side_effect=fake_run),
            ):
                status = _run(
                    ["python3", "-m", "venv", ".venv"],
                    root=Path(directory),
                    private_install=True,
                )
            restored = os.umask(0o027)
        finally:
            os.umask(previous)

        self.assertEqual(status, 0)
        self.assertEqual(observed, [0o077])
        self.assertEqual(restored, 0o027)

    def test_first_run_creates_installs_and_checks_readiness(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            commands: list[list[str]] = []

            def fake_run(
                command: list[str],
                *,
                cwd: Path,
                check: bool,
            ) -> subprocess.CompletedProcess[bytes]:
                self.assertEqual(cwd, root)
                self.assertFalse(check)
                commands.append(command)
                if command[1:3] == ["-m", "venv"]:
                    (root / ".venv/bin").mkdir(parents=True)
                    (root / ".venv/bin/python").touch()
                elif command[1:4] == ["-m", "pip", "install"]:
                    (root / ".venv/bin/master-agent").touch()
                return subprocess.CompletedProcess(command, 0)

            with patch("scripts.bootstrap_agent.subprocess.run", side_effect=fake_run):
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                commands,
                [
                    ["/usr/bin/python3", "-m", "venv", str(root / ".venv")],
                    [
                        str(root / ".venv/bin/python"),
                        "-m",
                        "pip",
                        "install",
                        "-e",
                        str(root),
                    ],
                    [
                        str(root / ".venv/bin/master-agent"),
                        "doctor",
                        "--require-level",
                        "install",
                    ],
                ],
            )
            self.assertTrue((root / ".venv/.master-agent-bootstrap-v1").is_file())

    def test_prepared_runtime_skips_environment_changes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            metadata = root / "pyproject.toml"
            metadata.write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            binary_dir = root / ".venv/bin"
            binary_dir.mkdir(parents=True)
            (binary_dir / "python").touch()
            (binary_dir / "master-agent").touch()
            digest = _metadata_digest(root)
            (root / ".venv/.master-agent-bootstrap-v1").write_text(
                f"{digest}\n", encoding="utf-8"
            )

            with patch("scripts.bootstrap_agent.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0)
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 14),
                )

            self.assertEqual(status, 0)
            run.assert_called_once_with(
                [
                    str(binary_dir / "master-agent"),
                    "doctor",
                    "--require-level",
                    "install",
                ],
                cwd=root,
                check=False,
            )

    def test_unmarked_existing_runtime_is_reused_for_offline_readiness(self) -> None:
        """A usable local environment is not rewritten solely for provenance."""

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary_dir = root / ".venv/bin"
            binary_dir.mkdir(parents=True)
            (binary_dir / "python").touch()
            (binary_dir / "master-agent").touch()
            stdout = StringIO()

            with (
                redirect_stdout(stdout),
                patch("scripts.bootstrap_agent.subprocess.run") as run,
            ):
                run.return_value = subprocess.CompletedProcess([], 0)
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            run.assert_called_once_with(
                [
                    str(binary_dir / "master-agent"),
                    "doctor",
                    "--require-level",
                    "install",
                ],
                cwd=root,
                check=False,
            )
            self.assertIn("Reusing the existing repository-local", stdout.getvalue())
            self.assertIn("setup_status: ready", stdout.getvalue())
            self.assertFalse((root / ".venv/.master-agent-bootstrap-v1").exists())

    def test_symbolic_link_environment_is_rejected_without_commands(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            target = root / "elsewhere"
            target.mkdir()
            (root / ".venv").symlink_to(target, target_is_directory=True)

            with (
                patch("scripts.bootstrap_agent.subprocess.run") as run,
                self.assertRaisesRegex(BootstrapError, "symbolic link"),
            ):
                bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            run.assert_not_called()

    def test_unsupported_python_is_rejected_without_commands(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with (
                patch("scripts.bootstrap_agent.subprocess.run") as run,
                self.assertRaisesRegex(BootstrapError, "Python 3.12 or newer"),
            ):
                bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 11),
                )

            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
