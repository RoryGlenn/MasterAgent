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

from scripts.bootstrap_agent import (
    BootstrapError,
    _installation_digest,
    _marker_digest,
    _record_metadata_digest,
    _run,
    bootstrap,
)


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

    def test_private_install_does_not_apply_posix_umask_on_windows(self) -> None:
        with (
            TemporaryDirectory() as directory,
            patch("scripts.bootstrap_agent.os.umask") as umask,
            patch("scripts.bootstrap_agent.subprocess.run") as run,
        ):
            run.return_value = subprocess.CompletedProcess([], 0)
            status = _run(
                ["python.exe", "-m", "venv", ".venv"],
                root=Path(directory),
                private_install=True,
                posix_permissions=False,
            )

        self.assertEqual(status, 0)
        umask.assert_not_called()

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
            digest = _installation_digest(root, root)
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

    def test_unmarked_existing_runtime_uses_managed_side_by_side_environment(
        self,
    ) -> None:
        """An unverifiable local environment is preserved but never executed."""

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            binary_dir = root / ".venv/bin"
            binary_dir.mkdir(parents=True)
            (binary_dir / "python").touch()
            (binary_dir / "master-agent").touch()
            digest = _installation_digest(root, root)
            managed = root / f".venv-master-agent-{digest[:12]}"
            stdout = StringIO()

            def fake_run(
                command: list[str],
                *,
                cwd: Path,
                check: bool,
            ) -> subprocess.CompletedProcess[bytes]:
                self.assertEqual(cwd, root)
                self.assertFalse(check)
                if command[1:3] == ["-m", "venv"]:
                    (managed / "bin").mkdir(parents=True)
                    (managed / "bin/python").touch()
                elif command[1:4] == ["-m", "pip", "install"]:
                    (managed / "bin/master-agent").touch()
                return subprocess.CompletedProcess(command, 0)

            with (
                redirect_stdout(stdout),
                patch(
                    "scripts.bootstrap_agent.subprocess.run", side_effect=fake_run
                ) as run,
            ):
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            self.assertEqual(run.call_count, 3)
            self.assertEqual(
                run.call_args_list[-1].args[0],
                [
                    str(managed / "bin/master-agent"),
                    "doctor",
                    "--require-level",
                    "install",
                ],
            )
            self.assertIn("side-by-side", stdout.getvalue())
            self.assertIn(
                f"command: {managed.relative_to(root) / 'bin/master-agent'}",
                stdout.getvalue(),
            )
            self.assertIn("setup_status: ready", stdout.getvalue())
            self.assertFalse((root / ".venv/.master-agent-bootstrap-v1").exists())
            self.assertTrue((managed / ".master-agent-bootstrap-v1").is_file())

    def test_symbolic_link_environment_is_left_untouched_for_side_by_side(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            target = root / "elsewhere"
            target.mkdir()
            (root / ".venv").symlink_to(target, target_is_directory=True)
            digest = _installation_digest(root, root)
            managed = root / f".venv-master-agent-{digest[:12]}"

            def fake_run(
                command: list[str],
                *,
                cwd: Path,
                check: bool,
            ) -> subprocess.CompletedProcess[bytes]:
                del cwd, check
                if command[1:3] == ["-m", "venv"]:
                    (managed / "bin").mkdir(parents=True)
                    (managed / "bin/python").touch()
                elif command[1:4] == ["-m", "pip", "install"]:
                    (managed / "bin/master-agent").touch()
                return subprocess.CompletedProcess(command, 0)

            with patch(
                "scripts.bootstrap_agent.subprocess.run", side_effect=fake_run
            ) as run:
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            self.assertEqual(run.call_count, 3)
            self.assertTrue((root / ".venv").is_symlink())

    def test_symbolic_link_marker_is_not_accepted_or_followed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            marker = root / ".master-agent-bootstrap-v1"
            outside = root / "outside"
            outside.write_text(f"{'a' * 64}\n", encoding="utf-8")
            marker.symlink_to(outside)

            self.assertEqual(_marker_digest(marker), "")
            _record_metadata_digest(marker, "b" * 64)

            self.assertEqual(outside.read_text(encoding="utf-8"), f"{'a' * 64}\n")
            self.assertFalse(marker.is_symlink())
            self.assertEqual(marker.read_text(encoding="utf-8"), f"{'b' * 64}\n")

    def test_hard_link_marker_is_not_accepted_or_overwritten(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            marker = root / ".master-agent-bootstrap-v1"
            outside = root / "outside"
            outside.write_text(f"{'a' * 64}\n", encoding="utf-8")
            try:
                os.link(outside, marker)
            except OSError as error:
                self.skipTest(f"hard links are unavailable: {error}")

            self.assertEqual(_marker_digest(marker), "")
            _record_metadata_digest(marker, "b" * 64)

            self.assertEqual(outside.read_text(encoding="utf-8"), f"{'a' * 64}\n")
            self.assertEqual(marker.read_text(encoding="utf-8"), f"{'b' * 64}\n")
            self.assertEqual(marker.stat().st_nlink, 1)

    def test_windows_uses_scripts_launchers_and_offline_wheel_source(self) -> None:
        with TemporaryDirectory(prefix="Master Agent Ω path ") as directory:
            root = Path(directory).resolve()
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            wheelhouse = root / "internal packages"
            wheelhouse.mkdir()
            wheel = root / "master_agent-1.0.0-py3-none-any.whl"
            wheel.write_bytes(b"test-wheel")
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
                    (root / ".venv/Scripts").mkdir(parents=True)
                    (root / ".venv/Scripts/python.exe").touch()
                elif command[1:4] == ["-m", "pip", "install"]:
                    (root / ".venv/Scripts/master-agent.exe").touch()
                return subprocess.CompletedProcess(command, 0)

            with patch("scripts.bootstrap_agent.subprocess.run", side_effect=fake_run):
                status = bootstrap(
                    root,
                    python_executable="C:/Python313/python.exe",
                    python_version=(3, 13),
                    platform_name="nt",
                    install_source=wheel,
                    no_index=True,
                    find_links=(wheelhouse,),
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                commands[1],
                [
                    str(root / ".venv/Scripts/python.exe"),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(wheelhouse),
                    str(wheel),
                ],
            )
            self.assertEqual(
                commands[2][0], str(root / ".venv/Scripts/master-agent.exe")
            )

    def test_explicit_source_tree_uses_its_metadata_and_editable_install(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "setup.py").write_text("from setuptools import setup\n")
            source = root / "approved source"
            source.mkdir()
            metadata = source / "pyproject.toml"
            metadata.write_text("[project]\nname='master-agent'\n", encoding="utf-8")
            (source / "setup.py").write_text("from setuptools import setup\n")
            before = _installation_digest(root, source)
            metadata.write_text(
                "[project]\nname='master-agent'\nversion='1.0.1'\n",
                encoding="utf-8",
            )
            after = _installation_digest(root, source)
            commands: list[list[str]] = []

            def fake_run(
                command: list[str],
                *,
                cwd: Path,
                check: bool,
            ) -> subprocess.CompletedProcess[bytes]:
                del cwd, check
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
                    install_source=source,
                )

            self.assertNotEqual(before, after)
            self.assertEqual(status, 0)
            self.assertEqual(commands[1][-2:], ["-e", str(source)])

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
