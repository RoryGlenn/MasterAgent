"""Regression tests for the repository-local first-run bootstrap."""

from __future__ import annotations

import os
import stat
import subprocess
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from master_agent.errors import ConfigurationError
from scripts.bootstrap_agent import (
    BootstrapError,
    EnvironmentAttestation,
    _dependency_policy_digest,
    _installation_digest,
    _installed_environment_digest,
    _marker_digest,
    _record_environment_attestation,
    _run,
    _runtime_probe,
    _stable_file_identity,
    _validate_windows_environment_permissions,
    bootstrap,
)


class AgentBootstrapTests(unittest.TestCase):
    """Keep first-run setup idempotent, local, and fail-closed."""

    @staticmethod
    def _write_project(root: Path, *, version: str = "1.0.0") -> None:
        (root / "pyproject.toml").write_text(
            f"[project]\nname='master-agent'\nversion='{version}'\n",
            encoding="utf-8",
        )
        (root / "setup.py").write_text(
            "from setuptools import setup\n",
            encoding="utf-8",
        )

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
            self._write_project(root)
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

            with (
                patch("scripts.bootstrap_agent.subprocess.run", side_effect=fake_run),
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
            ):
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
            self._write_project(root)
            binary_dir = root / ".venv/bin"
            binary_dir.mkdir(parents=True)
            (binary_dir / "python").touch()
            (binary_dir / "master-agent").touch()
            digest = _installation_digest(root, root)
            attestation = EnvironmentAttestation(
                installation_sha256=digest,
                dependency_policy_sha256=_dependency_policy_digest(root),
                project_version="1.0.0",
                runtime_probe_sha256="d" * 64,
            )
            _record_environment_attestation(
                root / ".venv/.master-agent-bootstrap-v1", attestation
            )

            with (
                patch("scripts.bootstrap_agent.subprocess.run") as run,
                patch("scripts.bootstrap_agent._runtime_probe", return_value="d" * 64),
            ):
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

    def test_legacy_marker_is_preserved_and_uses_side_by_side_environment(self) -> None:
        """A historical digest marker is not sufficient evidence for reuse."""

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._write_project(root)
            primary = root / ".venv/bin"
            primary.mkdir(parents=True)
            (primary / "python").touch()
            (primary / "master-agent").touch()
            digest = _installation_digest(root, root)
            marker = root / ".venv/.master-agent-bootstrap-v1"
            marker.write_text(f"{digest}\n", encoding="utf-8")
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

            with (
                patch(
                    "scripts.bootstrap_agent.subprocess.run", side_effect=fake_run
                ) as run,
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
            ):
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            self.assertEqual(marker.read_text(encoding="utf-8"), f"{digest}\n")
            self.assertNotIn(
                str(primary / "master-agent"),
                [call.args[0][0] for call in run.call_args_list],
            )
            self.assertEqual(
                run.call_args_list[-1].args[0][0], str(managed / "bin/master-agent")
            )

    def test_runtime_probe_mismatch_preserves_environment_and_repairs_side_by_side(
        self,
    ) -> None:
        """A changed installed runtime cannot reuse an otherwise matching marker."""

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._write_project(root)
            primary = root / ".venv/bin"
            primary.mkdir(parents=True)
            (primary / "python").touch()
            (primary / "master-agent").touch()
            digest = _installation_digest(root, root)
            _record_environment_attestation(
                root / ".venv/.master-agent-bootstrap-v1",
                EnvironmentAttestation(
                    installation_sha256=digest,
                    dependency_policy_sha256=_dependency_policy_digest(root),
                    project_version="1.0.0",
                    runtime_probe_sha256="a" * 64,
                ),
            )
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

            with (
                patch(
                    "scripts.bootstrap_agent.subprocess.run", side_effect=fake_run
                ) as run,
                patch(
                    "scripts.bootstrap_agent._runtime_probe",
                    side_effect=(
                        BootstrapError(
                            "managed environment contents do not match their attestation"
                        ),
                        "c" * 64,
                    ),
                ),
            ):
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            self.assertNotIn(
                str(primary / "master-agent"),
                [call.args[0][0] for call in run.call_args_list],
            )
            self.assertEqual(
                run.call_args_list[-1].args[0][0], str(managed / "bin/master-agent")
            )

    def test_attestation_mismatch_is_rejected_before_interpreter_execution(
        self,
    ) -> None:
        """Changed runtime bytes must fail before the candidate Python process starts."""

        environment = Path("/managed/.venv")
        with (
            patch(
                "scripts.bootstrap_agent._configured_python_version",
                return_value=(3, 12),
            ),
            patch(
                "scripts.bootstrap_agent._installed_environment_digest",
                return_value="b" * 64,
            ),
            patch("scripts.bootstrap_agent.subprocess.run") as run,
            self.assertRaisesRegex(BootstrapError, "do not match their attestation"),
        ):
            _runtime_probe(
                environment / "bin/python",
                environment=environment,
                expected_version="1.0.0",
                expected_runtime_digest="a" * 64,
            )

        run.assert_not_called()

    def test_windows_stable_identity_ignores_posix_metadata_projections(self) -> None:
        """Windows link counts, mode permissions, and change times are not identity."""

        left = Mock(
            st_dev=7,
            st_ino=19,
            st_mode=stat.S_IFREG | 0o644,
            st_nlink=1,
            st_size=42,
            st_mtime_ns=123,
            st_ctime_ns=456,
        )
        right = Mock(
            st_dev=7,
            st_ino=19,
            st_mode=stat.S_IFREG | 0o777,
            st_nlink=2,
            st_size=42,
            st_mtime_ns=123,
            st_ctime_ns=999,
        )
        with patch("scripts.bootstrap_agent.os.name", "nt"):
            self.assertEqual(
                _stable_file_identity(left),
                _stable_file_identity(right),
            )

    def test_windows_runtime_validates_every_environment_dacl(self) -> None:
        """The Windows runtime profile covers roots, directories, and files."""

        environment = Path("C:/repo/.venv")
        directories = (environment / "Lib", environment / "Lib/site-packages")
        files = (environment / "pyvenv.cfg", environment / "Scripts/python.exe")
        with patch(
            "master_agent.platform_runtime.windows.filesystem."
            "WindowsSecureFilesystemBackend"
        ) as backend_type:
            backend = backend_type.return_value
            _validate_windows_environment_permissions(
                environment,
                repository_root=Path("C:/repo"),
                files=files,
                directories=directories,
            )

        backend.pin_directory.assert_any_call(environment, require_private=True)
        for path in directories:
            backend.pin_directory.assert_any_call(path, require_private=True)
        for path in files:
            backend.pin_file.assert_any_call(path, require_private=True)

    def test_windows_runtime_dacl_rejection_becomes_bootstrap_failure(self) -> None:
        """Native policy denial must select repair rather than escape the bootstrap."""

        environment = Path("C:/repo/.venv")
        with (
            patch(
                "master_agent.platform_runtime.windows.filesystem."
                "WindowsSecureFilesystemBackend"
            ) as backend_type,
            self.assertRaisesRegex(BootstrapError, "write authority"),
        ):
            backend_type.return_value.pin_directory.side_effect = ConfigurationError(
                "untrusted writer"
            )
            _validate_windows_environment_permissions(
                environment,
                repository_root=Path("C:/repo"),
                files=(),
                directories=(),
            )

    def test_dependency_policy_change_prevents_environment_reuse(self) -> None:
        """The marker must match the currently declared dependency policy."""

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._write_project(root)
            primary = root / ".venv/bin"
            primary.mkdir(parents=True)
            (primary / "python").touch()
            (primary / "master-agent").touch()
            digest = _installation_digest(root, root)
            previous_policy = _dependency_policy_digest(root)
            _record_environment_attestation(
                root / ".venv/.master-agent-bootstrap-v1",
                EnvironmentAttestation(
                    installation_sha256=digest,
                    dependency_policy_sha256=previous_policy,
                    project_version="1.0.0",
                    runtime_probe_sha256="a" * 64,
                ),
            )
            (root / "requirements-runtime.lock").write_text(
                "example==1.0 --hash=sha256:" + "1" * 64 + "\n",
                encoding="utf-8",
            )
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

            with (
                patch(
                    "scripts.bootstrap_agent.subprocess.run", side_effect=fake_run
                ) as run,
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
            ):
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                )

            self.assertEqual(status, 0)
            self.assertNotEqual(previous_policy, _dependency_policy_digest(root))
            self.assertNotIn(
                str(primary / "master-agent"),
                [call.args[0][0] for call in run.call_args_list],
            )
            self.assertEqual(
                run.call_args_list[-1].args[0][0], str(managed / "bin/master-agent")
            )

    def test_runtime_probe_rejects_wrong_installed_version(self) -> None:
        with TemporaryDirectory() as directory:
            environment = Path(directory).resolve() / ".venv"
            environment_python = environment / "bin/python"
            environment_python.parent.mkdir(parents=True)
            environment_python.write_bytes(b"python")
            (environment / "bin/master-agent").write_bytes(b"launcher")
            (environment / "pyvenv.cfg").write_text(
                "include-system-site-packages = false\nversion = 3.12.0\n",
                encoding="utf-8",
            )
            metadata = (
                environment
                / "lib/python3.12/site-packages/master_agent-9.9.9.dist-info"
            )
            metadata.mkdir(parents=True)
            (metadata / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: master-agent\nVersion: 9.9.9\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BootstrapError, "version does not match"):
                _installed_environment_digest(
                    environment,
                    environment_python=environment_python,
                    python_version=(3, 12),
                    expected_version="1.0.0",
                )

    @unittest.skipUnless(os.name == "posix", "POSIX permission contract")
    def test_runtime_probe_rejects_shared_writable_installed_file(self) -> None:
        with TemporaryDirectory() as directory:
            environment = Path(directory).resolve() / ".venv"
            environment_python = environment / "bin/python"
            environment_python.parent.mkdir(parents=True)
            environment_python.write_bytes(b"python")
            command = environment / "bin/master-agent"
            command.write_bytes(b"launcher")
            command.chmod(0o666)
            (environment / "pyvenv.cfg").write_text(
                "include-system-site-packages = false\nversion = 3.12.0\n",
                encoding="utf-8",
            )
            metadata = (
                environment
                / "lib/python3.12/site-packages/master_agent-1.0.0.dist-info"
            )
            metadata.mkdir(parents=True)
            (metadata / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: master-agent\nVersion: 1.0.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BootstrapError, "untrusted principal"):
                _installed_environment_digest(
                    environment,
                    environment_python=environment_python,
                    python_version=(3, 12),
                    expected_version="1.0.0",
                )

    def test_unmarked_existing_runtime_uses_managed_side_by_side_environment(
        self,
    ) -> None:
        """An unverifiable local environment is preserved but never executed."""

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._write_project(root)
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
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
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
            self._write_project(root)
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

            with (
                patch(
                    "scripts.bootstrap_agent.subprocess.run", side_effect=fake_run
                ) as run,
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
            ):
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
            _record_environment_attestation(
                marker,
                EnvironmentAttestation(
                    installation_sha256="b" * 64,
                    dependency_policy_sha256="c" * 64,
                    project_version="1.0.0",
                    runtime_probe_sha256="d" * 64,
                ),
            )

            self.assertEqual(outside.read_text(encoding="utf-8"), f"{'a' * 64}\n")
            self.assertFalse(marker.is_symlink())
            self.assertEqual(_marker_digest(marker), "b" * 64)

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
            _record_environment_attestation(
                marker,
                EnvironmentAttestation(
                    installation_sha256="b" * 64,
                    dependency_policy_sha256="c" * 64,
                    project_version="1.0.0",
                    runtime_probe_sha256="d" * 64,
                ),
            )

            self.assertEqual(outside.read_text(encoding="utf-8"), f"{'a' * 64}\n")
            self.assertEqual(_marker_digest(marker), "b" * 64)
            self.assertEqual(marker.stat().st_nlink, 1)

    def test_windows_uses_scripts_launchers_and_offline_wheel_source(self) -> None:
        with TemporaryDirectory(prefix="Master Agent Ω path ") as directory:
            root = Path(directory).resolve()
            self._write_project(root)
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

            with (
                patch("scripts.bootstrap_agent.subprocess.run", side_effect=fake_run),
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
            ):
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
            self._write_project(root)
            source = root / "approved source"
            source.mkdir()
            metadata = source / "pyproject.toml"
            metadata.write_text(
                "[project]\nname='master-agent'\nversion='1.0.0'\n",
                encoding="utf-8",
            )
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

            with (
                patch("scripts.bootstrap_agent.subprocess.run", side_effect=fake_run),
                patch("scripts.bootstrap_agent._runtime_probe", return_value="c" * 64),
            ):
                status = bootstrap(
                    root,
                    python_executable="/usr/bin/python3",
                    python_version=(3, 12),
                    install_source=source,
                )

            self.assertNotEqual(before, after)
            self.assertEqual(status, 0)
            self.assertEqual(commands[1][-2:], ["-e", str(source)])

    def test_installation_digest_tracks_source_bytes_but_not_build_metadata(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._write_project(root)
            package = root / "src/master_agent"
            package.mkdir(parents=True)
            implementation = package / "__init__.py"
            implementation.write_text("VALUE = 1\n", encoding="utf-8")
            before = _installation_digest(root, root)
            implementation.write_text("VALUE = 2\n", encoding="utf-8")
            changed = _installation_digest(root, root)
            self.assertNotEqual(before, changed)

            build_metadata = root / "src/master_agent.egg-info"
            build_metadata.mkdir()
            (build_metadata / "SOURCES.txt").write_text(
                "generated\n",
                encoding="utf-8",
            )
            self.assertEqual(_installation_digest(root, root), changed)

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
