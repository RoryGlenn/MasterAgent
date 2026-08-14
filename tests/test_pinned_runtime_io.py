"""Integration tests for descriptor-backed runtime effects."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent import retention
from master_agent.audit import AuditLog
from master_agent.connectors import git_sandbox
from master_agent.connectors.git_sandbox import GitSandbox
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError
from master_agent.retention import RetentionConfig, write_retained_text
from master_agent.sqlite_safety import PinnedSQLiteDatabase

ROOT = Path(__file__).resolve().parents[1]


class PinnedSQLiteTests(unittest.TestCase):
    """Prove SQLite state uses the approved parent descriptor."""

    def test_constructor_rejects_replaced_pinned_parent_without_writing(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            displaced = root / "displaced"
            approved.mkdir(mode=0o700)
            pinned = PinnedDirectory.open(approved)
            try:
                approved.rename(displaced)
                approved.mkdir(mode=0o700)

                with self.assertRaisesRegex(ConfigurationError, "path was replaced"):
                    PinnedSQLiteDatabase(
                        pinned.path / "audit.sqlite3",
                        parent_directory=pinned,
                    )

                self.assertEqual(list(approved.iterdir()), [])
                self.assertEqual(list(displaced.iterdir()), [])
            finally:
                pinned.close()

    def test_audit_log_accepts_pinned_parent_and_rejects_later_replacement(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            displaced = root / "displaced"
            approved.mkdir(mode=0o700)
            pinned = PinnedDirectory.open(approved)
            audit = AuditLog(
                pinned.path / "audit.sqlite3",
                parent_directory=pinned,
            )
            try:
                approved.rename(displaced)
                approved.mkdir(mode=0o700)

                with self.assertRaisesRegex(ConfigurationError, "path was replaced"):
                    audit.verify_chain()

                self.assertEqual(list(approved.iterdir()), [])
            finally:
                audit.close()
                pinned.close()


class PinnedRetentionTests(unittest.TestCase):
    """Prove retention publication remains within the approved directory."""

    def test_parent_swap_during_prepare_rolls_back_only_through_dirfd(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            displaced = root / "displaced"
            approved.mkdir(mode=0o700)
            pinned = PinnedDirectory.open(approved)
            real_prepare = retention._prepare_restricted_temp_at
            calls = 0

            def prepare_then_swap(
                parent_descriptor: int,
                name: str,
                content: bytes,
            ) -> tuple[str, tuple[int, int]]:
                nonlocal calls
                result = real_prepare(parent_descriptor, name, content)
                calls += 1
                if calls == 1:
                    approved.rename(displaced)
                    approved.mkdir(mode=0o700)
                return result

            try:
                with (
                    patch.object(
                        retention,
                        "_prepare_restricted_temp_at",
                        side_effect=prepare_then_swap,
                    ),
                    self.assertRaisesRegex(ConfigurationError, "path was replaced"),
                ):
                    write_retained_text(
                        pinned.path / "evidence.txt",
                        "approved content",
                        evidence_type="run-result/test",
                        config=config,
                        parent_directory=pinned,
                    )

                self.assertEqual(list(approved.iterdir()), [])
                self.assertEqual(list(displaced.iterdir()), [])
            finally:
                pinned.close()

    def test_interruption_cleans_all_pinned_temporary_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pinned = PinnedDirectory.open(root)
            real_replace = retention.os.replace
            calls = 0

            def interrupt_second_replace(
                source: str,
                destination: str,
                *,
                src_dir_fd: int | None = None,
                dst_dir_fd: int | None = None,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt
                real_replace(
                    source,
                    destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            try:
                with (
                    patch.object(
                        retention.os,
                        "replace",
                        side_effect=interrupt_second_replace,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    retention._atomic_write_files(
                        {
                            pinned.path / "one.txt": b"one",
                            pinned.path / "two.txt": b"two",
                        },
                        parent_directory=pinned,
                    )

                self.assertEqual(list(root.iterdir()), [])
            finally:
                pinned.close()


@unittest.skipUnless(shutil.which("git"), "Git is required")
class PinnedGitSandboxTests(unittest.TestCase):
    """Prove fixed Git commands enter the inherited approved descriptor."""

    def test_launcher_uses_pinned_cwd_and_postvalidates_public_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            displaced = root / "displaced"
            attacker = root / "attacker"
            approved_head = _initialize_repository(approved, "approved")
            attacker_head = _initialize_repository(attacker, "attacker")
            self.assertNotEqual(approved_head, attacker_head)
            pinned = PinnedDirectory.open(approved)
            sandbox = GitSandbox(timeout_seconds=10)
            real_duplicate = pinned.duplicate_fd
            real_run = git_sandbox.subprocess.run
            observed_stdout: list[bytes] = []

            def duplicate_then_swap() -> int:
                descriptor = real_duplicate()
                approved.rename(displaced)
                attacker.rename(approved)
                return descriptor

            def observe_run(
                *args: object, **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                completed = real_run(*args, **kwargs)
                observed_stdout.append(completed.stdout)
                return completed

            try:
                with (
                    patch.object(
                        pinned,
                        "duplicate_fd",
                        side_effect=duplicate_then_swap,
                    ),
                    patch.object(
                        git_sandbox.subprocess,
                        "run",
                        side_effect=observe_run,
                    ),
                    self.assertRaisesRegex(ConfigurationError, "path was replaced"),
                ):
                    sandbox.run(
                        pinned.path,
                        ("rev-parse", "HEAD"),
                        working_directory=pinned,
                    )

                self.assertEqual(observed_stdout, [f"{approved_head}\n".encode()])
            finally:
                sandbox.close()
                pinned.close()


def _initialize_repository(path: Path, marker: str) -> str:
    """Create one deterministic single-commit repository and return its HEAD."""

    path.mkdir(mode=0o700)
    subprocess.run(
        ["git", "init", "--quiet", str(path)],
        check=True,
        capture_output=True,
    )
    (path / "marker.txt").write_text(marker, encoding="utf-8")
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Master Agent Test",
            "-c",
            "user.email=test@example.invalid",
            "add",
            "marker.txt",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Master Agent Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            marker,
        ],
        check=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    return (
        subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
    )


if __name__ == "__main__":
    unittest.main()
