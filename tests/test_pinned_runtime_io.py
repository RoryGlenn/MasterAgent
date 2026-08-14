"""Integration tests for descriptor-backed runtime effects."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
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

    def test_parent_swap_during_create_rolls_back_only_through_dirfd(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            displaced = root / "displaced"
            approved.mkdir(mode=0o700)
            pinned = PinnedDirectory.open(approved)
            real_open = retention._open_new_restricted_file_at
            calls = 0

            def open_then_swap(
                parent_descriptor: int,
                name: str,
            ) -> tuple[int, tuple[int, int]]:
                nonlocal calls
                result = real_open(parent_descriptor, name)
                calls += 1
                if calls == 1:
                    approved.rename(displaced)
                    approved.mkdir(mode=0o700)
                return result

            try:
                with (
                    patch.object(
                        retention,
                        "_open_new_restricted_file_at",
                        side_effect=open_then_swap,
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
                self.assertEqual(
                    {path.name for path in displaced.iterdir()},
                    {".master-agent-retention.flock"},
                )
            finally:
                pinned.close()

    def test_interruption_rolls_back_all_created_final_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pinned = PinnedDirectory.open(root)
            real_write = retention._write_restricted_descriptor
            calls = 0

            def interrupt_second_write(
                descriptor: int,
                content: bytes,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt
                real_write(descriptor, content)

            try:
                with (
                    patch.object(
                        retention,
                        "_write_restricted_descriptor",
                        side_effect=interrupt_second_write,
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

                self.assertEqual(
                    {path.name for path in root.iterdir()},
                    {".master-agent-retention.flock"},
                )
            finally:
                pinned.close()

    def test_concurrent_public_writers_cannot_mix_evidence_and_sidecar(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "evidence.txt"
            first_write_started = threading.Event()
            release_first_write = threading.Event()
            second_started = threading.Event()
            second_finished = threading.Event()
            real_write = retention._write_restricted_descriptor
            outcomes: dict[str, BaseException | None] = {}
            paused = False

            def pause_first_writer(descriptor: int, content: bytes) -> None:
                nonlocal paused
                if threading.current_thread().name == "retention-a" and not paused:
                    paused = True
                    first_write_started.set()
                    if not release_first_write.wait(timeout=5):
                        raise RuntimeError("test writer release timed out")
                real_write(descriptor, content)

            def write(label: str, content: str) -> None:
                if label == "b":
                    second_started.set()
                try:
                    write_retained_text(
                        path,
                        content,
                        evidence_type="run-result/test",
                        config=config,
                    )
                except BaseException as error:  # noqa: BLE001
                    outcomes[label] = error
                else:
                    outcomes[label] = None
                finally:
                    if label == "b":
                        second_finished.set()

            with patch.object(
                retention,
                "_write_restricted_descriptor",
                side_effect=pause_first_writer,
            ):
                first = threading.Thread(
                    target=write,
                    args=("a", "content-a"),
                    name="retention-a",
                )
                second = threading.Thread(
                    target=write,
                    args=("b", "content-b"),
                    name="retention-b",
                )
                first.start()
                self.assertTrue(first_write_started.wait(timeout=5))
                second.start()
                self.assertTrue(second_started.wait(timeout=5))
                self.assertFalse(second_finished.wait(timeout=0.1))
                release_first_write.set()
                first.join(timeout=5)
                second.join(timeout=5)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertIsNone(outcomes["a"])
            self.assertIsInstance(outcomes["b"], ConfigurationError)
            self.assertEqual(path.read_text(encoding="utf-8"), "content-a")
            sidecar = path.with_suffix(path.suffix + ".retention.json")
            manifest = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["content_digest"],
                retention.content_digest("content-a"),
            )


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
            observed_commands: list[list[str]] = []

            def duplicate_then_swap() -> int:
                descriptor = real_duplicate()
                approved.rename(displaced)
                attacker.rename(approved)
                return descriptor

            def observe_run(
                *args: object, **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                completed = real_run(*args, **kwargs)
                observed_commands.append(list(args[0]))
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
                self.assertEqual(
                    observed_commands[0][:4],
                    [sys.executable, "-I", "-S", "-c"],
                )
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
