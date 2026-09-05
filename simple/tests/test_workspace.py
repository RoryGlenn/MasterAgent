"""Exercise development workspaces against temporary real Git repositories."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from masteragent.workspace import (
    WorkspaceError,
    inspect_worktree,
    prepare_worktree,
    publish_branch,
    run_checks,
)


class WorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.git(self.repository, "init", "-b", "main")
        self.git(self.repository, "config", "user.name", "Workspace Test")
        self.git(self.repository, "config", "user.email", "workspace@example.invalid")
        (self.repository / "source.py").write_text("answer = 42\n", encoding="utf-8")
        self.git(self.repository, "add", "source.py")
        self.git(self.repository, "commit", "-m", "Initial commit")
        self.initial_head = self.git(self.repository, "rev-parse", "HEAD")
        self.destination = self.root / "task"

    @staticmethod
    def git(path: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(path), *arguments],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def prepare(self) -> dict[str, object]:
        return prepare_worktree(self.repository, self.destination, "task/example")

    def test_new_worktree_keeps_dirty_original_and_uses_current_head(self) -> None:
        (self.repository / "source.py").write_text("uncommitted\n", encoding="utf-8")
        (self.repository / "untracked.txt").write_text("keep me\n", encoding="utf-8")
        result = self.prepare()
        self.assertEqual(result["base"], self.initial_head)
        self.assertEqual(result["path"], str(self.destination.resolve()))
        self.assertEqual((self.destination / "source.py").read_text(), "answer = 42\n")
        self.assertFalse((self.destination / "untracked.txt").exists())
        self.assertEqual((self.repository / "source.py").read_text(), "uncommitted\n")
        self.assertEqual(self.git(self.repository, "branch", "--show-current"), "main")
        self.assertTrue(inspect_worktree(self.repository)["dirty"])
        self.assertFalse(inspect_worktree(self.destination)["dirty"])

    def test_resume_same_worktree_preserves_its_edits(self) -> None:
        result = self.prepare()
        (self.destination / "source.py").write_text("in progress\n", encoding="utf-8")
        resumed = self.prepare()
        self.assertEqual(resumed, result)
        self.assertEqual((self.destination / "source.py").read_text(), "in progress\n")
        with self.assertRaisesRegex(WorkspaceError, "different branch"):
            prepare_worktree(self.repository, self.destination, "task/different")
        with self.assertRaises(WorkspaceError):
            prepare_worktree(self.repository, self.destination / "subdirectory", "task/example")

    def test_existing_branch_is_reused_without_resetting(self) -> None:
        self.git(self.repository, "branch", "task/example")
        (self.repository / "source.py").write_text("newer main\n", encoding="utf-8")
        self.git(self.repository, "commit", "-am", "Advance main")
        self.prepare()
        self.assertEqual(inspect_worktree(self.destination)["head"], self.initial_head)

    def test_explicit_base_and_empty_directory(self) -> None:
        (self.repository / "source.py").write_text("newer main\n", encoding="utf-8")
        self.git(self.repository, "commit", "-am", "Advance main")
        self.destination.mkdir()
        result = prepare_worktree(
            self.repository, self.destination, "task/older", base=self.initial_head
        )
        self.assertEqual(result["base"], self.initial_head)
        self.assertEqual(inspect_worktree(self.destination)["head"], self.initial_head)

    def test_rejects_invalid_refs_and_original_directory(self) -> None:
        for branch in ("", "-b", "@", "@{-1}", "bad branch", "a..b", "x\ny", "x\x00y"):
            with self.subTest(branch=branch), self.assertRaises(WorkspaceError):
                prepare_worktree(self.repository, self.destination, branch)
        for base in ("", "--all", "missing-reference", "x\x00y"):
            with self.subTest(base=base), self.assertRaises(WorkspaceError):
                prepare_worktree(self.repository, self.destination, "task/example", base=base)
        with self.assertRaisesRegex(WorkspaceError, "separate directory"):
            prepare_worktree(self.repository, self.repository, "main")
        self.assertFalse(self.destination.exists())

    def test_rejects_other_repository_at_destination(self) -> None:
        self.destination.mkdir()
        self.git(self.destination, "init", "-b", "task/example")
        with self.assertRaisesRegex(WorkspaceError, "another repository"):
            self.prepare()

    def test_inspection_handles_staged_rename_and_untracked_paths(self) -> None:
        self.prepare()
        self.git(self.destination, "mv", "source.py", "source renamed.py")
        (self.destination / "new file.txt").write_text("new\n", encoding="utf-8")
        state = inspect_worktree(self.destination)
        self.assertEqual(state["branch"], "task/example")
        self.assertEqual(state["head"], self.initial_head)
        self.assertTrue(state["dirty"])
        self.assertEqual(set(state["changed_files"]), {"source renamed.py", "new file.txt"})

    def test_checks_capture_failures_and_use_workspace_directory(self) -> None:
        self.prepare()
        results = run_checks(
            self.destination,
            [
                [sys.executable, "-c", "from pathlib import Path; print(Path('source.py').read_text())"],
                [sys.executable, "-c", "import sys; print('failed', file=sys.stderr); sys.exit(3)"],
            ],
        )
        self.assertEqual([result["exit_code"] for result in results], [0, 3])
        self.assertIn("answer = 42", results[0]["output"])
        self.assertIn("failed", results[1]["output"])

    def test_checks_reject_shell_strings_and_validate_before_running(self) -> None:
        self.prepare()
        marker = self.destination / "marker"
        command = [sys.executable, "-c", "from pathlib import Path; Path('marker').touch()"]
        for commands in ([], "echo test", [[]], ["echo test"], [command, []]):
            with self.subTest(commands=commands), self.assertRaises(WorkspaceError):
                run_checks(self.destination, commands)  # type: ignore[arg-type]
        self.assertFalse(marker.exists())

    def test_check_timeout_is_reported(self) -> None:
        self.prepare()
        result = run_checks(
            self.destination,
            [[sys.executable, "-c", "import time; print('started', flush=True); time.sleep(10)"]],
            timeout=0.1,
        )[0]
        self.assertEqual(result["exit_code"], 124)
        self.assertIn("timed out", result["output"])

    def test_check_timeout_stops_children_holding_output_open(self) -> None:
        self.prepare()
        child = "import time; time.sleep(10)"
        parent = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
            "print('child started', flush=True); time.sleep(10)"
        )
        started = time.monotonic()
        result = run_checks(
            self.destination, [[sys.executable, "-c", parent]], timeout=0.3
        )[0]
        self.assertEqual(result["exit_code"], 124)
        self.assertLess(time.monotonic() - started, 5)

    def test_check_output_redacts_credentials_and_truncates(self) -> None:
        self.prepare()
        result = run_checks(
            self.destination,
            [[sys.executable, "-c", "print('https://name:private@host/path?token=secret'); print('a' * 30000)"]],
        )[0]
        self.assertNotIn("private", result["output"])
        self.assertNotIn("token=secret", result["output"])
        self.assertNotIn("private", str(result["command"]))
        self.assertIn("[redacted]", result["output"])
        self.assertIn("[output truncated]", result["output"])
        self.assertLess(len(result["output"]), 12_100)

    def test_publish_pushes_only_committed_branch_to_bare_remote(self) -> None:
        remote = self.root / "remote.git"
        remote.mkdir()
        self.git(remote, "init", "--bare")
        self.git(self.repository, "remote", "add", "origin", str(remote))
        self.prepare()
        (self.destination / "source.py").write_text("answer = 43\n", encoding="utf-8")
        self.git(self.destination, "commit", "-am", "Change answer")
        self.git(self.destination, "tag", "-a", "do-not-push", "-m", "Local tag")
        self.git(self.destination, "config", "push.followTags", "true")
        state = inspect_worktree(self.destination)
        result = publish_branch(self.destination)
        self.assertEqual(result, {"branch": "task/example", "commit": state["head"], "remote": "origin"})
        self.assertEqual(self.git(remote, "rev-parse", "refs/heads/task/example"), state["head"])
        self.assertEqual(self.git(remote, "for-each-ref", "--format=%(refname)"), "refs/heads/task/example")

    def test_publish_refuses_dirty_detached_and_unknown_remote(self) -> None:
        self.prepare()
        (self.destination / "untracked.txt").write_text("not committed\n", encoding="utf-8")
        with self.assertRaisesRegex(WorkspaceError, "remaining worktree changes"):
            publish_branch(self.destination)
        (self.destination / "untracked.txt").unlink()
        with self.assertRaisesRegex(WorkspaceError, "configured Git remote"):
            publish_branch(self.destination, "--all")
        self.git(self.destination, "checkout", "--detach")
        self.assertIsNone(inspect_worktree(self.destination)["branch"])
        with self.assertRaisesRegex(WorkspaceError, "detached"):
            publish_branch(self.destination)

    @unittest.skipIf(os.name == "nt", "POSIX shell hook fixture")
    def test_publish_respects_git_hooks_and_redacts_failure_credentials(self) -> None:
        remote = self.root / "remote.git"
        remote.mkdir()
        self.git(remote, "init", "--bare")
        self.git(self.repository, "remote", "add", "origin", str(remote))
        self.prepare()
        hook = self.repository / ".git" / "hooks" / "pre-push"
        hook.write_text(
            "#!/bin/sh\nprintf 'https://person:private@host/path?token=secret\\n' >&2\nexit 1\n",
            encoding="utf-8",
        )
        hook.chmod(0o700)
        with self.assertRaises(WorkspaceError) as raised:
            publish_branch(self.destination)
        self.assertNotIn("private", str(raised.exception))
        self.assertNotIn("token=secret", str(raised.exception))
        self.assertIn("[redacted]", str(raised.exception))
        self.assertEqual(self.git(remote, "for-each-ref", "--format=%(refname)"), "")

    def test_publish_never_force_updates_remote_branch(self) -> None:
        remote = self.root / "remote.git"
        remote.mkdir()
        self.git(remote, "init", "--bare")
        self.git(self.repository, "remote", "add", "origin", str(remote))
        self.prepare()
        (self.destination / "source.py").write_text("first\n", encoding="utf-8")
        self.git(self.destination, "commit", "-am", "First version")
        published = publish_branch(self.destination)
        self.git(self.destination, "reset", "--hard", self.initial_head)
        (self.destination / "source.py").write_text("second\n", encoding="utf-8")
        self.git(self.destination, "commit", "-am", "Divergent version")
        with self.assertRaises(WorkspaceError):
            publish_branch(self.destination)
        self.assertEqual(self.git(remote, "rev-parse", "refs/heads/task/example"), published["commit"])


if __name__ == "__main__":
    unittest.main()
