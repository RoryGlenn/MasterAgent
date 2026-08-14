"""Tests for fixed-operation local Git and Bitbucket branch publication."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from master_agent.connectors.git_remote import GitBranchPushConnector
from master_agent.connectors.git_sandbox import validate_remote_url
from master_agent.connectors.git_workspace import GitWorkspaceConnector
from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import RiskLevel
from tests.helpers import action_for


class GitWorkspaceConnectorTests(unittest.TestCase):
    """Validate local branch and patch rollback without shell execution."""

    def test_branch_creation_and_compensation_restore_original_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            head = _git(repository, "rev-parse", "HEAD")
            connector = GitWorkspaceConnector(workspace_root=root)
            action = action_for(
                "repository.branch.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=head,
                parameters={
                    "workspace": "repo",
                    "branch": "agent/change",
                    "base": "main",
                },
            )

            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            self.assertEqual(
                _git(repository, "branch", "--show-current"), "agent/change"
            )
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )
            self.assertEqual(_git(repository, "branch", "--show-current"), "main")
            self.assertNotIn(
                "agent/change", _git(repository, "branch", "--list", "agent/change")
            )

    def test_patch_apply_and_compensation_restore_clean_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            head = _git(repository, "rev-parse", "HEAD")
            connector = GitWorkspaceConnector(workspace_root=root)
            patch = (
                "diff --git a/README.md b/README.md\n"
                "--- a/README.md\n"
                "+++ b/README.md\n"
                "@@ -1 +1 @@\n"
                "-old\n"
                "+new\n"
            )
            action = action_for(
                "repository.patch.apply",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=head,
                parameters={
                    "workspace": "repo",
                    "patch_text": patch,
                    "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
                },
            )

            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            self.assertEqual((repository / "README.md").read_text(), "new\n")
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )
            self.assertEqual((repository / "README.md").read_text(), "old\n")
            self.assertEqual(_git(repository, "status", "--porcelain"), "")

    @unittest.skipUnless(os.name == "posix", "Git hook test requires POSIX")
    def test_commit_disables_repository_hooks_and_binds_exact_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            marker = root / "hook-ran"
            hook = repository / ".git/hooks/pre-commit"
            hook.write_text(
                f"#!/bin/sh\nprintf hook-ran > {marker}\n",
                encoding="utf-8",
            )
            hook.chmod(0o700)
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            head = _git(repository, "rev-parse", "HEAD")
            diff_digest = _diff_sha256(repository)
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=head,
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": diff_digest,
                },
            )

            result = GitWorkspaceConnector(workspace_root=root).execute(action)

            self.assertFalse(marker.exists())
            self.assertEqual(result.after["diff_sha256"], diff_digest)
            self.assertEqual(_git(repository, "show", "HEAD:README.md"), "approved")

    def test_commit_rejects_unrelated_preexisting_index_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            (repository / "UNRELATED.txt").write_text("unapproved\n", encoding="utf-8")
            _git(repository, "add", "UNRELATED.txt")
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": _diff_sha256(repository),
                },
            )

            with self.assertRaisesRegex(ConnectorError, "pre-existing staged"):
                GitWorkspaceConnector(workspace_root=root).execute(action)

            self.assertIn(
                "UNRELATED.txt", _git(repository, "diff", "--cached", "--name-only")
            )

    def test_patch_file_must_match_approved_digest_at_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            approved = _readme_patch("approved")
            path = root / "change.patch"
            path.write_text(approved, encoding="utf-8")
            action = action_for(
                "repository.patch.apply",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "workspace": "repo",
                    "patch_path": str(path),
                    "patch_root": str(root),
                    "patch_sha256": hashlib.sha256(
                        approved.encode("utf-8")
                    ).hexdigest(),
                },
            )
            path.write_text(_readme_patch("attacker"), encoding="utf-8")

            with self.assertRaisesRegex(VersionConflictError, "digest"):
                GitWorkspaceConnector(workspace_root=root).execute(action)

            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"), "old\n"
            )

    def test_compensation_refuses_to_clobber_concurrent_human_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            head = _git(repository, "rev-parse", "HEAD")
            connector = GitWorkspaceConnector(workspace_root=root)
            action = action_for(
                "repository.branch.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=head,
                parameters={
                    "workspace": "repo",
                    "branch": "agent/change",
                    "base": "main",
                },
            )
            result = connector.execute(action)
            (repository / "README.md").write_text(
                "human concurrent work\n",
                encoding="utf-8",
            )

            with self.assertRaises(VersionConflictError):
                connector.compensate(action, result)

            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "human concurrent work\n",
            )

    def test_patch_compensation_refuses_new_staged_human_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            head = _git(repository, "rev-parse", "HEAD")
            connector = GitWorkspaceConnector(workspace_root=root)
            patch = _readme_patch("new")
            action = action_for(
                "repository.patch.apply",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=head,
                parameters={
                    "workspace": "repo",
                    "patch_text": patch,
                    "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
                },
            )
            result = connector.execute(action)
            human_file = repository / "human.txt"
            human_file.write_text("keep me\n", encoding="utf-8")
            _git(repository, "add", "human.txt")

            with self.assertRaises(VersionConflictError):
                connector.compensate(action, result)

            self.assertEqual(human_file.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual((repository / "README.md").read_text(), "new\n")

    def test_local_core_worktree_cannot_escape_workspace_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace_root = root / "approved"
            repository = _repository(workspace_root / "repo")
            head = _git(repository, "rev-parse", "HEAD")
            outside = root / "outside"
            outside.mkdir()
            (outside / "README.md").write_text("human outside content\n")
            _git(repository, "config", "core.worktree", str(outside))
            action = action_for(
                "repository.branch.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=head,
                parameters={
                    "workspace": "repo",
                    "branch": "agent/escape",
                    "base": "main",
                },
            )

            with self.assertRaisesRegex(ConnectorError, "core.worktree"):
                GitWorkspaceConnector(workspace_root=workspace_root).execute(action)

            self.assertEqual(
                (outside / "README.md").read_text(),
                "human outside content\n",
            )

    def test_compensation_preserves_edit_injected_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            connector = GitWorkspaceConnector(workspace_root=root)
            action = action_for(
                "repository.branch.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "workspace": "repo",
                    "branch": "agent/change",
                    "base": "main",
                },
            )
            result = connector.execute(action)
            original_git = connector._git
            injected = False

            def racing_git(workspace: Path, *arguments: str):
                nonlocal injected
                if arguments == ("switch", "main") and not injected:
                    injected = True
                    (workspace / "README.md").write_text(
                        "human concurrent work\n",
                        encoding="utf-8",
                    )
                return original_git(workspace, *arguments)

            connector._git = racing_git  # type: ignore[method-assign]
            with self.assertRaisesRegex(VersionConflictError, "worktree changed"):
                connector.compensate(action, result)

            self.assertEqual(
                (repository / "README.md").read_text(),
                "human concurrent work\n",
            )
            self.assertIn(
                "agent/change",
                _git(repository, "branch", "--list", "agent/change"),
            )


class GitBranchPushConnectorTests(unittest.TestCase):
    """Validate new-branch-only publication and remote deletion rollback."""

    def test_publish_new_agent_branch_and_compensate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "--bare", str(remote)], check=True, capture_output=True
            )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(remote))
            _git(repository, "switch", "-c", "agent/change")
            (repository / "README.md").write_text("new\n", encoding="utf-8")
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "change")
            head = _git(repository, "rev-parse", "HEAD")
            connector = GitBranchPushConnector(
                repository_root=root,
                allow_file_remotes=True,
            )
            action = action_for(
                "bitbucket.branch.push",
                system="bitbucket",
                resource_type="branch",
                resource_id="agent/change",
                risk=RiskLevel.REVERSIBLE_WRITE,
                parameters={
                    "repository_path": str(repository),
                    "branch": "agent/change",
                    "remote": "origin",
                    "remote_url": str(remote),
                },
                expected_version=head,
            )

            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            self.assertTrue(
                _git(
                    repository,
                    "ls-remote",
                    "--heads",
                    "origin",
                    "refs/heads/agent/change",
                )
            )
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )
            self.assertEqual(
                _git(
                    repository,
                    "ls-remote",
                    "--heads",
                    "origin",
                    "refs/heads/agent/change",
                ),
                "",
            )

    @unittest.skipUnless(os.name == "posix", "executable config test requires POSIX")
    def test_repository_ssh_command_is_rejected_without_inheriting_secrets(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            _git(repository, "switch", "-c", "agent/change")
            marker = root / "ssh-ran"
            command = root / "malicious-ssh"
            command.write_text(
                f"#!/bin/sh\nprintf '%s' \"$AWS_SECRET_ACCESS_KEY\" > {marker}\nexit 1\n",
                encoding="utf-8",
            )
            command.chmod(0o700)
            _git(repository, "config", "core.sshCommand", str(command))
            _git(
                repository, "remote", "add", "origin", "ssh://git@example.test/repo.git"
            )
            action = action_for(
                "bitbucket.branch.push",
                system="bitbucket",
                resource_type="branch",
                resource_id="agent/change",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "repository_path": str(repository),
                    "branch": "agent/change",
                    "remote": "origin",
                    "remote_url": "ssh://git@example.test/repo.git",
                },
            )

            original = os.environ.get("AWS_SECRET_ACCESS_KEY")
            os.environ["AWS_SECRET_ACCESS_KEY"] = "synthetic-secret"
            try:
                with self.assertRaisesRegex(ConnectorError, "prohibited executable"):
                    GitBranchPushConnector(repository_root=root).execute(action)
            finally:
                if original is None:
                    os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
                else:
                    os.environ["AWS_SECRET_ACCESS_KEY"] = original
            self.assertFalse(marker.exists())

    def test_remote_must_still_equal_exact_approved_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved.git"
            changed = root / "changed.git"
            subprocess.run(
                ["git", "init", "--bare", str(approved)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "init", "--bare", str(changed)], check=True, capture_output=True
            )
            repository = _repository(root / "repo")
            _git(repository, "switch", "-c", "agent/change")
            _git(repository, "remote", "add", "origin", str(changed))
            action = action_for(
                "bitbucket.branch.push",
                system="bitbucket",
                resource_type="branch",
                resource_id="agent/change",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "repository_path": str(repository),
                    "branch": "agent/change",
                    "remote": "origin",
                    "remote_url": str(approved),
                },
            )

            with self.assertRaisesRegex(VersionConflictError, "remote URL changed"):
                GitBranchPushConnector(
                    repository_root=root,
                    allow_file_remotes=True,
                ).execute(action)

            self.assertEqual(
                _git(changed, "show-ref", "--heads", "agent/change", check=False),
                "",
            )

    def test_https_remote_rejects_all_userinfo(self) -> None:
        for remote_url in (
            "https://user@example.test/repo.git",
            "https://user:password@example.test/repo.git",
        ):
            with (
                self.subTest(remote_url=remote_url),
                self.assertRaisesRegex(ConnectorError, "invalid"),
            ):
                validate_remote_url(remote_url)

        self.assertEqual(
            validate_remote_url("ssh://git@example.test/repo.git"),
            "ssh://git@example.test/repo.git",
        )


def _repository(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "-b", "main", str(path)], check=True, capture_output=True
    )
    _git(path, "config", "user.name", "Master Agent Tests")
    _git(path, "config", "user.email", "master-agent@example.test")
    (path / "README.md").write_text("old\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    return path


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _diff_sha256(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "diff", "--binary", "--no-ext-diff"],
        check=True,
        capture_output=True,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def _readme_patch(value: str) -> str:
    return (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        f"+{value}\n"
    )


if __name__ == "__main__":
    unittest.main()
