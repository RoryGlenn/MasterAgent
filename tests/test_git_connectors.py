"""Tests for fixed-operation local Git and Bitbucket branch publication."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from master_agent.connectors.git_remote import GitBranchPushConnector
from master_agent.connectors.git_workspace import GitWorkspaceConnector
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
                parameters={"workspace": "repo", "branch": "agent/change", "base": "main"},
            )

            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            self.assertEqual(_git(repository, "branch", "--show-current"), "agent/change")
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )
            self.assertEqual(_git(repository, "branch", "--show-current"), "main")
            self.assertNotIn("agent/change", _git(repository, "branch", "--list", "agent/change"))

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
                parameters={"workspace": "repo", "patch_text": patch},
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


class GitBranchPushConnectorTests(unittest.TestCase):
    """Validate new-branch-only publication and remote deletion rollback."""

    def test_publish_new_agent_branch_and_compensate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(remote))
            _git(repository, "switch", "-c", "agent/change")
            (repository / "README.md").write_text("new\n", encoding="utf-8")
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "change")
            connector = GitBranchPushConnector(repository_root=root)
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
                },
            )

            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
            self.assertTrue(
                _git(repository, "ls-remote", "--heads", "origin", "refs/heads/agent/change")
            )
            compensation = connector.compensate(action, result)
            self.assertTrue(
                connector.verify_compensation(action, result, compensation).verified
            )
            self.assertEqual(
                _git(repository, "ls-remote", "--heads", "origin", "refs/heads/agent/change"),
                "",
            )


def _repository(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    _git(path, "config", "user.name", "Master Agent Tests")
    _git(path, "config", "user.email", "master-agent@example.test")
    (path / "README.md").write_text("old\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    return path


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
