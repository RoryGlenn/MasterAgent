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
from master_agent.models import CompensationMode, RiskLevel
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

    def test_branch_creation_rejects_a_base_that_would_require_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            _git(repository, "switch", "-c", "other")
            (repository / "README.md").write_text("other\n", encoding="utf-8")
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "other")
            other_head = _git(repository, "rev-parse", "HEAD")
            _git(repository, "switch", "main")
            connector = GitWorkspaceConnector(workspace_root=root)
            action = action_for(
                "repository.branch.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=other_head,
                parameters={
                    "workspace": "repo",
                    "branch": "agent/change",
                    "base": "other",
                },
            )

            with self.assertRaisesRegex(
                ConnectorError,
                "base must resolve to the current checked-out HEAD",
            ):
                connector.execute(action)

            self.assertEqual(_git(repository, "branch", "--show-current"), "main")
            self.assertEqual(_git(repository, "branch", "--list", "agent/change"), "")
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "old\n",
            )

    @unittest.skipUnless(os.name == "posix", "filter test requires POSIX")
    def test_branch_creation_never_executes_injected_checkout_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            (repository / ".gitattributes").write_text(
                "README.md filter=evil\n",
                encoding="utf-8",
            )
            _git(repository, "add", ".gitattributes")
            _git(repository, "commit", "-m", "add attributes")
            head = _git(repository, "rev-parse", "HEAD")
            _git(repository, "switch", "-c", "other")
            (repository / "README.md").write_text("other\n", encoding="utf-8")
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "other")
            _git(repository, "switch", "main")
            marker = root / "filter-ran"
            command = root / "smudge-filter"
            command.write_text(
                f"#!/bin/sh\nprintf filter > {marker}\ncat\n",
                encoding="utf-8",
            )
            command.chmod(0o700)
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
            original_ref_transaction = connector._git_ref_transaction
            injected = False
            switch_returncode: int | None = None

            def racing_ref_transaction(
                git_dir: Path,
                reason: str,
                ref: str,
                new_oid: str,
                old_oid: str,
            ):
                nonlocal injected, switch_returncode
                if ref == "refs/heads/agent/change" and not injected:
                    injected = True
                    with (repository / ".git/config").open(
                        "a",
                        encoding="utf-8",
                    ) as config:
                        config.write(f'\n[filter "evil"]\n\tsmudge = {command}\n')
                    switch_returncode = subprocess.run(
                        ["git", "-C", str(repository), "switch", "other"],
                        check=False,
                        capture_output=True,
                    ).returncode
                return original_ref_transaction(
                    git_dir,
                    reason,
                    ref,
                    new_oid,
                    old_oid,
                )

            connector._git_ref_transaction = racing_ref_transaction  # type: ignore[method-assign]
            with self.assertRaisesRegex(ConnectorError, "config identity changed"):
                connector.execute(action)
            del connector._git_ref_transaction

            self.assertTrue(injected)
            self.assertNotEqual(switch_returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(_git(repository, "branch", "--show-current"), "main")
            self.assertEqual(_git(repository, "branch", "--list", "agent/change"), "")
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "old\n",
            )

    @unittest.skipUnless(os.name == "posix", "filter test requires POSIX")
    def test_branch_compensation_never_executes_injected_checkout_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            (repository / ".gitattributes").write_text(
                "README.md filter=evil\n",
                encoding="utf-8",
            )
            _git(repository, "add", ".gitattributes")
            _git(repository, "commit", "-m", "add attributes")
            head = _git(repository, "rev-parse", "HEAD")
            _git(repository, "switch", "-c", "other")
            (repository / "README.md").write_text("other\n", encoding="utf-8")
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "other")
            _git(repository, "switch", "main")
            marker = root / "filter-ran"
            command = root / "smudge-filter"
            command.write_text(
                f"#!/bin/sh\nprintf filter > {marker}\ncat\n",
                encoding="utf-8",
            )
            command.chmod(0o700)
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
            original_head_transaction = connector._git_head_reflog_transaction
            injected = False
            switch_returncode: int | None = None

            def racing_head_transaction(
                git_dir: Path,
                reason: str,
                branch: str,
            ):
                nonlocal injected, switch_returncode
                if reason.startswith("checkout: moving") and not injected:
                    injected = True
                    with (repository / ".git/config").open(
                        "a",
                        encoding="utf-8",
                    ) as config:
                        config.write(f'\n[filter "evil"]\n\tsmudge = {command}\n')
                    switch_returncode = subprocess.run(
                        ["git", "-C", str(repository), "switch", "other"],
                        check=False,
                        capture_output=True,
                    ).returncode
                return original_head_transaction(git_dir, reason, branch)

            connector._git_head_reflog_transaction = racing_head_transaction  # type: ignore[method-assign]
            with self.assertRaisesRegex(ConnectorError, "config identity changed"):
                connector.compensate(action, result)
            del connector._git_head_reflog_transaction

            self.assertTrue(injected)
            self.assertNotEqual(switch_returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(
                _git(repository, "branch", "--show-current"),
                "agent/change",
            )
            self.assertEqual(
                _git(repository, "rev-parse", "refs/heads/agent/change"),
                head,
            )
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "old\n",
            )

    def test_branch_creation_pins_the_exact_new_ref_until_head_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            approved_head = _git(repository, "rev-parse", "HEAD")
            _git(repository, "switch", "-c", "other")
            (repository / "README.md").write_text("other\n", encoding="utf-8")
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "other")
            attacker_head = _git(repository, "rev-parse", "HEAD")
            _git(repository, "switch", "main")
            connector = GitWorkspaceConnector(workspace_root=root)
            action = action_for(
                "repository.branch.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "branch": "agent/change",
                    "base": "main",
                },
            )
            original_head_transaction = connector._git_head_reflog_transaction
            race_returncode: int | None = None

            def racing_head_transaction(
                git_dir: Path,
                reason: str,
                branch: str,
            ):
                nonlocal race_returncode
                if race_returncode is None:
                    race_returncode = subprocess.run(
                        [
                            "git",
                            "-C",
                            str(repository),
                            "update-ref",
                            "refs/heads/agent/change",
                            attacker_head,
                            approved_head,
                        ],
                        check=False,
                        capture_output=True,
                    ).returncode
                return original_head_transaction(git_dir, reason, branch)

            connector._git_head_reflog_transaction = racing_head_transaction  # type: ignore[method-assign]
            result = connector.execute(action)
            del connector._git_head_reflog_transaction

            self.assertNotEqual(race_returncode, 0)
            self.assertTrue(connector.verify(action, result).verified)
            self.assertEqual(
                _git(repository, "rev-parse", "refs/heads/agent/change"),
                approved_head,
            )
            self.assertEqual(
                _git(repository, "branch", "--show-current"), "agent/change"
            )
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "old\n",
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

    def test_isolated_worktree_snapshot_hashes_racy_same_size_edit(self) -> None:
        """A private index must not turn a same-stat edit falsely clean."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            readme = repository / "README.md"
            racy_timestamp_ns = 946_684_800_000_000_000
            os.utime(readme, ns=(racy_timestamp_ns, racy_timestamp_ns))
            _git(repository, "update-index", "--refresh")
            cached_metadata = readme.stat()
            readme.write_text("new\n", encoding="utf-8")
            os.utime(
                readme,
                ns=(cached_metadata.st_atime_ns, cached_metadata.st_mtime_ns),
            )
            connector = GitWorkspaceConnector(workspace_root=root)
            head = _git(repository, "rev-parse", "HEAD")

            with connector._sandbox.isolated_worktree_snapshot(
                repository,
                head=head,
            ) as snapshot:
                diff = connector._sandbox.run(
                    snapshot.git_dir,
                    (
                        "-c",
                        "core.trustctime=false",
                        "-c",
                        "core.checkStat=minimal",
                        "diff",
                        "--no-textconv",
                        "--binary",
                        "--no-ext-diff",
                        "--ignore-submodules=all",
                    ),
                    index_file=snapshot.index_file,
                    worktree=repository,
                )

            self.assertIn(b"+new", diff.stdout_bytes)

    def test_standalone_restore_is_disabled_after_precheck_edit(self) -> None:
        """A human edit after approval cannot reach a destructive reset path."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            connector = GitWorkspaceConnector(workspace_root=root)
            approved_head = _git(repository, "rev-parse", "HEAD")
            approved_status = hashlib.sha256(
                _git(repository, "status", "--porcelain=v1").encode("utf-8")
            ).hexdigest()
            action = action_for(
                "repository.worktree.restore",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "commit": approved_head,
                    "expected_worktree_status_sha256": approved_status,
                },
            )

            # Inject the edit after capturing the exact HEAD and worktree status
            # that the removed check-then-reset implementation trusted.
            (repository / "README.md").write_text(
                "human concurrent work\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConnectorError, "unsupported Git capability"):
                connector.execute(action)

            self.assertNotIn(action.capability, connector.capabilities)
            self.assertEqual(_git(repository, "rev-parse", "HEAD"), approved_head)
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "human concurrent work\n",
            )

    def test_local_git_rollback_is_advertised_as_in_process_only(self) -> None:
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
            compensation = result.compensation
            self.assertIsNotNone(compensation)
            assert compensation is not None

            self.assertEqual(
                compensation.mode,
                CompensationMode.IN_PROCESS,
            )
            self.assertIsNone(compensation.capability)

    def test_remote_push_reports_manual_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                capture_output=True,
            )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(remote))
            _git(repository, "switch", "-c", "agent/change")
            action = action_for(
                "repository.branch.push",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "workspace": "repo",
                    "remote": "origin",
                    "remote_url": str(remote),
                    "branch": "agent/change",
                },
            )
            connector = GitWorkspaceConnector(
                workspace_root=root,
                allow_file_remotes=True,
            )

            result = connector.execute(action)

            self.assertIsNotNone(result.compensation)
            assert result.compensation is not None
            self.assertEqual(result.compensation.mode, CompensationMode.MANUAL)
            self.assertIn(
                "remote branch rollback is manual", result.compensation.reason or ""
            )
            with self.assertRaisesRegex(
                ConnectorError,
                "automatic remote compensation is unavailable",
            ):
                connector.compensate(action, result)

    def test_push_publishes_approved_oid_when_branch_advances_at_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                capture_output=True,
            )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(remote))
            _git(repository, "switch", "-c", "agent/change")
            approved_commit = _git(repository, "rev-parse", "HEAD")
            action = action_for(
                "repository.branch.push",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_commit,
                parameters={
                    "workspace": "repo",
                    "remote": "origin",
                    "remote_url": str(remote),
                    "branch": "agent/change",
                },
            )
            connector = GitWorkspaceConnector(
                workspace_root=root,
                allow_file_remotes=True,
            )
            original_git = connector._git_publication
            raced_commit = ""

            def racing_git(publication: Path, *arguments: str):
                nonlocal raced_commit
                if arguments and arguments[0] == "push" and not raced_commit:
                    (repository / "README.md").write_text(
                        "unapproved concurrent commit\n",
                        encoding="utf-8",
                    )
                    _git(repository, "add", "README.md")
                    _git(repository, "commit", "-m", "concurrent change")
                    raced_commit = _git(repository, "rev-parse", "HEAD")
                return original_git(publication, *arguments)

            connector._git_publication = racing_git  # type: ignore[method-assign]
            result = connector.execute(action)
            del connector._git_publication

            remote_commit = _git(
                repository,
                "ls-remote",
                "--heads",
                str(remote),
                "refs/heads/agent/change",
            ).split()[0]
            self.assertNotEqual(raced_commit, approved_commit)
            self.assertEqual(_git(repository, "rev-parse", "HEAD"), raced_commit)
            self.assertEqual(remote_commit, approved_commit)
            self.assertEqual(result.after["commit"], approved_commit)

    def test_push_ignores_direct_url_rewrite_injected_at_publication_boundary(
        self,
    ) -> None:
        for rewrite_key in ("insteadOf", "pushInsteadOf"):
            with (
                self.subTest(rewrite_key=rewrite_key),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                approved = root / "approved.git"
                attacker = root / "attacker.git"
                for remote in (approved, attacker):
                    subprocess.run(
                        ["git", "init", "--bare", str(remote)],
                        check=True,
                        capture_output=True,
                    )
                repository = _repository(root / "repo")
                _git(repository, "remote", "add", "origin", str(approved))
                _git(repository, "switch", "-c", "agent/change")
                approved_commit = _git(repository, "rev-parse", "HEAD")
                action = action_for(
                    "repository.branch.push",
                    system="repository",
                    resource_type="workspace",
                    resource_id="repo",
                    risk=RiskLevel.REVERSIBLE_WRITE,
                    expected_version=approved_commit,
                    parameters={
                        "workspace": "repo",
                        "remote": "origin",
                        "remote_url": str(approved),
                        "branch": "agent/change",
                    },
                )
                connector = GitWorkspaceConnector(
                    workspace_root=root,
                    allow_file_remotes=True,
                )
                original_publication = connector._git_publication
                injected = False

                def racing_publication(
                    publication: Path,
                    *arguments: str,
                    _repository: Path = repository,
                    _attacker: Path = attacker,
                    _rewrite_key: str = rewrite_key,
                    _approved: Path = approved,
                    _original_publication=original_publication,
                ):
                    nonlocal injected
                    if arguments and arguments[0] == "push" and not injected:
                        injected = True
                        with (_repository / ".git/config").open(
                            "a",
                            encoding="utf-8",
                        ) as config:
                            config.write(
                                f'\n[url "{_attacker}"]\n'
                                f"\t{_rewrite_key} = {_approved}\n"
                            )
                    return _original_publication(publication, *arguments)

                connector._git_publication = racing_publication  # type: ignore[method-assign]
                with self.assertRaisesRegex(ConnectorError, "config identity changed"):
                    connector.execute(action)
                del connector._git_publication

                self.assertTrue(injected)
                self.assertEqual(
                    _git(approved, "rev-parse", "refs/heads/agent/change"),
                    approved_commit,
                )
                self.assertEqual(
                    _git(
                        attacker,
                        "rev-parse",
                        "--verify",
                        "refs/heads/agent/change",
                        check=False,
                    ),
                    "",
                )

    def test_pushurl_configuration_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved.git"
            attacker = root / "attacker.git"
            for remote in (approved, attacker):
                subprocess.run(
                    ["git", "init", "--bare", str(remote)],
                    check=True,
                    capture_output=True,
                )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(approved))
            _git(repository, "config", "remote.origin.pushurl", str(attacker))
            _git(repository, "switch", "-c", "agent/change")
            action = action_for(
                "repository.branch.push",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=_git(repository, "rev-parse", "HEAD"),
                parameters={
                    "workspace": "repo",
                    "remote": "origin",
                    "remote_url": str(approved),
                    "branch": "agent/change",
                },
            )

            with self.assertRaisesRegex(ConnectorError, "remote.origin.pushurl"):
                GitWorkspaceConnector(
                    workspace_root=root,
                    allow_file_remotes=True,
                ).execute(action)

            for remote in (approved, attacker):
                self.assertEqual(
                    _git(
                        remote,
                        "rev-parse",
                        "--verify",
                        "refs/heads/agent/change",
                        check=False,
                    ),
                    "",
                )

    def test_commit_isolates_index_at_content_binding_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            approved_head = _git(repository, "rev-parse", "HEAD")
            approved_digest = _diff_sha256(repository)
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": approved_digest,
                },
            )
            connector = GitWorkspaceConnector(workspace_root=root)
            original_git = connector._git
            injected = False
            stage_returncode: int | None = None

            def racing_git(workspace: Path, *arguments: str):
                nonlocal injected, stage_returncode
                if (
                    arguments
                    and arguments[0] in {"commit", "commit-tree"}
                    and not injected
                ):
                    injected = True
                    (workspace / "README.md").write_text(
                        "human boundary edit\n",
                        encoding="utf-8",
                    )
                    stage = subprocess.run(
                        ["git", "-C", str(workspace), "add", "README.md"],
                        check=False,
                        capture_output=True,
                    )
                    stage_returncode = stage.returncode
                return original_git(workspace, *arguments)

            connector._git = racing_git  # type: ignore[method-assign]
            result = connector.execute(action)
            del connector._git

            self.assertTrue(injected)
            self.assertIsNotNone(stage_returncode)
            self.assertNotEqual(stage_returncode, 0)
            self.assertEqual(_git(repository, "show", "HEAD:README.md"), "approved")
            self.assertEqual(_git(repository, "show", ":README.md"), "approved")
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "human boundary edit\n",
            )
            self.assertEqual(_git(repository, "status", "--porcelain"), "M README.md")
            self.assertEqual(result.after["diff_sha256"], approved_digest)

    def test_commit_hashes_raw_non_utf8_diff_bytes_without_replacement_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            connector = GitWorkspaceConnector(workspace_root=root)
            approved_head = _git(repository, "rev-parse", "HEAD")
            approved_bytes, attacker_bytes = _replacement_collision_payloads()
            (repository / "README.md").write_bytes(approved_bytes)
            approved_result = connector._git(
                repository,
                "diff",
                "--no-textconv",
                "--binary",
                "--no-ext-diff",
            )
            approved_digest = connector._diff_digest(repository)
            self.assertEqual(
                approved_digest,
                hashlib.sha256(approved_result.stdout_bytes).hexdigest(),
            )

            (repository / "README.md").write_bytes(attacker_bytes)
            attacker_result = connector._git(
                repository,
                "diff",
                "--no-textconv",
                "--binary",
                "--no-ext-diff",
            )
            self.assertEqual(approved_result.stdout, attacker_result.stdout)
            self.assertNotEqual(
                approved_result.stdout_bytes,
                attacker_result.stdout_bytes,
            )
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "message": "approved non-UTF-8 change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": approved_digest,
                },
            )

            with self.assertRaisesRegex(VersionConflictError, "approved diff digest"):
                connector.execute(action)

            self.assertEqual(_git(repository, "rev-parse", "HEAD"), approved_head)
            self.assertEqual(
                (repository / "README.md").read_bytes(),
                attacker_bytes,
            )

    @unittest.skipUnless(os.name == "posix", "textconv test requires POSIX")
    def test_diff_textconv_is_disabled_and_executable_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            marker = root / "textconv-ran"
            command = root / "textconv"
            command.write_text(
                f'#!/bin/sh\nprintf textconv > {marker}\ncat "$1"\n',
                encoding="utf-8",
            )
            command.chmod(0o700)
            (repository / ".gitattributes").write_text(
                "README.md diff=evil\n",
                encoding="utf-8",
            )
            _git(repository, "add", ".gitattributes")
            _git(repository, "commit", "-m", "add attributes")
            _git(repository, "config", "diff.evil.textconv", str(command))
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            connector = GitWorkspaceConnector(workspace_root=root)

            connector._diff_digest(repository)
            self.assertFalse(marker.exists())
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
                    "expected_diff_sha256": connector._diff_digest(repository),
                },
            )

            with self.assertRaisesRegex(ConnectorError, "diff.evil.textconv"):
                connector.execute(action)

            self.assertFalse(marker.exists())

    def test_diff_cachetextconv_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            _git(repository, "config", "diff.evil.cachetextconv", "true")
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

            with self.assertRaisesRegex(ConnectorError, "cachetextconv"):
                GitWorkspaceConnector(workspace_root=root).execute(action)

    @unittest.skipUnless(os.name == "posix", "filter test requires POSIX")
    def test_worktree_status_and_diff_ignore_filter_injected_at_subprocess_boundary(
        self,
    ) -> None:
        for git_command in ("status", "diff"):
            with (
                self.subTest(git_command=git_command),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                repository = _repository(root / "repo")
                marker = root / "filter-ran"
                command = root / "clean-filter"
                command.write_text(
                    f"#!/bin/sh\nprintf filter > {marker}\ncat\n",
                    encoding="utf-8",
                )
                command.chmod(0o700)
                (repository / "README.md").write_text(
                    "changed\n",
                    encoding="utf-8",
                )
                connector = GitWorkspaceConnector(workspace_root=root)
                original_run = connector._sandbox.run
                injected = False

                def racing_run(
                    git_dir: Path,
                    arguments: tuple[str, ...],
                    _git_command: str = git_command,
                    _repository: Path = repository,
                    _command: Path = command,
                    _original_run=original_run,
                    **kwargs,
                ):
                    nonlocal injected
                    if (
                        kwargs.get("worktree") is not None
                        and arguments
                        and arguments[0] == _git_command
                        and not injected
                    ):
                        injected = True
                        (_repository / ".gitattributes").write_text(
                            "README.md filter=evil\n",
                            encoding="utf-8",
                        )
                        with (_repository / ".git/config").open(
                            "a",
                            encoding="utf-8",
                        ) as config:
                            config.write(f'\n[filter "evil"]\n\tclean = {_command}\n')
                    return _original_run(git_dir, arguments, **kwargs)

                connector._sandbox.run = racing_run  # type: ignore[method-assign]
                if git_command == "status":
                    connector._status_digest(repository)
                else:
                    connector._diff_digest(repository)
                del connector._sandbox.run

                self.assertTrue(injected)
                self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "filter test requires POSIX")
    def test_commit_filter_injected_at_hash_boundary_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            marker = root / "filter-ran"
            command = root / "clean-filter"
            command.write_text(
                f"#!/bin/sh\nprintf filter > {marker}\ncat\n",
                encoding="utf-8",
            )
            command.chmod(0o700)
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            approved_head = _git(repository, "rev-parse", "HEAD")
            original_index = (repository / ".git/index").read_bytes()
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": _diff_sha256(repository),
                },
            )
            connector = GitWorkspaceConnector(workspace_root=root)
            original_git_bytes = connector._git_bytes
            injected = False

            def racing_git_bytes(
                workspace: Path,
                arguments: tuple[str, ...],
                payload: bytes,
            ):
                nonlocal injected
                if arguments and arguments[0] == "hash-object" and not injected:
                    injected = True
                    (workspace / ".gitattributes").write_text(
                        "README.md filter=evil\n",
                        encoding="utf-8",
                    )
                    with (workspace / ".git/config").open(
                        "a",
                        encoding="utf-8",
                    ) as config:
                        config.write(f'\n[filter "evil"]\n\tclean = {command}\n')
                return original_git_bytes(workspace, arguments, payload)

            connector._git_bytes = racing_git_bytes  # type: ignore[method-assign]
            with self.assertRaisesRegex(ConnectorError, "config identity changed"):
                connector.execute(action)
            del connector._git_bytes

            self.assertTrue(injected)
            self.assertFalse(marker.exists())
            self.assertEqual(_git(repository, "rev-parse", "HEAD"), approved_head)
            self.assertEqual((repository / ".git/index").read_bytes(), original_index)
            self.assertEqual(
                (repository / "README.md").read_text(encoding="utf-8"),
                "approved\n",
            )

    def test_commit_head_switch_at_ref_transaction_is_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            _git(repository, "branch", "other")
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            approved_head = _git(repository, "rev-parse", "HEAD")
            original_index = (repository / ".git/index").read_bytes()
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": _diff_sha256(repository),
                },
            )
            connector = GitWorkspaceConnector(workspace_root=root)
            original_transaction = connector._git_ref_transaction
            injected = False

            def racing_transaction(
                git_dir: Path,
                reason: str,
                ref: str,
                new_oid: str,
                old_oid: str,
            ):
                nonlocal injected
                if not injected:
                    injected = True
                    replacement = repository / ".git/HEAD.inject"
                    replacement.write_text(
                        "ref: refs/heads/other\n",
                        encoding="ascii",
                    )
                    os.replace(replacement, repository / ".git/HEAD")
                return original_transaction(
                    git_dir,
                    reason,
                    ref,
                    new_oid,
                    old_oid,
                )

            connector._git_ref_transaction = racing_transaction  # type: ignore[method-assign]
            with self.assertRaisesRegex(VersionConflictError, "rolled back"):
                connector.execute(action)
            del connector._git_ref_transaction

            self.assertTrue(injected)
            self.assertEqual(
                _git(repository, "rev-parse", "refs/heads/main"), approved_head
            )
            self.assertEqual(
                _git(repository, "rev-parse", "refs/heads/other"), approved_head
            )
            self.assertEqual(_git(repository, "branch", "--show-current"), "other")
            self.assertEqual((repository / ".git/index").read_bytes(), original_index)
            self.assertFalse((repository / ".git/index.lock").exists())
            self.assertFalse((repository / ".git/HEAD.lock").exists())

    @unittest.skipUnless(os.name == "posix", "hard-link test requires POSIX")
    def test_commit_refuses_hardlinked_reflog_without_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            approved_head = _git(repository, "rev-parse", "HEAD")
            branch_log = repository / ".git/logs/refs/heads/main"
            os.link(branch_log, root / "reflog-alias")
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": _diff_sha256(repository),
                },
            )

            with self.assertRaisesRegex(ConnectorError, "singly linked"):
                GitWorkspaceConnector(workspace_root=root).execute(action)

            self.assertEqual(_git(repository, "rev-parse", "HEAD"), approved_head)
            self.assertEqual(_git(repository, "diff", "--cached", "--name-only"), "")

    def test_commit_preserves_unrelated_shared_index_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _repository(root / "repo")
            (repository / "OTHER.txt").write_text("unchanged\n", encoding="utf-8")
            _git(repository, "add", "OTHER.txt")
            _git(repository, "commit", "-m", "add unrelated file")
            _git(repository, "update-index", "--assume-unchanged", "OTHER.txt")
            index_entry = _git(repository, "ls-files", "-v", "OTHER.txt")
            self.assertTrue(index_entry.startswith("h "))
            (repository / "README.md").write_text("approved\n", encoding="utf-8")
            approved_head = _git(repository, "rev-parse", "HEAD")
            action = action_for(
                "repository.commit.create",
                system="repository",
                resource_type="workspace",
                resource_id="repo",
                risk=RiskLevel.REVERSIBLE_WRITE,
                expected_version=approved_head,
                parameters={
                    "workspace": "repo",
                    "message": "approved change",
                    "paths": ["README.md"],
                    "expected_diff_sha256": _diff_sha256(repository),
                },
            )

            GitWorkspaceConnector(workspace_root=root).execute(action)

            self.assertEqual(
                _git(repository, "ls-files", "-v", "OTHER.txt"),
                index_entry,
            )
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
            original_head_transaction = connector._git_head_reflog_transaction
            injected = False

            def racing_head_transaction(
                git_dir: Path,
                reason: str,
                branch: str,
            ):
                nonlocal injected
                if reason.startswith("checkout: moving") and not injected:
                    injected = True
                    (repository / "README.md").write_text(
                        "human concurrent work\n",
                        encoding="utf-8",
                    )
                return original_head_transaction(git_dir, reason, branch)

            connector._git_head_reflog_transaction = racing_head_transaction  # type: ignore[method-assign]
            with self.assertRaisesRegex(VersionConflictError, "worktree changed"):
                connector.compensate(action, result)
            del connector._git_head_reflog_transaction

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

    def test_compensation_uses_atomic_lease_and_preserves_raced_remote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                capture_output=True,
            )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(remote))
            _git(repository, "switch", "-c", "agent/change")
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
                expected_version=_git(repository, "rev-parse", "HEAD"),
            )
            result = connector.execute(action)
            (repository / "README.md").write_text(
                "human concurrent change\n",
                encoding="utf-8",
            )
            _git(repository, "add", "README.md")
            _git(repository, "commit", "-m", "human concurrent change")
            raced_commit = _git(repository, "rev-parse", "HEAD")
            _git(
                repository,
                "push",
                str(remote),
                f"{raced_commit}:refs/heads/human/staging",
            )
            original_publication = connector._run_publication
            raced = False

            def racing_deletion(workspace: Path, *arguments: str):
                nonlocal raced
                if (
                    not raced
                    and arguments
                    and arguments[0] == "push"
                    and any("--force-with-lease=" in item for item in arguments)
                ):
                    raced = True
                    _git(
                        remote,
                        "update-ref",
                        "refs/heads/agent/change",
                        raced_commit,
                    )
                return original_publication(workspace, *arguments)

            connector._run_publication = racing_deletion  # type: ignore[method-assign]
            try:
                with self.assertRaisesRegex(
                    VersionConflictError,
                    "atomic deletion was refused",
                ):
                    connector.compensate(action, result)
            finally:
                del connector._run_publication

            self.assertTrue(raced)
            self.assertEqual(
                _git(remote, "rev-parse", "refs/heads/agent/change"),
                raced_commit,
            )

    def test_publish_uses_approved_oid_when_local_branch_races(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                capture_output=True,
            )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(remote))
            _git(repository, "switch", "-c", "agent/change")
            approved_commit = _git(repository, "rev-parse", "HEAD")
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
                expected_version=approved_commit,
            )
            original_publication = connector._run_publication
            raced_commit = ""

            def racing_publication(workspace: Path, *arguments: str):
                nonlocal raced_commit
                if arguments and arguments[0] == "push" and not raced_commit:
                    (repository / "README.md").write_text(
                        "unapproved concurrent commit\n",
                        encoding="utf-8",
                    )
                    _git(repository, "add", "README.md")
                    _git(repository, "commit", "-m", "concurrent change")
                    raced_commit = _git(repository, "rev-parse", "HEAD")
                return original_publication(workspace, *arguments)

            connector._run_publication = racing_publication  # type: ignore[method-assign]
            result = connector.execute(action)
            del connector._run_publication

            self.assertNotEqual(raced_commit, approved_commit)
            self.assertEqual(_git(repository, "rev-parse", "HEAD"), raced_commit)
            self.assertEqual(
                _git(remote, "rev-parse", "refs/heads/agent/change"),
                approved_commit,
            )
            self.assertEqual(result.after["commit"], approved_commit)

    def test_publication_ignores_injected_source_pushinstead_of(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved.git"
            attacker = root / "attacker.git"
            for remote in (approved, attacker):
                subprocess.run(
                    ["git", "init", "--bare", str(remote)],
                    check=True,
                    capture_output=True,
                )
            repository = _repository(root / "repo")
            _git(repository, "remote", "add", "origin", str(approved))
            _git(repository, "switch", "-c", "agent/change")
            approved_commit = _git(repository, "rev-parse", "HEAD")
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
                    "remote_url": str(approved),
                },
                expected_version=approved_commit,
            )
            original_publication = connector._run_publication
            injected = False

            def racing_publication(workspace: Path, *arguments: str):
                nonlocal injected
                if arguments and arguments[0] == "push" and not injected:
                    injected = True
                    with (repository / ".git/config").open(
                        "a",
                        encoding="utf-8",
                    ) as config:
                        config.write(
                            f'\n[url "{attacker}"]\n\tpushInsteadOf = {approved}\n'
                        )
                return original_publication(workspace, *arguments)

            connector._run_publication = racing_publication  # type: ignore[method-assign]
            with self.assertRaisesRegex(ConnectorError, "config identity changed"):
                connector.execute(action)
            del connector._run_publication

            self.assertTrue(injected)
            self.assertEqual(
                _git(approved, "rev-parse", "refs/heads/agent/change"),
                approved_commit,
            )
            self.assertEqual(
                _git(
                    attacker,
                    "rev-parse",
                    "--verify",
                    "refs/heads/agent/change",
                    check=False,
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


def _replacement_collision_payloads() -> tuple[bytes, bytes]:
    """Find distinct invalid UTF-8 blobs with one seven-hex Git abbreviation."""

    observed: dict[str, bytes] = {}
    for value in range(200_000):
        remaining = value
        invalid = bytearray()
        for _ in range(4):
            invalid.append(0x80 + (remaining & 0x3F))
            remaining >>= 6
        payload = b"value-" + bytes(invalid) + b"\n"
        framed = f"blob {len(payload)}\0".encode("ascii") + payload
        abbreviation = hashlib.sha1(
            framed,
            usedforsecurity=False,
        ).hexdigest()[:7]
        previous = observed.get(abbreviation)
        if previous is not None and previous != payload:
            return previous, payload
        observed[abbreviation] = payload
    raise AssertionError("failed to construct deterministic Git abbreviation collision")


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
