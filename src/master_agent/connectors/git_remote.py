"""Approved publication of new Git branches with bounded rollback."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from master_agent.connectors.git_sandbox import (
    GitSandbox,
    SandboxedGitResult,
    validate_remote_url,
)
from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import (
    ActionState,
    AgentAction,
    CompensationDescriptor,
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class GitBranchPushConnector:
    """Push only a new, prefixed branch and delete only that exact branch.

    The connector never invokes a shell, never force-pushes, and refuses to
    overwrite an existing remote branch. Compensation is allowed only while
    the remote ref still points at the commit created by the approved action.

    Parameters
    ----------
    repository_root
        Root beneath which all eligible repositories must reside.
    branch_prefix
        Required prefix for every branch the connector may publish.
    allowed_remotes
        Git remote names that may be used.
    timeout_seconds
        Per-command timeout.
    """

    _CAPABILITIES = frozenset({"bitbucket.branch.push"})

    def __init__(
        self,
        *,
        repository_root: Path,
        branch_prefix: str = "agent/",
        allowed_remotes: tuple[str, ...] = ("origin",),
        timeout_seconds: float = 120.0,
        allow_file_remotes: bool = False,
    ) -> None:
        root = repository_root.expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ConnectorError("repository_root must be an existing directory")
        if not branch_prefix or branch_prefix.startswith("-") or ".." in branch_prefix:
            raise ConnectorError("branch_prefix is unsafe")
        if not allowed_remotes or any(
            not _REMOTE_RE.fullmatch(item) for item in allowed_remotes
        ):
            raise ConnectorError("allowed_remotes contains an unsafe remote name")
        self._repository_root = root
        self._branch_prefix = branch_prefix
        self._allowed_remotes = frozenset(allowed_remotes)
        self._allow_file_remotes = allow_file_remotes
        self._sandbox = GitSandbox(
            timeout_seconds=timeout_seconds,
            allow_file_protocol=allow_file_remotes,
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return the connector system."""

        return "bitbucket"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Push a new branch without force or ref rewriting."""

        self._validate(action)
        repository = self._repository(action.parameters)
        self._sandbox.validate_repository_config(repository)
        branch = self._branch(action.parameters)
        remote = str(action.parameters.get("remote", "origin")).strip()
        if remote not in self._allowed_remotes:
            raise ConnectorError("Git remote is not allowlisted")

        with self._sandbox.lock_repository_config(repository) as config_guard:
            self._sandbox.validate_repository_config(repository)
            current_branch = self._run(
                repository, "branch", "--show-current"
            ).stdout.strip()
            if current_branch != branch:
                raise ConnectorError(
                    "only the current checked-out branch may be pushed"
                )
            commit = self._run(repository, "rev-parse", "HEAD").stdout.strip()
            if not action.target.expected_version:
                raise ConnectorError(
                    "branch publication requires an approved commit hash"
                )
            if action.target.expected_version != commit:
                raise VersionConflictError(
                    "repository HEAD changed since approval: "
                    f"expected {action.target.expected_version}, observed {commit}"
                )
            if self._run_worktree(
                repository,
                "status",
                "--porcelain",
                "--ignore-submodules=all",
            ).stdout.strip():
                raise ConnectorError(
                    "repository worktree must be clean before publication"
                )

            remote_url = self._approved_remote_url(action, repository, remote)
            config_guard.validate()
            existing = self._remote_hash(repository, remote_url, branch)
            config_guard.validate()
            if existing is not None:
                raise VersionConflictError(
                    "remote branch already exists; overwrite is prohibited"
                )

            self._run_publication(
                repository,
                "push",
                remote_url,
                f"{commit}:refs/heads/{branch}",
            )
            config_guard.validate()
            observed = self._remote_hash(repository, remote_url, branch)
            config_guard.validate()
        if observed != commit:
            raise ConnectorError("remote branch does not point to the approved commit")

        after = {
            "repository_path": str(repository),
            "remote": remote,
            "remote_url": remote_url,
            "branch": branch,
            "commit": commit,
            "created_new_ref": True,
        }
        self._last[action.target.resource_id] = deepcopy(after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={"remote_commit": None},
            after=after,
            connector_reference=f"git:{remote}/{branch}",
            message="new review branch pushed without force",
            compensation=CompensationDescriptor(
                kind="delete_exact_new_branch",
                mode=CompensationMode.IN_PROCESS,
                target_resource_id=branch,
                reason=(
                    "remote deletion requires the originating connector's "
                    "allowlisted repository boundary"
                ),
            ).to_dict(),
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return the last normalized result for a branch target."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify the remote branch points to the approved commit."""

        after = result.after or {}
        repository = self._repository(after)
        self._sandbox.validate_repository_config(repository)
        remote = str(after.get("remote", ""))
        remote_url = validate_remote_url(
            str(after.get("remote_url", "")),
            allow_file=self._allow_file_remotes,
        )
        branch = str(after.get("branch", ""))
        expected = str(after.get("commit", ""))
        with self._sandbox.lock_repository_config(repository) as config_guard:
            self._sandbox.validate_repository_config(repository)
            config_guard.validate()
            observed_hash = self._remote_hash(repository, remote_url, branch)
            config_guard.validate()
        observed = {"remote": remote, "branch": branch, "commit": observed_hash}
        verified = bool(expected and observed_hash == expected)
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified newly published branch by remote ref lookup"
                if verified
                else "remote branch did not match the approved commit"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Delete only the exact new remote branch while it remains unchanged."""

        after = result.after or {}
        repository = self._repository(after)
        self._sandbox.validate_repository_config(repository)
        remote = str(after.get("remote", ""))
        remote_url = validate_remote_url(
            str(after.get("remote_url", "")),
            allow_file=self._allow_file_remotes,
        )
        branch = str(after.get("branch", ""))
        expected = str(after.get("commit", ""))
        if remote not in self._allowed_remotes:
            raise ConnectorError("rollback remote is not allowlisted")
        self._validate_branch(branch)
        with self._sandbox.lock_repository_config(repository) as config_guard:
            self._sandbox.validate_repository_config(repository)
            config_guard.validate()
            observed = self._remote_hash(repository, remote_url, branch)
            config_guard.validate()
            if not observed:
                raise VersionConflictError("remote branch is already absent")
            if observed != expected:
                raise VersionConflictError(
                    "remote branch advanced after publication; automatic deletion "
                    "is prohibited"
                )
            self._run_publication(
                repository,
                "push",
                remote_url,
                f":refs/heads/{branch}",
            )
            config_guard.validate()
            remaining = self._remote_hash(repository, remote_url, branch)
            config_guard.validate()
        compensation = ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=after,
            after={
                "repository_path": str(repository),
                "remote": remote,
                "remote_url": remote_url,
                "branch": branch,
                "commit": remaining,
                "deleted": remaining is None,
            },
            connector_reference=f"git:{remote}/{branch}",
            message="exact new remote branch deleted",
        )
        self._last[action.target.resource_id] = deepcopy(dict(compensation.after or {}))
        return compensation

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Verify the compensated remote branch no longer exists."""

        after = compensation.after or {}
        repository = self._repository(after)
        self._sandbox.validate_repository_config(repository)
        remote = str(after.get("remote", ""))
        remote_url = validate_remote_url(
            str(after.get("remote_url", "")),
            allow_file=self._allow_file_remotes,
        )
        branch = str(after.get("branch", ""))
        with self._sandbox.lock_repository_config(repository) as config_guard:
            self._sandbox.validate_repository_config(repository)
            config_guard.validate()
            observed_hash = self._remote_hash(repository, remote_url, branch)
            config_guard.validate()
        verified = observed_hash is None
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed={"remote": remote, "branch": branch, "commit": observed_hash},
            message=(
                "verified remote branch deletion"
                if verified
                else "remote branch still exists after compensation"
            ),
        )

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("Git publication connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported Git publication capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("branch publication must use reversible_write risk")
        if not action.requires_approval:
            raise ConnectorError("branch publication requires explicit approval")

    def _repository(self, parameters: Mapping[str, Any]) -> Path:
        value = str(parameters.get("repository_path", "")).strip()
        if not value:
            raise ConnectorError("repository_path is required")
        path = Path(value).expanduser().resolve()
        try:
            path.relative_to(self._repository_root)
        except ValueError as error:
            raise ConnectorError(
                "repository_path is outside repository_root"
            ) from error
        if not (path / ".git").exists():
            raise ConnectorError("repository_path is not a Git worktree")
        return path

    def _branch(self, parameters: Mapping[str, Any]) -> str:
        branch = str(parameters.get("branch", "")).strip()
        self._validate_branch(branch)
        return branch

    def _validate_branch(self, branch: str) -> None:
        if (
            not _BRANCH_RE.fullmatch(branch)
            or not branch.startswith(self._branch_prefix)
            or branch.endswith(("/", ".lock"))
            or branch.startswith("-")
            or ".." in branch
            or "//" in branch
            or "@{" in branch
        ):
            raise ConnectorError("branch is outside the approved branch namespace")

    def _remote_hash(
        self, repository: Path, remote_url: str, branch: str
    ) -> str | None:
        result = self._run_publication(
            repository,
            "ls-remote",
            "--heads",
            remote_url,
            f"refs/heads/{branch}",
        ).stdout.strip()
        return result.split()[0] if result else None

    def _approved_remote_url(
        self,
        action: AgentAction,
        repository: Path,
        remote: str,
    ) -> str:
        approved = validate_remote_url(
            str(action.parameters.get("remote_url", "")),
            allow_file=self._allow_file_remotes,
        )
        observed = validate_remote_url(
            self._run(repository, "remote", "get-url", remote).stdout.strip(),
            allow_file=self._allow_file_remotes,
        )
        if observed != approved:
            raise VersionConflictError("Git remote URL changed since approval")
        return approved

    def _run(self, repository: Path, *arguments: str) -> SandboxedGitResult:
        return self._sandbox.run(repository, arguments)

    def _run_worktree(
        self,
        repository: Path,
        *arguments: str,
    ) -> SandboxedGitResult:
        head = self._run(repository, "rev-parse", "HEAD").stdout.strip()
        with self._sandbox.isolated_worktree_snapshot(
            repository,
            head=head,
        ) as snapshot:
            return self._sandbox.run(
                snapshot.git_dir,
                arguments,
                index_file=snapshot.index_file,
                worktree=repository,
            )

    def _run_publication(
        self,
        repository: Path,
        *arguments: str,
    ) -> SandboxedGitResult:
        with self._sandbox.isolated_publication_repository(
            repository
        ) as publication_repository:
            return self._sandbox.run(
                publication_repository,
                arguments,
                bare_repository=True,
            )
