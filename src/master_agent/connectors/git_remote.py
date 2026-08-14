"""Approved publication of new Git branches with bounded rollback."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import (
    ActionState,
    AgentAction,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)


_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True, slots=True)
class _CommandResult:
    """Result from one fixed Git command."""

    stdout: str
    stderr: str


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
    ) -> None:
        root = repository_root.expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ConnectorError("repository_root must be an existing directory")
        if not branch_prefix or branch_prefix.startswith("-") or ".." in branch_prefix:
            raise ConnectorError("branch_prefix is unsafe")
        if not allowed_remotes or any(not _REMOTE_RE.fullmatch(item) for item in allowed_remotes):
            raise ConnectorError("allowed_remotes contains an unsafe remote name")
        self._repository_root = root
        self._branch_prefix = branch_prefix
        self._allowed_remotes = frozenset(allowed_remotes)
        self._timeout_seconds = timeout_seconds
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
        branch = self._branch(action.parameters)
        remote = str(action.parameters.get("remote", "origin")).strip()
        if remote not in self._allowed_remotes:
            raise ConnectorError("Git remote is not allowlisted")

        current_branch = self._run(repository, "branch", "--show-current").stdout.strip()
        if current_branch != branch:
            raise ConnectorError("only the current checked-out branch may be pushed")
        commit = self._run(repository, "rev-parse", "HEAD").stdout.strip()
        if action.target.expected_version and action.target.expected_version != commit:
            raise VersionConflictError(
                "repository HEAD changed since approval: "
                f"expected {action.target.expected_version}, observed {commit}"
            )
        if self._run(repository, "status", "--porcelain").stdout.strip():
            raise ConnectorError("repository worktree must be clean before publication")

        existing = self._remote_hash(repository, remote, branch)
        if existing is not None:
            raise VersionConflictError("remote branch already exists; overwrite is prohibited")

        self._validate_remote(repository, remote)
        self._run(
            repository,
            "push",
            "--set-upstream",
            remote,
            f"refs/heads/{branch}:refs/heads/{branch}",
        )
        observed = self._remote_hash(repository, remote, branch)
        if observed != commit:
            raise ConnectorError("remote branch does not point to the approved commit")

        after = {
            "repository_path": str(repository),
            "remote": remote,
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
            compensation={
                "kind": "delete_exact_new_branch",
                "remote": remote,
                "branch": branch,
                "expected_commit": commit,
            },
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
        remote = str(after.get("remote", ""))
        branch = str(after.get("branch", ""))
        expected = str(after.get("commit", ""))
        observed_hash = self._remote_hash(repository, remote, branch)
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
        remote = str(after.get("remote", ""))
        branch = str(after.get("branch", ""))
        expected = str(after.get("commit", ""))
        if remote not in self._allowed_remotes:
            raise ConnectorError("rollback remote is not allowlisted")
        self._validate_branch(branch)
        observed = self._remote_hash(repository, remote, branch)
        if not observed:
            raise VersionConflictError("remote branch is already absent")
        if observed != expected:
            raise VersionConflictError(
                "remote branch advanced after publication; automatic deletion is prohibited"
            )
        self._run(
            repository,
            "push",
            remote,
            f":refs/heads/{branch}",
        )
        remaining = self._remote_hash(repository, remote, branch)
        compensation = ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=after,
            after={
                "repository_path": str(repository),
                "remote": remote,
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
        remote = str(after.get("remote", ""))
        branch = str(after.get("branch", ""))
        observed_hash = self._remote_hash(repository, remote, branch)
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
            raise ConnectorError(f"unsupported Git publication capability: {action.capability}")
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
            raise ConnectorError("repository_path is outside repository_root") from error
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
            or branch.endswith("/")
            or branch.endswith(".lock")
            or branch.startswith("-")
            or ".." in branch
            or "//" in branch
            or "@{" in branch
        ):
            raise ConnectorError("branch is outside the approved branch namespace")

    def _remote_hash(self, repository: Path, remote: str, branch: str) -> str | None:
        result = self._run(
            repository,
            "ls-remote",
            "--heads",
            remote,
            f"refs/heads/{branch}",
        ).stdout.strip()
        return result.split()[0] if result else None

    def _validate_remote(self, repository: Path, remote: str) -> None:
        value = self._run(repository, "remote", "get-url", remote).stdout.strip()
        allowed = (
            value.startswith("https://")
            or value.startswith("ssh://")
            or re.match(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:", value)
            or value.startswith("file://")
            or Path(value).is_absolute()
        )
        if not allowed:
            raise ConnectorError("Git remote URL scheme is not approved")

    def _run(self, repository: Path, *arguments: str) -> _CommandResult:
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/false",
                "SSH_ASKPASS": "/bin/false",
            }
        )
        try:
            completed = subprocess.run(
                ["git", "-c", "credential.helper=", *arguments],
                cwd=repository,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ConnectorError(
                f"fixed Git operation failed: {type(error).__name__}"
            ) from error
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        if completed.returncode != 0:
            diagnostic = " ".join(stderr.strip().split())[:500]
            raise ConnectorError(
                f"Git operation returned {completed.returncode}: "
                f"{diagnostic or 'no diagnostic'}"
            )
        return _CommandResult(stdout=stdout, stderr=stderr)
