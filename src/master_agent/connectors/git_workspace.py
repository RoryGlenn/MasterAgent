"""Fixed-operation local Git connector for approved branch workflows."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from master_agent.connectors.base import CompensatingConnector
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


@dataclass(frozen=True, slots=True)
class GitCommandResult:
    """Secret-safe result from a fixed Git invocation."""

    stdout: str
    stderr: str
    returncode: int


class GitWorkspaceConnector(CompensatingConnector):
    """Perform a narrow, reviewable local Git branch/patch/push workflow.

    The connector never invokes a shell. Every command is an explicit ``git``
    argv list, workspaces must be beneath ``workspace_root``, force pushes are
    absent, and protected branches cannot be created or pushed.
    """

    _CAPABILITIES = frozenset(
        {
            "repository.branch.create",
            "repository.patch.apply",
            "repository.commit.create",
            "repository.branch.push",
            "repository.worktree.restore",
        }
    )

    def __init__(
        self,
        *,
        workspace_root: Path,
        allowed_remotes: tuple[str, ...] = ("origin",),
        protected_branches: tuple[str, ...] = ("main", "master", "develop", "release"),
        timeout_seconds: float = 60.0,
    ) -> None:
        self._workspace_root = workspace_root.expanduser().resolve()
        self._workspace_root.mkdir(parents=True, exist_ok=True)
        self._allowed_remotes = frozenset(allowed_remotes)
        self._protected = frozenset(protected_branches)
        self._timeout_seconds = timeout_seconds
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "repository"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Execute one fixed Git operation."""

        self._validate(action)
        workspace = self._workspace(action)
        if action.capability == "repository.branch.create":
            result = self._create_branch(action, workspace)
        elif action.capability == "repository.patch.apply":
            result = self._apply_patch(action, workspace)
        elif action.capability == "repository.commit.create":
            result = self._create_commit(action, workspace)
        elif action.capability == "repository.branch.push":
            result = self._push_branch(action, workspace)
        else:
            result = self._restore(action, workspace)
        if result.after is not None:
            self._last[action.target.resource_id] = deepcopy(dict(result.after))
        return result

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return last operation metadata."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify local/remote Git state after execution."""

        workspace = self._workspace(action)
        after = result.after or {}
        if action.capability == "repository.branch.push":
            remote = str(after.get("remote", ""))
            branch = str(after.get("branch", ""))
            local_hash = str(after.get("commit", ""))
            remote_hash = self._remote_branch_hash(workspace, remote, branch)
            observed = {"remote": remote, "branch": branch, "commit": remote_hash}
            verified = bool(remote_hash and remote_hash == local_hash)
        elif action.capability == "repository.patch.apply":
            observed = {
                "head": self._git(workspace, "rev-parse", "HEAD").stdout.strip(),
                "diff_sha256": hashlib.sha256(
                    self._git(workspace, "diff", "--binary").stdout.encode("utf-8")
                ).hexdigest(),
            }
            verified = observed["diff_sha256"] == after.get("diff_sha256")
        else:
            observed = {
                "branch": self._current_branch(workspace),
                "head": self._git(workspace, "rev-parse", "HEAD").stdout.strip(),
            }
            expected_head = after.get("commit") or after.get("head")
            expected_branch = after.get("branch")
            verified = (
                (not expected_head or observed["head"] == expected_head)
                and (not expected_branch or observed["branch"] == expected_branch)
            )
        return VerificationResult(
            action_id=action.action_id,
            verified=bool(verified),
            observed=observed,
            message=(
                "verified fixed Git operation"
                if verified
                else "Git state did not match approved operation"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Restore the exact local Git state captured before a reversible action."""

        if action.capability == "repository.branch.push":
            raise ConnectorError(
                "automatic remote compensation is unavailable; use bitbucket.branch.push"
            )
        if action.capability == "repository.worktree.restore":
            raise ConnectorError("restore actions are not recursively compensatable")
        workspace = self._workspace(action)
        before = result.before or {}
        previous_head = str(before.get("head", "")).strip()
        previous_branch = str(before.get("branch", "")).strip()
        if not previous_head:
            raise ConnectorError("Git compensation is missing the previous HEAD")
        current = {
            "head": self._head(workspace),
            "branch": self._current_branch(workspace),
        }
        self._git(workspace, "reset", "--hard", previous_head)
        if previous_branch and self._current_branch(workspace) != previous_branch:
            _branch(previous_branch, allow_protected=True)
            self._git(workspace, "switch", previous_branch)
        created_branch = (
            str((result.after or {}).get("branch", "")).strip()
            if action.capability == "repository.branch.create"
            else ""
        )
        if created_branch and created_branch != previous_branch:
            _branch(created_branch)
            self._git(workspace, "branch", "-D", created_branch)
        observed = {
            "head": self._head(workspace),
            "branch": self._current_branch(workspace),
            "worktree_clean": not bool(
                self._git(workspace, "status", "--porcelain").stdout.strip()
            ),
            "deleted_branch": created_branch or None,
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after=observed,
            connector_reference=str(workspace),
            message="restored local Git state captured before the action",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Verify the prior branch, HEAD, and clean worktree were restored."""

        prior = original.before or {}
        observed = compensation.after or {}
        verified = bool(
            observed.get("head") == prior.get("head")
            and observed.get("branch") == prior.get("branch")
            and observed.get("worktree_clean")
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified local Git rollback"
                if verified
                else "local Git rollback did not restore the prior state"
            ),
        )

    def _create_branch(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        branch = _branch(_required(action.parameters, "branch"))
        base = _branch(_required(action.parameters, "base"), allow_protected=True)
        if branch in self._protected:
            raise ConnectorError("cannot create a configured protected branch")
        self._require_clean(workspace)
        base_hash = self._git(workspace, "rev-parse", base).stdout.strip()
        if action.target.expected_version and action.target.expected_version != base_hash:
            raise VersionConflictError(
                f"repository base changed: expected {action.target.expected_version}, observed {base_hash}"
            )
        before = {"branch": self._current_branch(workspace), "head": self._head(workspace)}
        self._git(workspace, "switch", "-c", branch, base)
        after = {
            "branch": branch,
            "head": self._head(workspace),
            "base": base,
            "base_hash": base_hash,
            "compensation": {
                "capability": "repository.worktree.restore",
                "commit": before["head"],
                "branch": before["branch"],
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=str(workspace),
            message="local Git branch created",
        )

    def _apply_patch(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        expected_head = action.target.expected_version
        current_head = self._head(workspace)
        if expected_head and expected_head != current_head:
            raise VersionConflictError(
                f"repository HEAD changed: expected {expected_head}, observed {current_head}"
            )
        self._require_clean(workspace)
        patch_text = str(action.parameters.get("patch_text", ""))
        patch_path = str(action.parameters.get("patch_path", "")).strip()
        if bool(patch_text) == bool(patch_path):
            raise ConnectorError("exactly one of patch_text or patch_path is required")
        if patch_path:
            root_value = str(action.parameters.get("patch_root", "")).strip()
            if not root_value:
                raise ConnectorError("patch_path requires an explicit patch_root")
            root = Path(root_value).expanduser().resolve()
            path = Path(patch_path).expanduser().resolve()
            try:
                path.relative_to(root)
            except ValueError as error:
                raise ConnectorError("patch_path is outside patch_root") from error
            if not path.is_file():
                raise ConnectorError("patch_path is not a file")
            payload = path.read_bytes()
        else:
            payload = patch_text.encode("utf-8")
        if not payload or len(payload) > 5 * 1024 * 1024:
            raise ConnectorError("patch is empty or exceeds 5 MiB")
        before = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": self._diff_digest(workspace),
        }
        self._git_bytes(
            workspace,
            ("apply", "--check", "--whitespace=error-all", "-"),
            payload,
        )
        self._git_bytes(
            workspace,
            ("apply", "--whitespace=error-all", "-"),
            payload,
        )
        diff = self._git(workspace, "diff", "--binary").stdout
        after = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest(),
            "changed_files": tuple(
                line for line in self._git(workspace, "diff", "--name-only").stdout.splitlines() if line
            ),
            "compensation": {
                "capability": "repository.worktree.restore",
                "commit": current_head,
                "branch": self._current_branch(workspace),
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=str(workspace),
            message="approved patch applied to local worktree",
        )

    def _create_commit(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        current_head = self._head(workspace)
        if action.target.expected_version and action.target.expected_version != current_head:
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {current_head}"
            )
        message = _required(action.parameters, "message")
        paths = action.parameters.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ConnectorError("commit paths must be a non-empty list")
        normalized = tuple(_relative_path(str(item)) for item in paths)
        before = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": self._diff_digest(workspace),
        }
        self._git(workspace, "add", "--", *normalized)
        staged = self._git(workspace, "diff", "--cached", "--name-only").stdout.splitlines()
        if not staged:
            raise ConnectorError("no approved changes were staged for commit")
        self._git(workspace, "commit", "-m", message)
        commit = self._head(workspace)
        after = {
            "branch": self._current_branch(workspace),
            "commit": commit,
            "parent": current_head,
            "paths": tuple(staged),
            "compensation": {
                "capability": "repository.worktree.restore",
                "commit": current_head,
                "branch": self._current_branch(workspace),
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=f"git:{commit}",
            message="approved local Git commit created",
        )

    def _push_branch(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        remote = str(action.parameters.get("remote", "origin")).strip()
        if remote not in self._allowed_remotes:
            raise ConnectorError("Git remote is not allowlisted")
        branch = _branch(
            str(action.parameters.get("branch", self._current_branch(workspace)))
        )
        if branch in self._protected:
            raise ConnectorError("protected branch pushes are prohibited")
        if branch != self._current_branch(workspace):
            raise ConnectorError("only the current branch may be pushed")
        self._validate_remote_url(workspace, remote)
        commit = self._head(workspace)
        if action.target.expected_version and action.target.expected_version != commit:
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {commit}"
            )
        before_hash = self._remote_branch_hash(workspace, remote, branch)
        self._git(workspace, "push", "--set-upstream", remote, branch)
        after_hash = self._remote_branch_hash(workspace, remote, branch)
        if after_hash != commit:
            raise ConnectorError("remote branch did not resolve to the pushed commit")
        after = {
            "remote": remote,
            "branch": branch,
            "commit": commit,
            "previous_remote_commit": before_hash,
            "force": False,
            "compensation": {
                "kind": "open_revert_or_decline_pr",
                "automatic_remote_branch_delete_disabled": True,
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={"remote_commit": before_hash},
            after=after,
            connector_reference=f"git:{remote}/{branch}",
            message="approved branch pushed without force",
        )

    def _restore(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        commit = _required(action.parameters, "commit")
        branch = str(action.parameters.get("branch", "")).strip()
        current = {"head": self._head(workspace), "branch": self._current_branch(workspace)}
        if action.target.expected_version and action.target.expected_version != current["head"]:
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {current['head']}"
            )
        self._git(workspace, "rev-parse", "--verify", f"{commit}^{{commit}}")
        self._git(workspace, "reset", "--hard", commit)
        if branch:
            _branch(branch, allow_protected=True)
            self._git(workspace, "switch", branch)
        after = {"head": self._head(workspace), "branch": self._current_branch(workspace)}
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after=after,
            connector_reference=str(workspace),
            message="local worktree restored to approved commit",
        )

    def _workspace(self, action: AgentAction) -> Path:
        value = str(action.parameters.get("workspace", action.target.resource_id)).strip()
        path = Path(value)
        if path.is_absolute():
            resolved = path.expanduser().resolve()
        else:
            resolved = (self._workspace_root / path).resolve()
        try:
            resolved.relative_to(self._workspace_root)
        except ValueError as error:
            raise ConnectorError("Git workspace is outside workspace_root") from error
        if not (resolved / ".git").exists():
            raise ConnectorError("Git workspace does not contain a .git directory")
        return resolved

    def _git(self, workspace: Path, *args: str) -> GitCommandResult:
        return self._run(workspace, ("git", "-c", "credential.helper=", *args))

    def _git_bytes(
        self,
        workspace: Path,
        args: Sequence[str],
        payload: bytes,
    ) -> GitCommandResult:
        return self._run(
            workspace,
            ("git", "-c", "credential.helper=", *args),
            input_bytes=payload,
        )

    def _run(
        self,
        workspace: Path,
        argv: Sequence[str],
        *,
        input_bytes: bytes | None = None,
    ) -> GitCommandResult:
        try:
            completed = subprocess.run(
                list(argv),
                cwd=workspace,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout_seconds,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": os.environ.get("HOME", ""),
                    "SSH_AUTH_SOCK": os.environ.get("SSH_AUTH_SOCK", ""),
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_ASKPASS": "/bin/false",
                    "SSH_ASKPASS": "/bin/false",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ConnectorError(f"fixed Git operation failed: {type(error).__name__}") from error
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        if completed.returncode != 0:
            excerpt = " ".join(stderr.strip().split())[:500]
            raise ConnectorError(
                f"Git operation returned {completed.returncode}: {excerpt or 'no diagnostic'}"
            )
        return GitCommandResult(stdout=stdout, stderr=stderr, returncode=0)

    def _head(self, workspace: Path) -> str:
        return self._git(workspace, "rev-parse", "HEAD").stdout.strip()

    def _current_branch(self, workspace: Path) -> str:
        return self._git(workspace, "branch", "--show-current").stdout.strip()

    def _require_clean(self, workspace: Path) -> None:
        if self._git(workspace, "status", "--porcelain").stdout.strip():
            raise ConnectorError("Git workspace must be clean before branch creation")

    def _diff_digest(self, workspace: Path) -> str:
        return hashlib.sha256(
            self._git(workspace, "diff", "--binary").stdout.encode("utf-8")
        ).hexdigest()

    def _remote_branch_hash(self, workspace: Path, remote: str, branch: str) -> str | None:
        result = self._git(workspace, "ls-remote", "--heads", remote, branch).stdout.strip()
        if not result:
            return None
        return result.split()[0]

    def _validate_remote_url(self, workspace: Path, remote: str) -> None:
        url = self._git(workspace, "remote", "get-url", remote).stdout.strip()
        if not (
            url.startswith("https://")
            or url.startswith("ssh://")
            or re.match(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:", url)
            or url.startswith("file://")
            or Path(url).is_absolute()
        ):
            raise ConnectorError("Git remote URL scheme is not allowed")

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("Git workspace connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(f"unsupported Git capability: {action.capability}")
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("Git mutations must use reversible_write risk")


def _required(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip()
    if not value:
        raise ConnectorError(f"missing required parameter: {key}")
    return value


def _branch(value: str, *, allow_protected: bool = False) -> str:
    if (
        not _BRANCH_RE.fullmatch(value)
        or value.endswith("/")
        or ".." in value
        or "//" in value
        or value.startswith("-")
        or value.endswith(".lock")
        or "@{" in value
    ):
        raise ConnectorError("unsafe Git branch name")
    return value


def _relative_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ConnectorError("commit path must remain inside the workspace")
    return path.as_posix()
