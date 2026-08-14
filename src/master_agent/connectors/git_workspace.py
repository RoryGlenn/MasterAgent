"""Fixed-operation local Git connector for approved branch workflows."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from master_agent.connectors.base import CompensatingConnector
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
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")


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
        allow_file_remotes: bool = False,
    ) -> None:
        self._workspace_root = workspace_root.expanduser().resolve()
        self._workspace_root.mkdir(parents=True, exist_ok=True)
        self._allowed_remotes = frozenset(allowed_remotes)
        self._protected = frozenset(protected_branches)
        self._allow_file_remotes = allow_file_remotes
        self._sandbox = GitSandbox(
            timeout_seconds=timeout_seconds,
            allow_file_protocol=allow_file_remotes,
        )
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
        self._sandbox.validate_repository_config(workspace)
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
        self._sandbox.validate_repository_config(workspace)
        after = result.after or {}
        if action.capability == "repository.branch.push":
            remote = str(after.get("remote", ""))
            remote_url = validate_remote_url(
                str(after.get("remote_url", "")),
                allow_file=self._allow_file_remotes,
            )
            branch = str(after.get("branch", ""))
            local_hash = str(after.get("commit", ""))
            remote_hash = self._remote_branch_hash(workspace, remote_url, branch)
            observed = {"remote": remote, "branch": branch, "commit": remote_hash}
            verified = bool(remote_hash and remote_hash == local_hash)
        elif action.capability == "repository.patch.apply":
            observed = {
                "head": self._git(workspace, "rev-parse", "HEAD").stdout.strip(),
                "diff_sha256": hashlib.sha256(
                    self._git(
                        workspace,
                        "diff",
                        "--binary",
                        "--no-ext-diff",
                    ).stdout.encode("utf-8")
                ).hexdigest(),
                "worktree_status_sha256": self._status_digest(workspace),
            }
            verified = (
                observed["diff_sha256"] == after.get("diff_sha256")
                and observed["worktree_status_sha256"]
                == after.get("worktree_status_sha256")
            )
        else:
            observed = {
                "branch": self._current_branch(workspace),
                "head": self._git(workspace, "rev-parse", "HEAD").stdout.strip(),
                "worktree_status_sha256": self._status_digest(workspace),
            }
            expected_head = after.get("commit") or after.get("head")
            expected_branch = after.get("branch")
            verified = (
                (not expected_head or observed["head"] == expected_head)
                and (not expected_branch or observed["branch"] == expected_branch)
                and (
                    not after.get("worktree_status_sha256")
                    or observed["worktree_status_sha256"]
                    == after.get("worktree_status_sha256")
                )
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
        if not self.verify(action, result).verified:
            raise VersionConflictError(
                "Git state changed after execution; automatic compensation is refused"
            )
        workspace = self._workspace(action)
        self._sandbox.validate_repository_config(workspace)
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
        if (
            action.target.expected_version
            and action.target.expected_version != base_hash
        ):
            raise VersionConflictError(
                f"repository base changed: expected {action.target.expected_version}, observed {base_hash}"
            )
        before = {
            "branch": self._current_branch(workspace),
            "head": self._head(workspace),
        }
        self._git(workspace, "switch", "-c", branch, base)
        post_status = self._status_digest(workspace)
        after = {
            "branch": branch,
            "head": self._head(workspace),
            "base": base,
            "base_hash": base_hash,
            "worktree_status_sha256": post_status,
            "compensation": {
                "capability": "repository.worktree.restore",
                "commit": before["head"],
                "branch": before["branch"],
                "expected_version": base_hash,
                "expected_worktree_status_sha256": post_status,
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=str(workspace),
            message="local Git branch created",
            compensation=_compensation_descriptor(after),
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
        expected_patch_digest = _sha256_parameter(action.parameters, "patch_sha256")
        observed_patch_digest = hashlib.sha256(payload).hexdigest()
        if observed_patch_digest != expected_patch_digest:
            raise VersionConflictError("approved patch content digest does not match")
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
        post_status = self._status_digest(workspace)
        after = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest(),
            "worktree_status_sha256": post_status,
            "changed_files": tuple(
                line
                for line in self._git(
                    workspace, "diff", "--name-only"
                ).stdout.splitlines()
                if line
            ),
            "compensation": {
                "capability": "repository.worktree.restore",
                "commit": current_head,
                "branch": self._current_branch(workspace),
                "expected_version": current_head,
                "expected_worktree_status_sha256": post_status,
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=str(workspace),
            message="approved patch applied to local worktree",
            compensation=_compensation_descriptor(after),
        )

    def _create_commit(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        current_head = self._head(workspace)
        if not action.target.expected_version:
            raise ConnectorError("commit creation requires an approved repository HEAD")
        if action.target.expected_version != current_head:
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {current_head}"
            )
        message = _required(action.parameters, "message")
        paths = action.parameters.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ConnectorError("commit paths must be a non-empty list")
        normalized = tuple(_relative_path(str(item)) for item in paths)
        if len(normalized) != len(set(normalized)):
            raise ConnectorError("commit paths must be unique")
        if self._git(workspace, "diff", "--cached", "--name-only").stdout.strip():
            raise ConnectorError(
                "repository index contains pre-existing staged changes"
            )
        self._sandbox.reject_path_filters(workspace, normalized)
        expected_diff_digest = _sha256_parameter(
            action.parameters,
            "expected_diff_sha256",
        )
        before = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": self._diff_digest(workspace),
        }
        self._git(workspace, "add", "--", *normalized)
        try:
            staged = self._git(
                workspace,
                "diff",
                "--cached",
                "--name-only",
            ).stdout.splitlines()
            if not staged:
                raise ConnectorError("no approved changes were staged for commit")
            if set(staged) != set(normalized):
                raise ConnectorError(
                    "staged paths differ from the exact approved path set"
                )
            observed_diff_digest = hashlib.sha256(
                self._git(
                    workspace,
                    "diff",
                    "--cached",
                    "--binary",
                    "--no-ext-diff",
                ).stdout.encode("utf-8")
            ).hexdigest()
            if observed_diff_digest != expected_diff_digest:
                raise VersionConflictError(
                    "staged content differs from the approved diff digest"
                )
            self._git(
                workspace,
                "commit",
                "--no-verify",
                "--no-gpg-sign",
                "-m",
                message,
            )
        except Exception:
            # Restore the previously empty index while preserving reviewed
            # worktree content for operator inspection.
            self._git(workspace, "reset", "--mixed", current_head)
            raise
        commit = self._head(workspace)
        post_status = self._status_digest(workspace)
        after = {
            "branch": self._current_branch(workspace),
            "commit": commit,
            "parent": current_head,
            "paths": tuple(staged),
            "diff_sha256": observed_diff_digest,
            "worktree_status_sha256": post_status,
            "compensation": {
                "capability": "repository.worktree.restore",
                "commit": current_head,
                "branch": self._current_branch(workspace),
                "expected_version": commit,
                "expected_worktree_status_sha256": post_status,
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=f"git:{commit}",
            message="approved local Git commit created",
            compensation=_compensation_descriptor(after),
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
        remote_url = self._approved_remote_url(action, workspace, remote)
        commit = self._head(workspace)
        if not action.target.expected_version:
            raise ConnectorError("branch push requires an approved commit hash")
        if action.target.expected_version != commit:
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {commit}"
            )
        before_hash = self._remote_branch_hash(workspace, remote_url, branch)
        self._git(
            workspace,
            "push",
            remote_url,
            f"refs/heads/{branch}:refs/heads/{branch}",
        )
        after_hash = self._remote_branch_hash(workspace, remote_url, branch)
        if after_hash != commit:
            raise ConnectorError("remote branch did not resolve to the pushed commit")
        after = {
            "remote": remote,
            "remote_url": remote_url,
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
            compensation=_compensation_descriptor(after),
        )

    def _restore(self, action: AgentAction, workspace: Path) -> ExecutionResult:
        commit = _required(action.parameters, "commit")
        branch = str(action.parameters.get("branch", "")).strip()
        current = {
            "head": self._head(workspace),
            "branch": self._current_branch(workspace),
        }
        if (
            action.target.expected_version
            and action.target.expected_version != current["head"]
        ):
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {current['head']}"
            )
        expected_status = str(
            action.parameters.get("expected_worktree_status_sha256", "")
        ).strip()
        if expected_status and expected_status != self._status_digest(workspace):
            raise VersionConflictError(
                "repository worktree changed after approval; restore is prohibited"
            )
        self._git(workspace, "rev-parse", "--verify", f"{commit}^{{commit}}")
        self._git(workspace, "reset", "--hard", commit)
        if branch:
            _branch(branch, allow_protected=True)
            self._git(workspace, "switch", branch)
        after = {
            "head": self._head(workspace),
            "branch": self._current_branch(workspace),
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after=after,
            connector_reference=str(workspace),
            message="local worktree restored to approved commit",
        )

    def _workspace(self, action: AgentAction) -> Path:
        value = str(
            action.parameters.get("workspace", action.target.resource_id)
        ).strip()
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

    def _git(self, workspace: Path, *args: str) -> SandboxedGitResult:
        return self._run(workspace, args)

    def _git_bytes(
        self,
        workspace: Path,
        args: Sequence[str],
        payload: bytes,
    ) -> SandboxedGitResult:
        return self._run(workspace, args, input_bytes=payload)

    def _run(
        self,
        workspace: Path,
        argv: Sequence[str],
        *,
        input_bytes: bytes | None = None,
    ) -> SandboxedGitResult:
        return self._sandbox.run(workspace, argv, input_bytes=input_bytes)

    def _head(self, workspace: Path) -> str:
        return self._git(workspace, "rev-parse", "HEAD").stdout.strip()

    def _current_branch(self, workspace: Path) -> str:
        return self._git(workspace, "branch", "--show-current").stdout.strip()

    def _require_clean(self, workspace: Path) -> None:
        if self._git(workspace, "status", "--porcelain").stdout.strip():
            raise ConnectorError("Git workspace must be clean before branch creation")

    def _diff_digest(self, workspace: Path) -> str:
        return hashlib.sha256(
            self._git(
                workspace,
                "diff",
                "--binary",
                "--no-ext-diff",
            ).stdout.encode("utf-8")
        ).hexdigest()

    def _status_digest(self, workspace: Path) -> str:
        return hashlib.sha256(
            self._git(workspace, "status", "--porcelain=v1").stdout.encode(
                "utf-8"
            )
        ).hexdigest()

    def _remote_branch_hash(
        self, workspace: Path, remote_url: str, branch: str
    ) -> str | None:
        result = self._git(
            workspace,
            "ls-remote",
            "--heads",
            remote_url,
            f"refs/heads/{branch}",
        ).stdout.strip()
        if not result:
            return None
        return result.split()[0]

    def _approved_remote_url(
        self,
        action: AgentAction,
        workspace: Path,
        remote: str,
    ) -> str:
        approved = validate_remote_url(
            _required(action.parameters, "remote_url"),
            allow_file=self._allow_file_remotes,
        )
        observed = validate_remote_url(
            self._git(workspace, "remote", "get-url", remote).stdout.strip(),
            allow_file=self._allow_file_remotes,
        )
        if observed != approved:
            raise VersionConflictError("Git remote URL changed since approval")
        return approved

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("Git workspace connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(f"unsupported Git capability: {action.capability}")
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("Git mutations must use reversible_write risk")


def _compensation_descriptor(after: Mapping[str, Any]) -> dict[str, Any]:
    raw = after.get("compensation")
    if not isinstance(raw, Mapping):
        raise ConnectorError("Git result omitted typed compensation metadata")
    return CompensationDescriptor.from_dict(raw).to_dict()


def _required(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip()
    if not value:
        raise ConnectorError(f"missing required parameter: {key}")
    return value


def _branch(value: str, *, allow_protected: bool = False) -> str:
    if (
        not _BRANCH_RE.fullmatch(value)
        or value.endswith(("/", ".lock"))
        or ".." in value
        or "//" in value
        or value.startswith("-")
        or "@{" in value
    ):
        raise ConnectorError("unsafe Git branch name")
    return value


def _relative_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ConnectorError("commit path must remain inside the workspace")
    return path.as_posix()


def _sha256_parameter(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ConnectorError(f"{key} must be an approved SHA-256 digest")
    return value
