"""Fixed-operation local Git connector for approved branch workflows."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any, Self

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
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_MAX_INDEX_BYTES = 128 * 1024 * 1024
_MAX_BLOB_BYTES = 128 * 1024 * 1024


class _LockedRepositoryIndex:
    """Hold Git's index and HEAD locks through atomic commit publication."""

    def __init__(self, workspace: Path, *, expected_branch: str) -> None:
        self._git_path = workspace / ".git"
        self._expected_head = f"ref: refs/heads/{expected_branch}\n".encode("ascii")
        self._directory_fd = -1
        self._lock_fd = -1
        self._head_fd = -1
        self._head_lock_fd = -1
        self._directory_identity: tuple[int, int] | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._head_identity: tuple[int, int] | None = None
        self._head_lock_identity: tuple[int, int] | None = None
        self._prepared = False
        self._installed = False

    def __enter__(self) -> Self:
        try:
            path_metadata = self._git_path.lstat()
            if not stat.S_ISDIR(path_metadata.st_mode):
                raise VersionConflictError("repository Git metadata changed")
            self._directory_fd = os.open(
                self._git_path,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            directory_metadata = os.fstat(self._directory_fd)
            if _identity(path_metadata) != _identity(directory_metadata):
                raise VersionConflictError("repository Git metadata changed")
            self._directory_identity = _identity(directory_metadata)
            self._lock_fd = os.open(
                "index.lock",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=self._directory_fd,
            )
            lock_metadata = os.fstat(self._lock_fd)
            self._lock_identity = _identity(lock_metadata)
            if not stat.S_ISREG(lock_metadata.st_mode):
                raise VersionConflictError("repository index lock is not a file")
            self._head_lock_fd = os.open(
                "HEAD.lock",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=self._directory_fd,
            )
            head_lock_metadata = os.fstat(self._head_lock_fd)
            self._head_lock_identity = _identity(head_lock_metadata)
            if not stat.S_ISREG(head_lock_metadata.st_mode):
                raise VersionConflictError("repository HEAD lock is not a file")
            self._head_fd = os.open(
                "HEAD",
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._directory_fd,
            )
            head_metadata = os.fstat(self._head_fd)
            self._head_identity = _identity(head_metadata)
            if (
                not stat.S_ISREG(head_metadata.st_mode)
                or head_metadata.st_size != len(self._expected_head)
                or _read_fd(self._head_fd, len(self._expected_head) + 1)
                != self._expected_head
            ):
                raise VersionConflictError(
                    "repository HEAD is not the approved symbolic branch"
                )
            return self
        except FileExistsError as error:
            self.close()
            raise VersionConflictError(
                "repository index is busy; commit creation is refused"
            ) from error
        except Exception:
            self.close()
            raise

    def __exit__(self, *_: object) -> None:
        self.close()

    def prepare_from(self, source: Path) -> None:
        """Copy a complete isolated index into the held standard lock file."""

        if self._lock_fd < 0:
            raise ConnectorError("repository index lock is unavailable")
        source_fd = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.ftruncate(self._lock_fd, 0)
            os.lseek(self._lock_fd, 0, os.SEEK_SET)
            self._copy_index(source_fd, self._lock_fd)
            os.fsync(self._lock_fd)
            self._prepared = True
        finally:
            os.close(source_fd)

    def seed_isolated(self, destination: Path) -> bool:
        """Copy the locked shared index so unrelated entries and flags survive."""

        if self._directory_fd < 0:
            raise ConnectorError("repository index lock is unavailable")
        try:
            source_fd = os.open(
                "index",
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._directory_fd,
            )
        except FileNotFoundError:
            return False
        destination_fd = -1
        try:
            destination_fd = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            self._copy_index(source_fd, destination_fd)
            os.fsync(destination_fd)
            return True
        finally:
            os.close(source_fd)
            if destination_fd >= 0:
                os.close(destination_fd)

    def install(self) -> None:
        """Atomically replace the shared index with the prepared reviewed index."""

        if not self._prepared:
            raise ConnectorError("reviewed Git index was not prepared")
        self._validate_paths()
        os.close(self._lock_fd)
        self._lock_fd = -1
        os.replace(
            "index.lock",
            "index",
            src_dir_fd=self._directory_fd,
            dst_dir_fd=self._directory_fd,
        )
        self._installed = True
        os.fsync(self._directory_fd)

    def validate_head(self) -> None:
        """Prove HEAD still names the exact branch pinned at lock acquisition."""

        if (
            self._head_fd < 0
            or self._head_identity is None
            or not self._path_is_ours("HEAD.lock", self._head_lock_identity)
        ):
            raise VersionConflictError("repository HEAD lock identity changed")
        try:
            metadata = os.stat(
                "HEAD",
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise VersionConflictError("repository HEAD changed") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or _identity(metadata) != self._head_identity
            or _read_fd(self._head_fd, len(self._expected_head) + 1)
            != self._expected_head
        ):
            raise VersionConflictError("repository HEAD changed")

    def close(self) -> None:
        """Release the lock without touching the original index on failure."""

        if self._head_fd >= 0:
            os.close(self._head_fd)
            self._head_fd = -1
        if self._head_lock_fd >= 0:
            os.close(self._head_lock_fd)
            self._head_lock_fd = -1
        if self._lock_fd >= 0:
            os.close(self._lock_fd)
            self._lock_fd = -1
        if self._directory_fd >= 0:
            if self._path_is_ours("HEAD.lock", self._head_lock_identity):
                try:
                    os.unlink("HEAD.lock", dir_fd=self._directory_fd)
                except FileNotFoundError:
                    pass
            if not self._installed and self._path_is_ours(
                "index.lock", self._lock_identity
            ):
                try:
                    os.unlink("index.lock", dir_fd=self._directory_fd)
                except FileNotFoundError:
                    pass
            os.close(self._directory_fd)
            self._directory_fd = -1

    def _validate_paths(self) -> None:
        try:
            metadata = self._git_path.lstat()
        except FileNotFoundError as error:
            raise VersionConflictError("repository Git metadata changed") from error
        if (
            self._directory_identity is None
            or _identity(metadata) != self._directory_identity
            or not self._path_is_ours("index.lock", self._lock_identity)
        ):
            raise VersionConflictError("repository index identity changed")
        self.validate_head()

    def _path_is_ours(
        self,
        name: str,
        identity: tuple[int, int] | None,
    ) -> bool:
        if self._directory_fd < 0 or identity is None:
            return False
        try:
            metadata = os.stat(
                name,
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        return _identity(metadata) == identity

    @staticmethod
    def _copy_index(source_fd: int, destination_fd: int) -> None:
        metadata = os.fstat(source_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_INDEX_BYTES
        ):
            raise ConnectorError("Git index is invalid or too large")
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ConnectorError("Git index ended unexpectedly")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise ConnectorError("Git index write failed")
                view = view[written:]
            remaining -= len(chunk)


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return (metadata.st_dev, metadata.st_ino)


def _read_fd(file_descriptor: int, maximum_bytes: int) -> bytes:
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    return os.read(file_descriptor, maximum_bytes)


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
        else:
            result = self._push_branch(action, workspace)
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
                    self._git_worktree(
                        workspace,
                        "diff",
                        "--no-textconv",
                        "--binary",
                        "--no-ext-diff",
                        "--ignore-submodules=all",
                    ).stdout_bytes
                ).hexdigest(),
                "worktree_status_sha256": self._status_digest(workspace),
            }
            verified = observed["diff_sha256"] == after.get("diff_sha256") and observed[
                "worktree_status_sha256"
            ] == after.get("worktree_status_sha256")
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
                "automatic remote compensation is unavailable; use a separately "
                "reviewed provider recovery"
            )
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
        expected_status = str(before.get("worktree_status_sha256", "")).strip()
        created_branch = ""
        if action.capability == "repository.branch.create":
            created_branch = self._compensate_branch_creation(
                workspace,
                result=result,
                previous_branch=previous_branch,
                previous_head=previous_head,
                expected_status=expected_status,
            )
        elif action.capability == "repository.patch.apply":
            payload = self._patch_payload(action)
            self._git_bytes(
                workspace,
                ("apply", "--reverse", "--check", "--whitespace=error-all", "-"),
                payload,
            )
            self._git_bytes(
                workspace,
                ("apply", "--reverse", "--whitespace=error-all", "-"),
                payload,
            )
        elif action.capability == "repository.commit.create":
            current_branch = self._current_branch(workspace)
            if not current_branch:
                raise ConnectorError(
                    "detached-HEAD commits require manual compensation"
                )
            _branch(current_branch, allow_protected=True)
            self._git(
                workspace,
                "update-ref",
                f"refs/heads/{current_branch}",
                previous_head,
                current["head"],
            )
            # Reset only the index to the compare-and-swapped ref. The worktree,
            # including any concurrent human edits, is deliberately preserved.
            self._git(workspace, "reset", "--mixed", "HEAD")
        else:  # pragma: no cover - all compensatable capabilities are enumerated.
            raise ConnectorError("automatic Git compensation is unavailable")

        observed_status = self._status_digest(workspace)
        if expected_status and observed_status != expected_status:
            raise VersionConflictError(
                "Git worktree changed during compensation; human content was preserved"
            )
        observed = {
            "head": self._head(workspace),
            "branch": self._current_branch(workspace),
            "worktree_status_sha256": observed_status,
            "worktree_clean": not bool(
                self._git_worktree(
                    workspace,
                    "status",
                    "--porcelain",
                    "--ignore-submodules=all",
                ).stdout.strip()
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
        expected_status = str(prior.get("worktree_status_sha256", "")).strip()
        verified = bool(
            observed.get("head") == prior.get("head")
            and observed.get("branch") == prior.get("branch")
            and (
                observed.get("worktree_status_sha256") == expected_status
                if expected_status
                else observed.get("worktree_clean")
            )
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

    def _compensate_branch_creation(
        self,
        workspace: Path,
        *,
        result: ExecutionResult,
        previous_branch: str,
        previous_head: str,
        expected_status: str,
    ) -> str:
        """Switch back and delete only the exact unchanged branch ref."""

        created_branch = str((result.after or {}).get("branch", "")).strip()
        created_head = str((result.after or {}).get("head", "")).strip()
        if not created_branch or not created_head or not previous_branch:
            raise ConnectorError("branch compensation metadata is incomplete")
        _branch(created_branch)
        _branch(previous_branch, allow_protected=True)
        if self._current_branch(workspace) != created_branch:
            raise VersionConflictError("created branch is no longer checked out")
        if self._head(workspace) != created_head:
            raise VersionConflictError("created branch advanced after creation")
        previous_ref = self._git(
            workspace,
            "rev-parse",
            f"refs/heads/{previous_branch}",
        ).stdout.strip()
        if previous_ref != previous_head:
            raise VersionConflictError("previous branch advanced after branch creation")
        self._git(workspace, "switch", previous_branch)
        if expected_status and self._status_digest(workspace) != expected_status:
            raise VersionConflictError(
                "Git worktree changed during compensation; created branch was retained"
            )
        self._git(
            workspace,
            "update-ref",
            "-d",
            f"refs/heads/{created_branch}",
            created_head,
        )
        return created_branch

    def _patch_payload(self, action: AgentAction) -> bytes:
        """Read and revalidate the exact approval-bound patch bytes."""

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
        if hashlib.sha256(payload).hexdigest() != expected_patch_digest:
            raise VersionConflictError("approved patch content digest does not match")
        return payload

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
            "worktree_status_sha256": self._status_digest(workspace),
        }
        self._git(workspace, "switch", "-c", branch, base)
        post_status = self._status_digest(workspace)
        after = {
            "branch": branch,
            "head": self._head(workspace),
            "base": base,
            "base_hash": base_hash,
            "worktree_status_sha256": post_status,
            "compensation": _in_process_compensation("restore_local_branch_state"),
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
        payload = self._patch_payload(action)
        before = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": self._diff_digest(workspace),
            "worktree_status_sha256": self._status_digest(workspace),
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
        diff = self._git_worktree(
            workspace,
            "diff",
            "--no-textconv",
            "--binary",
            "--no-ext-diff",
            "--ignore-submodules=all",
        ).stdout_bytes
        post_status = self._status_digest(workspace)
        after = {
            "head": current_head,
            "branch": self._current_branch(workspace),
            "diff_sha256": hashlib.sha256(diff).hexdigest(),
            "worktree_status_sha256": post_status,
            "changed_files": tuple(
                line
                for line in self._git_worktree(
                    workspace,
                    "diff",
                    "--no-textconv",
                    "--no-ext-diff",
                    "--ignore-submodules=all",
                    "--name-only",
                ).stdout.splitlines()
                if line
            ),
            "compensation": _in_process_compensation("reverse_approved_local_patch"),
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
        if (
            not isinstance(paths, Sequence)
            or isinstance(paths, (str, bytes))
            or not paths
        ):
            raise ConnectorError("commit paths must be a non-empty list")
        normalized = tuple(_relative_path(str(item)) for item in paths)
        if len(normalized) != len(set(normalized)):
            raise ConnectorError("commit paths must be unique")
        branch = self._current_branch(workspace)
        if not branch:
            raise ConnectorError("commit creation requires a checked-out branch")
        _branch(branch, allow_protected=True)
        expected_diff_digest = _sha256_parameter(
            action.parameters,
            "expected_diff_sha256",
        )
        with self._sandbox.lock_repository_config(workspace) as config_guard:
            self._sandbox.validate_repository_config(workspace)
            config_guard.validate()
            if self._git(
                workspace,
                "diff",
                "--no-textconv",
                "--no-ext-diff",
                "--cached",
                "--name-only",
                current_head,
                "--",
            ).stdout.strip():
                raise ConnectorError(
                    "repository index contains pre-existing staged changes"
                )
            self._sandbox.reject_path_filters(workspace, normalized)
            before = {
                "head": current_head,
                "branch": branch,
                "diff_sha256": expected_diff_digest,
                "worktree_status_sha256": self._status_digest(workspace),
            }
            with _LockedRepositoryIndex(
                workspace,
                expected_branch=branch,
            ) as shared_index:
                if (
                    self._head(workspace) != current_head
                    or self._current_branch(workspace) != branch
                ):
                    raise VersionConflictError(
                        "repository branch or HEAD changed before commit isolation"
                    )
                if self._git(
                    workspace,
                    "diff",
                    "--no-textconv",
                    "--no-ext-diff",
                    "--cached",
                    "--name-only",
                    current_head,
                    "--",
                ).stdout.strip():
                    raise VersionConflictError(
                        "repository index changed before the commit lock was acquired"
                    )
                with self._sandbox.isolated_index() as isolated_index:
                    if not shared_index.seed_isolated(isolated_index):
                        self._git_index(
                            workspace,
                            isolated_index,
                            "read-tree",
                            current_head,
                        )
                    self._stage_raw_paths(
                        workspace,
                        isolated_index,
                        normalized,
                    )
                    staged = self._git_index(
                        workspace,
                        isolated_index,
                        "diff",
                        "--no-textconv",
                        "--no-ext-diff",
                        "--cached",
                        "--name-only",
                        current_head,
                        "--",
                    ).stdout.splitlines()
                    if not staged:
                        raise ConnectorError(
                            "no approved changes were staged for commit"
                        )
                    if set(staged) != set(normalized):
                        raise ConnectorError(
                            "staged paths differ from the exact approved path set"
                        )
                    observed_diff_digest = hashlib.sha256(
                        self._git_index(
                            workspace,
                            isolated_index,
                            "diff",
                            "--no-textconv",
                            "--cached",
                            "--binary",
                            "--no-ext-diff",
                            current_head,
                            "--",
                        ).stdout_bytes
                    ).hexdigest()
                    if observed_diff_digest != expected_diff_digest:
                        raise VersionConflictError(
                            "staged content differs from the approved diff digest"
                        )
                    tree = self._git_index(
                        workspace,
                        isolated_index,
                        "write-tree",
                    ).stdout.strip()
                    commit = self._git(
                        workspace,
                        "commit-tree",
                        tree,
                        "-p",
                        current_head,
                        "-m",
                        message,
                    ).stdout.strip()
                    observed_tree = self._git(
                        workspace,
                        "rev-parse",
                        "--verify",
                        f"{commit}^{{tree}}",
                    ).stdout.strip()
                    if observed_tree != tree:
                        raise ConnectorError(
                            "created Git commit does not contain the approved tree"
                        )
                    shared_index.prepare_from(isolated_index)

                if (
                    self._head(workspace) != current_head
                    or self._current_branch(workspace) != branch
                ):
                    raise VersionConflictError(
                        "repository branch or HEAD changed before commit publication"
                    )
                config_guard.validate()
                shared_index.validate_head()
                reflog_reason = f"commit: {message.splitlines()[0]}"
                with self._sandbox.isolated_ref_transaction_repository(
                    workspace,
                    branch=branch,
                ) as ref_transaction:
                    published_record = (current_head, commit, reflog_reason)
                    try:
                        self._git_ref_transaction(
                            ref_transaction.git_dir,
                            reflog_reason,
                            f"refs/heads/{branch}",
                            commit,
                            current_head,
                        )
                    except ConnectorError as error:
                        raise VersionConflictError(
                            "repository branch advanced before commit publication"
                        ) from error
                    try:
                        ref_transaction.validate_records((published_record,))
                        config_guard.validate()
                        shared_index.validate_head()
                        shared_index.install()
                    except (ConnectorError, VersionConflictError) as error:
                        try:
                            self._git_ref_transaction(
                                ref_transaction.git_dir,
                                "rollback: repository metadata changed",
                                f"refs/heads/{branch}",
                                current_head,
                                commit,
                            )
                            ref_transaction.validate_records(
                                (
                                    published_record,
                                    (
                                        commit,
                                        current_head,
                                        "rollback: repository metadata changed",
                                    ),
                                )
                            )
                        except ConnectorError as rollback_error:
                            raise ConnectorError(
                                "repository metadata changed and branch restoration "
                                "could not be confirmed"
                            ) from rollback_error
                        raise VersionConflictError(
                            "repository metadata changed; commit publication was rolled back"
                        ) from error

            post_status = self._status_digest(workspace)
            config_guard.validate()

        after = {
            "branch": self._current_branch(workspace),
            "commit": commit,
            "parent": current_head,
            "paths": tuple(staged),
            "diff_sha256": observed_diff_digest,
            "worktree_status_sha256": post_status,
            "compensation": _in_process_compensation("restore_local_commit_ref"),
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

    def _stage_raw_paths(
        self,
        workspace: Path,
        isolated_index: Path,
        paths: Sequence[str],
    ) -> None:
        """Stage exact raw file bytes without repository-controlled conversions."""

        for relative in paths:
            existing = self._git_index(
                workspace,
                isolated_index,
                "ls-files",
                "--stage",
                "--",
                relative,
            ).stdout.strip()
            opened = _read_workspace_regular_file(workspace, relative)
            if opened is None:
                if not existing:
                    raise ConnectorError(
                        "approved commit path is neither tracked nor a regular file"
                    )
                self._git_index(
                    workspace,
                    isolated_index,
                    "update-index",
                    "--force-remove",
                    "--",
                    relative,
                )
                continue
            payload, file_mode = opened
            mode = (
                existing.split(maxsplit=1)[0]
                if existing
                else ("100755" if file_mode & stat.S_IXUSR else "100644")
            )
            blob = self._git_bytes(
                workspace,
                ("hash-object", "--no-filters", "-w", "--stdin"),
                payload,
            ).stdout.strip()
            self._git_index(
                workspace,
                isolated_index,
                "update-index",
                "--add",
                "--cacheinfo",
                mode,
                blob,
                relative,
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
        commit = self._head(workspace)
        if not action.target.expected_version:
            raise ConnectorError("branch push requires an approved commit hash")
        if action.target.expected_version != commit:
            raise VersionConflictError(
                f"repository HEAD changed: expected {action.target.expected_version}, observed {commit}"
            )
        with self._sandbox.lock_repository_config(workspace) as config_guard:
            self._sandbox.validate_repository_config(workspace)
            remote_url = self._approved_remote_url(action, workspace, remote)
            config_guard.validate()
            with self._sandbox.isolated_publication_repository(
                workspace
            ) as publication_repository:
                before_hash = self._remote_branch_hash_from(
                    publication_repository,
                    remote_url,
                    branch,
                )
                config_guard.validate()
                self._git_publication(
                    publication_repository,
                    "push",
                    remote_url,
                    f"{commit}:refs/heads/{branch}",
                )
                config_guard.validate()
                after_hash = self._remote_branch_hash_from(
                    publication_repository,
                    remote_url,
                    branch,
                )
            config_guard.validate()
        if after_hash != commit:
            raise ConnectorError("remote branch did not resolve to the pushed commit")
        after = {
            "remote": remote,
            "remote_url": remote_url,
            "branch": branch,
            "commit": commit,
            "previous_remote_commit": before_hash,
            "force": False,
            "compensation": CompensationDescriptor(
                kind="review_remote_branch_recovery",
                mode=CompensationMode.MANUAL,
                reason=(
                    "remote branch rollback is manual because rewriting or deleting "
                    "a published ref could destroy concurrent work"
                ),
            ).to_dict(),
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

    def _git_index(
        self,
        workspace: Path,
        index_file: Path,
        *args: str,
    ) -> SandboxedGitResult:
        return self._run(workspace, args, index_file=index_file)

    def _git_worktree(
        self,
        workspace: Path,
        *args: str,
    ) -> SandboxedGitResult:
        head = self._head(workspace)
        with self._sandbox.isolated_worktree_snapshot(
            workspace,
            head=head,
        ) as snapshot:
            return self._sandbox.run(
                snapshot.git_dir,
                args,
                index_file=snapshot.index_file,
                worktree=workspace,
            )

    def _git_publication(
        self,
        repository: Path,
        *args: str,
    ) -> SandboxedGitResult:
        return self._sandbox.run(
            repository,
            args,
            bare_repository=True,
        )

    def _git_ref_transaction(
        self,
        git_dir: Path,
        reason: str,
        ref: str,
        new_oid: str,
        old_oid: str,
    ) -> SandboxedGitResult:
        return self._sandbox.run(
            git_dir,
            (
                "--git-dir",
                str(git_dir),
                "-c",
                "core.logAllRefUpdates=true",
                "update-ref",
                "-m",
                reason,
                ref,
                new_oid,
                old_oid,
            ),
            bare_repository=True,
        )

    def _run(
        self,
        workspace: Path,
        argv: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        index_file: Path | None = None,
    ) -> SandboxedGitResult:
        return self._sandbox.run(
            workspace,
            argv,
            input_bytes=input_bytes,
            index_file=index_file,
        )

    def _head(self, workspace: Path) -> str:
        return self._git(workspace, "rev-parse", "HEAD").stdout.strip()

    def _current_branch(self, workspace: Path) -> str:
        return self._git(workspace, "branch", "--show-current").stdout.strip()

    def _require_clean(self, workspace: Path) -> None:
        if self._git_worktree(
            workspace,
            "status",
            "--porcelain",
            "--ignore-submodules=all",
        ).stdout.strip():
            raise ConnectorError("Git workspace must be clean before branch creation")

    def _diff_digest(self, workspace: Path) -> str:
        return hashlib.sha256(
            self._git_worktree(
                workspace,
                "diff",
                "--no-textconv",
                "--binary",
                "--no-ext-diff",
                "--ignore-submodules=all",
            ).stdout_bytes
        ).hexdigest()

    def _status_digest(self, workspace: Path) -> str:
        return hashlib.sha256(
            self._git_worktree(
                workspace,
                "status",
                "--porcelain=v1",
                "--ignore-submodules=all",
            ).stdout_bytes
        ).hexdigest()

    def _remote_branch_hash(
        self, workspace: Path, remote_url: str, branch: str
    ) -> str | None:
        with self._sandbox.isolated_publication_repository(
            workspace
        ) as publication_repository:
            return self._remote_branch_hash_from(
                publication_repository,
                remote_url,
                branch,
            )

    def _remote_branch_hash_from(
        self,
        publication_repository: Path,
        remote_url: str,
        branch: str,
    ) -> str | None:
        result = self._git_publication(
            publication_repository,
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


def _in_process_compensation(kind: str) -> dict[str, Any]:
    """Describe rollback that is safe only inside the verified connector flow."""

    return CompensationDescriptor(
        kind=kind,
        mode=CompensationMode.IN_PROCESS,
        reason=(
            "local Git rollback is available only through verified in-process "
            "compensation; destructive standalone worktree restore is disabled"
        ),
    ).to_dict()


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
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path == Path(".")
        or any(part.casefold() == ".git" for part in path.parts)
        or any(character in value for character in ("\n", "\r", "\0"))
    ):
        raise ConnectorError("commit path must remain inside the workspace")
    return path.as_posix()


def _read_workspace_regular_file(
    workspace: Path,
    relative: str,
) -> tuple[bytes, int] | None:
    """Safe-open and snapshot one regular workspace file without following links."""

    root_metadata = workspace.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise VersionConflictError("repository workspace identity changed")
    root_fd = os.open(
        workspace,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    directory_fds = [root_fd]
    directory_chain: list[tuple[int, str, tuple[int, int]]] = []
    file_fd = -1
    try:
        if _identity(os.fstat(root_fd)) != _identity(root_metadata):
            raise VersionConflictError("repository workspace identity changed")
        parts = Path(relative).parts
        current_fd = root_fd
        for part in parts[:-1]:
            child_fd = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current_fd,
            )
            child_metadata = os.fstat(child_fd)
            if not stat.S_ISDIR(child_metadata.st_mode):
                raise ConnectorError("approved commit path parent is not a directory")
            directory_chain.append((current_fd, part, _identity(child_metadata)))
            directory_fds.append(child_fd)
            current_fd = child_fd
        try:
            file_fd = os.open(
                parts[-1],
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current_fd,
            )
        except FileNotFoundError:
            return None
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_BLOB_BYTES:
            raise ConnectorError(
                "approved commit paths must be bounded regular files or tracked deletions"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise VersionConflictError(
                    "approved commit path changed while being read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise VersionConflictError("approved commit path changed while being read")
        after = os.fstat(file_fd)
        if (
            _identity(after) != _identity(before)
            or after.st_mode != before.st_mode
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or _identity(workspace.lstat()) != _identity(root_metadata)
        ):
            raise VersionConflictError("approved commit path changed while being read")
        for parent_fd, name, identity in directory_chain:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode) or _identity(metadata) != identity:
                raise VersionConflictError("approved commit path parent changed")
        return b"".join(chunks), before.st_mode
    except OSError as error:
        raise ConnectorError(
            "approved commit path could not be safely opened"
        ) from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _sha256_parameter(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ConnectorError(f"{key} must be an approved SHA-256 digest")
    return value
