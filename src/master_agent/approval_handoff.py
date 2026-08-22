"""Private, resumable handoffs for approval-gated applied runs.

Approval requests are review artifacts, never authority.  They retain the exact
non-secret invocation needed to retry one already-bound plan, while the normal
plan fingerprint, authenticated approval, execution-context, policy, and
provider gates remain authoritative at resume time.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Self
from uuid import UUID

from master_agent.directory_safety import PinnedDirectory, pin_directory
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import AgentAction, ChangePlan, ExecutionContext
from master_agent.platform_runtime import (
    PlatformContract,
    get_atomic_publication_recovery_backend,
    get_secure_filesystem_backend,
    require_persistent_state_platform,
    require_platform_contract,
)

_SCHEMA = "master-agent/approval-request@1"
_MAX_REQUEST_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ApprovalRunInvocation:
    """The complete non-secret CLI selection needed to retry an applied run."""

    plan_path: str
    approval_paths: tuple[str, ...]
    approval_authorities: str
    database: str
    connector_mode: str
    integrations: str | None
    result_json: str | None
    retention: str | None
    evidence_type: str
    identities: str | None
    include_writes: bool
    include_communications: bool
    workspace_root: str | None
    draft_output_dir: str
    capabilities: str | None
    governance: str | None
    policy: str | None
    sources_of_truth: str | None
    plugin_names: tuple[str, ...]
    plugin_lock: str | None
    credentials_file: str | None
    credential_mappings: tuple[str, ...]
    connector_urls: tuple[str, ...]
    organization_profile: str | None = None

    def __post_init__(self) -> None:
        if self.connector_mode not in {"mock", "live"}:
            raise ValidationError(
                "approval request connector mode must be mock or live"
            )
        if not isinstance(self.include_writes, bool) or not isinstance(
            self.include_communications, bool
        ):
            raise ValidationError("approval request connector gates must be booleans")
        for name, value in (
            ("plan_path", self.plan_path),
            ("approval_authorities", self.approval_authorities),
            ("database", self.database),
            ("draft_output_dir", self.draft_output_dir),
        ):
            _validate_absolute_path(value, name)
        for name, optional_value in (
            ("integrations", self.integrations),
            ("result_json", self.result_json),
            ("retention", self.retention),
            ("identities", self.identities),
            ("workspace_root", self.workspace_root),
            ("capabilities", self.capabilities),
            ("governance", self.governance),
            ("policy", self.policy),
            ("sources_of_truth", self.sources_of_truth),
            ("plugin_lock", self.plugin_lock),
            ("credentials_file", self.credentials_file),
            ("organization_profile", self.organization_profile),
        ):
            if optional_value is not None:
                _validate_absolute_path(optional_value, name)
        for path in self.approval_paths:
            _validate_absolute_path(path, "approval_paths")
        if not self.evidence_type.strip():
            raise ValidationError("approval request evidence type must not be empty")
        for name, values in (
            ("plugin_names", self.plugin_names),
            ("credential_mappings", self.credential_mappings),
            ("connector_urls", self.connector_urls),
        ):
            for value in values:
                _validate_text(value, name)
        if len(set(self.approval_paths)) != len(self.approval_paths):
            raise ValidationError("approval request approval paths must be unique")

    @classmethod
    def capture(
        cls,
        *,
        plan_path: Path,
        approval_paths: Sequence[Path],
        approval_authorities: Path,
        database: Path,
        connector_mode: str,
        integrations: Path | None,
        result_json: Path | None,
        retention: Path | None,
        evidence_type: str,
        identities: Path | None,
        include_writes: bool,
        include_communications: bool,
        workspace_root: Path | None,
        draft_output_dir: Path,
        capabilities: Path | None,
        governance: Path | None,
        policy: Path | None,
        sources_of_truth: Path | None,
        plugin_names: Sequence[str],
        plugin_lock: Path | None,
        credentials_file: Path | None,
        credential_mappings: Sequence[str],
        connector_urls: Sequence[str],
        organization_profile: Path | None = None,
    ) -> Self:
        """Capture path spellings independently of the caller's future CWD."""

        return cls(
            plan_path=_canonical_path(plan_path),
            approval_paths=tuple(
                dict.fromkeys(_canonical_path(path) for path in approval_paths)
            ),
            approval_authorities=_canonical_path(approval_authorities),
            database=_canonical_path(database),
            connector_mode=connector_mode,
            integrations=_canonical_optional_path(integrations),
            result_json=_canonical_optional_path(result_json),
            retention=_canonical_optional_path(retention),
            evidence_type=evidence_type,
            identities=_canonical_optional_path(identities),
            include_writes=include_writes,
            include_communications=include_communications,
            workspace_root=_canonical_optional_path(workspace_root),
            draft_output_dir=_canonical_path(draft_output_dir),
            capabilities=_canonical_optional_path(capabilities),
            governance=_canonical_optional_path(governance),
            policy=_canonical_optional_path(policy),
            sources_of_truth=_canonical_optional_path(sources_of_truth),
            plugin_names=tuple(plugin_names),
            plugin_lock=_canonical_optional_path(plugin_lock),
            credentials_file=_canonical_optional_path(credentials_file),
            credential_mappings=tuple(credential_mappings),
            connector_urls=tuple(connector_urls),
            organization_profile=_canonical_optional_path(organization_profile),
        )

    def with_approvals(self, paths: Sequence[Path]) -> Self:
        """Carry existing approvals into a later dual-approval handoff."""

        combined = tuple(
            dict.fromkeys(
                (*self.approval_paths, *(_canonical_path(path) for path in paths))
            )
        )
        return replace(self, approval_paths=combined)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible, secret-free invocation."""

        payload: dict[str, object] = {
            "plan_path": self.plan_path,
            "approval_paths": list(self.approval_paths),
            "approval_authorities": self.approval_authorities,
            "database": self.database,
            "connector_mode": self.connector_mode,
            "integrations": self.integrations,
            "result_json": self.result_json,
            "retention": self.retention,
            "evidence_type": self.evidence_type,
            "identities": self.identities,
            "include_writes": self.include_writes,
            "include_communications": self.include_communications,
            "workspace_root": self.workspace_root,
            "draft_output_dir": self.draft_output_dir,
            "capabilities": self.capabilities,
            "governance": self.governance,
            "policy": self.policy,
            "sources_of_truth": self.sources_of_truth,
            "plugin_names": list(self.plugin_names),
            "plugin_lock": self.plugin_lock,
            "credentials_file": self.credentials_file,
            "credential_mappings": list(self.credential_mappings),
            "connector_urls": list(self.connector_urls),
        }
        # Keep schema-1 requests produced before organization profiles byte- and
        # fingerprint-compatible. Profile-aware requests add the field only
        # when the high-level workflow actually bound one.
        if self.organization_profile is not None:
            payload["organization_profile"] = self.organization_profile
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Parse a strict invocation payload."""

        _reject_unknown(
            data,
            {
                "plan_path",
                "approval_paths",
                "approval_authorities",
                "database",
                "connector_mode",
                "integrations",
                "result_json",
                "retention",
                "evidence_type",
                "identities",
                "include_writes",
                "include_communications",
                "workspace_root",
                "draft_output_dir",
                "capabilities",
                "governance",
                "policy",
                "sources_of_truth",
                "plugin_names",
                "plugin_lock",
                "credentials_file",
                "credential_mappings",
                "connector_urls",
                "organization_profile",
            },
            "approval request run",
        )
        return cls(
            plan_path=_required_string(data, "plan_path"),
            approval_paths=_string_tuple(data, "approval_paths"),
            approval_authorities=_required_string(data, "approval_authorities"),
            database=_required_string(data, "database"),
            connector_mode=_required_string(data, "connector_mode"),
            integrations=_optional_string(data, "integrations"),
            result_json=_optional_string(data, "result_json"),
            retention=_optional_string(data, "retention"),
            evidence_type=_required_string(data, "evidence_type"),
            identities=_optional_string(data, "identities"),
            include_writes=_required_bool(data, "include_writes"),
            include_communications=_required_bool(data, "include_communications"),
            workspace_root=_optional_string(data, "workspace_root"),
            draft_output_dir=_required_string(data, "draft_output_dir"),
            capabilities=_optional_string(data, "capabilities"),
            governance=_optional_string(data, "governance"),
            policy=_optional_string(data, "policy"),
            sources_of_truth=_optional_string(data, "sources_of_truth"),
            plugin_names=_string_tuple(data, "plugin_names"),
            plugin_lock=_optional_string(data, "plugin_lock"),
            credentials_file=_optional_string(data, "credentials_file"),
            credential_mappings=_string_tuple(data, "credential_mappings"),
            connector_urls=_string_tuple(data, "connector_urls"),
            organization_profile=_optional_string(data, "organization_profile"),
        )


@dataclass(frozen=True, slots=True)
class RequiredApproval:
    """One exact action that remains pending authenticated approval."""

    action: AgentAction
    reason: str

    def __post_init__(self) -> None:
        _validate_text(self.reason, "approval reason")

    def to_dict(self) -> dict[str, object]:
        return {"action": self.action.to_dict(), "reason": self.reason}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _reject_unknown(data, {"action", "reason"}, "required approval")
        action = data.get("action")
        if not isinstance(action, Mapping):
            raise ValidationError("approval request action must be an object")
        return cls(
            action=AgentAction.from_dict(action),
            reason=_required_string(data, "reason"),
        )


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """A non-authoritative review and resume artifact for one exact plan."""

    plan_fingerprint: str
    goal: str
    execution_context: ExecutionContext
    required_approvals: tuple[RequiredApproval, ...]
    run: ApprovalRunInvocation
    schema: str = _SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _SCHEMA:
            raise ValidationError("unsupported approval request schema")
        _validate_sha256(self.plan_fingerprint, "approval request plan fingerprint")
        _validate_text(self.goal, "approval request goal")
        if not self.required_approvals:
            raise ValidationError("approval request must contain pending actions")
        action_ids = [item.action.action_id for item in self.required_approvals]
        if len(set(action_ids)) != len(action_ids):
            raise ValidationError("approval request action IDs must be unique")
        runtime = self.execution_context.runtime
        if runtime is None:
            raise ValidationError("approval request plan must have a bound runtime")
        if not any(
            item.name == "approval_authorities" for item in runtime.configurations
        ):
            raise ValidationError(
                "approval request plan must bind approval-authorities configuration"
            )

    @property
    def fingerprint(self) -> str:
        """Return a stable digest for the complete request review surface."""

        return _fingerprint(self._unsigned_dict())

    @property
    def filename(self) -> str:
        """Return a deterministic bounded name inside the approved artifact root."""

        return (
            f"approval-request-{self.plan_fingerprint[:16]}-"
            f"{self.fingerprint[:16]}.json"
        )

    @property
    def action_ids(self) -> tuple[UUID, ...]:
        return tuple(item.action.action_id for item in self.required_approvals)

    @classmethod
    def build(
        cls,
        *,
        plan: ChangePlan,
        run: ApprovalRunInvocation,
        pending: Sequence[tuple[UUID, str]],
    ) -> Self:
        """Build a request from the policy decisions in an applied run report."""

        if plan.execution_context is None:
            raise ValidationError("approval request requires a bound plan")
        actions = {action.action_id: action for action in plan.actions}
        required: list[RequiredApproval] = []
        for action_id, reason in pending:
            try:
                action = actions[action_id]
            except KeyError as error:
                raise ValidationError(
                    "approval report references an action outside the plan"
                ) from error
            required.append(RequiredApproval(action=action, reason=reason))
        request = cls(
            plan_fingerprint=plan.fingerprint,
            goal=plan.goal,
            execution_context=plan.execution_context,
            required_approvals=tuple(required),
            run=run,
        )
        request.validate_plan(plan)
        return request

    def validate_plan(self, plan: ChangePlan) -> None:
        """Reject stale, swapped, or selectively edited plan references."""

        if plan.fingerprint != self.plan_fingerprint:
            raise ValidationError("approval request plan fingerprint changed")
        if plan.goal != self.goal:
            raise ValidationError("approval request plan goal changed")
        if plan.execution_context != self.execution_context:
            raise ValidationError("approval request execution context changed")
        actions = {action.action_id: action for action in plan.actions}
        for item in self.required_approvals:
            if actions.get(item.action.action_id) != item.action:
                raise ValidationError("approval request action manifest changed")

    def _unsigned_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_fingerprint": self.plan_fingerprint,
            "goal": self.goal,
            "execution_context": self.execution_context.to_dict(),
            "required_approvals": [item.to_dict() for item in self.required_approvals],
            "run": self.run.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        payload = self._unsigned_dict()
        payload["fingerprint"] = self.fingerprint
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _reject_unknown(
            data,
            {
                "schema",
                "plan_fingerprint",
                "goal",
                "execution_context",
                "required_approvals",
                "run",
                "fingerprint",
            },
            "approval request",
        )
        context = data.get("execution_context")
        required = data.get("required_approvals")
        run = data.get("run")
        if not isinstance(context, Mapping):
            raise ValidationError(
                "approval request execution context must be an object"
            )
        if not isinstance(required, list) or not all(
            isinstance(item, Mapping) for item in required
        ):
            raise ValidationError("approval request actions must be a list of objects")
        if not isinstance(run, Mapping):
            raise ValidationError("approval request run must be an object")
        request = cls(
            schema=_required_string(data, "schema"),
            plan_fingerprint=_required_string(data, "plan_fingerprint"),
            goal=_required_string(data, "goal"),
            execution_context=ExecutionContext.from_dict(context),
            required_approvals=tuple(
                RequiredApproval.from_dict(item) for item in required
            ),
            run=ApprovalRunInvocation.from_dict(run),
        )
        supplied = _required_string(data, "fingerprint")
        if supplied != request.fingerprint:
            raise ValidationError("approval request fingerprint changed")
        return request


def publish_approval_request(
    output_root: Path | PinnedDirectory,
    request: ApprovalRequest,
) -> Path:
    """Create or safely reuse one exact mode-0600 request in a pinned root."""

    require_persistent_state_platform()
    payload = _json_bytes(request.to_dict())
    with pin_directory(output_root) as directory:
        _publish_restricted_bytes(
            directory,
            request.filename,
            payload,
            reuse_identical=True,
        )
        return directory.path / request.filename


def load_approval_request(path: Path) -> ApprovalRequest:
    """Read one bounded request through a private no-follow parent directory."""

    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if selected.name in {"", ".", ".."}:
        raise ConfigurationError("approval request path is invalid")
    if os.name == "nt":
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        backend = get_secure_filesystem_backend()
        if not isinstance(backend, WindowsSecureFilesystemBackend):
            raise ConfigurationError("native Windows secure filesystem is unavailable")
        try:
            _canonical, payload, _identity = backend.read_restricted_file(
                selected,
                _MAX_REQUEST_BYTES,
                require_private=True,
            )
        except (ConfigurationError, OSError) as error:
            raise ConfigurationError(
                "approval request could not be opened safely"
            ) from error
    else:
        with PinnedDirectory.open(selected.parent) as directory:
            payload = _read_restricted_bytes(directory, selected.name)
    try:
        raw = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("approval request is not valid UTF-8 JSON") from error
    if not isinstance(raw, Mapping):
        raise ValidationError("approval request must be a JSON object")
    return ApprovalRequest.from_dict(raw)


def write_restricted_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Create one private JSON artifact without overwriting an existing name."""

    require_persistent_state_platform()
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    with PinnedDirectory.open(selected.parent) as directory:
        _publish_restricted_bytes(
            directory,
            selected.name,
            _json_bytes(payload),
            reuse_identical=False,
        )


def _publish_restricted_bytes(
    directory: PinnedDirectory,
    name: str,
    payload: bytes,
    *,
    reuse_identical: bool,
) -> None:
    if name in {"", ".", ".."} or Path(name).name != name:
        raise ConfigurationError("restricted artifact escaped its private directory")
    if len(payload) > _MAX_REQUEST_BYTES:
        raise ValidationError("restricted artifact exceeds the 8 MiB limit")
    if directory.object_identity.platform == "windows":
        atomic = get_atomic_publication_recovery_backend()
        with atomic.open_transaction(
            directory.path / name,
            max_bytes=_MAX_REQUEST_BYTES,
            create=True,
        ) as transaction:
            existing = transaction.read_bytes()
            if existing is not None:
                if reuse_identical and existing == payload:
                    return
                raise ConfigurationError(
                    "restricted artifact already exists; use a fresh private output name"
                )
            transaction.publish_bytes(payload, expected=None)
            directory.validate()
            return
    parent = directory.fileno()
    descriptor = -1
    created_identity: tuple[int, int, int, int, int] | None = None
    owned_identity: tuple[int, int, int] | None = None
    completed = False
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent,
            )
        except FileExistsError:
            if reuse_identical and _read_restricted_bytes(directory, name) == payload:
                return
            raise ConfigurationError(
                "restricted artifact already exists; use a fresh private output name"
            ) from None
        initial = os.fstat(descriptor)
        owned_identity = (initial.st_dev, initial.st_ino, initial.st_uid)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_uid != os.getuid()
            or initial.st_nlink != 1
            or stat.S_IMODE(initial.st_mode) & 0o077
        ):
            raise ConfigurationError("restricted artifact file is unsafe")
        os.fchmod(descriptor, 0o600)
        created_identity = _restricted_identity(os.fstat(descriptor))
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short restricted artifact write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        directory.validate()
        published = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _restricted_identity(published) != created_identity:
            raise ConfigurationError("restricted artifact publication was replaced")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _read_descriptor(descriptor) != payload:
            raise ConfigurationError("restricted artifact bytes changed during write")
        os.fsync(parent)
        directory.validate()
        completed = True
    except OSError as error:
        raise ConfigurationError("restricted artifact destination changed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not completed and owned_identity is not None:
            _unlink_if_owned(parent, name, owned_identity)


def _read_restricted_bytes(directory: PinnedDirectory, name: str) -> bytes:
    if name in {"", ".", ".."} or Path(name).name != name:
        raise ConfigurationError("restricted artifact escaped its private directory")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory.fileno(),
        )
    except OSError as error:
        raise ConfigurationError(
            "restricted artifact could not be opened safely"
        ) from error
    try:
        _restricted_identity(os.fstat(descriptor))
        payload = _read_descriptor(descriptor)
        directory.validate()
        return payload
    finally:
        os.close(descriptor)


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_REQUEST_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > _MAX_REQUEST_BYTES:
        raise ValidationError("restricted artifact exceeds the 8 MiB limit")
    return payload


def _restricted_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ConfigurationError("restricted artifact file is unsafe")
    return identity


def _unlink_if_owned(
    parent: int,
    name: str,
    expected: tuple[int, int, int],
) -> None:
    """Remove only the exact owner-private inode created by this call."""

    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    observed = (current.st_dev, current.st_ino, current.st_uid)
    if (
        observed != expected
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) & 0o077
    ):
        raise ConfigurationError(
            "restricted artifact rollback refused after identity change"
        )
    try:
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
    except OSError as error:
        raise ConfigurationError(
            "restricted artifact rollback was incomplete"
        ) from error


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _fingerprint(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"approval request repeats JSON key: {key}")
        result[key] = value
    return result


def _canonical_path(path: Path) -> str:
    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    return str(selected.resolve(strict=False))


def _canonical_optional_path(path: Path | None) -> str | None:
    return _canonical_path(path) if path is not None else None


def _validate_absolute_path(value: str, name: str) -> None:
    _validate_text(value, name)
    if not Path(value).is_absolute():
        raise ValidationError(f"approval request {name} must be an absolute path")


def _validate_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must be a non-empty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValidationError(f"{name} contains terminal-control characters")


def _validate_sha256(value: str, name: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValidationError(f"{name} must be lowercase SHA-256")


def _required_string(data: Mapping[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str):
        raise ValidationError(f"approval request {name} must be a string")
    return value


def _optional_string(data: Mapping[str, Any], name: str) -> str | None:
    value = data.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"approval request {name} must be a string or null")
    return value


def _required_bool(data: Mapping[str, Any], name: str) -> bool:
    value = data.get(name)
    if not isinstance(value, bool):
        raise ValidationError(f"approval request {name} must be a boolean")
    return value


def _string_tuple(data: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = data.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"approval request {name} must be a string list")
    return tuple(value)


def _reject_unknown(
    data: Mapping[str, Any],
    allowed: set[str],
    name: str,
) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValidationError(f"{name} contains unknown fields: {', '.join(unknown)}")
