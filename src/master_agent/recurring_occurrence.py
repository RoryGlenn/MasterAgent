"""Authenticated exact-bound recurring occurrence artifacts."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from importlib import metadata, resources
from pathlib import Path
from typing import Any, Self
from zoneinfo import TZPATH, ZoneInfo

from master_agent import __version__
from master_agent.approval_handoff import ApprovalRunInvocation, write_restricted_json
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    RiskLevel,
)
from master_agent.planners.base import bind_systems_governance
from master_agent.platform_runtime.contracts import PlatformObjectIdentity
from master_agent.recurring import (
    CatchUpPolicy,
    RecurringConfig,
    RecurringStateStore,
    RegisteredWorkflow,
)

SCHEMA = "master-agent/recurring-occurrence@1"
MAX_OCCURRENCE_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_CONTAINER_ITEMS = 4096
MAX_JSON_STRING_CHARACTERS = 256 * 1024
MAX_JSON_NODES = 100_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:authorization|credential|hmac|password|refresh_token|secret|signature|token)(?:_|$)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]+PRIVATE KEY-----|\b(?:gh[opsu]_|sk-[A-Za-z0-9])\S{12,})"
)
_UNBOUND_EXECUTION_KEY = re.compile(
    r"(?:^|_)(?:argv|command|cwd|env|environment|executable|shell)(?:_|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class RecurringOccurrence:
    """One strict immutable occurrence review and execution surface."""

    workflow_name: str
    registration: Mapping[str, Any]
    registration_digest: str
    source_plan_fingerprint: str
    execution_key: str
    plan: ChangePlan
    invocation: ApprovalRunInvocation
    scheduled_at: datetime
    local_time: str
    timezone: str
    timezone_identity: str
    utc_offset_minutes: int
    fold: int
    not_before: datetime
    expires_at: datetime
    approval_resume_deadline: datetime
    roots: Mapping[str, str]
    root_identities: Mapping[str, Any]
    runtime_identity: Mapping[str, str]
    created_at: datetime
    trust_mode: str = "local_state"
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValidationError("unsupported recurring occurrence schema")
        if self.trust_mode != "local_state":
            raise ValidationError("unsupported recurring occurrence trust mode")
        if not self.workflow_name or any(ord(char) < 32 for char in self.workflow_name):
            raise ValidationError("recurring occurrence workflow name is invalid")
        for name, value in (
            ("registration_digest", self.registration_digest),
            ("source_plan_fingerprint", self.source_plan_fingerprint),
            ("execution_key", self.execution_key),
            ("timezone_identity", self.timezone_identity),
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValidationError(f"recurring occurrence {name} is invalid")
        if self.plan.fingerprint == self.source_plan_fingerprint:
            effect_actions = tuple(
                item
                for item in self.plan.actions
                if item.risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
            )
            if effect_actions:
                raise ValidationError(
                    "recurring effect plan did not receive occurrence-scoped idempotency"
                )
        if (
            self.plan.execution_context is None
            or self.plan.execution_context.runtime is None
        ):
            raise ValidationError("recurring occurrence requires a bound runtime plan")
        if self.fold not in {0, 1}:
            raise ValidationError("recurring occurrence fold is invalid")
        if (
            isinstance(self.utc_offset_minutes, bool)
            or not -24 * 60 < self.utc_offset_minutes < 24 * 60
        ):
            raise ValidationError("recurring occurrence UTC offset is invalid")
        for name, timestamp in (
            ("scheduled_at", self.scheduled_at),
            ("not_before", self.not_before),
            ("expires_at", self.expires_at),
            ("approval_resume_deadline", self.approval_resume_deadline),
            ("created_at", self.created_at),
        ):
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValidationError(f"recurring occurrence {name} must be aware")
        if self.scheduled_at.astimezone(UTC) != self.not_before.astimezone(UTC):
            raise ValidationError("recurring occurrence not-before instant changed")
        if self.expires_at < self.not_before:
            raise ValidationError("recurring occurrence expiry precedes its schedule")
        if self.approval_resume_deadline < self.expires_at:
            raise ValidationError("recurring approval deadline precedes apply expiry")
        try:
            local_wall_time = datetime.fromisoformat(self.local_time)
            zone = ZoneInfo(self.timezone)
        except (ValueError, KeyError) as error:
            raise ValidationError(
                "recurring occurrence local time is invalid"
            ) from error
        if local_wall_time.tzinfo is not None:
            raise ValidationError("recurring occurrence local time must be naive")
        observed_local = self.scheduled_at.astimezone(zone)
        observed_offset = int(
            (observed_local.utcoffset() or timedelta()).total_seconds() // 60
        )
        if (
            observed_local.replace(tzinfo=None) != local_wall_time
            or observed_local.fold != self.fold
            or observed_offset != self.utc_offset_minutes
        ):
            raise ValidationError("recurring occurrence timezone facts changed")
        registration = _freeze_mapping(self.registration, "registration")
        roots = _freeze_string_mapping(self.roots, "roots")
        root_identities = _freeze_mapping(self.root_identities, "root identities")
        runtime_identity = _freeze_string_mapping(
            self.runtime_identity,
            "runtime_identity",
        )
        if _fingerprint(registration) != self.registration_digest:
            raise ValidationError("recurring occurrence registration digest changed")
        if set(roots) != {
            "claim",
            "lock",
            "occurrence",
            "output",
            "audit",
            "artifact",
            "workspace",
            "result",
        }:
            raise ValidationError("recurring occurrence roots are incomplete")
        if set(root_identities) != set(roots):
            raise ValidationError("recurring occurrence root identities are incomplete")
        try:
            for value in root_identities.values():
                if not isinstance(value, Mapping):
                    raise TypeError("root identity must be an object")
                PlatformObjectIdentity.from_dict(value)
        except (TypeError, ValueError) as error:
            raise ValidationError(
                "recurring occurrence root identity is invalid"
            ) from error
        if any(not value for value in roots.values()):
            raise ValidationError("recurring occurrence roots must all be selected")
        selected_roots = list(roots.values())
        if len(selected_roots) != len(set(selected_roots)):
            raise ValidationError(
                "recurring occurrence roots must be pairwise distinct"
            )
        if any(not Path(value).is_absolute() for value in selected_roots):
            raise ValidationError("recurring occurrence roots must be absolute")
        _validate_invocation_against_plan(self.invocation, self.plan)
        for action in self.plan.actions:
            _reject_sensitive_material(action.parameters)
            _reject_unbound_execution(action.parameters)
        object.__setattr__(self, "registration", registration)
        object.__setattr__(self, "roots", roots)
        object.__setattr__(self, "root_identities", root_identities)
        object.__setattr__(self, "runtime_identity", runtime_identity)

    @property
    def fingerprint(self) -> str:
        """Return the digest of every unsigned occurrence field."""

        return _fingerprint(self._unsigned_dict())

    @property
    def artifact_sha256(self) -> str:
        """Return the exact canonical file digest used by trusted state."""

        return hashlib.sha256(_json_bytes(self.to_dict())).hexdigest()

    def _unsigned_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "trust_mode": self.trust_mode,
            "workflow_name": self.workflow_name,
            "registration": dict(self.registration),
            "registration_digest": self.registration_digest,
            "source_plan_fingerprint": self.source_plan_fingerprint,
            "execution_key": self.execution_key,
            "plan": self.plan.to_dict(),
            "invocation": self.invocation.to_dict(),
            "scheduled_at": self.scheduled_at.astimezone(UTC).isoformat(),
            "local_time": self.local_time,
            "timezone": self.timezone,
            "timezone_identity": self.timezone_identity,
            "utc_offset_minutes": self.utc_offset_minutes,
            "fold": self.fold,
            "not_before": self.not_before.astimezone(UTC).isoformat(),
            "expires_at": self.expires_at.astimezone(UTC).isoformat(),
            "approval_resume_deadline": self.approval_resume_deadline.astimezone(
                UTC
            ).isoformat(),
            "roots": dict(self.roots),
            "root_identities": dict(self.root_identities),
            "runtime_identity": dict(self.runtime_identity),
            "created_at": self.created_at.astimezone(UTC).isoformat(),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the canonical JSON document."""

        payload = self._unsigned_dict()
        payload["fingerprint"] = self.fingerprint
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Parse one strict canonical occurrence mapping."""

        expected = {
            "schema",
            "trust_mode",
            "workflow_name",
            "registration",
            "registration_digest",
            "source_plan_fingerprint",
            "execution_key",
            "plan",
            "invocation",
            "scheduled_at",
            "local_time",
            "timezone",
            "timezone_identity",
            "utc_offset_minutes",
            "fold",
            "not_before",
            "expires_at",
            "approval_resume_deadline",
            "roots",
            "root_identities",
            "runtime_identity",
            "created_at",
            "fingerprint",
        }
        if set(data) != expected:
            raise ValidationError(
                "recurring occurrence fields are incomplete or unknown"
            )
        registration = _mapping(data, "registration")
        raw_plan = _mapping(data, "plan")
        raw_invocation = _mapping(data, "invocation")
        roots = _mapping(data, "roots")
        root_identities = _mapping(data, "root_identities")
        runtime_identity = _mapping(data, "runtime_identity")
        plan = ChangePlan.from_dict(raw_plan)
        if plan.to_dict() != dict(raw_plan):
            raise ValidationError("recurring occurrence plan is not canonical")
        invocation = ApprovalRunInvocation.from_dict(raw_invocation)
        if invocation.to_dict() != dict(raw_invocation):
            raise ValidationError("recurring occurrence invocation is not canonical")
        occurrence = cls(
            schema=_string(data, "schema"),
            trust_mode=_string(data, "trust_mode"),
            workflow_name=_string(data, "workflow_name"),
            registration=registration,
            registration_digest=_string(data, "registration_digest"),
            source_plan_fingerprint=_string(data, "source_plan_fingerprint"),
            execution_key=_string(data, "execution_key"),
            plan=plan,
            invocation=invocation,
            scheduled_at=_aware_datetime(data, "scheduled_at"),
            local_time=_string(data, "local_time"),
            timezone=_string(data, "timezone"),
            timezone_identity=_string(data, "timezone_identity"),
            utc_offset_minutes=_integer(data, "utc_offset_minutes"),
            fold=_integer(data, "fold"),
            not_before=_aware_datetime(data, "not_before"),
            expires_at=_aware_datetime(data, "expires_at"),
            approval_resume_deadline=_aware_datetime(
                data,
                "approval_resume_deadline",
            ),
            roots={str(key): str(value) for key, value in roots.items()},
            root_identities=root_identities,
            runtime_identity={
                str(key): str(value) for key, value in runtime_identity.items()
            },
            created_at=_aware_datetime(data, "created_at"),
        )
        if _string(data, "fingerprint") != occurrence.fingerprint:
            raise ValidationError("recurring occurrence fingerprint changed")
        return occurrence


def bind_local_occurrence(
    *,
    config: RecurringConfig,
    workflow_name: str,
    requested_local_time: datetime,
    plan: ChangePlan,
    invocation: ApprovalRunInvocation,
    output: Path,
    created_at: datetime | None = None,
) -> RecurringOccurrence:
    """Create, publish, and trusted-state-register one exact local occurrence."""

    try:
        workflow = config.workflows[workflow_name]
    except KeyError as error:
        raise ConfigurationError(
            f"recurring workflow is not registered: {workflow_name}"
        ) from error
    if not workflow.enabled or workflow.revoked:
        raise ConfigurationError("recurring workflow is disabled or revoked")
    if config.occurrence_root is None:
        raise ConfigurationError("exact recurring execution requires occurrence_root")
    _validate_plan_scope(plan, workflow)
    registration = registration_snapshot(workflow)
    registration_digest = _fingerprint(registration)
    scheduled_at = workflow.schedule.resolve_occurrence(requested_local_time)
    local = scheduled_at.astimezone(ZoneInfo(workflow.schedule.timezone))
    if local.replace(tzinfo=None) != requested_local_time or local.fold not in {0, 1}:
        raise ConfigurationError("recurring occurrence local time changed")
    source_plan_fingerprint = plan.fingerprint
    execution_key = _fingerprint(
        {
            "registration_digest": registration_digest,
            "scheduled_at": scheduled_at.isoformat(),
            "plan_fingerprint": source_plan_fingerprint,
        }
    )
    scoped_plan = _scope_effect_idempotency(plan, execution_key)
    context = scoped_plan.execution_context
    if context is None or context.runtime is None:  # pragma: no cover - scope gate.
        raise ConfigurationError("recurring scoped plan lost its runtime binding")
    runtime = context.runtime
    roots = {
        "claim": str(config.state_database.parent),
        "lock": str(config.lock_dir),
        "occurrence": str(config.occurrence_root),
        "output": str(workflow.output_dir),
        "audit": str(Path(runtime.audit_database).parent),
        "artifact": runtime.artifact_root,
        "workspace": runtime.workspace_root or "",
        "result": str(Path(runtime.result_json).parent) if runtime.result_json else "",
    }
    now = (created_at or datetime.now(UTC)).astimezone(UTC)
    occurrence = RecurringOccurrence(
        workflow_name=workflow.name,
        registration=registration,
        registration_digest=registration_digest,
        source_plan_fingerprint=source_plan_fingerprint,
        execution_key=execution_key,
        plan=scoped_plan,
        invocation=invocation,
        scheduled_at=scheduled_at,
        local_time=requested_local_time.isoformat(),
        timezone=workflow.schedule.timezone,
        timezone_identity=timezone_identity(workflow.schedule.timezone),
        utc_offset_minutes=int(
            (local.utcoffset() or timedelta()).total_seconds() // 60
        ),
        fold=local.fold,
        not_before=scheduled_at,
        expires_at=scheduled_at
        + timedelta(minutes=workflow.schedule.max_lateness_minutes),
        approval_resume_deadline=scheduled_at
        + timedelta(minutes=workflow.approval_resume_minutes),
        roots=roots,
        root_identities=_capture_root_identities(roots),
        runtime_identity=current_runtime_identity(),
        created_at=now,
    )
    selected = output.expanduser().resolve(strict=False)
    if selected.parent != config.occurrence_root:
        raise ConfigurationError("occurrence output must be inside occurrence_root")
    _validate_bound_roots(occurrence)
    write_restricted_json(selected, occurrence.to_dict())
    store = RecurringStateStore(config.state_database)
    try:
        store.register_occurrence_artifact(
            workflow_name=workflow.name,
            scheduled_at=scheduled_at,
            artifact_fingerprint=occurrence.fingerprint,
            artifact_sha256=occurrence.artifact_sha256,
            registration_digest=registration_digest,
            execution_key=execution_key,
            resume_deadline=occurrence.approval_resume_deadline,
        )
    finally:
        store.close()
    return occurrence


def load_occurrence(path: Path, *, require_private: bool = True) -> RecurringOccurrence:
    """Load one bounded strict occurrence without touching trusted claim state."""

    selected = path.expanduser().resolve(strict=False)
    with PinnedDirectory.open(selected.parent, require_private=require_private) as root:
        _path, payload, _identity = root.read_child_bytes(
            selected.name,
            max_bytes=MAX_OCCURRENCE_BYTES,
            require_private=require_private,
        )
    return parse_occurrence(payload)


def parse_occurrence(payload: bytes) -> RecurringOccurrence:
    """Parse bounded UTF-8 JSON with duplicate and non-finite values rejected."""

    if len(payload) > MAX_OCCURRENCE_BYTES:
        raise ValidationError("recurring occurrence exceeds the 8 MiB limit")
    try:
        raw = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError, MemoryError) as error:
        raise ValidationError(
            "recurring occurrence is not bounded valid UTF-8 JSON"
        ) from error
    if not isinstance(raw, Mapping):
        raise ValidationError("recurring occurrence must be a JSON object")
    _validate_json_shape(raw)
    occurrence = RecurringOccurrence.from_dict(raw)
    if _json_bytes(occurrence.to_dict()) != payload:
        raise ValidationError("recurring occurrence is not canonical JSON")
    return occurrence


def authenticate_occurrence(
    occurrence: RecurringOccurrence,
    *,
    config: RecurringConfig,
    now: datetime | None = None,
    allow_approval_resume: bool = False,
) -> RecurringStateStore:
    """Validate current registration, runtime, time, roots, and trusted state."""

    try:
        workflow = config.workflows[occurrence.workflow_name]
    except KeyError as error:
        raise ConfigurationError(
            "recurring occurrence registration is missing"
        ) from error
    if not workflow.enabled or workflow.revoked:
        raise ConfigurationError("recurring workflow is disabled or revoked")
    if registration_snapshot(workflow) != occurrence.registration:
        raise ConfigurationError("recurring occurrence registration changed")
    if (
        config.occurrence_root is None
        or str(config.occurrence_root) != occurrence.roots["occurrence"]
    ):
        raise ConfigurationError("recurring occurrence root changed")
    if str(config.state_database.parent) != occurrence.roots["claim"]:
        raise ConfigurationError("recurring claim root changed")
    if str(config.lock_dir) != occurrence.roots["lock"]:
        raise ConfigurationError("recurring lock root changed")
    if timezone_identity(occurrence.timezone) != occurrence.timezone_identity:
        raise ConfigurationError("recurring timezone data changed")
    if current_runtime_identity() != occurrence.runtime_identity:
        raise ConfigurationError("recurring runtime or package identity changed")
    _validate_bound_roots(occurrence)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if current < occurrence.not_before:
        raise ConfigurationError("recurring occurrence is not due yet")
    deadline = (
        occurrence.approval_resume_deadline
        if allow_approval_resume
        else occurrence.expires_at
    )
    if current > deadline:
        raise ConfigurationError("recurring occurrence is outside its time window")
    latest = workflow.schedule.scheduled_at_or_before(current)
    if (
        workflow.catch_up_policy is CatchUpPolicy.LATEST_ONLY
        and not allow_approval_resume
        and latest != occurrence.scheduled_at
    ):
        raise ConfigurationError("latest-only catch-up superseded this occurrence")
    store = RecurringStateStore(config.state_database)
    try:
        store.authenticate_occurrence_artifact(
            workflow_name=occurrence.workflow_name,
            scheduled_at=occurrence.scheduled_at,
            artifact_fingerprint=occurrence.fingerprint,
            artifact_sha256=occurrence.artifact_sha256,
            registration_digest=occurrence.registration_digest,
            execution_key=occurrence.execution_key,
        )
    except BaseException:
        store.close()
        raise
    return store


def registration_snapshot(workflow: RegisteredWorkflow) -> Mapping[str, Any]:
    """Return every authority-relevant registration field."""

    return _freeze_mapping(
        {
            "name": workflow.name,
            "enabled": workflow.enabled,
            "revoked": workflow.revoked,
            "generation": workflow.generation,
            "kind": str(workflow.kind),
            "delivery_mode": str(workflow.delivery_mode),
            "schedule": {
                "weekday": workflow.schedule.weekday,
                "hour": workflow.schedule.hour,
                "minute": workflow.schedule.minute,
                "timezone": workflow.schedule.timezone,
                "dst_fold": str(workflow.schedule.fold_policy),
                "max_lateness_minutes": workflow.schedule.max_lateness_minutes,
                "catch_up_policy": str(workflow.catch_up_policy),
                "approval_resume_minutes": workflow.approval_resume_minutes,
            },
            "output_dir": str(workflow.output_dir),
            "integration_config": str(workflow.integration_config),
            "workflow_config": str(workflow.workflow_config),
            "identity_config": str(workflow.identity_config)
            if workflow.identity_config
            else None,
            "retention_config": str(workflow.retention_config)
            if workflow.retention_config
            else None,
            "configuration_sha256": {
                "integrations": _file_sha256(workflow.integration_config),
                "workflow": _file_sha256(workflow.workflow_config),
                "identities": (
                    _file_sha256(workflow.identity_config)
                    if workflow.identity_config
                    else None
                ),
                "retention": (
                    _file_sha256(workflow.retention_config)
                    if workflow.retention_config
                    else None
                ),
            },
            "allowed_capabilities": list(workflow.allowed_capabilities),
            "allowed_recipients": list(workflow.allowed_recipients),
            "canonical_sources": list(workflow.canonical_sources),
        },
        "registration",
    )


def _file_sha256(path: Path) -> str:
    """Digest one identity-pinned bounded registration input."""

    try:
        with PinnedDirectory.open(path.parent, require_private=False) as root:
            _selected, payload, _identity = root.read_child_bytes(
                path.name,
                max_bytes=8 * 1024 * 1024,
                require_private=False,
            )
    except (ConfigurationError, OSError) as error:
        raise ConfigurationError(
            f"recurring registration input could not be pinned: {path}"
        ) from error
    return hashlib.sha256(payload).hexdigest()


def timezone_identity(name: str) -> str:
    """Digest the active IANA timezone rules without trusting a display label."""

    relative = Path(*name.split("/"))
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ConfigurationError("recurring timezone name is invalid")
    for root in TZPATH:
        candidate = Path(root) / relative
        try:
            payload = candidate.read_bytes()
        except OSError:
            continue
        return hashlib.sha256(payload).hexdigest()
    try:
        package_file = resources.files("tzdata.zoneinfo").joinpath(*relative.parts)
        payload = package_file.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        try:
            version = metadata.version("tzdata")
        except metadata.PackageNotFoundError as error:
            raise ConfigurationError(
                "recurring timezone rules are unavailable"
            ) from error
        payload = f"tzdata:{version}:{name}".encode()
    return hashlib.sha256(payload).hexdigest()


def current_runtime_identity() -> Mapping[str, str]:
    """Return a content-free identity for the executing package and interpreter."""

    package_root = Path(__file__).resolve().parent
    package_digest = hashlib.sha256()
    for candidate in sorted(package_root.rglob("*.py")):
        if candidate.is_symlink():
            raise ConfigurationError("recurring runtime package contains a symlink")
        payload = candidate.read_bytes()
        package_digest.update(candidate.relative_to(package_root).as_posix().encode())
        package_digest.update(b"\0")
        package_digest.update(payload)
        package_digest.update(b"\0")
    executable = Path(sys.executable).resolve(strict=True)
    if executable.is_symlink():  # pragma: no cover - resolve removes final symlink.
        raise ConfigurationError("recurring interpreter identity is ambiguous")
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    return _freeze_string_mapping(
        {
            "master_agent_version": __version__,
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": str(executable),
            "executable_sha256": executable_sha256,
            "package_tree_sha256": package_digest.hexdigest(),
            "platform": sys.platform,
        },
        "runtime_identity",
    )


def occurrence_summary(occurrence: RecurringOccurrence) -> dict[str, object]:
    """Return the content-free review surface for inspect and dry-run."""

    return {
        "schema": occurrence.schema,
        "fingerprint": occurrence.fingerprint,
        "trust_mode": occurrence.trust_mode,
        "workflow": occurrence.workflow_name,
        "registration_generation": occurrence.registration["generation"],
        "scheduled_at": occurrence.scheduled_at.isoformat(),
        "local_time": occurrence.local_time,
        "timezone": occurrence.timezone,
        "fold": occurrence.fold,
        "not_before": occurrence.not_before.isoformat(),
        "expires_at": occurrence.expires_at.isoformat(),
        "approval_resume_deadline": occurrence.approval_resume_deadline.isoformat(),
        "catch_up_policy": occurrence.registration["schedule"]["catch_up_policy"],
        "execution_key": occurrence.execution_key,
        "plan_fingerprint": occurrence.plan.fingerprint,
        "actions": [
            {
                "action_id": str(action.action_id),
                "capability": action.capability,
                "target": f"{action.target.system}://{action.target.resource_id}",
                "risk": str(action.risk),
                "requires_approval": action.requires_approval,
            }
            for action in occurrence.plan.actions
        ],
        "roots": dict(occurrence.roots),
        "runtime_identity": dict(occurrence.runtime_identity),
    }


def _validate_plan_scope(plan: ChangePlan, workflow: RegisteredWorkflow) -> None:
    if plan.systems_assessment is None or plan.systems_decision is None:
        raise ConfigurationError(
            "recurring plan must carry a bound systems-governance decision"
        )
    if plan.execution_context is None or plan.execution_context.runtime is None:
        raise ConfigurationError("recurring plan must be approval-bound before bind")
    allowed_capabilities = set(workflow.allowed_capabilities)
    allowed_sources = set(workflow.canonical_sources)
    allowed_recipients = set(workflow.allowed_recipients)
    for action in plan.actions:
        if action.authority_source is not AuthoritySource.REGISTERED_WORKFLOW:
            raise ConfigurationError(
                "recurring action authority is not registered_workflow"
            )
        if action.capability not in allowed_capabilities:
            raise ConfigurationError(
                f"recurring plan exceeds capability scope: {action.capability}"
            )
        source = f"{action.target.system}://{action.target.resource_id}"
        if (
            action.target.system not in {"local", "powerpoint"}
            and source not in allowed_sources
        ):
            raise ConfigurationError(f"recurring plan exceeds source scope: {source}")
        for recipient in _action_recipients(action):
            if recipient not in allowed_recipients:
                raise ConfigurationError(
                    f"recurring plan exceeds recipient scope: {recipient}"
                )


def _action_recipients(action: AgentAction) -> tuple[str, ...]:
    recipients: list[str] = []
    for key in ("recipient", "to", "chat_id", "channel_id", "destination_id"):
        value = action.parameters.get(key)
        if isinstance(value, str) and value:
            recipients.append(value)
    values = action.parameters.get("recipients")
    if isinstance(values, (list, tuple)):
        recipients.extend(str(item) for item in values)
    return tuple(recipients)


def _scope_effect_idempotency(plan: ChangePlan, execution_key: str) -> ChangePlan:
    actions: list[AgentAction] = []
    for action in plan.actions:
        if action.risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}:
            actions.append(
                replace(
                    action,
                    idempotency_key=f"{execution_key}:{action.idempotency_key}",
                )
            )
            continue
        if action.risk is RiskLevel.LOCAL_GENERATION:
            parameters = dict(action.parameters)
            raw_name = str(parameters.get("output_name", "")).strip()
            if raw_name:
                selected = Path(raw_name)
                parameters["output_name"] = (
                    f"{selected.stem}-{execution_key[:20]}{selected.suffix}"
                )
            actions.append(
                replace(
                    action,
                    target=replace(
                        action.target,
                        resource_id=(
                            f"{action.target.resource_id}-{execution_key[:20]}"
                        ),
                    ),
                    parameters=parameters,
                )
            )
            continue
        actions.append(action)
    assessment = plan.systems_assessment
    if assessment is None:  # pragma: no cover - binder scope gate.
        raise ConfigurationError("recurring plan lost its systems assessment")
    scoped = replace(
        plan,
        actions=tuple(actions),
        systems_assessment=None,
        systems_decision=None,
    )
    return bind_systems_governance(scoped, assessment)


def _validate_invocation_against_plan(
    invocation: ApprovalRunInvocation,
    plan: ChangePlan,
) -> None:
    context = plan.execution_context
    if context is None or context.runtime is None:  # pragma: no cover - caller gate.
        raise ValidationError("recurring plan lost its runtime binding")
    runtime = context.runtime
    expected = {
        "database": runtime.audit_database,
        "draft_output_dir": runtime.artifact_root,
        "workspace_root": runtime.workspace_root,
        "result_json": runtime.result_json,
        "connector_mode": runtime.connector_mode,
        "include_writes": runtime.include_writes,
        "include_communications": runtime.include_communications,
        "credentials_file": runtime.credential_file,
    }
    actual = {
        "database": invocation.database,
        "draft_output_dir": invocation.draft_output_dir,
        "workspace_root": invocation.workspace_root,
        "result_json": invocation.result_json,
        "connector_mode": invocation.connector_mode,
        "include_writes": invocation.include_writes,
        "include_communications": invocation.include_communications,
        "credentials_file": invocation.credentials_file,
    }
    if actual != expected:
        raise ValidationError("recurring invocation differs from the bound runtime")
    if runtime.evidence_type != (
        invocation.evidence_type if invocation.result_json is not None else None
    ):
        raise ValidationError("recurring invocation evidence type changed")
    if invocation.approval_paths:
        raise ValidationError("recurring bind cannot embed approval artifacts")


def _validate_bound_roots(occurrence: RecurringOccurrence) -> None:
    pins: list[PinnedDirectory] = []
    try:
        for name, value in occurrence.roots.items():
            if value:
                pin = PinnedDirectory.open(Path(value))
                pins.append(pin)
                expected = occurrence.root_identities[name]
                if pin.object_identity.to_dict() != expected:
                    raise ConfigurationError(f"recurring root identity changed: {name}")
        for pin in pins:
            pin.validate()
    finally:
        for pin in reversed(pins):
            pin.close()


def _capture_root_identities(roots: Mapping[str, str]) -> Mapping[str, Any]:
    pins: list[PinnedDirectory] = []
    identities: dict[str, object] = {}
    try:
        for name, value in roots.items():
            pin = PinnedDirectory.open(Path(value))
            pins.append(pin)
            identities[name] = pin.object_identity.to_dict()
        return _freeze_mapping(identities, "root identities")
    finally:
        for pin in reversed(pins):
            pin.close()


def _reject_sensitive_material(value: object, *, key: str = "") -> None:
    if key and _SENSITIVE_KEY.search(key):
        raise ValidationError(
            "recurring occurrence contains secret or approval material"
        )
    if isinstance(value, Mapping):
        for nested_key, nested in value.items():
            _reject_sensitive_material(nested, key=str(nested_key))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_sensitive_material(nested)
    elif isinstance(value, str) and _SENSITIVE_VALUE.search(value):
        raise ValidationError("recurring occurrence contains secret-like material")


def _reject_unbound_execution(value: object, *, key: str = "") -> None:
    if key and _UNBOUND_EXECUTION_KEY.search(key):
        raise ValidationError(
            "recurring occurrence contains unbound command or environment selection"
        )
    if isinstance(value, Mapping):
        for nested_key, nested in value.items():
            _reject_unbound_execution(nested, key=str(nested_key))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_unbound_execution(nested)


def _validate_json_shape(value: object) -> None:
    """Enforce deterministic depth, fan-out, string, control, and node limits."""

    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValidationError("recurring occurrence JSON has too many values")
        if depth > MAX_JSON_DEPTH:
            raise ValidationError("recurring occurrence JSON is too deeply nested")
        if isinstance(current, Mapping):
            if len(current) > MAX_JSON_CONTAINER_ITEMS:
                raise ValidationError("recurring occurrence JSON object is too large")
            for key, nested in current.items():
                if not isinstance(key, str):  # pragma: no cover - JSON invariant.
                    raise ValidationError("recurring occurrence JSON key is invalid")
                _validate_json_text(key)
                stack.append((nested, depth + 1))
        elif isinstance(current, list):
            if len(current) > MAX_JSON_CONTAINER_ITEMS:
                raise ValidationError("recurring occurrence JSON list is too large")
            stack.extend((nested, depth + 1) for nested in current)
        elif isinstance(current, str):
            _validate_json_text(current)


def _validate_json_text(value: str) -> None:
    if len(value) > MAX_JSON_STRING_CHARACTERS:
        raise ValidationError("recurring occurrence JSON string is too large")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise ValidationError("recurring occurrence JSON contains controls")


def _freeze_mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(
            json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError(f"recurring occurrence {name} is invalid") from error
    if not isinstance(payload, Mapping):
        raise ValidationError(f"recurring occurrence {name} must be an object")
    return payload


def _freeze_string_mapping(value: Mapping[str, str], name: str) -> Mapping[str, str]:
    if any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise ValidationError(f"recurring occurrence {name} must contain strings")
    return dict(sorted(value.items()))


def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValidationError(f"recurring occurrence {key} must be an object")
    return value


def _string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"recurring occurrence {key} must be a string")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise ValidationError(f"recurring occurrence {key} contains controls")
    return value


def _integer(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"recurring occurrence {key} must be an integer")
    return value


def _aware_datetime(data: Mapping[str, Any], key: str) -> datetime:
    try:
        value = datetime.fromisoformat(_string(data, key))
    except ValueError as error:
        raise ValidationError(f"recurring occurrence {key} is invalid") from error
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"recurring occurrence {key} must be timezone-aware")
    return value.astimezone(UTC)


def _unique_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate recurring occurrence JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite recurring occurrence number: {value}")


def _fingerprint(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
