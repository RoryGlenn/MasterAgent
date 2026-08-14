"""Typed domain models used by the governed runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
import math
from typing import Any, Mapping, Never
from uuid import UUID, uuid4

from master_agent.errors import ValidationError


class RiskLevel(StrEnum):
    """Risk category for an executable action."""

    READ_ONLY = "read_only"
    LOCAL_GENERATION = "local_generation"
    REVERSIBLE_WRITE = "reversible_write"
    EXTERNAL_COMMUNICATION = "external_communication"
    HIGH_IMPACT = "high_impact"
    DESTRUCTIVE = "destructive"


class AuthoritySource(StrEnum):
    """Source that authorizes an action."""

    DIRECT_USER = "direct_user"
    REGISTERED_WORKFLOW = "registered_workflow"
    ORGANIZATION_POLICY = "organization_policy"
    RETRIEVED_INTERNAL_CONTENT = "retrieved_internal_content"
    RETRIEVED_EXTERNAL_CONTENT = "retrieved_external_content"


class DataClassification(StrEnum):
    """Information classification carried by an action."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ActionState(StrEnum):
    """Terminal and non-terminal states for an action."""

    PLANNED = "planned"
    PERMITTED = "permitted"
    APPROVAL_REQUIRED = "approval_required"
    PROHIBITED = "prohibited"
    SKIPPED = "skipped"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    VERIFIED = "verified"
    CONFLICTED = "conflicted"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    COMPENSATION_FAILED = "compensation_failed"
    REUSED = "reused"
    INDETERMINATE = "indeterminate"


class CompensationMode(StrEnum):
    """How a compensation operation may be invoked."""

    PLAN = "plan"
    IN_PROCESS = "in_process"
    MANUAL = "manual"


@dataclass(frozen=True, slots=True)
class ResourceRef:
    """Reference to an internal or external resource.

    Parameters
    ----------
    system
        Connector system identifier, such as ``jira`` or ``confluence``.
    resource_type
        Domain resource type, such as ``issue`` or ``page``.
    resource_id
        Stable ID understood by the connector.
    expected_version
        Optional version precondition captured during planning.
    """

    system: str
    resource_type: str
    resource_id: str
    expected_version: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("system", self.system),
            ("resource_type", self.resource_type),
            ("resource_id", self.resource_id),
        ):
            if not value.strip():
                raise ValidationError(f"{name} must not be empty")

    @property
    def uri(self) -> str:
        """Return a stable URI-like representation."""

        return f"{self.system}:{self.resource_id}"


@dataclass(frozen=True, slots=True)
class AgentAction:
    """A validated, proposed operation.

    Parameters
    ----------
    capability
        Domain-specific capability name.
    target
        Target resource.
    parameters
        Structured connector parameters. Production connectors should replace
        this mapping with dedicated capability-specific parameter models.
    risk
        Risk tier used by policy.
    authority_source
        Source that authorizes the action.
    requires_approval
        Whether the planner believes approval is required. Policy may require
        approval even when this is false.
    idempotency_key
        Stable key that prevents duplicate execution.
    justification
        Human-readable reason for the action.
    dependencies
        Action IDs that must succeed before this action runs.
    action_id
        Unique action identifier.
    """

    capability: str
    target: ResourceRef
    parameters: Mapping[str, Any]
    risk: RiskLevel
    authority_source: AuthoritySource
    requires_approval: bool
    idempotency_key: str
    justification: str
    data_classification: DataClassification = DataClassification.INTERNAL
    dependencies: tuple[UUID, ...] = ()
    action_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.requires_approval, bool):
            raise ValidationError("requires_approval must be a boolean")
        if "." not in self.capability or not self.capability.strip():
            raise ValidationError(
                "capability must be a non-empty domain-specific dotted name"
            )
        if not self.idempotency_key.strip():
            raise ValidationError("idempotency_key must not be empty")
        if not self.justification.strip():
            raise ValidationError("justification must not be empty")
        if self.action_id in self.dependencies:
            raise ValidationError("an action cannot depend on itself")
        object.__setattr__(self, "parameters", _freeze_json_mapping(self.parameters))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the action to JSON-compatible data."""

        return {
            "action_id": str(self.action_id),
            "capability": self.capability,
            "target": {
                "system": self.target.system,
                "resource_type": self.target.resource_type,
                "resource_id": self.target.resource_id,
                "expected_version": self.target.expected_version,
            },
            "parameters": _jsonable(self.parameters),
            "risk": str(self.risk),
            "data_classification": str(self.data_classification),
            "authority_source": str(self.authority_source),
            "requires_approval": self.requires_approval,
            "idempotency_key": self.idempotency_key,
            "justification": self.justification,
            "dependencies": [str(item) for item in self.dependencies],
        }

    @property
    def effect_fingerprint(self) -> str:
        """Return a stable digest binding an idempotency key to one effect."""

        payload = {
            "capability": self.capability,
            "target": {
                "system": self.target.system,
                "resource_type": self.target.resource_type,
                "resource_id": self.target.resource_id,
                "expected_version": self.target.expected_version,
            },
            "parameters": _jsonable(self.parameters),
            "risk": str(self.risk),
            "data_classification": str(self.data_classification),
            "authority_source": str(self.authority_source),
            "requires_approval": self.requires_approval,
        }
        material = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentAction:
        """Create an action from JSON-compatible data."""

        target_data = _expect_mapping(data, "target")
        return cls(
            capability=str(data["capability"]),
            target=ResourceRef(
                system=str(target_data["system"]),
                resource_type=str(target_data["resource_type"]),
                resource_id=str(target_data["resource_id"]),
                expected_version=(
                    str(target_data["expected_version"])
                    if target_data.get("expected_version") is not None
                    else None
                ),
            ),
            parameters=dict(_expect_mapping(data, "parameters")),
            risk=RiskLevel(str(data["risk"])),
            data_classification=DataClassification(
                str(data.get("data_classification", DataClassification.INTERNAL))
            ),
            authority_source=AuthoritySource(str(data["authority_source"])),
            requires_approval=_strict_bool(data.get("requires_approval"), "requires_approval"),
            idempotency_key=str(data["idempotency_key"]),
            justification=str(data["justification"]),
            dependencies=tuple(UUID(str(item)) for item in data.get("dependencies", [])),
            action_id=UUID(str(data["action_id"])),
        )


@dataclass(frozen=True, slots=True)
class ChangePlan:
    """Immutable set of actions proposed for one user goal."""

    goal: str
    actions: tuple[AgentAction, ...]
    created_by: str
    plan_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "2.0"
    workflow_id: str | None = None
    workflow_fingerprint: str | None = None
    compensate_on_failure: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.compensate_on_failure, bool):
            raise ValidationError("compensate_on_failure must be a boolean")
        if not self.goal.strip():
            raise ValidationError("goal must not be empty")
        if not self.created_by.strip():
            raise ValidationError("created_by must not be empty")
        if self.workflow_id is not None and not self.workflow_id.strip():
            raise ValidationError("workflow_id must not be empty when supplied")
        if self.workflow_fingerprint is not None and not self.workflow_fingerprint.strip():
            raise ValidationError("workflow_fingerprint must not be empty when supplied")
        if self.workflow_fingerprint is not None and self.workflow_id is None:
            raise ValidationError("workflow_fingerprint requires workflow_id")
        object.__setattr__(self, "actions", tuple(self.actions))
        if not self.actions:
            raise ValidationError("a change plan must contain at least one action")
        action_ids = [action.action_id for action in self.actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValidationError("action IDs must be unique")
        idempotency_keys = [action.idempotency_key for action in self.actions]
        if len(idempotency_keys) != len(set(idempotency_keys)):
            raise ValidationError("idempotency keys must be unique within a plan")
        known = set(action_ids)
        for action in self.actions:
            unknown = set(action.dependencies) - known
            if unknown:
                raise ValidationError(
                    f"action {action.action_id} has unknown dependencies: {unknown}"
                )
        _validate_acyclic(self.actions)

    @property
    def fingerprint(self) -> str:
        """Return the immutable SHA-256 fingerprint used by approvals."""

        payload = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the plan to JSON-compatible data."""

        return {
            "schema_version": self.schema_version,
            "plan_id": str(self.plan_id),
            "goal": self.goal,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "workflow_id": self.workflow_id,
            "workflow_fingerprint": self.workflow_fingerprint,
            "compensate_on_failure": self.compensate_on_failure,
            "actions": [action.to_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangePlan:
        """Create a plan from JSON-compatible data."""

        actions_data = data.get("actions")
        if not isinstance(actions_data, list):
            raise ValidationError("actions must be a list")
        return cls(
            schema_version=str(data.get("schema_version", "1.0")),
            plan_id=UUID(str(data["plan_id"])),
            goal=str(data["goal"]),
            created_by=str(data["created_by"]),
            created_at=datetime.fromisoformat(str(data["created_at"])),
            workflow_id=(
                str(data["workflow_id"])
                if data.get("workflow_id") is not None
                else None
            ),
            workflow_fingerprint=(
                str(data["workflow_fingerprint"])
                if data.get("workflow_fingerprint") is not None
                else None
            ),
            compensate_on_failure=_strict_bool(
                data.get("compensate_on_failure", False),
                "compensate_on_failure",
            ),
            actions=tuple(AgentAction.from_dict(item) for item in actions_data),
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """Approval bound to an immutable plan and explicit actions."""

    plan_fingerprint: str
    approved_action_ids: tuple[UUID, ...]
    approved_by: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature: str
    signature_scheme: str = "hmac-sha256"
    approval_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.plan_fingerprint.strip():
            raise ValidationError("plan_fingerprint must not be empty")
        if not self.approved_action_ids:
            raise ValidationError("approval must cover at least one action")
        object.__setattr__(self, "approved_action_ids", tuple(self.approved_action_ids))
        if not self.approved_by.strip():
            raise ValidationError("approved_by must not be empty")
        if self.approved_by != self.approved_by.strip():
            raise ValidationError("approved_by must not contain surrounding whitespace")
        if not self.key_id.strip() or self.key_id != self.key_id.strip():
            raise ValidationError("key_id must be a non-empty normalized identifier")
        if not self.signature.strip():
            raise ValidationError("approval signature must not be empty")
        if not self.signature_scheme.strip():
            raise ValidationError("approval signature scheme must not be empty")
        if self.expires_at <= self.issued_at:
            raise ValidationError("approval must expire after it is issued")

    def covers(self, plan: ChangePlan, action: AgentAction, now: datetime) -> bool:
        """Return whether the approval covers an action in an exact plan."""

        return (
            self.plan_fingerprint == plan.fingerprint
            and action.action_id in self.approved_action_ids
            and self.issued_at <= now < self.expires_at
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the approval to JSON-compatible data."""

        return {
            "approval_id": str(self.approval_id),
            "plan_fingerprint": self.plan_fingerprint,
            "approved_action_ids": [str(item) for item in self.approved_action_ids],
            "approved_by": self.approved_by,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "key_id": self.key_id,
            "signature_scheme": self.signature_scheme,
            "signature": self.signature,
        }

    def signing_payload(self) -> bytes:
        """Return the canonical byte sequence authenticated by the signature."""

        payload = self.to_dict()
        payload.pop("signature")
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Approval:
        """Create an approval from JSON-compatible data."""

        return cls(
            approval_id=UUID(str(data["approval_id"])),
            plan_fingerprint=str(data["plan_fingerprint"]),
            approved_action_ids=tuple(
                UUID(str(item)) for item in data["approved_action_ids"]
            ),
            approved_by=str(data["approved_by"]),
            issued_at=datetime.fromisoformat(str(data["issued_at"])),
            expires_at=datetime.fromisoformat(str(data["expires_at"])),
            key_id=str(data["key_id"]),
            signature=str(data["signature"]),
            signature_scheme=str(data.get("signature_scheme", "hmac-sha256")),
        )


@dataclass(frozen=True, slots=True)
class CompensationDescriptor:
    """Typed, persisted description of an available rollback operation."""

    kind: str
    mode: CompensationMode
    capability: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    expected_version: str | None = None
    target_resource_id: str | None = None
    reason: str | None = None
    schema: str = "master-agent/compensation@1"

    def __post_init__(self) -> None:
        if not self.kind.strip():
            raise ValidationError("compensation kind must not be empty")
        if self.mode is CompensationMode.PLAN and not (
            self.capability and self.capability.strip()
        ):
            raise ValidationError(
                "plan compensation requires an executable capability"
            )
        if self.mode is not CompensationMode.PLAN and not (
            self.reason and self.reason.strip()
        ):
            raise ValidationError(
                "non-plan compensation requires an operator-facing reason"
            )
        object.__setattr__(self, "parameters", _freeze_json_mapping(self.parameters))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the descriptor to a stable versioned object."""

        return {
            "schema": self.schema,
            "kind": self.kind,
            "mode": str(self.mode),
            "capability": self.capability,
            "parameters": _jsonable(self.parameters),
            "expected_version": self.expected_version,
            "target_resource_id": self.target_resource_id,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompensationDescriptor":
        """Parse a versioned descriptor or a supported legacy descriptor."""

        if data.get("schema") == "master-agent/compensation@1":
            parameters = data.get("parameters", {})
            if not isinstance(parameters, Mapping):
                raise ValidationError("compensation parameters must be an object")
            return cls(
                schema=str(data["schema"]),
                kind=str(data["kind"]),
                mode=CompensationMode(str(data["mode"])),
                capability=(
                    str(data["capability"])
                    if data.get("capability") is not None
                    else None
                ),
                parameters=dict(parameters),
                expected_version=(
                    str(data["expected_version"])
                    if data.get("expected_version") is not None
                    else None
                ),
                target_resource_id=(
                    str(data["target_resource_id"])
                    if data.get("target_resource_id") is not None
                    else None
                ),
                reason=(
                    str(data["reason"])
                    if data.get("reason") is not None
                    else None
                ),
            )

        capability = str(data.get("capability", "")).strip()
        excluded = {
            "capability",
            "expected_version",
            "kind",
            "automatic_delete_disabled",
            "automatic_remote_branch_delete_disabled",
        }
        if capability:
            return cls(
                kind=str(data.get("kind", "legacy_plan_compensation")),
                mode=CompensationMode.PLAN,
                capability=capability,
                parameters={
                    str(key): value
                    for key, value in data.items()
                    if key not in excluded and value is not None
                },
                expected_version=(
                    str(data["expected_version"])
                    if data.get("expected_version") is not None
                    else None
                ),
            )
        return cls(
            kind=str(data.get("kind", "legacy_in_process_compensation")),
            mode=CompensationMode.IN_PROCESS,
            reason="connector only exposes in-process compensation",
        )


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Structured connector execution result."""

    action_id: UUID
    state: ActionState
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None
    connector_reference: str | None = None
    message: str = ""
    compensation: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to JSON-compatible data."""

        return {
            "action_id": str(self.action_id),
            "state": str(self.state),
            "before": _jsonable(self.before),
            "after": _jsonable(self.after),
            "connector_reference": self.connector_reference,
            "message": self.message,
            "compensation": _jsonable(self.compensation),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionResult":
        """Create an execution result from JSON-compatible data."""

        before = data.get("before")
        after = data.get("after")
        compensation = data.get("compensation")
        if before is not None and not isinstance(before, Mapping):
            raise ValidationError("execution result before must be an object or null")
        if after is not None and not isinstance(after, Mapping):
            raise ValidationError("execution result after must be an object or null")
        if compensation is not None and not isinstance(compensation, Mapping):
            raise ValidationError(
                "execution result compensation must be an object or null"
            )
        return cls(
            action_id=UUID(str(data["action_id"])),
            state=ActionState(str(data["state"])),
            before=dict(before) if isinstance(before, Mapping) else None,
            after=dict(after) if isinstance(after, Mapping) else None,
            connector_reference=(
                str(data["connector_reference"])
                if data.get("connector_reference") is not None
                else None
            ),
            message=str(data.get("message", "")),
            compensation=(
                dict(compensation) if isinstance(compensation, Mapping) else None
            ),
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Result of independent post-execution verification."""

    action_id: UUID
    verified: bool
    observed: Mapping[str, Any] | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the verification result."""

        return {
            "action_id": str(self.action_id),
            "verified": self.verified,
            "observed": _jsonable(self.observed),
            "message": self.message,
        }



def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be a boolean")
    return value

def _expect_mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValidationError(f"{key} must be an object")
    return value


def _jsonable(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [_jsonable(item) for item in value]
    return value


def _freeze_json_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Recursively freeze and validate a JSON-compatible mapping."""

    frozen = _freeze_json(value, path="mapping")
    if not isinstance(frozen, Mapping):  # pragma: no cover - type guard.
        raise ValidationError("value must be an object")
    return frozen


def _freeze_json(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"{path} keys must be strings")
            frozen[key] = _freeze_json(item, path=f"{path}.{key}")
        return _FrozenDict(frozen)
    if isinstance(value, (tuple, list)):
        return _FrozenList(
            _freeze_json(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{path} contains a non-finite number")
        return value
    raise ValidationError(
        f"{path} contains a non-JSON-compatible value: {type(value).__name__}"
    )


class _FrozenDict(dict[str, Any]):
    """A JSON-serializable dictionary that rejects ordinary mutation."""

    def _immutable(self, *_args: Any, **_kwargs: Any) -> Never:
        raise TypeError("approved action parameters are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __deepcopy__(self, _memo: dict[int, Any]) -> "_FrozenDict":
        return self


class _FrozenList(list[Any]):
    """A JSON-serializable list that rejects ordinary mutation."""

    def _immutable(self, *_args: Any, **_kwargs: Any) -> Never:
        raise TypeError("approved action parameters are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __deepcopy__(self, _memo: dict[int, Any]) -> "_FrozenList":
        return self


def _validate_acyclic(actions: tuple[AgentAction, ...]) -> None:
    dependencies = {
        action.action_id: set(action.dependencies) for action in actions
    }
    visiting: set[UUID] = set()
    visited: set[UUID] = set()

    def visit(action_id: UUID) -> None:
        if action_id in visited:
            return
        if action_id in visiting:
            raise ValidationError("action dependency graph contains a cycle")
        visiting.add(action_id)
        for dependency in dependencies[action_id]:
            visit(dependency)
        visiting.remove(action_id)
        visited.add(action_id)

    for current in dependencies:
        visit(current)
