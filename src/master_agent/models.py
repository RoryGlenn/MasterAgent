"""Typed domain models used by the governed runtime."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from master_agent.errors import ValidationError
from master_agent.platform_runtime.contracts import (
    FilesystemObjectKind,
    PlatformObjectIdentity,
)
from master_agent.resource_limits import (
    MAX_ACTION_DEPENDENCIES,
    MAX_ACTION_PARAMETER_BYTES,
    MAX_PLAN_ACTIONS,
    MAX_PLAN_BYTES,
    MAX_PLAN_PARAMETER_BYTES,
    measure_json_resources,
    validate_bounded_string,
)

_CAPSULE_CAPABILITY_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9][a-z0-9_-]*)+")
_CAPSULE_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_STRATEGY_INTENT_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")


class RiskLevel(StrEnum):
    """Risk category for an executable action."""

    READ_ONLY = "read_only"
    LOCAL_GENERATION = "local_generation"
    REVERSIBLE_WRITE = "reversible_write"
    EXTERNAL_COMMUNICATION = "external_communication"
    HIGH_IMPACT = "high_impact"
    DESTRUCTIVE = "destructive"


class SystemsGateRoute(StrEnum):
    """Path selected by the systems-governance gate."""

    FAST_PATH = "fast_path"
    GATED = "gated"


class ComplexityKind(StrEnum):
    """Kinds of durable complexity introduced by an intervention."""

    DEPENDENCY = "dependency"
    PERSISTENT_SERVICE = "persistent_service"
    AGENT = "agent"
    CONFIGURATION_SURFACE = "configuration_surface"
    AUTHORITATIVE_DOCUMENT = "authoritative_document"
    STATE_STORE = "state_store"
    CONNECTOR = "connector"
    USER_WORKFLOW = "user_workflow"


_COMPLEXITY_WEIGHTS: dict[ComplexityKind, int] = {
    ComplexityKind.DEPENDENCY: 1,
    ComplexityKind.PERSISTENT_SERVICE: 2,
    ComplexityKind.AGENT: 2,
    ComplexityKind.CONFIGURATION_SURFACE: 1,
    ComplexityKind.AUTHORITATIVE_DOCUMENT: 1,
    ComplexityKind.STATE_STORE: 2,
    ComplexityKind.CONNECTOR: 1,
    ComplexityKind.USER_WORKFLOW: 1,
}


@dataclass(frozen=True, slots=True)
class ComplexityItem:
    """One weighted complexity cost introduced by an intervention."""

    kind: ComplexityKind
    description: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ComplexityKind):
            raise ValidationError("complexity item kind is invalid")
        _require_systems_text(self.description, "complexity item description")

    @property
    def weight(self) -> int:
        """Return the budget cost for this item."""

        return _COMPLEXITY_WEIGHTS[self.kind]

    def to_dict(self) -> dict[str, object]:
        """Serialize the complexity item."""

        return {
            "kind": str(self.kind),
            "description": self.description,
            "weight": self.weight,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ComplexityItem:
        """Parse one complexity item and reject forged weights."""

        item = cls(
            kind=ComplexityKind(str(data.get("kind", ""))),
            description=str(data.get("description", "")),
        )
        supplied_weight = _strict_int(data.get("weight"), "complexity item weight")
        if supplied_weight != item.weight:
            raise ValidationError("complexity item weight does not match its kind")
        return item


@dataclass(frozen=True, slots=True)
class StrategyActionIntent:
    """One bounded action intent that follows a strategy's guiding policy."""

    intent_id: str
    description: str
    expected_effect: str
    schema: str = "master-agent/strategy-action-intent@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/strategy-action-intent@1":
            raise ValidationError("unsupported strategy action intent schema")
        if _STRATEGY_INTENT_PATTERN.fullmatch(self.intent_id) is None:
            raise ValidationError("strategy action intent ID is invalid")
        _require_systems_text(self.description, "strategy action description")
        _require_systems_text(self.expected_effect, "strategy expected effect")

    def to_dict(self) -> dict[str, object]:
        """Serialize the coherent-action intent."""

        return {
            "schema": self.schema,
            "intent_id": self.intent_id,
            "description": self.description,
            "expected_effect": self.expected_effect,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StrategyActionIntent:
        """Parse one coherent-action intent."""

        return cls(
            schema=str(data.get("schema", "")),
            intent_id=str(data.get("intent_id", "")),
            description=str(data.get("description", "")),
            expected_effect=str(data.get("expected_effect", "")),
        )


@dataclass(frozen=True, slots=True)
class StrategyKernel:
    """A bounded diagnosis, guiding policy, and coherent action set."""

    diagnosis: str
    guiding_policy: str
    proximate_objective: str
    tradeoffs: tuple[str, ...]
    coherent_actions: tuple[StrategyActionIntent, ...]
    schema: str = "master-agent/strategy-kernel@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/strategy-kernel@1":
            raise ValidationError("unsupported strategy kernel schema")
        for name in ("diagnosis", "guiding_policy", "proximate_objective"):
            _require_systems_text(getattr(self, name), f"strategy {name}")
        tradeoffs = tuple(islice(iter(self.tradeoffs), MAX_PLAN_ACTIONS + 1))
        if len(tradeoffs) > MAX_PLAN_ACTIONS:
            raise ValidationError(
                f"strategy kernel exceeds the {MAX_PLAN_ACTIONS}-tradeoff limit"
            )
        tradeoffs = _normalize_systems_text_tuple(tradeoffs, "strategy tradeoffs")
        if not tradeoffs:
            raise ValidationError("strategy kernel must state at least one tradeoff")
        object.__setattr__(self, "tradeoffs", tradeoffs)
        coherent_actions = tuple(
            islice(iter(self.coherent_actions), MAX_PLAN_ACTIONS + 1)
        )
        if len(coherent_actions) > MAX_PLAN_ACTIONS:
            raise ValidationError(
                f"strategy kernel exceeds the {MAX_PLAN_ACTIONS}-intent limit"
            )
        if not coherent_actions or not all(
            isinstance(item, StrategyActionIntent) for item in coherent_actions
        ):
            raise ValidationError(
                "strategy kernel must contain coherent StrategyActionIntent values"
            )
        intent_ids = [item.intent_id for item in coherent_actions]
        if len(intent_ids) != len(set(intent_ids)):
            raise ValidationError("strategy coherent action IDs must be unique")
        object.__setattr__(self, "coherent_actions", coherent_actions)

    @property
    def fingerprint(self) -> str:
        """Return the stable digest of the complete strategy kernel."""

        return _stable_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        """Serialize the strategy kernel."""

        return {
            "schema": self.schema,
            "diagnosis": self.diagnosis,
            "guiding_policy": self.guiding_policy,
            "proximate_objective": self.proximate_objective,
            "tradeoffs": list(self.tradeoffs),
            "coherent_actions": [item.to_dict() for item in self.coherent_actions],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StrategyKernel:
        """Parse a strategy kernel from a bounded assessment payload."""

        raw_actions = data.get("coherent_actions")
        if not isinstance(raw_actions, list) or not all(
            isinstance(item, Mapping) for item in raw_actions
        ):
            raise ValidationError("strategy coherent_actions must be a list")
        return cls(
            schema=str(data.get("schema", "")),
            diagnosis=str(data.get("diagnosis", "")),
            guiding_policy=str(data.get("guiding_policy", "")),
            proximate_objective=str(data.get("proximate_objective", "")),
            tradeoffs=_systems_text_list(data, "tradeoffs"),
            coherent_actions=tuple(
                StrategyActionIntent.from_dict(item) for item in raw_actions
            ),
        )


@dataclass(frozen=True, slots=True)
class StrategyActionTrace:
    """Bind one exact plan action to one strategy action intent."""

    action_id: UUID
    intent_id: str
    schema: str = "master-agent/strategy-action-trace@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/strategy-action-trace@1":
            raise ValidationError("unsupported strategy action trace schema")
        if not isinstance(self.action_id, UUID):
            raise ValidationError("strategy action trace action_id is invalid")
        if _STRATEGY_INTENT_PATTERN.fullmatch(self.intent_id) is None:
            raise ValidationError("strategy action trace intent_id is invalid")

    def to_dict(self) -> dict[str, object]:
        """Serialize the strategy trace."""

        return {
            "schema": self.schema,
            "action_id": str(self.action_id),
            "intent_id": self.intent_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StrategyActionTrace:
        """Parse a strategy trace."""

        return cls(
            schema=str(data.get("schema", "")),
            action_id=UUID(str(data.get("action_id", ""))),
            intent_id=str(data.get("intent_id", "")),
        )


@dataclass(frozen=True, slots=True)
class SystemsAssessment:
    """Structured diagnosis completed before non-trivial planning."""

    desired_outcome: str
    current_behavior: str
    constraint: str
    leverage_point: str
    simplest_intervention: str
    success_metric: str
    failure_condition: str
    low_risk: bool
    reversible: bool
    well_understood: bool
    stocks: tuple[str, ...] = ()
    flows: tuple[str, ...] = ()
    feedback_loops: tuple[str, ...] = ()
    delays: tuple[str, ...] = ()
    unintended_consequences: tuple[str, ...] = ()
    removable_complexity: tuple[str, ...] = ()
    alternatives_considered: tuple[str, ...] = ()
    added_complexity: tuple[ComplexityItem, ...] = ()
    existing_mechanisms_insufficient_because: str = ""
    reversibility_strategy: str = ""
    strategy_kernel: StrategyKernel | None = None
    schema: str = "master-agent/systems-assessment@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/systems-assessment@1":
            raise ValidationError("unsupported systems assessment schema")
        for name in (
            "desired_outcome",
            "current_behavior",
            "constraint",
            "leverage_point",
            "simplest_intervention",
            "success_metric",
            "failure_condition",
        ):
            _require_systems_text(getattr(self, name), f"systems assessment {name}")
        for name in ("low_risk", "reversible", "well_understood"):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"systems assessment {name} must be a boolean")
        for name in (
            "stocks",
            "flows",
            "feedback_loops",
            "delays",
            "unintended_consequences",
            "removable_complexity",
            "alternatives_considered",
        ):
            object.__setattr__(
                self,
                name,
                _normalize_systems_text_tuple(
                    getattr(self, name), f"systems assessment {name}"
                ),
            )
        complexity = tuple(self.added_complexity)
        if not all(isinstance(item, ComplexityItem) for item in complexity):
            raise ValidationError(
                "systems assessment added_complexity must contain ComplexityItem values"
            )
        object.__setattr__(self, "added_complexity", complexity)
        for name in (
            "existing_mechanisms_insufficient_because",
            "reversibility_strategy",
        ):
            value = getattr(self, name)
            if value:
                _require_systems_text(value, f"systems assessment {name}")
        if self.strategy_kernel is not None and not isinstance(
            self.strategy_kernel, StrategyKernel
        ):
            raise ValidationError(
                "systems assessment strategy_kernel must be a StrategyKernel"
            )

    @classmethod
    def for_fast_path(
        cls,
        *,
        desired_outcome: str,
        current_behavior: str,
        constraint: str,
        leverage_point: str,
        simplest_intervention: str,
        success_metric: str,
        failure_condition: str,
    ) -> SystemsAssessment:
        """Construct an explicit known-safe static workflow assessment."""

        return cls(
            desired_outcome=desired_outcome,
            current_behavior=current_behavior,
            constraint=constraint,
            leverage_point=leverage_point,
            simplest_intervention=simplest_intervention,
            success_metric=success_metric,
            failure_condition=failure_condition,
            low_risk=True,
            reversible=True,
            well_understood=True,
        )

    @classmethod
    def for_static_intervention(
        cls,
        *,
        desired_outcome: str,
        current_behavior: str,
        constraint: str,
        stocks: tuple[str, ...],
        flows: tuple[str, ...],
        feedback_loops: tuple[str, ...],
        delays: tuple[str, ...],
        leverage_point: str,
        simplest_intervention: str,
        success_metric: str,
        failure_condition: str,
        unintended_consequences: tuple[str, ...],
        removable_complexity: tuple[str, ...],
        strategy_kernel: StrategyKernel,
        reversible: bool,
        well_understood: bool,
        alternatives_considered: tuple[str, ...] = (),
        added_complexity: tuple[ComplexityItem, ...] = (),
        existing_mechanisms_insufficient_because: str = "",
        reversibility_strategy: str = "",
    ) -> SystemsAssessment:
        """Construct an explicit assessment for one static effect workflow."""

        return cls(
            desired_outcome=desired_outcome,
            current_behavior=current_behavior,
            constraint=constraint,
            stocks=stocks,
            flows=flows,
            feedback_loops=feedback_loops,
            delays=delays,
            leverage_point=leverage_point,
            simplest_intervention=simplest_intervention,
            success_metric=success_metric,
            failure_condition=failure_condition,
            unintended_consequences=unintended_consequences,
            removable_complexity=removable_complexity,
            alternatives_considered=alternatives_considered,
            added_complexity=added_complexity,
            existing_mechanisms_insufficient_because=(
                existing_mechanisms_insufficient_because
            ),
            reversibility_strategy=reversibility_strategy,
            low_risk=False,
            reversible=reversible,
            well_understood=well_understood,
            strategy_kernel=strategy_kernel,
        )

    @property
    def fast_path_requested(self) -> bool:
        """Return whether all explicit fast-path predicates are true."""

        return self.low_risk and self.reversible and self.well_understood

    @property
    def complexity_score(self) -> int:
        """Return the total weighted complexity cost."""

        return sum(item.weight for item in self.added_complexity)

    @property
    def success_metric_sha256(self) -> str:
        """Return the content-free identity of the stated success metric."""

        return hashlib.sha256(self.success_metric.encode("utf-8")).hexdigest()

    @property
    def fingerprint(self) -> str:
        """Return a stable digest that binds a decision to this assessment."""

        return _stable_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        """Serialize the assessment to JSON-compatible data."""

        payload: dict[str, object] = {
            "schema": self.schema,
            "desired_outcome": self.desired_outcome,
            "current_behavior": self.current_behavior,
            "constraint": self.constraint,
            "stocks": list(self.stocks),
            "flows": list(self.flows),
            "feedback_loops": list(self.feedback_loops),
            "delays": list(self.delays),
            "leverage_point": self.leverage_point,
            "simplest_intervention": self.simplest_intervention,
            "success_metric": self.success_metric,
            "failure_condition": self.failure_condition,
            "unintended_consequences": list(self.unintended_consequences),
            "removable_complexity": list(self.removable_complexity),
            "alternatives_considered": list(self.alternatives_considered),
            "added_complexity": [item.to_dict() for item in self.added_complexity],
            "existing_mechanisms_insufficient_because": (
                self.existing_mechanisms_insufficient_because
            ),
            "reversibility_strategy": self.reversibility_strategy,
            "low_risk": self.low_risk,
            "reversible": self.reversible,
            "well_understood": self.well_understood,
            "complexity_score": self.complexity_score,
        }
        if self.strategy_kernel is not None:
            payload["strategy_kernel"] = self.strategy_kernel.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SystemsAssessment:
        """Parse a systems assessment from a bounded plan payload."""

        raw_complexity = data.get("added_complexity", [])
        if not isinstance(raw_complexity, list) or not all(
            isinstance(item, Mapping) for item in raw_complexity
        ):
            raise ValidationError("systems assessment added_complexity must be a list")
        raw_strategy = data.get("strategy_kernel")
        if raw_strategy is not None and not isinstance(raw_strategy, Mapping):
            raise ValidationError(
                "systems assessment strategy_kernel must be an object"
            )
        assessment = cls(
            schema=str(data.get("schema", "")),
            desired_outcome=str(data.get("desired_outcome", "")),
            current_behavior=str(data.get("current_behavior", "")),
            constraint=str(data.get("constraint", "")),
            stocks=_systems_text_list(data, "stocks"),
            flows=_systems_text_list(data, "flows"),
            feedback_loops=_systems_text_list(data, "feedback_loops"),
            delays=_systems_text_list(data, "delays"),
            leverage_point=str(data.get("leverage_point", "")),
            simplest_intervention=str(data.get("simplest_intervention", "")),
            success_metric=str(data.get("success_metric", "")),
            failure_condition=str(data.get("failure_condition", "")),
            unintended_consequences=_systems_text_list(data, "unintended_consequences"),
            removable_complexity=_systems_text_list(data, "removable_complexity"),
            alternatives_considered=_systems_text_list(data, "alternatives_considered"),
            added_complexity=tuple(
                ComplexityItem.from_dict(item) for item in raw_complexity
            ),
            existing_mechanisms_insufficient_because=str(
                data.get("existing_mechanisms_insufficient_because", "")
            ),
            reversibility_strategy=str(data.get("reversibility_strategy", "")),
            low_risk=_strict_bool(data.get("low_risk"), "systems assessment low_risk"),
            reversible=_strict_bool(
                data.get("reversible"), "systems assessment reversible"
            ),
            well_understood=_strict_bool(
                data.get("well_understood"), "systems assessment well_understood"
            ),
            strategy_kernel=(
                StrategyKernel.from_dict(raw_strategy)
                if isinstance(raw_strategy, Mapping)
                else None
            ),
        )
        if data.get("complexity_score") != assessment.complexity_score:
            raise ValidationError(
                "systems assessment complexity score does not match its items"
            )
        return assessment


_STRATEGY_COHERENCE_FINDINGS: tuple[str, ...] = (
    "diagnosis_addresses_constraint",
    "guiding_policy_targets_leverage_point",
    "proximate_objective_advances_outcome",
    "coherent_actions_support_success_metric",
    "tradeoffs_cover_alternatives",
)


@dataclass(frozen=True, slots=True)
class StrategyCoherenceReview:
    """Fingerprint-bound findings from a trusted strategy review boundary."""

    assessment_fingerprint: str
    strategy_kernel_fingerprint: str
    diagnosis_addresses_constraint: bool
    guiding_policy_targets_leverage_point: bool
    proximate_objective_advances_outcome: bool
    coherent_actions_support_success_metric: bool
    tradeoffs_cover_alternatives: bool
    reason_codes: tuple[str, ...]
    schema: str = "master-agent/strategy-coherence-review@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/strategy-coherence-review@1":
            raise ValidationError("unsupported strategy coherence review schema")
        for name in ("assessment_fingerprint", "strategy_kernel_fingerprint"):
            if re.fullmatch(r"[0-9a-f]{64}", getattr(self, name)) is None:
                raise ValidationError(
                    f"strategy coherence {name} must be a SHA-256 digest"
                )
        for name in _STRATEGY_COHERENCE_FINDINGS:
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"strategy coherence {name} must be a boolean")
        codes = tuple(islice(iter(self.reason_codes), MAX_PLAN_ACTIONS + 1))
        if len(codes) > MAX_PLAN_ACTIONS:
            raise ValidationError(
                f"strategy coherence exceeds the {MAX_PLAN_ACTIONS}-reason limit"
            )
        if any(
            not isinstance(item, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None
            for item in codes
        ):
            raise ValidationError("strategy coherence reason codes are invalid")
        if len(codes) != len(set(codes)):
            raise ValidationError("strategy coherence reason codes must be unique")
        missing = {
            name
            for name in _STRATEGY_COHERENCE_FINDINGS
            if getattr(self, name) and name not in codes
        }
        if missing:
            raise ValidationError(
                "positive strategy coherence findings require matching reason codes: "
                + ", ".join(sorted(missing))
            )
        object.__setattr__(self, "reason_codes", codes)

    @classmethod
    def for_review(
        cls,
        *,
        assessment: SystemsAssessment,
        diagnosis_addresses_constraint: bool,
        guiding_policy_targets_leverage_point: bool,
        proximate_objective_advances_outcome: bool,
        coherent_actions_support_success_metric: bool,
        tradeoffs_cover_alternatives: bool,
        reason_codes: tuple[str, ...],
    ) -> StrategyCoherenceReview:
        """Bind explicit coherence findings to one exact assessment and kernel."""

        kernel = assessment.strategy_kernel
        if kernel is None:
            raise ValidationError(
                "strategy coherence review requires a strategy kernel"
            )
        return cls(
            assessment_fingerprint=assessment.fingerprint,
            strategy_kernel_fingerprint=kernel.fingerprint,
            diagnosis_addresses_constraint=diagnosis_addresses_constraint,
            guiding_policy_targets_leverage_point=(
                guiding_policy_targets_leverage_point
            ),
            proximate_objective_advances_outcome=(proximate_objective_advances_outcome),
            coherent_actions_support_success_metric=(
                coherent_actions_support_success_metric
            ),
            tradeoffs_cover_alternatives=tradeoffs_cover_alternatives,
            reason_codes=reason_codes,
        )

    @classmethod
    def for_static_intervention(
        cls, assessment: SystemsAssessment
    ) -> StrategyCoherenceReview:
        """Record the explicit code-owned review of a registered intervention."""

        return cls.for_review(
            assessment=assessment,
            diagnosis_addresses_constraint=True,
            guiding_policy_targets_leverage_point=True,
            proximate_objective_advances_outcome=True,
            coherent_actions_support_success_metric=True,
            tradeoffs_cover_alternatives=True,
            reason_codes=(*_STRATEGY_COHERENCE_FINDINGS, "static_intervention"),
        )

    @property
    def fingerprint(self) -> str:
        """Return the stable digest of the complete coherence review."""

        return _stable_sha256(self.to_dict())

    @property
    def all_findings_confirmed(self) -> bool:
        """Return whether the trusted boundary confirmed every relationship."""

        return all(getattr(self, name) for name in _STRATEGY_COHERENCE_FINDINGS)

    def to_dict(self) -> dict[str, object]:
        """Serialize the content-free coherence review."""

        return {
            "schema": self.schema,
            "assessment_fingerprint": self.assessment_fingerprint,
            "strategy_kernel_fingerprint": self.strategy_kernel_fingerprint,
            **{name: getattr(self, name) for name in _STRATEGY_COHERENCE_FINDINGS},
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StrategyCoherenceReview:
        """Parse bounded coherence-review evidence."""

        return cls(
            schema=str(data.get("schema", "")),
            assessment_fingerprint=str(data.get("assessment_fingerprint", "")),
            strategy_kernel_fingerprint=str(
                data.get("strategy_kernel_fingerprint", "")
            ),
            diagnosis_addresses_constraint=_strict_bool(
                data.get("diagnosis_addresses_constraint"),
                "strategy coherence diagnosis_addresses_constraint",
            ),
            guiding_policy_targets_leverage_point=_strict_bool(
                data.get("guiding_policy_targets_leverage_point"),
                "strategy coherence guiding_policy_targets_leverage_point",
            ),
            proximate_objective_advances_outcome=_strict_bool(
                data.get("proximate_objective_advances_outcome"),
                "strategy coherence proximate_objective_advances_outcome",
            ),
            coherent_actions_support_success_metric=_strict_bool(
                data.get("coherent_actions_support_success_metric"),
                "strategy coherence coherent_actions_support_success_metric",
            ),
            tradeoffs_cover_alternatives=_strict_bool(
                data.get("tradeoffs_cover_alternatives"),
                "strategy coherence tradeoffs_cover_alternatives",
            ),
            reason_codes=_systems_text_list(data, "reason_codes"),
        )


@dataclass(frozen=True, slots=True)
class SystemsGateDecision:
    """Immutable result of evaluating one plan and assessment.

    ``permitted`` records structural eligibility. A true
    ``requires_human_review`` still blocks runtime admission until the policy
    engine authenticates an exact whole-plan approval.
    """

    route: SystemsGateRoute
    permitted: bool
    reasons: tuple[str, ...]
    complexity_score: int
    assessment_fingerprint: str
    requires_human_review: bool = False
    strategy_coherence_review_fingerprint: str | None = None
    schema: str = "master-agent/systems-gate-decision@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/systems-gate-decision@1":
            raise ValidationError("unsupported systems gate decision schema")
        if not isinstance(self.route, SystemsGateRoute):
            raise ValidationError("systems gate decision route is invalid")
        if not isinstance(self.permitted, bool):
            raise ValidationError("systems gate decision permitted must be a boolean")
        if not isinstance(self.requires_human_review, bool):
            raise ValidationError(
                "systems gate decision requires_human_review must be a boolean"
            )
        reasons = _normalize_systems_text_tuple(self.reasons, "systems gate reasons")
        if not reasons:
            raise ValidationError("systems gate decision must include a reason")
        object.__setattr__(self, "reasons", reasons)
        if (
            not isinstance(self.complexity_score, int)
            or isinstance(self.complexity_score, bool)
            or self.complexity_score < 0
        ):
            raise ValidationError("systems gate complexity score cannot be negative")
        if not re.fullmatch(r"[0-9a-f]{64}", self.assessment_fingerprint):
            raise ValidationError(
                "systems gate assessment fingerprint must be a SHA-256 digest"
            )
        if self.strategy_coherence_review_fingerprint is not None and (
            re.fullmatch(r"[0-9a-f]{64}", self.strategy_coherence_review_fingerprint)
            is None
        ):
            raise ValidationError(
                "systems gate strategy coherence fingerprint must be a SHA-256 digest"
            )

    @property
    def fingerprint(self) -> str:
        """Return the stable digest of the complete gate decision."""

        return _stable_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        """Serialize the gate decision."""

        payload: dict[str, object] = {
            "schema": self.schema,
            "route": str(self.route),
            "permitted": self.permitted,
            "reasons": list(self.reasons),
            "complexity_score": self.complexity_score,
            "assessment_fingerprint": self.assessment_fingerprint,
            "requires_human_review": self.requires_human_review,
        }
        if self.strategy_coherence_review_fingerprint is not None:
            payload["strategy_coherence_review_fingerprint"] = (
                self.strategy_coherence_review_fingerprint
            )
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SystemsGateDecision:
        """Parse a gate decision from a plan payload."""

        return cls(
            schema=str(data.get("schema", "")),
            route=SystemsGateRoute(str(data.get("route", ""))),
            permitted=_strict_bool(
                data.get("permitted"), "systems gate decision permitted"
            ),
            reasons=_systems_text_list(data, "reasons"),
            complexity_score=_strict_int(
                data.get("complexity_score"),
                "systems gate decision complexity_score",
            ),
            assessment_fingerprint=str(data.get("assessment_fingerprint", "")),
            requires_human_review=_strict_bool(
                data.get("requires_human_review", False),
                "systems gate decision requires_human_review",
            ),
            strategy_coherence_review_fingerprint=(
                str(data["strategy_coherence_review_fingerprint"])
                if data.get("strategy_coherence_review_fingerprint") is not None
                else None
            ),
        )


class SystemsMetricStatus(StrEnum):
    """Conservative result of checking the intervention success metric."""

    NOT_OBSERVED = "not_observed"
    CONFIRMED_MOVED = "confirmed_moved"
    CONFIRMED_UNCHANGED = "confirmed_unchanged"


@dataclass(frozen=True, slots=True)
class SystemsOutcomeEvidence:
    """Content-free, fingerprint-bound evidence from an outcome observer."""

    assessment_fingerprint: str
    decision_fingerprint: str
    success_metric_sha256: str
    metric_status: SystemsMetricStatus
    unintended_effects_detected: bool
    observed_complexity_score: int | None
    removal_candidate_count: int
    stop_condition_checked: bool
    stop_condition_triggered: bool | None
    reason_codes: tuple[str, ...]
    schema: str = "master-agent/systems-outcome-evidence@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/systems-outcome-evidence@1":
            raise ValidationError("unsupported systems outcome evidence schema")
        for name in (
            "assessment_fingerprint",
            "decision_fingerprint",
            "success_metric_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", getattr(self, name)):
                raise ValidationError(
                    f"systems outcome evidence {name} must be a SHA-256 digest"
                )
        if not isinstance(self.metric_status, SystemsMetricStatus):
            raise ValidationError("systems outcome evidence metric status is invalid")
        if self.metric_status not in {
            SystemsMetricStatus.CONFIRMED_MOVED,
            SystemsMetricStatus.CONFIRMED_UNCHANGED,
        }:
            raise ValidationError(
                "systems outcome evidence must independently observe the metric"
            )
        for name in (
            "unintended_effects_detected",
            "stop_condition_checked",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(
                    f"systems outcome evidence {name} must be a boolean"
                )
        if self.stop_condition_checked and not isinstance(
            self.stop_condition_triggered, bool
        ):
            raise ValidationError(
                "checked systems outcome evidence requires a stop-condition result"
            )
        if (
            not self.stop_condition_checked
            and self.stop_condition_triggered is not None
        ):
            raise ValidationError(
                "unchecked systems outcome evidence cannot state a stop result"
            )
        if self.observed_complexity_score is not None and (
            not isinstance(self.observed_complexity_score, int)
            or isinstance(self.observed_complexity_score, bool)
            or self.observed_complexity_score < 0
        ):
            raise ValidationError(
                "systems outcome evidence observed_complexity_score must be "
                "non-negative or null"
            )
        if (
            not isinstance(self.removal_candidate_count, int)
            or isinstance(self.removal_candidate_count, bool)
            or self.removal_candidate_count < 0
        ):
            raise ValidationError(
                "systems outcome evidence removal_candidate_count must be a "
                "non-negative integer"
            )
        codes = tuple(self.reason_codes)
        if not codes or any(
            re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in codes
        ):
            raise ValidationError("systems outcome evidence reason codes are invalid")
        object.__setattr__(self, "reason_codes", codes)

    @classmethod
    def for_observation(
        cls,
        *,
        assessment: SystemsAssessment,
        decision: SystemsGateDecision,
        metric_status: SystemsMetricStatus,
        unintended_effects_detected: bool,
        observed_complexity_score: int | None,
        removal_candidate_count: int,
        stop_condition_checked: bool,
        stop_condition_triggered: bool | None,
        reason_codes: tuple[str, ...],
    ) -> SystemsOutcomeEvidence:
        """Bind independently measured values to the admitted systems records."""

        return cls(
            assessment_fingerprint=assessment.fingerprint,
            decision_fingerprint=decision.fingerprint,
            success_metric_sha256=assessment.success_metric_sha256,
            metric_status=metric_status,
            unintended_effects_detected=unintended_effects_detected,
            observed_complexity_score=observed_complexity_score,
            removal_candidate_count=removal_candidate_count,
            stop_condition_checked=stop_condition_checked,
            stop_condition_triggered=stop_condition_triggered,
            reason_codes=reason_codes,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize content-free observer evidence."""

        return {
            "schema": self.schema,
            "assessment_fingerprint": self.assessment_fingerprint,
            "decision_fingerprint": self.decision_fingerprint,
            "success_metric_sha256": self.success_metric_sha256,
            "metric_status": str(self.metric_status),
            "unintended_effects_detected": self.unintended_effects_detected,
            "observed_complexity_score": self.observed_complexity_score,
            "removal_candidate_count": self.removal_candidate_count,
            "stop_condition_checked": self.stop_condition_checked,
            "stop_condition_triggered": self.stop_condition_triggered,
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SystemsOutcomeEvidence:
        """Parse bounded observer evidence."""

        return cls(
            schema=str(data.get("schema", "")),
            assessment_fingerprint=str(data.get("assessment_fingerprint", "")),
            decision_fingerprint=str(data.get("decision_fingerprint", "")),
            success_metric_sha256=str(data.get("success_metric_sha256", "")),
            metric_status=SystemsMetricStatus(str(data.get("metric_status", ""))),
            unintended_effects_detected=_strict_bool(
                data.get("unintended_effects_detected"),
                "systems outcome evidence unintended_effects_detected",
            ),
            observed_complexity_score=(
                _strict_int(
                    data.get("observed_complexity_score"),
                    "systems outcome evidence observed_complexity_score",
                )
                if data.get("observed_complexity_score") is not None
                else None
            ),
            removal_candidate_count=_strict_int(
                data.get("removal_candidate_count"),
                "systems outcome evidence removal_candidate_count",
            ),
            stop_condition_checked=_strict_bool(
                data.get("stop_condition_checked"),
                "systems outcome evidence stop_condition_checked",
            ),
            stop_condition_triggered=(
                _strict_bool(
                    data.get("stop_condition_triggered"),
                    "systems outcome evidence stop_condition_triggered",
                )
                if data.get("stop_condition_triggered") is not None
                else None
            ),
            reason_codes=_systems_text_list(data, "reason_codes"),
        )


@dataclass(frozen=True, slots=True)
class SystemsPostExecutionReview:
    """Content-free review of one admitted intervention after execution."""

    assessment_fingerprint: str
    decision_fingerprint: str
    success_metric_sha256: str
    metric_status: SystemsMetricStatus
    unintended_effects_detected: bool
    planned_complexity_score: int
    removal_candidate_count: int
    stop_condition_checked: bool
    reassessment_required: bool
    reason_codes: tuple[str, ...]
    observed_complexity_score: int | None = None
    complexity_growth: int | None = None
    stop_condition_triggered: bool | None = None
    schema: str = "master-agent/systems-post-execution-review@2"

    def __post_init__(self) -> None:
        if self.schema not in {
            "master-agent/systems-post-execution-review@1",
            "master-agent/systems-post-execution-review@2",
        }:
            raise ValidationError("unsupported systems post-execution review schema")
        for name in (
            "assessment_fingerprint",
            "decision_fingerprint",
            "success_metric_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", getattr(self, name)):
                raise ValidationError(f"systems review {name} must be a SHA-256 digest")
        if not isinstance(self.metric_status, SystemsMetricStatus):
            raise ValidationError("systems review metric status is invalid")
        for name in (
            "unintended_effects_detected",
            "stop_condition_checked",
            "reassessment_required",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"systems review {name} must be a boolean")
        for name in ("planned_complexity_score", "removal_candidate_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValidationError(
                    f"systems review {name} must be a non-negative integer"
                )
        if self.observed_complexity_score is not None and (
            not isinstance(self.observed_complexity_score, int)
            or isinstance(self.observed_complexity_score, bool)
            or self.observed_complexity_score < 0
        ):
            raise ValidationError(
                "systems review observed_complexity_score must be non-negative"
            )
        if self.complexity_growth is not None and (
            not isinstance(self.complexity_growth, int)
            or isinstance(self.complexity_growth, bool)
        ):
            raise ValidationError("systems review complexity_growth must be an integer")
        if self.stop_condition_triggered is not None and not isinstance(
            self.stop_condition_triggered, bool
        ):
            raise ValidationError(
                "systems review stop_condition_triggered must be a boolean or null"
            )
        if self.schema == "master-agent/systems-post-execution-review@2":
            if self.stop_condition_checked and not isinstance(
                self.stop_condition_triggered, bool
            ):
                raise ValidationError(
                    "checked systems review requires a stop-condition result"
                )
            if (
                not self.stop_condition_checked
                and self.stop_condition_triggered is not None
            ):
                raise ValidationError(
                    "unchecked systems review cannot state a stop-condition result"
                )
        codes = tuple(self.reason_codes)
        if not codes or any(
            re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in codes
        ):
            raise ValidationError("systems review reason codes are invalid")
        object.__setattr__(self, "reason_codes", codes)

    def to_dict(self) -> dict[str, object]:
        """Serialize content-free review evidence."""

        payload: dict[str, object] = {
            "schema": self.schema,
            "assessment_fingerprint": self.assessment_fingerprint,
            "decision_fingerprint": self.decision_fingerprint,
            "success_metric_sha256": self.success_metric_sha256,
            "metric_status": str(self.metric_status),
            "unintended_effects_detected": self.unintended_effects_detected,
            "planned_complexity_score": self.planned_complexity_score,
            "removal_candidate_count": self.removal_candidate_count,
            "stop_condition_checked": self.stop_condition_checked,
            "reassessment_required": self.reassessment_required,
            "reason_codes": list(self.reason_codes),
        }
        if self.schema == "master-agent/systems-post-execution-review@2":
            payload.update(
                observed_complexity_score=self.observed_complexity_score,
                complexity_growth=self.complexity_growth,
                stop_condition_triggered=self.stop_condition_triggered,
            )
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SystemsPostExecutionReview:
        """Parse content-free review evidence."""

        schema = str(data.get("schema", ""))
        return cls(
            schema=schema,
            assessment_fingerprint=str(data.get("assessment_fingerprint", "")),
            decision_fingerprint=str(data.get("decision_fingerprint", "")),
            success_metric_sha256=str(data.get("success_metric_sha256", "")),
            metric_status=SystemsMetricStatus(str(data.get("metric_status", ""))),
            unintended_effects_detected=_strict_bool(
                data.get("unintended_effects_detected"),
                "systems review unintended_effects_detected",
            ),
            planned_complexity_score=_strict_int(
                data.get("planned_complexity_score"),
                "systems review planned_complexity_score",
            ),
            removal_candidate_count=_strict_int(
                data.get("removal_candidate_count"),
                "systems review removal_candidate_count",
            ),
            stop_condition_checked=_strict_bool(
                data.get("stop_condition_checked"),
                "systems review stop_condition_checked",
            ),
            reassessment_required=_strict_bool(
                data.get("reassessment_required"),
                "systems review reassessment_required",
            ),
            reason_codes=_systems_text_list(data, "reason_codes"),
            observed_complexity_score=(
                _strict_int(
                    data.get("observed_complexity_score"),
                    "systems review observed_complexity_score",
                )
                if data.get("observed_complexity_score") is not None
                else None
            ),
            complexity_growth=(
                _strict_int(
                    data.get("complexity_growth"),
                    "systems review complexity_growth",
                )
                if data.get("complexity_growth") is not None
                else None
            ),
            stop_condition_triggered=(
                _strict_bool(
                    data.get("stop_condition_triggered"),
                    "systems review stop_condition_triggered",
                )
                if data.get("stop_condition_triggered") is not None
                else None
            ),
        )


def _require_systems_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must not be empty")
    if value != value.strip():
        raise ValidationError(f"{name} must be trimmed")
    validate_bounded_string(value, context=name)
    _reject_control_characters(value, name)


def _normalize_systems_text_tuple(
    values: tuple[str, ...], name: str
) -> tuple[str, ...]:
    normalized = tuple(values)
    for value in normalized:
        _require_systems_text(value, name)
    return normalized


def _stable_sha256(value: Mapping[str, object]) -> str:
    material = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _systems_text_list(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"systems {key} must be a string list")
    return tuple(value)


def _strict_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{name} must be an integer")
    return value


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
            validate_bounded_string(value, context=name)
            _reject_control_characters(value, name)
        if self.expected_version is not None:
            validate_bounded_string(
                self.expected_version,
                context="expected_version",
            )

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
        _reject_control_characters(self.capability, "capability")
        validate_bounded_string(self.capability, context="capability")
        if not self.idempotency_key.strip():
            raise ValidationError("idempotency_key must not be empty")
        if not self.justification.strip():
            raise ValidationError("justification must not be empty")
        for name, value in (
            ("idempotency_key", self.idempotency_key),
            ("justification", self.justification),
        ):
            validate_bounded_string(value, context=name)
        dependencies = tuple(
            islice(iter(self.dependencies), MAX_ACTION_DEPENDENCIES + 1)
        )
        if len(dependencies) > MAX_ACTION_DEPENDENCIES:
            raise ValidationError(
                f"action dependencies exceed the {MAX_ACTION_DEPENDENCIES}-item limit"
            )
        if self.action_id in dependencies:
            raise ValidationError("an action cannot depend on itself")
        measure_json_resources(
            self.parameters,
            context="action parameters",
            max_bytes=MAX_ACTION_PARAMETER_BYTES,
        )
        object.__setattr__(self, "parameters", freeze_json_mapping(self.parameters))
        object.__setattr__(self, "dependencies", dependencies)

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
        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise ValidationError("dependencies must be a list")
        risk = RiskLevel(str(data["risk"]))
        if risk is RiskLevel.READ_ONLY and "data_classification" not in data:
            raise ValidationError(
                "serialized read actions require an explicit data_classification"
            )
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
            risk=risk,
            data_classification=DataClassification(
                str(data.get("data_classification", DataClassification.INTERNAL))
            ),
            authority_source=AuthoritySource(str(data["authority_source"])),
            requires_approval=_strict_bool(
                data.get("requires_approval"), "requires_approval"
            ),
            idempotency_key=str(data["idempotency_key"]),
            justification=str(data["justification"]),
            dependencies=tuple(UUID(str(item)) for item in dependencies),
            action_id=UUID(str(data["action_id"])),
        )


@dataclass(frozen=True, slots=True)
class ConnectorExecutionBinding:
    """Secret-free identity of one connector's approved live destination."""

    system: str
    deployment: str
    config_identity_sha256: str
    resolved_base_url: str
    resolved_origin: str
    implementation: str = "native"
    authentication_mode: str = "none"
    credential_scopes: tuple[str, ...] = ()
    credential_identity: str | None = None
    ca_bundle_path: str | None = None
    ca_bundle_sha256: str | None = None
    network_profile_name: str = "direct"
    network_profile_sha256: str | None = None
    proxy_origin: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("system", self.system),
            ("deployment", self.deployment),
            ("implementation", self.implementation),
            ("resolved_base_url", self.resolved_base_url),
            ("resolved_origin", self.resolved_origin),
            ("authentication_mode", self.authentication_mode),
        ):
            if not value.strip():
                raise ValidationError(f"connector execution binding {name} is empty")
        if self.implementation != "native":
            raise ValidationError(
                "connector execution binding implementation is unsupported"
            )
        _validate_sha256(
            self.config_identity_sha256,
            "connector execution binding config_identity_sha256",
        )
        if (self.ca_bundle_path is None) != (self.ca_bundle_sha256 is None):
            raise ValidationError(
                "connector execution binding CA path and digest must be supplied together"
            )
        if (
            self.credential_identity is not None
            and not self.credential_identity.strip()
        ):
            raise ValidationError(
                "connector execution binding credential_identity is empty"
            )
        scopes = tuple(sorted(set(self.credential_scopes)))
        if any(not scope.strip() for scope in scopes):
            raise ValidationError(
                "connector execution binding credential scope is empty"
            )
        if len(scopes) > 128 or any(len(scope) > 256 for scope in scopes):
            raise ValidationError(
                "connector execution binding credential scopes are too large"
            )
        for scope in scopes:
            _reject_control_characters(
                scope,
                "connector execution binding credential scope",
            )
        if self.ca_bundle_path is not None and not self.ca_bundle_path.strip():
            raise ValidationError("connector execution binding CA path is empty")
        if self.ca_bundle_sha256 is not None:
            _validate_sha256(
                self.ca_bundle_sha256,
                "connector execution binding ca_bundle_sha256",
            )
        if not self.network_profile_name.strip():
            raise ValidationError(
                "connector execution binding network profile name is empty"
            )
        if self.network_profile_sha256 is not None:
            _validate_sha256(
                self.network_profile_sha256,
                "connector execution binding network_profile_sha256",
            )
        if self.proxy_origin is not None:
            parsed_proxy = urlsplit(self.proxy_origin)
            if (
                parsed_proxy.scheme != "http"
                or not parsed_proxy.hostname
                or parsed_proxy.username is not None
                or parsed_proxy.password is not None
                or parsed_proxy.path not in {"", "/"}
                or parsed_proxy.query
                or parsed_proxy.fragment
            ):
                raise ValidationError(
                    "connector execution binding proxy origin is invalid"
                )
        object.__setattr__(self, "credential_scopes", scopes)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the connector binding."""

        payload: dict[str, Any] = {
            "system": self.system,
            "deployment": self.deployment,
            "implementation": self.implementation,
            "config_identity_sha256": self.config_identity_sha256,
            "resolved_base_url": self.resolved_base_url,
            "resolved_origin": self.resolved_origin,
            "authentication_mode": self.authentication_mode,
            "ca_bundle_path": self.ca_bundle_path,
            "ca_bundle_sha256": self.ca_bundle_sha256,
            "network_profile_name": self.network_profile_name,
            "network_profile_sha256": self.network_profile_sha256,
            "proxy_origin": self.proxy_origin,
        }
        payload["credential_scopes"] = list(self.credential_scopes)
        if self.credential_identity is not None:
            payload["credential_identity"] = self.credential_identity
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ConnectorExecutionBinding:
        """Parse a connector binding."""

        if "implementation" not in data:
            raise ValidationError(
                "connector execution binding implementation is required"
            )
        raw_scopes = data.get("credential_scopes", [])
        if not isinstance(raw_scopes, list) or not all(
            isinstance(item, str) for item in raw_scopes
        ):
            raise ValidationError(
                "connector execution binding credential_scopes must be strings"
            )
        return cls(
            system=str(data["system"]),
            deployment=str(data["deployment"]),
            implementation=str(data["implementation"]),
            config_identity_sha256=str(data["config_identity_sha256"]),
            resolved_base_url=str(data["resolved_base_url"]),
            resolved_origin=str(data["resolved_origin"]),
            authentication_mode=str(data.get("authentication_mode", "none")),
            credential_scopes=tuple(str(item) for item in raw_scopes),
            credential_identity=(
                str(data["credential_identity"])
                if data.get("credential_identity") is not None
                else None
            ),
            ca_bundle_path=(
                str(data["ca_bundle_path"])
                if data.get("ca_bundle_path") is not None
                else None
            ),
            ca_bundle_sha256=(
                str(data["ca_bundle_sha256"])
                if data.get("ca_bundle_sha256") is not None
                else None
            ),
            network_profile_name=str(data.get("network_profile_name", "direct")),
            network_profile_sha256=(
                str(data["network_profile_sha256"])
                if data.get("network_profile_sha256") is not None
                else None
            ),
            proxy_origin=(
                str(data["proxy_origin"])
                if data.get("proxy_origin") is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class ConfigurationExecutionBinding:
    """Digest of one trusted, secret-free runtime configuration snapshot."""

    name: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValidationError("configuration execution binding name is empty")
        _validate_sha256(self.sha256, f"configuration binding {self.name} sha256")

    def to_dict(self) -> dict[str, str]:
        """Serialize the configuration binding."""

        return {"name": self.name, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ConfigurationExecutionBinding:
        """Parse a configuration binding."""

        return cls(name=str(data["name"]), sha256=str(data["sha256"]))


@dataclass(frozen=True, slots=True)
class RuntimePathExecutionBinding:
    """Canonical path plus the exact directory identity approved for one effect."""

    name: str
    path: str
    anchor_path: str
    device: int
    inode: int
    owner: int
    mode: int
    object_identity: PlatformObjectIdentity | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValidationError("runtime path execution binding name is empty")
        if not self.path.strip() or not Path(self.path).is_absolute():
            raise ValidationError(
                f"runtime path execution binding {self.name} must be absolute"
            )
        if not self.anchor_path.strip() or not Path(self.anchor_path).is_absolute():
            raise ValidationError(
                f"runtime path execution binding {self.name} anchor must be absolute"
            )
        if self.anchor_path != self.path:
            raise ValidationError(
                f"runtime path execution binding {self.name} must pin its exact path"
            )
        identity = self.object_identity
        if identity is None:
            try:
                identity = PlatformObjectIdentity.from_posix(
                    kind=FilesystemObjectKind.DIRECTORY,
                    device=self.device,
                    inode=self.inode,
                    owner=self.owner,
                    mode=self.mode,
                )
            except ValueError as error:
                raise ValidationError(
                    f"runtime path execution binding {self.name} identity is invalid"
                ) from error
        if identity.kind is not FilesystemObjectKind.DIRECTORY:
            raise ValidationError(
                f"runtime path execution binding {self.name} must identify a directory"
            )
        if identity.platform == "posix":
            legacy = (self.device, self.inode, self.owner, self.mode)
            native = (identity.device, identity.inode, identity.owner, identity.mode)
            if legacy != native:
                raise ValidationError(
                    f"runtime path execution binding {self.name} POSIX identity drifted"
                )
        elif (self.device, self.inode, self.owner, self.mode) != (0, 0, 0, 0):
            raise ValidationError(
                f"runtime path execution binding {self.name} mixes native identities"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the path binding."""

        payload: dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "anchor_path": self.anchor_path,
            "device": self.device,
            "inode": self.inode,
            "owner": self.owner,
            "mode": self.mode,
        }
        if self.object_identity is not None:
            payload["object_identity"] = self.object_identity.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RuntimePathExecutionBinding:
        """Parse a path binding."""

        raw_identity = data.get("object_identity")
        try:
            if "object_identity" not in data:
                identity = None
            elif isinstance(raw_identity, Mapping):
                identity = PlatformObjectIdentity.from_dict(raw_identity)
            else:
                raise TypeError("runtime path object identity is not an object")
        except (TypeError, ValueError) as error:
            raise ValidationError("runtime path object identity is invalid") from error

        return cls(
            name=str(data["name"]),
            path=str(data["path"]),
            anchor_path=str(data.get("anchor_path", "")),
            device=int(data.get("device", -1)),
            inode=int(data.get("inode", -1)),
            owner=int(data.get("owner", -1)),
            mode=int(data.get("mode", -1)),
            object_identity=identity,
        )

    def _identity(self) -> PlatformObjectIdentity:
        """Return an explicit native identity or a legacy exact POSIX view."""

        if self.object_identity is not None:
            return self.object_identity
        try:
            return PlatformObjectIdentity.from_posix(
                kind=FilesystemObjectKind.DIRECTORY,
                device=self.device,
                inode=self.inode,
                owner=self.owner,
                mode=self.mode,
            )
        except ValueError as error:  # pragma: no cover - guarded in __post_init__.
            raise ValidationError("runtime path object identity is invalid") from error

    @property
    def platform_identity(self) -> PlatformObjectIdentity:
        """Return the exact native identity, including legacy POSIX bindings."""

        return self._identity()


@dataclass(frozen=True, slots=True)
class RuntimeExecutionBinding:
    """All non-secret CLI and policy inputs that can change an applied run."""

    connector_mode: str
    include_writes: bool
    include_communications: bool
    audit_database: str
    artifact_root: str
    workspace_root: str | None
    result_json: str | None
    evidence_type: str | None
    configurations: tuple[ConfigurationExecutionBinding, ...]
    runtime_paths: tuple[RuntimePathExecutionBinding, ...]
    credential_file: str | None = None
    publication_roots: tuple[RuntimePathExecutionBinding, ...] = ()
    schema: str = "master-agent/runtime-execution-binding@2"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/runtime-execution-binding@2":
            raise ValidationError("unsupported runtime execution binding schema")
        if self.connector_mode not in {"mock", "live"}:
            raise ValidationError("runtime connector_mode must be mock or live")
        if not isinstance(self.include_writes, bool) or not isinstance(
            self.include_communications, bool
        ):
            raise ValidationError("runtime connector gates must be booleans")
        for name, value in (
            ("audit_database", self.audit_database),
            ("artifact_root", self.artifact_root),
        ):
            if not value.strip() or not Path(value).is_absolute():
                raise ValidationError(f"runtime {name} must be an absolute path")
        for name, optional_value in (
            ("workspace_root", self.workspace_root),
            ("result_json", self.result_json),
            ("credential_file", self.credential_file),
        ):
            if optional_value is not None and (
                not optional_value.strip() or not Path(optional_value).is_absolute()
            ):
                raise ValidationError(f"runtime {name} must be an absolute path")
        if (self.result_json is None) != (self.evidence_type is None):
            raise ValidationError(
                "runtime result_json and evidence_type must be supplied together"
            )
        if self.evidence_type is not None and not self.evidence_type.strip():
            raise ValidationError("runtime evidence_type is empty")
        writable_directories = {
            "audit.parent": str(Path(self.audit_database).parent),
            "artifact.root": self.artifact_root,
        }
        if self.result_json is not None:
            writable_directories["result.parent"] = str(Path(self.result_json).parent)
        if len(set(writable_directories.values())) != len(writable_directories):
            raise ValidationError(
                "runtime audit, artifact, and result directories must be "
                "pairwise distinct"
            )
        configurations = tuple(sorted(self.configurations, key=lambda item: item.name))
        runtime_paths = tuple(sorted(self.runtime_paths, key=lambda item: item.name))
        publication_roots = tuple(
            sorted(self.publication_roots, key=lambda item: item.name)
        )
        if len({item.name for item in configurations}) != len(configurations):
            raise ValidationError("runtime configuration binding names must be unique")
        if len({item.name for item in runtime_paths}) != len(runtime_paths):
            raise ValidationError("runtime path identity names must be unique")
        if len({item.name for item in publication_roots}) != len(publication_roots):
            raise ValidationError("runtime publication root names must be unique")
        expected_runtime_paths = {
            "audit.parent": str(Path(self.audit_database).parent),
            "artifact.root": self.artifact_root,
        }
        if self.workspace_root is not None:
            expected_runtime_paths["workspace.root"] = self.workspace_root
        if self.result_json is not None:
            expected_runtime_paths["result.parent"] = str(Path(self.result_json).parent)
        observed_runtime_paths = {item.name: item.path for item in runtime_paths}
        if observed_runtime_paths != expected_runtime_paths:
            raise ValidationError(
                "runtime path identities must exactly cover selected writable roots"
            )
        writable_identities = [
            item._identity().object_key
            for item in runtime_paths
            if item.name in {"audit.parent", "artifact.root", "result.parent"}
        ]
        if len(set(writable_identities)) != len(writable_identities):
            raise ValidationError(
                "runtime audit, artifact, and result directory identities must be "
                "pairwise distinct"
            )
        object.__setattr__(self, "configurations", configurations)
        object.__setattr__(self, "runtime_paths", runtime_paths)
        object.__setattr__(self, "publication_roots", publication_roots)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the runtime binding."""

        payload: dict[str, Any] = {
            "schema": self.schema,
            "connector_mode": self.connector_mode,
            "include_writes": self.include_writes,
            "include_communications": self.include_communications,
            "audit_database": self.audit_database,
            "artifact_root": self.artifact_root,
            "workspace_root": self.workspace_root,
            "result_json": self.result_json,
            "evidence_type": self.evidence_type,
            "configurations": [item.to_dict() for item in self.configurations],
            "runtime_paths": [item.to_dict() for item in self.runtime_paths],
            "publication_roots": [item.to_dict() for item in self.publication_roots],
        }
        if self.credential_file is not None:
            payload["credential_file"] = self.credential_file
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RuntimeExecutionBinding:
        """Parse a runtime binding."""

        configurations = data.get("configurations")
        runtime_paths = data.get("runtime_paths")
        publication_roots = data.get("publication_roots", [])
        if not isinstance(configurations, list) or not all(
            isinstance(item, Mapping) for item in configurations
        ):
            raise ValidationError("runtime configurations must be a list of objects")
        if not isinstance(publication_roots, list) or not all(
            isinstance(item, Mapping) for item in publication_roots
        ):
            raise ValidationError("runtime publication_roots must be a list of objects")
        if not isinstance(runtime_paths, list) or not all(
            isinstance(item, Mapping) for item in runtime_paths
        ):
            raise ValidationError("runtime runtime_paths must be a list of objects")
        return cls(
            schema=str(data.get("schema", "")),
            connector_mode=str(data["connector_mode"]),
            include_writes=_strict_bool(
                data.get("include_writes"), "runtime include_writes"
            ),
            include_communications=_strict_bool(
                data.get("include_communications"),
                "runtime include_communications",
            ),
            audit_database=str(data["audit_database"]),
            artifact_root=str(data["artifact_root"]),
            workspace_root=(
                str(data["workspace_root"])
                if data.get("workspace_root") is not None
                else None
            ),
            result_json=(
                str(data["result_json"])
                if data.get("result_json") is not None
                else None
            ),
            credential_file=(
                str(data["credential_file"])
                if data.get("credential_file") is not None
                else None
            ),
            evidence_type=(
                str(data["evidence_type"])
                if data.get("evidence_type") is not None
                else None
            ),
            configurations=tuple(
                ConfigurationExecutionBinding.from_dict(item) for item in configurations
            ),
            runtime_paths=tuple(
                RuntimePathExecutionBinding.from_dict(item) for item in runtime_paths
            ),
            publication_roots=tuple(
                RuntimePathExecutionBinding.from_dict(item)
                for item in publication_roots
            ),
        )


@dataclass(frozen=True, slots=True)
class PluginExecutionBinding:
    """Exact reviewed identity of one approved connector plugin."""

    name: str
    group: str
    entry_point: str
    distribution: str
    distribution_version: str
    artifact_sha256: str
    identity_sha256: str

    def __post_init__(self) -> None:
        for name, value in (
            ("name", self.name),
            ("group", self.group),
            ("entry_point", self.entry_point),
            ("distribution", self.distribution),
            ("distribution_version", self.distribution_version),
        ):
            if not value.strip():
                raise ValidationError(f"plugin execution binding {name} is empty")
        _validate_sha256(
            self.artifact_sha256,
            "plugin execution binding artifact_sha256",
        )
        _validate_sha256(
            self.identity_sha256,
            "plugin execution binding identity_sha256",
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize the plugin binding."""

        return {
            "name": self.name,
            "group": self.group,
            "entry_point": self.entry_point,
            "distribution": self.distribution,
            "distribution_version": self.distribution_version,
            "artifact_sha256": self.artifact_sha256,
            "identity_sha256": self.identity_sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PluginExecutionBinding:
        """Parse a plugin binding."""

        return cls(
            name=str(data["name"]),
            group=str(data["group"]),
            entry_point=str(data["entry_point"]),
            distribution=str(data["distribution"]),
            distribution_version=str(data["distribution_version"]),
            artifact_sha256=str(data["artifact_sha256"]),
            identity_sha256=str(data["identity_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class CapabilityCapsuleExecutionBinding:
    """Exact promoted capsule identity and authority constraints bound to a plan."""

    capability_id: str
    version: str
    risk: RiskLevel
    manifest_sha256: str
    source_sha256: str
    artifact_sha256: str
    dependency_lock_sha256: str
    sbom_sha256: str
    test_suite_sha256: str
    validation_result_sha256: str
    sandbox_validation_sha256: str
    verification_contract_sha256: str
    compensation_contract_sha256: str
    policy_contract_sha256: str
    worker_sha256: str
    publisher: str
    reviewer: str
    signer_key_id: str
    authenticated_principal: str = "local:operator"
    agent_identity: str = "master-agent"
    tenant_id: str = "local"
    provider_account_id: str = "none"
    credential_provider_id: str = "none"
    allowed_origins: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = ()
    allowed_path_prefixes: tuple[str, ...] = ()
    credential_names: tuple[str, ...] = ()
    credential_scopes: tuple[str, ...] = ()
    data_classification: DataClassification = DataClassification.INTERNAL
    retention_class: str = "ephemeral"
    max_input_bytes: int = 65_536
    max_output_bytes: int = 65_536
    timeout_seconds: int = 5
    cpu_seconds: int = 2
    memory_bytes: int = 134_217_728
    max_processes: int = 1
    state: str = "enabled"

    def __post_init__(self) -> None:
        if not isinstance(self.risk, RiskLevel) or not isinstance(
            self.data_classification, DataClassification
        ):
            raise ValidationError("capsule binding risk or classification is malformed")
        validate_bounded_string(
            self.capability_id, context="capsule binding capability_id"
        )
        validate_bounded_string(self.version, context="capsule binding version")
        if _CAPSULE_CAPABILITY_PATTERN.fullmatch(self.capability_id) is None:
            raise ValidationError("capsule binding capability_id is malformed")
        if _CAPSULE_VERSION_PATTERN.fullmatch(self.version) is None:
            raise ValidationError("capsule binding version is malformed")
        for name, value in (
            ("publisher", self.publisher),
            ("reviewer", self.reviewer),
            ("signer_key_id", self.signer_key_id),
            ("authenticated_principal", self.authenticated_principal),
            ("agent_identity", self.agent_identity),
            ("tenant_id", self.tenant_id),
            ("provider_account_id", self.provider_account_id),
            ("credential_provider_id", self.credential_provider_id),
            ("retention_class", self.retention_class),
        ):
            if not value or value != value.strip():
                raise ValidationError(f"capsule binding {name} is empty or malformed")
            _validate_approval_claim(value, f"capsule binding {name}")
            validate_bounded_string(value, context=f"capsule binding {name}")
        if self.publisher.casefold() == self.reviewer.casefold():
            raise ValidationError("capsule publisher and reviewer must be distinct")
        if self.state != "enabled":
            raise ValidationError("only enabled capability capsules may bind to plans")
        for name, value in (
            ("manifest_sha256", self.manifest_sha256),
            ("source_sha256", self.source_sha256),
            ("artifact_sha256", self.artifact_sha256),
            ("dependency_lock_sha256", self.dependency_lock_sha256),
            ("sbom_sha256", self.sbom_sha256),
            ("test_suite_sha256", self.test_suite_sha256),
            ("validation_result_sha256", self.validation_result_sha256),
            ("sandbox_validation_sha256", self.sandbox_validation_sha256),
            ("verification_contract_sha256", self.verification_contract_sha256),
            ("compensation_contract_sha256", self.compensation_contract_sha256),
            ("policy_contract_sha256", self.policy_contract_sha256),
            ("worker_sha256", self.worker_sha256),
        ):
            _validate_sha256(value, f"capsule binding {name}")
        for name, values in (
            ("allowed_origins", self.allowed_origins),
            ("allowed_methods", self.allowed_methods),
            ("allowed_path_prefixes", self.allowed_path_prefixes),
            ("credential_names", self.credential_names),
            ("credential_scopes", self.credential_scopes),
        ):
            if (
                not isinstance(values, tuple)
                or len(values) != len(set(values))
                or any(not value or value != value.strip() for value in values)
            ):
                raise ValidationError(f"capsule binding {name} is malformed")
            for value in values:
                _reject_control_characters(value, f"capsule binding {name}")
                validate_bounded_string(value, context=f"capsule binding {name}")
        for limit_name, limit_value, minimum, maximum in (
            ("max_input_bytes", self.max_input_bytes, 1, 1024 * 1024),
            ("max_output_bytes", self.max_output_bytes, 1, 1024 * 1024),
            ("timeout_seconds", self.timeout_seconds, 1, 30),
            ("cpu_seconds", self.cpu_seconds, 1, 10),
            ("memory_bytes", self.memory_bytes, 32 * 1024 * 1024, 512 * 1024 * 1024),
            ("max_processes", self.max_processes, 1, 4),
        ):
            if (
                not isinstance(limit_value, int)
                or isinstance(limit_value, bool)
                or not minimum <= limit_value <= maximum
            ):
                raise ValidationError(
                    f"capsule binding {limit_name} is outside its safe bound"
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize every security-relevant capsule execution fact."""

        return {
            "capability_id": self.capability_id,
            "version": self.version,
            "risk": str(self.risk),
            "manifest_sha256": self.manifest_sha256,
            "source_sha256": self.source_sha256,
            "artifact_sha256": self.artifact_sha256,
            "dependency_lock_sha256": self.dependency_lock_sha256,
            "sbom_sha256": self.sbom_sha256,
            "test_suite_sha256": self.test_suite_sha256,
            "validation_result_sha256": self.validation_result_sha256,
            "sandbox_validation_sha256": self.sandbox_validation_sha256,
            "verification_contract_sha256": self.verification_contract_sha256,
            "compensation_contract_sha256": self.compensation_contract_sha256,
            "policy_contract_sha256": self.policy_contract_sha256,
            "worker_sha256": self.worker_sha256,
            "publisher": self.publisher,
            "reviewer": self.reviewer,
            "signer_key_id": self.signer_key_id,
            "authenticated_principal": self.authenticated_principal,
            "agent_identity": self.agent_identity,
            "tenant_id": self.tenant_id,
            "provider_account_id": self.provider_account_id,
            "credential_provider_id": self.credential_provider_id,
            "allowed_origins": list(self.allowed_origins),
            "allowed_methods": list(self.allowed_methods),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "credential_names": list(self.credential_names),
            "credential_scopes": list(self.credential_scopes),
            "data_classification": str(self.data_classification),
            "retention_class": self.retention_class,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "timeout_seconds": self.timeout_seconds,
            "cpu_seconds": self.cpu_seconds,
            "memory_bytes": self.memory_bytes,
            "max_processes": self.max_processes,
            "state": self.state,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CapabilityCapsuleExecutionBinding:
        """Parse an immutable capsule binding from a plan."""

        return cls(
            capability_id=str(data["capability_id"]),
            version=str(data["version"]),
            risk=RiskLevel(str(data["risk"])),
            manifest_sha256=str(data["manifest_sha256"]),
            source_sha256=str(data["source_sha256"]),
            artifact_sha256=str(data["artifact_sha256"]),
            dependency_lock_sha256=str(data["dependency_lock_sha256"]),
            sbom_sha256=str(data["sbom_sha256"]),
            test_suite_sha256=str(data["test_suite_sha256"]),
            validation_result_sha256=str(data["validation_result_sha256"]),
            sandbox_validation_sha256=str(data["sandbox_validation_sha256"]),
            verification_contract_sha256=str(data["verification_contract_sha256"]),
            compensation_contract_sha256=str(data["compensation_contract_sha256"]),
            policy_contract_sha256=str(data["policy_contract_sha256"]),
            worker_sha256=str(data["worker_sha256"]),
            publisher=str(data["publisher"]),
            reviewer=str(data["reviewer"]),
            signer_key_id=str(data["signer_key_id"]),
            authenticated_principal=str(data["authenticated_principal"]),
            agent_identity=str(data["agent_identity"]),
            tenant_id=str(data["tenant_id"]),
            provider_account_id=str(data["provider_account_id"]),
            credential_provider_id=str(data["credential_provider_id"]),
            allowed_origins=_capsule_binding_strings(data, "allowed_origins"),
            allowed_methods=_capsule_binding_strings(data, "allowed_methods"),
            allowed_path_prefixes=_capsule_binding_strings(
                data, "allowed_path_prefixes"
            ),
            credential_names=_capsule_binding_strings(data, "credential_names"),
            credential_scopes=_capsule_binding_strings(data, "credential_scopes"),
            data_classification=DataClassification(str(data["data_classification"])),
            retention_class=str(data["retention_class"]),
            max_input_bytes=_required_positive_int(data, "max_input_bytes"),
            max_output_bytes=_required_positive_int(data, "max_output_bytes"),
            timeout_seconds=_required_positive_int(data, "timeout_seconds"),
            cpu_seconds=_required_positive_int(data, "cpu_seconds"),
            memory_bytes=_required_positive_int(data, "memory_bytes"),
            max_processes=_required_positive_int(data, "max_processes"),
            state=str(data["state"]),
        )


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Reviewed connector identities and metadata-only plugin inventory binding."""

    integrations_sha256: str
    connectors: tuple[ConnectorExecutionBinding, ...] = ()
    plugins: tuple[PluginExecutionBinding, ...] = ()
    capsules: tuple[CapabilityCapsuleExecutionBinding, ...] = ()
    runtime: RuntimeExecutionBinding | None = None
    schema: str = "master-agent/execution-context@2"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/execution-context@2":
            raise ValidationError("unsupported execution context schema")
        _validate_sha256(
            self.integrations_sha256,
            "execution context integrations_sha256",
        )
        connectors = tuple(sorted(self.connectors, key=lambda item: item.system))
        plugins = tuple(sorted(self.plugins, key=lambda item: item.name))
        capsules = tuple(
            sorted(self.capsules, key=lambda item: (item.capability_id, item.version))
        )
        if len({item.system for item in connectors}) != len(connectors):
            raise ValidationError("execution context connector systems must be unique")
        if len({item.name for item in plugins}) != len(plugins):
            raise ValidationError("execution context plugin names must be unique")
        capsule_names = [item.capability_id for item in capsules]
        if len(capsule_names) != len(set(capsule_names)):
            raise ValidationError(
                "execution context capsule capabilities must be unique"
            )
        object.__setattr__(self, "connectors", connectors)
        object.__setattr__(self, "plugins", plugins)
        object.__setattr__(self, "capsules", capsules)

    @property
    def fingerprint(self) -> str:
        """Return the stable digest used for runtime equality diagnostics."""

        payload = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the execution context."""

        payload: dict[str, Any] = {
            "schema": self.schema,
            "integrations_sha256": self.integrations_sha256,
            "connectors": [item.to_dict() for item in self.connectors],
            "plugins": [item.to_dict() for item in self.plugins],
        }
        if self.runtime is not None:
            payload["runtime"] = self.runtime.to_dict()
        if self.capsules:
            payload["capsules"] = [item.to_dict() for item in self.capsules]
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionContext:
        """Parse an execution context."""

        if data.get("schema") != "master-agent/execution-context@2":
            raise ValidationError("unsupported execution context schema")
        connectors = data.get("connectors")
        plugins = data.get("plugins")
        capsules = data.get("capsules", [])
        if not isinstance(connectors, list):
            raise ValidationError("execution context connectors must be a list")
        if not isinstance(plugins, list):
            raise ValidationError("execution context plugins must be a list")
        if not isinstance(capsules, list):
            raise ValidationError("execution context capsules must be a list")
        if not all(isinstance(item, Mapping) for item in connectors):
            raise ValidationError("execution context connectors must be objects")
        if not all(isinstance(item, Mapping) for item in plugins):
            raise ValidationError("execution context plugins must be objects")
        if not all(isinstance(item, Mapping) for item in capsules):
            raise ValidationError("execution context capsules must be objects")
        return cls(
            schema=str(data.get("schema", "")),
            integrations_sha256=str(data["integrations_sha256"]),
            connectors=tuple(
                ConnectorExecutionBinding.from_dict(item) for item in connectors
            ),
            plugins=tuple(PluginExecutionBinding.from_dict(item) for item in plugins),
            capsules=tuple(
                CapabilityCapsuleExecutionBinding.from_dict(item) for item in capsules
            ),
            runtime=(
                RuntimeExecutionBinding.from_dict(_expect_mapping(data, "runtime"))
                if data.get("runtime") is not None
                else None
            ),
        )


_TRUSTED_STRATEGY_COHERENCE_ADMISSION = object()


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
    execution_context: ExecutionContext | None = None
    systems_assessment: SystemsAssessment | None = None
    systems_decision: SystemsGateDecision | None = None
    strategy_traces: tuple[StrategyActionTrace, ...] = ()
    strategy_coherence_review: StrategyCoherenceReview | None = None
    _trusted_strategy_coherence_admission: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.compensate_on_failure, bool):
            raise ValidationError("compensate_on_failure must be a boolean")
        if self.strategy_coherence_review is not None and not isinstance(
            self.strategy_coherence_review, StrategyCoherenceReview
        ):
            raise ValidationError(
                "plan strategy_coherence_review must be a StrategyCoherenceReview"
            )
        if (self.systems_assessment is None) != (self.systems_decision is None):
            raise ValidationError(
                "systems assessment and gate decision must be supplied together"
            )
        if self.systems_assessment is not None:
            if not isinstance(
                self.systems_assessment, SystemsAssessment
            ) or not isinstance(self.systems_decision, SystemsGateDecision):
                raise ValidationError("systems governance binding is invalid")
            if not self.systems_decision.permitted:
                raise ValidationError("a denied systems decision cannot bind a plan")
            if (
                self.systems_decision.assessment_fingerprint
                != self.systems_assessment.fingerprint
            ):
                raise ValidationError(
                    "systems gate decision is not bound to the plan assessment"
                )
            if (
                self.systems_decision.complexity_score
                != self.systems_assessment.complexity_score
            ):
                raise ValidationError(
                    "systems gate decision complexity does not match the assessment"
                )
            review_fingerprint = (
                self.strategy_coherence_review.fingerprint
                if self.strategy_coherence_review is not None
                else None
            )
            if (
                self.systems_decision.strategy_coherence_review_fingerprint
                != review_fingerprint
            ):
                raise ValidationError(
                    "systems gate decision does not match the strategy coherence review"
                )
        if not self.goal.strip():
            raise ValidationError("goal must not be empty")
        validate_bounded_string(self.goal, context="goal")
        _reject_control_characters(self.goal, "goal")
        if not self.created_by.strip():
            raise ValidationError("created_by must not be empty")
        validate_bounded_string(self.created_by, context="created_by")
        if self.workflow_id is not None and not self.workflow_id.strip():
            raise ValidationError("workflow_id must not be empty when supplied")
        if (
            self.workflow_fingerprint is not None
            and not self.workflow_fingerprint.strip()
        ):
            raise ValidationError(
                "workflow_fingerprint must not be empty when supplied"
            )
        if self.workflow_fingerprint is not None and self.workflow_id is None:
            raise ValidationError("workflow_fingerprint requires workflow_id")
        for name, value in (
            ("workflow_id", self.workflow_id),
            ("workflow_fingerprint", self.workflow_fingerprint),
        ):
            if value is not None:
                validate_bounded_string(value, context=name)
        actions = tuple(islice(iter(self.actions), MAX_PLAN_ACTIONS + 1))
        if len(actions) > MAX_PLAN_ACTIONS:
            raise ValidationError(
                f"change plan exceeds the {MAX_PLAN_ACTIONS}-action limit"
            )
        object.__setattr__(self, "actions", actions)
        traces = tuple(islice(iter(self.strategy_traces), MAX_PLAN_ACTIONS + 1))
        if len(traces) > MAX_PLAN_ACTIONS:
            raise ValidationError(
                f"change plan exceeds the {MAX_PLAN_ACTIONS}-strategy-trace limit"
            )
        if not all(isinstance(item, StrategyActionTrace) for item in traces):
            raise ValidationError(
                "change plan strategy_traces must contain StrategyActionTrace values"
            )
        object.__setattr__(self, "strategy_traces", traces)
        if not actions:
            raise ValidationError("a change plan must contain at least one action")
        if not all(isinstance(action, AgentAction) for action in actions):
            raise ValidationError("change plan actions must be AgentAction instances")
        parameter_bytes = 0
        for action in actions:
            parameter_bytes += measure_json_resources(
                action.parameters,
                context="action parameters",
                max_bytes=MAX_ACTION_PARAMETER_BYTES,
            ).scalar_bytes
            if parameter_bytes > MAX_PLAN_PARAMETER_BYTES:
                raise ValidationError(
                    "change plan exceeds the aggregate parameter-byte limit"
                )
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
        if self.systems_assessment is not None:
            measure_json_resources(
                {
                    "systems_assessment": self.systems_assessment.to_dict(),
                    "systems_decision": self.systems_decision.to_dict()
                    if self.systems_decision is not None
                    else None,
                    "strategy_coherence_review": (
                        self.strategy_coherence_review.to_dict()
                        if self.strategy_coherence_review is not None
                        else None
                    ),
                },
                context="systems governance binding",
                max_bytes=MAX_PLAN_BYTES,
            )

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

    def _with_trusted_strategy_coherence_admission(self) -> ChangePlan:
        """Mark an exact in-process plan admitted by a trusted planning binder."""

        object.__setattr__(
            self,
            "_trusted_strategy_coherence_admission",
            _TRUSTED_STRATEGY_COHERENCE_ADMISSION,
        )
        return self

    def _has_trusted_strategy_coherence_admission(self) -> bool:
        """Return whether trusted in-process admission created this exact plan."""

        return (
            self._trusted_strategy_coherence_admission
            is _TRUSTED_STRATEGY_COHERENCE_ADMISSION
        )

    def execution_snapshot(self) -> ChangePlan:
        """Clone immutable plan data while preserving trusted local admission."""

        snapshot = ChangePlan.from_dict(self.to_dict())
        if self._has_trusted_strategy_coherence_admission():
            snapshot._with_trusted_strategy_coherence_admission()
        return snapshot

    def to_dict(self) -> dict[str, Any]:
        """Serialize the plan to JSON-compatible data."""

        payload: dict[str, Any] = {
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
        if self.execution_context is not None:
            payload["execution_context"] = self.execution_context.to_dict()
        if self.strategy_traces:
            payload["strategy_traces"] = [
                item.to_dict() for item in self.strategy_traces
            ]
        if self.strategy_coherence_review is not None:
            payload["strategy_coherence_review"] = (
                self.strategy_coherence_review.to_dict()
            )
        if self.systems_assessment is not None:
            if self.systems_decision is None:  # pragma: no cover - validated above.
                raise ValidationError("systems gate decision is missing")
            payload["systems_assessment"] = self.systems_assessment.to_dict()
            payload["systems_decision"] = self.systems_decision.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangePlan:
        """Create a plan from JSON-compatible data."""

        measure_json_resources(
            data,
            context="change plan",
            max_bytes=MAX_PLAN_BYTES,
        )
        actions_data = data.get("actions")
        if not isinstance(actions_data, list):
            raise ValidationError("actions must be a list")
        if len(actions_data) > MAX_PLAN_ACTIONS:
            raise ValidationError(
                f"change plan exceeds the {MAX_PLAN_ACTIONS}-action limit"
            )
        if not all(isinstance(item, Mapping) for item in actions_data):
            raise ValidationError("actions must contain objects")
        traces_data = data.get("strategy_traces", [])
        if not isinstance(traces_data, list) or not all(
            isinstance(item, Mapping) for item in traces_data
        ):
            raise ValidationError("strategy_traces must contain objects")
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
            execution_context=(
                ExecutionContext.from_dict(_expect_mapping(data, "execution_context"))
                if data.get("execution_context") is not None
                else None
            ),
            systems_assessment=(
                SystemsAssessment.from_dict(_expect_mapping(data, "systems_assessment"))
                if data.get("systems_assessment") is not None
                else None
            ),
            systems_decision=(
                SystemsGateDecision.from_dict(_expect_mapping(data, "systems_decision"))
                if data.get("systems_decision") is not None
                else None
            ),
            strategy_traces=tuple(
                StrategyActionTrace.from_dict(item) for item in traces_data
            ),
            strategy_coherence_review=(
                StrategyCoherenceReview.from_dict(
                    _expect_mapping(data, "strategy_coherence_review")
                )
                if data.get("strategy_coherence_review") is not None
                else None
            ),
            actions=tuple(AgentAction.from_dict(item) for item in actions_data),
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """Approval bound to an immutable plan and explicit actions."""

    plan_fingerprint: str
    approved_action_ids: tuple[UUID, ...]
    approved_by: str
    issuer: str
    tenant: str
    roles: tuple[str, ...]
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
        _validate_approval_claim(self.approved_by, "approved_by")
        _validate_approval_claim(self.issuer, "approval issuer")
        _validate_approval_claim(self.tenant, "approval tenant")
        if not self.roles:
            raise ValidationError("approval roles must not be empty")
        normalized_roles: list[str] = []
        role_keys: set[str] = set()
        for role in self.roles:
            _validate_approval_claim(role, "approval role")
            role_key = unicodedata.normalize("NFKC", role).casefold()
            if role_key in role_keys:
                raise ValidationError("approval roles must be unique")
            role_keys.add(role_key)
            normalized_roles.append(role)
        object.__setattr__(
            self,
            "roles",
            tuple(sorted(normalized_roles, key=lambda item: item.casefold())),
        )
        _validate_approval_claim(self.key_id, "approval key_id")
        if not self.signature.strip():
            raise ValidationError("approval signature must not be empty")
        if not self.signature_scheme.strip():
            raise ValidationError("approval signature scheme must not be empty")
        for value, name in (
            (self.issued_at, "approval issued_at"),
            (self.expires_at, "approval expires_at"),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValidationError(f"{name} must include a timezone offset")
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
            "issuer": self.issuer,
            "tenant": self.tenant,
            "roles": list(self.roles),
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
            approved_by=_required_approval_string(data, "approved_by"),
            issuer=_required_approval_string(data, "issuer"),
            tenant=_required_approval_string(data, "tenant"),
            roles=_approval_roles_from_data(data),
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
        if self.schema != "master-agent/compensation@1":
            raise ValidationError("unsupported compensation descriptor schema")
        if not self.kind.strip():
            raise ValidationError("compensation kind must not be empty")
        if self.mode is CompensationMode.PLAN and not (
            self.capability and self.capability.strip()
        ):
            raise ValidationError("plan compensation requires an executable capability")
        if self.mode is not CompensationMode.PLAN and not (
            self.reason and self.reason.strip()
        ):
            raise ValidationError(
                "non-plan compensation requires an operator-facing reason"
            )
        object.__setattr__(self, "parameters", freeze_json_mapping(self.parameters))

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
    def from_dict(cls, data: Mapping[str, Any]) -> CompensationDescriptor:
        """Parse the one supported versioned compensation descriptor."""

        if data.get("schema") != "master-agent/compensation@1":
            raise ValidationError(
                "compensation descriptor must use master-agent/compensation@1"
            )
        parameters = data.get("parameters", {})
        if not isinstance(parameters, Mapping):
            raise ValidationError("compensation parameters must be an object")
        return cls(
            schema=str(data["schema"]),
            kind=str(data["kind"]),
            mode=CompensationMode(str(data["mode"])),
            capability=(
                str(data["capability"]) if data.get("capability") is not None else None
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
            reason=(str(data["reason"]) if data.get("reason") is not None else None),
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
    compensation: CompensationDescriptor | None = None
    _before_digest: str = field(init=False, repr=False, compare=False)
    _after_digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.before is not None:
            freeze_json_mapping(self.before)
            object.__setattr__(
                self,
                "before",
                deepcopy(dict(self.before)),
            )
        if self.after is not None:
            freeze_json_mapping(self.after)
            object.__setattr__(
                self,
                "after",
                deepcopy(dict(self.after)),
            )
        if self.compensation is not None and not isinstance(
            self.compensation, CompensationDescriptor
        ):
            raise ValidationError(
                "execution result compensation must be a CompensationDescriptor"
            )
        object.__setattr__(self, "_before_digest", _result_state_digest(self.before))
        object.__setattr__(self, "_after_digest", _result_state_digest(self.after))

    def validate_integrity(self) -> None:
        """Reject mutation of the connector snapshot after it was returned."""

        if _result_state_digest(self.before) != self._before_digest:
            raise ValidationError("execution result before-state changed after return")
        if _result_state_digest(self.after) != self._after_digest:
            raise ValidationError("execution result after-state changed after return")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to JSON-compatible data."""

        self.validate_integrity()
        return {
            "action_id": str(self.action_id),
            "state": str(self.state),
            "before": _jsonable(self.before),
            "after": _jsonable(self.after),
            "connector_reference": self.connector_reference,
            "message": self.message,
            "compensation": (
                self.compensation.to_dict() if self.compensation is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionResult:
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
                CompensationDescriptor.from_dict(compensation)
                if isinstance(compensation, Mapping)
                else None
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


def _validate_sha256(value: str, name: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")


def _capsule_binding_strings(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"capsule binding {key} must be a string list")
    return tuple(value)


def _required_positive_int(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValidationError(f"capsule binding {key} must be positive")
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


def _result_state_digest(value: Mapping[str, Any] | None) -> str:
    payload = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def freeze_json_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
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
        return _FrozenMapping(frozen)
    if isinstance(value, (tuple, list)):
        return tuple(
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


@dataclass(frozen=True, slots=True)
class _FrozenMapping(Mapping[str, Any]):
    """A mapping that is not a mutable-dictionary subclass."""

    _items: tuple[tuple[str, Any], ...]

    def __init__(self, values: Mapping[str, Any]) -> None:
        object.__setattr__(self, "_items", tuple(values.items()))

    def __getitem__(self, key: str) -> Any:
        for candidate, value in self._items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and dict(self.items()) == dict(other.items())

    def __deepcopy__(self, _memo: dict[int, Any]) -> _FrozenMapping:
        return self


def _reject_control_characters(value: str, name: str) -> None:
    """Reject terminal-control bytes from fields rendered during approval."""

    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        raise ValidationError(f"{name} must not contain control characters")


def _validate_approval_claim(value: str, name: str) -> None:
    """Require one stable, printable, Unicode-normalized approval claim."""

    if not value or value != value.strip():
        raise ValidationError(f"{name} must be a non-empty normalized value")
    if unicodedata.normalize("NFC", value) != value:
        raise ValidationError(f"{name} must use Unicode NFC normalization")
    _reject_control_characters(value, name)


def _required_approval_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValidationError(f"approval {key} must be a string")
    return value


def _approval_roles_from_data(data: Mapping[str, Any]) -> tuple[str, ...]:
    roles = data.get("roles")
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise ValidationError("approval roles must be a string list")
    return tuple(roles)


def _validate_acyclic(actions: tuple[AgentAction, ...]) -> None:
    dependencies = {action.action_id: set(action.dependencies) for action in actions}
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
