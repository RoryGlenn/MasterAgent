"""Planner contracts and the systems-governance planning gate."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from master_agent.errors import ValidationError
from master_agent.models import ChangePlan, RiskLevel


class Planner(Protocol):
    """Convert a user goal into a typed, non-authoritative plan."""

    def plan(self, goal: str) -> ChangePlan:
        """Return a validated plan for a goal."""


class SystemsAssessor(Protocol):
    """Diagnose the system that produces a requested outcome."""

    def assess(self, goal: str) -> SystemsAssessment:
        """Return a structured assessment before planning begins."""


class SystemsAwarePlanner(Protocol):
    """Build a plan from a goal and its completed systems assessment."""

    def plan(
        self,
        goal: str,
        *,
        systems_assessment: SystemsAssessment,
    ) -> ChangePlan:
        """Return a plan that consumes the systems assessment."""


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
        _require_text(self.description, "complexity item description")

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
            _require_text(getattr(self, name), f"systems assessment {name}")
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
                _normalize_text_tuple(
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
            if value and value != value.strip():
                raise ValidationError(f"systems assessment {name} must be trimmed")

    @property
    def fast_path_requested(self) -> bool:
        """Return whether all explicit fast-path predicates are true."""

        return self.low_risk and self.reversible and self.well_understood

    @property
    def complexity_score(self) -> int:
        """Return the total weighted complexity cost."""

        return sum(item.weight for item in self.added_complexity)

    @property
    def fingerprint(self) -> str:
        """Return a stable digest that binds a decision to this assessment."""

        material = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Serialize the assessment to JSON-compatible data."""

        return {
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


@dataclass(frozen=True, slots=True)
class SystemsGateDecision:
    """Immutable result of evaluating one plan and assessment."""

    route: SystemsGateRoute
    permitted: bool
    reasons: tuple[str, ...]
    complexity_score: int
    assessment_fingerprint: str
    requires_human_review: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.route, SystemsGateRoute):
            raise ValidationError("systems gate decision route is invalid")
        if not isinstance(self.permitted, bool):
            raise ValidationError("systems gate decision permitted must be a boolean")
        if not isinstance(self.requires_human_review, bool):
            raise ValidationError(
                "systems gate decision requires_human_review must be a boolean"
            )
        reasons = _normalize_text_tuple(self.reasons, "systems gate reasons")
        if not reasons:
            raise ValidationError("systems gate decision must include a reason")
        object.__setattr__(self, "reasons", reasons)
        if self.complexity_score < 0:
            raise ValidationError("systems gate complexity score cannot be negative")
        _require_text(
            self.assessment_fingerprint,
            "systems gate assessment fingerprint",
        )


@dataclass(frozen=True, slots=True)
class GovernedPlan:
    """Plan bundled with the assessment and decision that admitted it."""

    plan: ChangePlan
    assessment: SystemsAssessment
    decision: SystemsGateDecision

    def __post_init__(self) -> None:
        if not self.decision.permitted:
            raise ValidationError(
                "a denied systems decision cannot bind a governed plan"
            )
        if self.decision.assessment_fingerprint != self.assessment.fingerprint:
            raise ValidationError(
                "systems gate decision is not bound to the supplied assessment"
            )


class SystemsGovernanceGate:
    """Fail closed before a planner may return an actionable plan."""

    _FAST_PATH_RISKS = frozenset(
        {
            RiskLevel.READ_ONLY,
            RiskLevel.LOCAL_GENERATION,
        }
    )

    def __init__(self, *, max_automatic_complexity_score: int = 4) -> None:
        if (
            not isinstance(max_automatic_complexity_score, int)
            or isinstance(max_automatic_complexity_score, bool)
            or max_automatic_complexity_score < 0
        ):
            raise ValidationError(
                "max_automatic_complexity_score must be a non-negative integer"
            )
        self._max_automatic_complexity_score = max_automatic_complexity_score

    def evaluate(
        self,
        plan: ChangePlan,
        assessment: SystemsAssessment,
    ) -> SystemsGateDecision:
        """Evaluate a plan against the systems-governance contract."""

        route = (
            SystemsGateRoute.FAST_PATH
            if assessment.fast_path_requested
            else SystemsGateRoute.GATED
        )
        reasons: list[str] = []
        requires_human_review = False

        if route is SystemsGateRoute.FAST_PATH:
            unsafe = sorted(
                {
                    str(action.risk)
                    for action in plan.actions
                    if action.risk not in self._FAST_PATH_RISKS
                }
            )
            if unsafe:
                reasons.append(
                    "fast path permits read-only or local-generation actions only; "
                    f"found {', '.join(unsafe)}"
                )
            if assessment.added_complexity:
                reasons.append("fast path cannot introduce durable complexity")
        else:
            for name, values in (
                ("stocks", assessment.stocks),
                ("flows", assessment.flows),
                ("feedback_loops", assessment.feedback_loops),
                ("delays", assessment.delays),
                ("unintended_consequences", assessment.unintended_consequences),
            ):
                if not values:
                    reasons.append(f"gated assessment requires {name}")

        if assessment.added_complexity:
            if not assessment.alternatives_considered:
                reasons.append(
                    "added complexity requires simpler alternatives considered"
                )
            if not assessment.existing_mechanisms_insufficient_because:
                reasons.append(
                    "added complexity requires evidence that existing mechanisms "
                    "are insufficient"
                )
            if not assessment.reversibility_strategy:
                reasons.append(
                    "added complexity requires an explicit removal or reversibility "
                    "strategy"
                )

        if assessment.complexity_score > self._max_automatic_complexity_score:
            requires_human_review = True
            reasons.append(
                "complexity score "
                f"{assessment.complexity_score} exceeds automatic budget "
                f"{self._max_automatic_complexity_score}"
            )

        permitted = not reasons
        if permitted:
            reasons.append(
                "explicit fast path accepted"
                if route is SystemsGateRoute.FAST_PATH
                else "systems governance assessment complete"
            )
        return SystemsGateDecision(
            route=route,
            permitted=permitted,
            reasons=tuple(reasons),
            complexity_score=assessment.complexity_score,
            assessment_fingerprint=assessment.fingerprint,
            requires_human_review=requires_human_review,
        )

    def enforce(
        self,
        plan: ChangePlan,
        assessment: SystemsAssessment,
    ) -> SystemsGateDecision:
        """Return a permitted decision or raise a validation error."""

        decision = self.evaluate(plan, assessment)
        if not decision.permitted:
            raise ValidationError(
                "systems governance denied plan: " + "; ".join(decision.reasons)
            )
        return decision


class GovernedPlanner:
    """Require diagnosis before planning and bind the resulting decision."""

    def __init__(
        self,
        *,
        assessor: SystemsAssessor,
        planner: SystemsAwarePlanner,
        gate: SystemsGovernanceGate | None = None,
    ) -> None:
        self._assessor = assessor
        self._planner = planner
        self._gate = gate or SystemsGovernanceGate()

    def plan(self, goal: str) -> GovernedPlan:
        """Assess, plan, and enforce the systems gate in that order."""

        _require_text(goal, "planner goal")
        assessment = self._assessor.assess(goal)
        if not isinstance(assessment, SystemsAssessment):
            raise ValidationError(
                "systems assessor must return a SystemsAssessment instance"
            )
        plan = self._planner.plan(goal, systems_assessment=assessment)
        if not isinstance(plan, ChangePlan):
            raise ValidationError("systems-aware planner must return a ChangePlan")
        decision = self._gate.enforce(plan, assessment)
        return GovernedPlan(plan=plan, assessment=assessment, decision=decision)


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must not be empty")
    if value != value.strip():
        raise ValidationError(f"{name} must be trimmed")


def _normalize_text_tuple(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    normalized = tuple(values)
    for value in normalized:
        _require_text(value, name)
    return normalized
