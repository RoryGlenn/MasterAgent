"""Planner contracts and the systems-governance planning gate."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from master_agent.errors import ValidationError
from master_agent.models import (
    ActionState,
    Approval,
    ChangePlan,
    ComplexityItem,
    ComplexityKind,
    RiskLevel,
    SystemsAssessment,
    SystemsGateDecision,
    SystemsGateRoute,
    SystemsMetricStatus,
    SystemsPostExecutionReview,
)

if TYPE_CHECKING:
    from master_agent.policy import PolicyEngine


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


@dataclass(frozen=True, slots=True)
class GovernedPlan:
    """Plan bundled with the assessment and decision that admitted it."""

    plan: ChangePlan
    assessment: SystemsAssessment
    decision: SystemsGateDecision

    def __post_init__(self) -> None:
        if self.plan.systems_assessment != self.assessment:
            raise ValidationError("governed plan does not contain its assessment")
        if self.plan.systems_decision != self.decision:
            raise ValidationError("governed plan does not contain its gate decision")


class SystemsGovernanceGate:
    """Fail closed before a planner may return an actionable plan."""

    _FAST_PATH_RISKS = frozenset({RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION})

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
        self, plan: ChangePlan, assessment: SystemsAssessment
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
        non_review_reason_count = len(reasons) - int(requires_human_review)
        permitted = non_review_reason_count == 0
        if permitted and not requires_human_review:
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
        """Return an automatically permitted decision or raise."""

        decision = self.evaluate(plan, assessment)
        if not decision.permitted:
            raise ValidationError(
                "systems governance denied plan: " + "; ".join(decision.reasons)
            )
        if decision.requires_human_review:
            raise ValidationError(
                "systems governance requires authenticated human review: "
                + "; ".join(decision.reasons)
            )
        return decision


def bind_systems_governance(
    plan: ChangePlan,
    assessment: SystemsAssessment,
    *,
    gate: SystemsGovernanceGate | None = None,
) -> ChangePlan:
    """Admit an unbound plan and return an immutable governed replacement."""

    if plan.systems_assessment is not None or plan.systems_decision is not None:
        raise ValidationError("plan already contains a systems governance binding")
    selected_gate = gate or SystemsGovernanceGate()
    decision = selected_gate.evaluate(plan, assessment)
    if not decision.permitted:
        raise ValidationError(
            "systems governance denied plan: " + "; ".join(decision.reasons)
        )
    return replace(plan, systems_assessment=assessment, systems_decision=decision)


def bind_fast_path_governance(
    plan: ChangePlan,
    *,
    current_behavior: str,
    constraint: str,
    leverage_point: str,
    success_metric: str,
    failure_condition: str,
) -> ChangePlan:
    """Bind an explicit assessment for a known-safe static workflow."""

    assessment = SystemsAssessment(
        desired_outcome=plan.goal,
        current_behavior=current_behavior,
        constraint=constraint,
        leverage_point=leverage_point,
        simplest_intervention=plan.goal,
        success_metric=success_metric,
        failure_condition=failure_condition,
        low_risk=True,
        reversible=True,
        well_understood=True,
    )
    return bind_systems_governance(plan, assessment)


def enforce_systems_governance(
    plan: ChangePlan,
    *,
    gate: SystemsGovernanceGate | None = None,
    policy: PolicyEngine | None = None,
    approvals: Iterable[Approval] = (),
) -> SystemsGateDecision:
    """Reject missing, stale, denied, or forged plan governance evidence."""

    assessment = plan.systems_assessment
    bound_decision = plan.systems_decision
    if assessment is None or bound_decision is None:
        raise ValidationError("plan is missing a systems governance binding")
    selected_gate = gate or SystemsGovernanceGate()
    expected = selected_gate.evaluate(plan, assessment)
    if bound_decision != expected:
        raise ValidationError("plan systems governance decision is stale or forged")
    if not expected.permitted:
        raise ValidationError(
            "systems governance denied plan: " + "; ".join(expected.reasons)
        )
    if expected.requires_human_review and (
        policy is None
        or not _has_authenticated_whole_plan_review(
            policy=policy,
            plan=plan,
            approvals=tuple(approvals),
        )
    ):
        raise ValidationError(
            "systems governance requires authenticated human review: "
            + "; ".join(expected.reasons)
        )
    return bound_decision


def _has_authenticated_whole_plan_review(
    *,
    policy: PolicyEngine,
    plan: ChangePlan,
    approvals: tuple[Approval, ...],
) -> bool:
    """Return whether one authenticated human approved every plan action."""

    authenticated = policy.authenticated_approvals(plan, approvals)
    action_ids = {action.action_id for action in plan.actions}
    return any(
        action_ids.issubset(approval.approved_action_ids)
        for approval, _subject in authenticated
    )


def build_systems_post_execution_review(
    *,
    assessment: SystemsAssessment,
    decision: SystemsGateDecision,
    states: Iterable[ActionState],
    dry_run: bool,
) -> SystemsPostExecutionReview:
    """Build conservative, content-free post-execution systems evidence."""

    observed_states = tuple(states)
    unintended_states = {
        ActionState.INDETERMINATE,
        ActionState.COMPENSATION_FAILED,
    }
    unintended_effects = any(item in unintended_states for item in observed_states)
    successful = all(
        item in {ActionState.PLANNED, ActionState.VERIFIED, ActionState.REUSED}
        for item in observed_states
    )
    reason_codes = ["dry_run_metric_not_observed" if dry_run else "metric_not_observed"]
    if not successful:
        reason_codes.append("execution_unsuccessful")
    if unintended_effects:
        reason_codes.append("unintended_effect_possible")
    reason_codes.append("stop_condition_not_observed")
    return SystemsPostExecutionReview(
        assessment_fingerprint=assessment.fingerprint,
        decision_fingerprint=decision.fingerprint,
        success_metric_sha256=hashlib.sha256(
            assessment.success_metric.encode("utf-8")
        ).hexdigest(),
        metric_status=SystemsMetricStatus.NOT_OBSERVED,
        unintended_effects_detected=unintended_effects,
        planned_complexity_score=assessment.complexity_score,
        removal_candidate_count=len(assessment.removable_complexity),
        stop_condition_checked=False,
        reassessment_required=True,
        reason_codes=tuple(reason_codes),
    )


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
        """Assess, plan, enforce, and immutably bind in that order."""

        _require_text(goal, "planner goal")
        assessment = self._assessor.assess(goal)
        if not isinstance(assessment, SystemsAssessment):
            raise ValidationError(
                "systems assessor must return a SystemsAssessment instance"
            )
        plan = self._planner.plan(goal, systems_assessment=assessment)
        if not isinstance(plan, ChangePlan):
            raise ValidationError("systems-aware planner must return a ChangePlan")
        governed_plan = bind_systems_governance(plan, assessment, gate=self._gate)
        decision = governed_plan.systems_decision
        if decision is None:  # pragma: no cover - guaranteed by binding.
            raise ValidationError("systems governance decision was not bound")
        return GovernedPlan(
            plan=governed_plan, assessment=assessment, decision=decision
        )


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must not be empty")
    if value != value.strip():
        raise ValidationError(f"{name} must be trimmed")


__all__ = [
    "ComplexityItem",
    "ComplexityKind",
    "GovernedPlan",
    "GovernedPlanner",
    "Planner",
    "SystemsAssessment",
    "SystemsAssessor",
    "SystemsAwarePlanner",
    "SystemsGateDecision",
    "SystemsGateRoute",
    "SystemsGovernanceGate",
    "bind_fast_path_governance",
    "bind_systems_governance",
    "build_systems_post_execution_review",
    "enforce_systems_governance",
]
