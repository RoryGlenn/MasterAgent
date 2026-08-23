"""Planner contracts and the systems-governance planning gate."""

from __future__ import annotations

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
    StrategyActionTrace,
    StrategyCoherenceReview,
    SystemsAssessment,
    SystemsGateDecision,
    SystemsGateRoute,
    SystemsMetricStatus,
    SystemsOutcomeEvidence,
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


class StrategyCoherenceReviewer(Protocol):
    """Review semantic handoffs without granting runtime authority."""

    def review(self, *, assessment: SystemsAssessment) -> StrategyCoherenceReview:
        """Return explicit findings bound to one assessment and strategy kernel."""


class SystemsOutcomeEvidenceProvider(Protocol):
    """Observe bounded post-execution evidence without granting authority."""

    def observe(
        self,
        *,
        assessment: SystemsAssessment,
        decision: SystemsGateDecision,
        states: tuple[ActionState, ...],
    ) -> SystemsOutcomeEvidence:
        """Return independently measured, content-free outcome evidence."""


class SystemsOutcomeObserver(Protocol):
    """Validated post-execution observer boundary."""

    def observe(
        self,
        *,
        assessment: SystemsAssessment,
        decision: SystemsGateDecision,
        states: tuple[ActionState, ...],
    ) -> SystemsOutcomeEvidence:
        """Return evidence after the ordinary runtime has finished actions."""


class EvidenceBackedSystemsAssessor:
    """Return one explicit typed assessment for its exact planning goal."""

    def __init__(self, assessment: SystemsAssessment) -> None:
        if not isinstance(assessment, SystemsAssessment):
            raise ValidationError(
                "evidence-backed assessor requires a SystemsAssessment"
            )
        self._assessment = assessment

    def assess(self, goal: str) -> SystemsAssessment:
        """Return the bound assessment and reject goal substitution."""

        _require_text(goal, "planner goal")
        if goal != self._assessment.desired_outcome:
            raise ValidationError(
                "systems assessment desired outcome does not match the planner goal"
            )
        return self._assessment


class EvidenceBackedStrategyCoherenceReviewer:
    """Return one explicit coherence review for its exact planning evidence."""

    def __init__(self, review: StrategyCoherenceReview) -> None:
        if not isinstance(review, StrategyCoherenceReview):
            raise ValidationError(
                "evidence-backed coherence reviewer requires a StrategyCoherenceReview"
            )
        self._review = review

    def review(self, *, assessment: SystemsAssessment) -> StrategyCoherenceReview:
        """Return the bound review and reject assessment or kernel substitution."""

        kernel = assessment.strategy_kernel
        if kernel is None:
            raise ValidationError(
                "strategy coherence review requires a strategy kernel"
            )
        if self._review.assessment_fingerprint != assessment.fingerprint:
            raise ValidationError(
                "strategy coherence review does not match the systems assessment"
            )
        if self._review.strategy_kernel_fingerprint != kernel.fingerprint:
            raise ValidationError(
                "strategy coherence review does not match the strategy kernel"
            )
        return self._review


class EvidenceBackedSystemsOutcomeObserver:
    """Adapt one explicit evidence provider to the post-execution boundary."""

    def __init__(self, provider: SystemsOutcomeEvidenceProvider) -> None:
        if not callable(getattr(provider, "observe", None)):
            raise ValidationError("systems outcome evidence provider is invalid")
        self._provider = provider

    def observe(
        self,
        *,
        assessment: SystemsAssessment,
        decision: SystemsGateDecision,
        states: tuple[ActionState, ...],
    ) -> SystemsOutcomeEvidence:
        """Return validated typed evidence from the configured provider."""

        evidence = self._provider.observe(
            assessment=assessment,
            decision=decision,
            states=states,
        )
        if not isinstance(evidence, SystemsOutcomeEvidence):
            raise ValidationError(
                "systems outcome provider must return SystemsOutcomeEvidence"
            )
        return evidence


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
        if plan.goal != assessment.desired_outcome:
            reasons.append("plan goal does not match the assessed desired outcome")
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
            if plan.strategy_coherence_review is not None:
                reasons.append("fast path cannot carry a strategy coherence review")
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
            if assessment.strategy_kernel is None:
                reasons.append("gated assessment requires a strategy_kernel")
            reasons.extend(_strategy_coherence_reasons(plan, assessment))
        reasons.extend(_strategy_trace_reasons(plan, assessment))
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
            strategy_coherence_review_fingerprint=(
                plan.strategy_coherence_review.fingerprint
                if route is SystemsGateRoute.GATED
                and plan.strategy_coherence_review is not None
                else None
            ),
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


def bind_static_intervention_governance(
    plan: ChangePlan,
    assessment: SystemsAssessment,
    *,
    gate: SystemsGovernanceGate | None = None,
) -> ChangePlan:
    """Bind a static workflow by mapping actions to declared intents in order."""

    kernel = assessment.strategy_kernel
    if kernel is None:
        raise ValidationError("static intervention requires a strategy kernel")
    if len(kernel.coherent_actions) != len(plan.actions):
        raise ValidationError(
            "static intervention requires exactly one intent per plan action"
        )
    traced_plan = replace(
        plan,
        strategy_traces=tuple(
            StrategyActionTrace(action_id=action.action_id, intent_id=intent.intent_id)
            for action, intent in zip(
                plan.actions, kernel.coherent_actions, strict=True
            )
        ),
        strategy_coherence_review=(
            StrategyCoherenceReview.for_static_intervention(assessment)
        ),
    )
    return bind_systems_governance(traced_plan, assessment, gate=gate)


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

    assessment = SystemsAssessment.for_fast_path(
        desired_outcome=plan.goal,
        current_behavior=current_behavior,
        constraint=constraint,
        leverage_point=leverage_point,
        simplest_intervention=plan.goal,
        success_metric=success_metric,
        failure_condition=failure_condition,
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
    observer: SystemsOutcomeObserver | None = None,
) -> SystemsPostExecutionReview:
    """Build fingerprint-bound evidence or a conservative fallback review."""

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
    metric_sha256 = assessment.success_metric_sha256
    observer_failure: str | None = None
    evidence: SystemsOutcomeEvidence | None = None
    if not dry_run and observer is not None:
        try:
            candidate = observer.observe(
                assessment=assessment,
                decision=decision,
                states=observed_states,
            )
            if not isinstance(candidate, SystemsOutcomeEvidence):
                observer_failure = "observer_invalid"
            elif candidate.assessment_fingerprint != assessment.fingerprint:
                observer_failure = "observer_assessment_mismatch"
            elif candidate.decision_fingerprint != decision.fingerprint:
                observer_failure = "observer_decision_mismatch"
            elif candidate.success_metric_sha256 != metric_sha256:
                observer_failure = "observer_metric_mismatch"
            else:
                evidence = candidate
        except Exception:  # noqa: BLE001 - observation cannot invalidate completed work.
            observer_failure = "observer_invalid"
    if evidence is not None:
        observed_unintended_effects = (
            evidence.unintended_effects_detected or unintended_effects
        )
        complexity_growth = (
            evidence.observed_complexity_score - assessment.complexity_score
            if evidence.observed_complexity_score is not None
            else None
        )
        reassessment_required = any(
            (
                evidence.metric_status is SystemsMetricStatus.CONFIRMED_UNCHANGED,
                not successful,
                observed_unintended_effects,
                not evidence.stop_condition_checked,
                evidence.stop_condition_triggered is True,
                complexity_growth is None,
                complexity_growth is not None and complexity_growth > 0,
            )
        )
        reason_codes = list(evidence.reason_codes)
        if not successful and "execution_unsuccessful" not in reason_codes:
            reason_codes.append("execution_unsuccessful")
        if unintended_effects and "unintended_effect_possible" not in reason_codes:
            reason_codes.append("unintended_effect_possible")
        if (
            evidence.observed_complexity_score is None
            and "complexity_not_observed" not in reason_codes
        ):
            reason_codes.append("complexity_not_observed")
        if (
            not evidence.stop_condition_checked
            and "stop_condition_not_observed" not in reason_codes
        ):
            reason_codes.append("stop_condition_not_observed")
        return SystemsPostExecutionReview(
            assessment_fingerprint=assessment.fingerprint,
            decision_fingerprint=decision.fingerprint,
            success_metric_sha256=metric_sha256,
            metric_status=evidence.metric_status,
            unintended_effects_detected=observed_unintended_effects,
            planned_complexity_score=assessment.complexity_score,
            observed_complexity_score=evidence.observed_complexity_score,
            complexity_growth=complexity_growth,
            removal_candidate_count=evidence.removal_candidate_count,
            stop_condition_checked=evidence.stop_condition_checked,
            stop_condition_triggered=evidence.stop_condition_triggered,
            reassessment_required=reassessment_required,
            reason_codes=tuple(reason_codes),
        )
    reason_codes = ["dry_run_metric_not_observed" if dry_run else "metric_not_observed"]
    if observer_failure is not None:
        reason_codes.append(observer_failure)
    elif observer is None:
        reason_codes.append("observer_unavailable")
    if not successful:
        reason_codes.append("execution_unsuccessful")
    if unintended_effects:
        reason_codes.append("unintended_effect_possible")
    reason_codes.append("stop_condition_not_observed")
    return SystemsPostExecutionReview(
        assessment_fingerprint=assessment.fingerprint,
        decision_fingerprint=decision.fingerprint,
        success_metric_sha256=metric_sha256,
        metric_status=SystemsMetricStatus.NOT_OBSERVED,
        unintended_effects_detected=unintended_effects,
        planned_complexity_score=assessment.complexity_score,
        removal_candidate_count=len(assessment.removable_complexity),
        stop_condition_checked=False,
        reassessment_required=True,
        reason_codes=tuple(reason_codes),
    )


def _strategy_trace_reasons(
    plan: ChangePlan, assessment: SystemsAssessment
) -> tuple[str, ...]:
    """Return every bounded action-to-strategy coverage failure."""

    kernel = assessment.strategy_kernel
    traces = plan.strategy_traces
    if kernel is None:
        return ("strategy traces require a strategy kernel",) if traces else ()
    reasons: list[str] = []
    action_ids = {action.action_id for action in plan.actions}
    trace_action_ids = [trace.action_id for trace in traces]
    if len(trace_action_ids) != len(set(trace_action_ids)):
        reasons.append("strategy traces contain duplicate action IDs")
    if action_ids - set(trace_action_ids):
        reasons.append("strategy traces do not cover every plan action")
    if set(trace_action_ids) - action_ids:
        reasons.append("strategy traces contain unknown or stale action IDs")
    intent_ids = {intent.intent_id for intent in kernel.coherent_actions}
    traced_intent_ids = {trace.intent_id for trace in traces}
    if traced_intent_ids - intent_ids:
        reasons.append("strategy traces contain unknown intent IDs")
    if intent_ids - traced_intent_ids:
        reasons.append("strategy traces do not use every coherent action intent")
    return tuple(reasons)


def _strategy_coherence_reasons(
    plan: ChangePlan, assessment: SystemsAssessment
) -> tuple[str, ...]:
    """Return every strategy-to-systems coherence-evidence failure."""

    review = plan.strategy_coherence_review
    if review is None:
        return ("gated plan requires a strategy coherence review",)
    kernel = assessment.strategy_kernel
    reasons: list[str] = []
    if review.assessment_fingerprint != assessment.fingerprint:
        reasons.append("strategy coherence review assessment fingerprint is stale")
    if kernel is None:
        reasons.append("strategy coherence review requires a strategy kernel")
    elif review.strategy_kernel_fingerprint != kernel.fingerprint:
        reasons.append("strategy coherence review kernel fingerprint is stale")
    for name in (
        "diagnosis_addresses_constraint",
        "guiding_policy_targets_leverage_point",
        "proximate_objective_advances_outcome",
        "coherent_actions_support_success_metric",
        "tradeoffs_cover_alternatives",
    ):
        if not getattr(review, name):
            reasons.append(f"strategy coherence finding is false: {name}")
    return tuple(reasons)


class GovernedPlanner:
    """Require diagnosis before planning and bind the resulting decision."""

    def __init__(
        self,
        *,
        assessor: SystemsAssessor,
        planner: SystemsAwarePlanner,
        coherence_reviewer: StrategyCoherenceReviewer | None = None,
        gate: SystemsGovernanceGate | None = None,
    ) -> None:
        self._assessor = assessor
        self._planner = planner
        self._coherence_reviewer = coherence_reviewer
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
        if plan.strategy_coherence_review is not None:
            raise ValidationError(
                "systems-aware planner cannot review its own strategy coherence"
            )
        if not assessment.fast_path_requested:
            if self._coherence_reviewer is None:
                raise ValidationError(
                    "gated planning requires a strategy coherence reviewer"
                )
            review = self._coherence_reviewer.review(assessment=assessment)
            if not isinstance(review, StrategyCoherenceReview):
                raise ValidationError(
                    "strategy coherence reviewer must return a StrategyCoherenceReview"
                )
            plan = replace(plan, strategy_coherence_review=review)
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
    "EvidenceBackedStrategyCoherenceReviewer",
    "EvidenceBackedSystemsAssessor",
    "EvidenceBackedSystemsOutcomeObserver",
    "GovernedPlan",
    "GovernedPlanner",
    "Planner",
    "StrategyCoherenceReviewer",
    "SystemsAssessment",
    "SystemsAssessor",
    "SystemsAwarePlanner",
    "SystemsGateDecision",
    "SystemsGateRoute",
    "SystemsGovernanceGate",
    "SystemsOutcomeEvidenceProvider",
    "SystemsOutcomeObserver",
    "bind_fast_path_governance",
    "bind_static_intervention_governance",
    "bind_systems_governance",
    "build_systems_post_execution_review",
    "enforce_systems_governance",
]
