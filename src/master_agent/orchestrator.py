"""Dependency-aware, policy-gated workflow execution."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from master_agent.audit import AuditLog, IdempotencyClaimState, implemented_audit_sink
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.connectors.base import (
    CompensatingConnector,
    Connector,
    IdempotencyRecordingConnector,
    IdempotencyVerifyingConnector,
)
from master_agent.connectors.mock import MockConnector
from master_agent.errors import (
    ConfigurationError,
    ConnectorError,
    MasterAgentError,
    PreEffectError,
    StructuredDataTypeError,
    ValidationError,
    VersionConflictError,
)
from master_agent.evidence import audit_message_metadata, result_audit_summary
from master_agent.governance import GovernanceProfile
from master_agent.http import (
    HttpActionBudget,
    activate_http_action_budget,
    connector_http_action_budget,
)
from master_agent.models import (
    ActionState,
    AgentAction,
    Approval,
    ChangePlan,
    CompensationMode,
    ConnectorExecutionBinding,
    ExecutionResult,
    RiskLevel,
    SystemsPostExecutionReview,
)
from master_agent.planners.base import (
    build_systems_post_execution_review,
    enforce_systems_governance,
)
from master_agent.policy import PolicyEngine
from master_agent.provider_egress import (
    ProviderDataEgressBinding,
    ProviderDataRoute,
    bind_provider_data_egress,
    provider_result_audit_summary,
    sanitize_provider_result,
)
from master_agent.registry import ConnectorRegistry


@dataclass(frozen=True, slots=True)
class ActionReport:
    """Final report for one action."""

    action_id: UUID
    capability: str
    state: ActionState
    message: str
    result: ExecutionResult | None = None
    compensation: ExecutionResult | None = None
    egress: ProviderDataEgressBinding | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the action report."""

        return {
            "action_id": str(self.action_id),
            "capability": self.capability,
            "state": str(self.state),
            "message": self.message,
            "result": self.result.to_dict() if self.result is not None else None,
            "compensation": (
                self.compensation.to_dict() if self.compensation is not None else None
            ),
            "egress": self.egress.to_dict() if self.egress is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> ActionReport:
        """Create an action report from persisted JSON data."""

        result_data = data.get("result")
        compensation_data = data.get("compensation")
        egress_data = data.get("egress")
        if result_data is not None and not isinstance(result_data, Mapping):
            raise ValueError("action report result must be an object or null")
        if compensation_data is not None and not isinstance(compensation_data, Mapping):
            raise ValueError("action report compensation must be an object or null")
        if egress_data is not None and not isinstance(egress_data, Mapping):
            raise ValueError("action report egress must be an object or null")
        return cls(
            action_id=UUID(str(data["action_id"])),
            capability=str(data["capability"]),
            state=ActionState(str(data["state"])),
            message=str(data.get("message", "")),
            result=(
                ExecutionResult.from_dict(result_data)
                if isinstance(result_data, Mapping)
                else None
            ),
            compensation=(
                ExecutionResult.from_dict(compensation_data)
                if isinstance(compensation_data, Mapping)
                else None
            ),
            egress=(
                ProviderDataEgressBinding.from_dict(egress_data)
                if isinstance(egress_data, Mapping)
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class RunReport:
    """Final report for a plan execution attempt."""

    run_id: UUID
    plan_id: UUID
    plan_fingerprint: str
    dry_run: bool
    actions: tuple[ActionReport, ...]
    systems_review: SystemsPostExecutionReview | None = None

    @property
    def successful(self) -> bool:
        """Return whether every action reached a successful state."""

        return all(
            item.state
            in {
                ActionState.PLANNED,
                ActionState.VERIFIED,
                ActionState.REUSED,
            }
            for item in self.actions
        )

    @property
    def compensated(self) -> bool:
        """Return whether at least one side effect was rolled back."""

        return any(item.state is ActionState.COMPENSATED for item in self.actions)

    def to_dict(self) -> dict[str, object]:
        """Serialize the run report and retrieved evidence."""

        payload: dict[str, object] = {
            "run_id": str(self.run_id),
            "plan_id": str(self.plan_id),
            "plan_fingerprint": self.plan_fingerprint,
            "dry_run": self.dry_run,
            "successful": self.successful,
            "compensated": self.compensated,
            "actions": [item.to_dict() for item in self.actions],
        }
        if self.systems_review is not None:
            payload["systems_review"] = self.systems_review.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RunReport:
        """Create a run report from persisted JSON data."""

        raw_actions = data.get("actions")
        if not isinstance(raw_actions, list):
            raise StructuredDataTypeError("run report actions must be a list")
        actions: list[ActionReport] = []
        for item in raw_actions:
            if not isinstance(item, Mapping):
                raise StructuredDataTypeError("run report action must be an object")
            actions.append(ActionReport.from_dict(item))
        raw_review = data.get("systems_review")
        if raw_review is not None and not isinstance(raw_review, Mapping):
            raise StructuredDataTypeError(
                "run report systems_review must be an object or null"
            )
        return cls(
            run_id=UUID(str(data["run_id"])),
            plan_id=UUID(str(data["plan_id"])),
            plan_fingerprint=str(data["plan_fingerprint"]),
            dry_run=_strict_bool(data.get("dry_run"), "run report dry_run"),
            actions=tuple(actions),
            systems_review=(
                SystemsPostExecutionReview.from_dict(raw_review)
                if isinstance(raw_review, Mapping)
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class _ExecutedAction:
    action: AgentAction
    connector: Connector
    result: ExecutionResult
    report_index: int
    http_budget: HttpActionBudget | None


class WorkflowOrchestrator:
    """Execute a plan only through policy-approved connectors."""

    def __init__(
        self,
        *,
        policy: PolicyEngine,
        sources: SourceOfTruthRegistry,
        connectors: ConnectorRegistry,
        audit: AuditLog,
        capabilities: CapabilityCatalog | None = None,
        governance: GovernanceProfile | None = None,
    ) -> None:
        self._policy = policy
        self._sources = sources
        self._connectors = connectors
        self._audit = audit
        self._capabilities = capabilities
        self._governance = governance

    def run(
        self,
        plan: ChangePlan,
        *,
        approvals: Iterable[Approval] = (),
        dry_run: bool = True,
    ) -> RunReport:
        """Evaluate and optionally execute a plan.

        Parameters
        ----------
        plan
            Immutable action plan.
        approvals
            Approvals bound to the exact plan fingerprint.
        dry_run
            When true, evaluate without invoking connectors.

        Returns
        -------
        RunReport
            Per-action state, evidence, and compensation outcomes.
        """

        # Never execute caller-owned objects.  The deserialize/validate pass
        # creates a private, recursively immutable snapshot whose fingerprint
        # is the exact artifact evaluated by policy and passed to connectors.
        plan = ChangePlan.from_dict(plan.to_dict())
        approvals_tuple = tuple(approvals)
        systems_decision = enforce_systems_governance(
            plan,
            policy=self._policy,
            approvals=approvals_tuple,
        )
        systems_assessment = plan.systems_assessment
        if systems_assessment is None:  # pragma: no cover - enforced above.
            raise ValidationError("plan is missing a systems governance assessment")
        run_id = uuid4()
        reports: list[ActionReport] = []
        state_by_id: dict[UUID, ActionState] = {}
        side_effects_may_have_occurred: list[_ExecutedAction] = []
        ordered = _topological_order(plan.actions)
        abort_remaining = False

        self._audit.record(
            run_id=run_id,
            plan_id=plan.plan_id,
            action_id=None,
            event_type="plan_started",
            payload={
                "goal_digest": hashlib.sha256(plan.goal.encode("utf-8")).hexdigest(),
                "goal_length": len(plan.goal),
                "fingerprint": plan.fingerprint,
                "dry_run": dry_run,
                "workflow_id": plan.workflow_id,
                "workflow_fingerprint": plan.workflow_fingerprint,
                "compensate_on_failure": plan.compensate_on_failure,
                "systems_assessment_fingerprint": systems_assessment.fingerprint,
                "systems_decision_fingerprint": systems_decision.fingerprint,
                "systems_route": systems_decision.route,
                "systems_complexity_score": systems_decision.complexity_score,
                **(
                    {
                        "capsule_bindings": [
                            item.to_dict() for item in plan.execution_context.capsules
                        ]
                    }
                    if plan.execution_context is not None
                    and plan.execution_context.capsules
                    else {}
                ),
            },
        )

        for action in ordered:
            if abort_remaining:
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.SKIPPED,
                    message="plan stopped after a failure and compensation attempt",
                )
                reports.append(report)
                state_by_id[action.action_id] = report.state
                self._record_action(run_id, plan, action, report)
                continue

            catalog_ok, catalog_reason = self._validate_capability(action)
            if not catalog_ok:
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.PROHIBITED,
                    message=catalog_reason,
                )
                reports.append(report)
                state_by_id[action.action_id] = report.state
                self._record_action(run_id, plan, action, report)
                abort_remaining = self._maybe_compensate(
                    run_id=run_id,
                    plan=plan,
                    reports=reports,
                    executed=side_effects_may_have_occurred,
                    dry_run=dry_run,
                )
                continue

            failed_dependencies = [
                dependency
                for dependency in action.dependencies
                if not _dependency_succeeded(
                    state_by_id.get(dependency),
                    dry_run=dry_run,
                )
            ]
            if failed_dependencies:
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.SKIPPED,
                    message=f"dependencies did not succeed: {failed_dependencies}",
                )
                reports.append(report)
                state_by_id[action.action_id] = report.state
                self._record_action(run_id, plan, action, report)
                continue

            source_ok, source_reason = self._sources.validate(plan, action)
            if not source_ok:
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.PROHIBITED,
                    message=source_reason,
                )
                reports.append(report)
                state_by_id[action.action_id] = report.state
                self._record_action(run_id, plan, action, report)
                abort_remaining = self._maybe_compensate(
                    run_id=run_id,
                    plan=plan,
                    reports=reports,
                    executed=side_effects_may_have_occurred,
                    dry_run=dry_run,
                )
                continue

            minimum_approvers = self._minimum_approvers(action)
            decision = self._policy.evaluate(
                plan=plan,
                action=action,
                approvals=approvals_tuple,
                minimum_distinct_approvers=minimum_approvers,
            )
            if not decision.permitted:
                state = (
                    ActionState.APPROVAL_REQUIRED
                    if decision.approval_required
                    else ActionState.PROHIBITED
                )
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=state,
                    message=decision.reason,
                )
                reports.append(report)
                state_by_id[action.action_id] = report.state
                self._record_action(run_id, plan, action, report)
                abort_remaining = self._maybe_compensate(
                    run_id=run_id,
                    plan=plan,
                    reports=reports,
                    executed=side_effects_may_have_occurred,
                    dry_run=dry_run,
                )
                continue

            if dry_run:
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.PLANNED,
                    message=f"permitted dry run: {decision.reason}",
                )
                reports.append(report)
                state_by_id[action.action_id] = report.state
                self._record_action(run_id, plan, action, report)
                continue

            connector: Connector | None = None
            result: ExecutionResult | None = None
            claim_token: str | None = None
            http_budget: HttpActionBudget | None = None
            egress: ProviderDataEgressBinding | None = None
            try:
                connector = self._connectors.resolve(
                    action.target.system,
                    action.capability,
                )
                execution_ok, execution_reason = self._validate_execution_contract(
                    plan,
                    action,
                    connector,
                )
                if not execution_ok:
                    report = ActionReport(
                        action_id=action.action_id,
                        capability=action.capability,
                        state=ActionState.PROHIBITED,
                        message=execution_reason,
                    )
                    reports.append(report)
                    state_by_id[action.action_id] = report.state
                    self._record_action(run_id, plan, action, report)
                    abort_remaining = self._maybe_compensate(
                        run_id=run_id,
                        plan=plan,
                        reports=reports,
                        executed=side_effects_may_have_occurred,
                        dry_run=dry_run,
                    )
                    continue
                try:
                    egress = self._provider_data_egress_binding(
                        plan,
                        action,
                        connector,
                    )
                except ConfigurationError as error:
                    report = ActionReport(
                        action_id=action.action_id,
                        capability=action.capability,
                        state=ActionState.PROHIBITED,
                        message=str(error),
                    )
                    reports.append(report)
                    state_by_id[action.action_id] = report.state
                    self._record_action(run_id, plan, action, report)
                    abort_remaining = self._maybe_compensate(
                        run_id=run_id,
                        plan=plan,
                        reports=reports,
                        executed=side_effects_may_have_occurred,
                        dry_run=dry_run,
                    )
                    continue
                if egress is not None:
                    self._audit.record(
                        run_id=run_id,
                        plan_id=plan.plan_id,
                        action_id=action.action_id,
                        event_type="provider_data_egress_authorized",
                        payload={
                            "egress": egress.to_dict(),
                            "egress_fingerprint": egress.fingerprint,
                        },
                    )
                http_budget = connector_http_action_budget(connector)
                if _uses_idempotency(action):
                    claim = self._audit.claim_action(
                        idempotency_key=action.idempotency_key,
                        action_fingerprint=action.effect_fingerprint,
                        plan_id=plan.plan_id,
                        action_id=action.action_id,
                    )
                    if claim.state is IdempotencyClaimState.COMPLETED:
                        if not isinstance(connector, IdempotencyVerifyingConnector):
                            report = ActionReport(
                                action_id=action.action_id,
                                capability=action.capability,
                                state=ActionState.CONFLICTED,
                                message=(
                                    "prior idempotent completion cannot be "
                                    "independently reverified by this connector"
                                ),
                            )
                            reports.append(report)
                            state_by_id[action.action_id] = report.state
                            self._record_action(run_id, plan, action, report)
                            abort_remaining = self._maybe_compensate(
                                run_id=run_id,
                                plan=plan,
                                reports=reports,
                                executed=side_effects_may_have_occurred,
                                dry_run=dry_run,
                            )
                            continue
                        try:
                            with activate_http_action_budget(http_budget):
                                reuse_verification = connector.verify_completed(
                                    action,
                                    claim.result or {},
                                )
                        except (
                            ConnectorError,
                            KeyError,
                            OSError,
                            RuntimeError,
                            TypeError,
                            ValueError,
                        ) as error:
                            report = ActionReport(
                                action_id=action.action_id,
                                capability=action.capability,
                                state=ActionState.CONFLICTED,
                                message=(
                                    "prior idempotent completion could not be "
                                    "independently reverified: " + type(error).__name__
                                ),
                            )
                            reports.append(report)
                            state_by_id[action.action_id] = report.state
                            self._record_action(run_id, plan, action, report)
                            abort_remaining = self._maybe_compensate(
                                run_id=run_id,
                                plan=plan,
                                reports=reports,
                                executed=side_effects_may_have_occurred,
                                dry_run=dry_run,
                            )
                            continue
                        if not reuse_verification.verified:
                            report = ActionReport(
                                action_id=action.action_id,
                                capability=action.capability,
                                state=ActionState.CONFLICTED,
                                message=(
                                    "prior idempotent effect no longer verifies: "
                                    f"{reuse_verification.message}"
                                ),
                            )
                            reports.append(report)
                            state_by_id[action.action_id] = report.state
                            self._record_action(run_id, plan, action, report)
                            abort_remaining = self._maybe_compensate(
                                run_id=run_id,
                                plan=plan,
                                reports=reports,
                                executed=side_effects_may_have_occurred,
                                dry_run=dry_run,
                            )
                            continue
                        report = ActionReport(
                            action_id=action.action_id,
                            capability=action.capability,
                            state=ActionState.REUSED,
                            message=(
                                "the same idempotent action already completed; "
                                "verified result metadata reused"
                            ),
                        )
                        reports.append(report)
                        state_by_id[action.action_id] = report.state
                        self._record_action(
                            run_id,
                            plan,
                            action,
                            report,
                            extra={"prior_result": claim.result or {}},
                        )
                        continue
                    if claim.state is IdempotencyClaimState.CONFLICT:
                        report = ActionReport(
                            action_id=action.action_id,
                            capability=action.capability,
                            state=ActionState.CONFLICTED,
                            message=(
                                "idempotency key is bound to a different action effect"
                            ),
                        )
                        reports.append(report)
                        state_by_id[action.action_id] = report.state
                        self._record_action(run_id, plan, action, report)
                        abort_remaining = self._maybe_compensate(
                            run_id=run_id,
                            plan=plan,
                            reports=reports,
                            executed=side_effects_may_have_occurred,
                            dry_run=dry_run,
                        )
                        continue
                    if claim.state is IdempotencyClaimState.IN_PROGRESS:
                        report = ActionReport(
                            action_id=action.action_id,
                            capability=action.capability,
                            state=ActionState.CONFLICTED,
                            message=("idempotent action is already in progress"),
                        )
                        reports.append(report)
                        state_by_id[action.action_id] = report.state
                        self._record_action(run_id, plan, action, report)
                        abort_remaining = self._maybe_compensate(
                            run_id=run_id,
                            plan=plan,
                            reports=reports,
                            executed=side_effects_may_have_occurred,
                            dry_run=dry_run,
                        )
                        continue
                    if claim.state is IdempotencyClaimState.INDETERMINATE:
                        reconciliation_record = _indeterminate_result(claim.result)
                        reconciliation_message: str | None = None
                        if reconciliation_record is not None and isinstance(
                            connector, IdempotencyVerifyingConnector
                        ):
                            try:
                                with activate_http_action_budget(http_budget):
                                    reconciliation = connector.verify_completed(
                                        action,
                                        reconciliation_record,
                                    )
                                if reconciliation.verified:
                                    self._audit.resolve_indeterminate_action(
                                        idempotency_key=action.idempotency_key,
                                        action_fingerprint=action.effect_fingerprint,
                                        expected_outcome=claim.result or {},
                                        completed_result=reconciliation_record,
                                    )
                                    report = ActionReport(
                                        action_id=action.action_id,
                                        capability=action.capability,
                                        state=ActionState.REUSED,
                                        message=(
                                            "durable indeterminate outcome was "
                                            "independently reconciled against "
                                            "provider state"
                                        ),
                                    )
                                    reports.append(report)
                                    state_by_id[action.action_id] = report.state
                                    self._record_action(
                                        run_id,
                                        plan,
                                        action,
                                        report,
                                        extra={"prior_result": reconciliation_record},
                                    )
                                    continue
                                reconciliation_message = reconciliation.message
                            except (
                                ConnectorError,
                                KeyError,
                                OSError,
                                RuntimeError,
                                TypeError,
                                ValueError,
                            ) as error:
                                reconciliation_message = type(error).__name__
                        report = ActionReport(
                            action_id=action.action_id,
                            capability=action.capability,
                            state=ActionState.CONFLICTED,
                            message=(
                                "idempotent action has a durable indeterminate "
                                "outcome; provider reconciliation or operator "
                                "resolution is required before retry"
                                + (
                                    ""
                                    if reconciliation_message is None
                                    else (
                                        "; reconciliation did not verify: "
                                        + reconciliation_message
                                    )
                                )
                            ),
                        )
                        reports.append(report)
                        state_by_id[action.action_id] = report.state
                        self._record_action(run_id, plan, action, report)
                        abort_remaining = self._maybe_compensate(
                            run_id=run_id,
                            plan=plan,
                            reports=reports,
                            executed=side_effects_may_have_occurred,
                            dry_run=dry_run,
                        )
                        continue
                    claim_token = claim.token
                    if claim_token is None:  # pragma: no cover - invariant guard.
                        raise RuntimeError("idempotency claim omitted its token")
                with activate_http_action_budget(http_budget):
                    result = connector.execute(action)
                    if not isinstance(result, ExecutionResult):
                        raise ConnectorError(
                            "connector returned an invalid execution result"
                        )
                    if _uses_idempotency(action):
                        self._audit.record(
                            run_id=run_id,
                            plan_id=plan.plan_id,
                            action_id=action.action_id,
                            event_type="side_effect_may_have_occurred",
                            payload={
                                "capability": action.capability,
                                "result": result_audit_summary(result),
                            },
                        )
                    # Keep the runtime's exact post-execute snapshot private.
                    # Verification receives a separate copy so a connector
                    # cannot rewrite evidence that may need reconciliation or
                    # compensation after verification fails.
                    result = _copy_execution_result(result)
                    if action.risk is RiskLevel.REVERSIBLE_WRITE:
                        side_effects_may_have_occurred.append(
                            _ExecutedAction(
                                action=action,
                                connector=connector,
                                result=result,
                                report_index=len(reports),
                                http_budget=http_budget,
                            )
                        )
                    _validate_execution_result(action, result)
                    verification = connector.verify(
                        action,
                        _copy_execution_result(result),
                    )
                if not verification.verified:
                    outcome_persisted = self._persist_idempotency_outcome(
                        action=action,
                        claim_token=claim_token,
                        state=IdempotencyClaimState.INDETERMINATE,
                        message=verification.message,
                        result=result,
                        connector=connector,
                    )
                    report = ActionReport(
                        action_id=action.action_id,
                        capability=action.capability,
                        state=ActionState.INDETERMINATE,
                        message=(
                            "connector may have produced a side effect but "
                            f"verification failed: {verification.message}"
                            + (
                                ""
                                if outcome_persisted
                                else "; durable outcome could not be finalized"
                            )
                        ),
                        result=result,
                    )
                else:
                    recheck_error: ConfigurationError | None = None
                    if egress is not None:
                        try:
                            execution_ok, execution_reason = (
                                self._validate_execution_contract(
                                    plan,
                                    action,
                                    connector,
                                )
                            )
                            if not execution_ok:
                                raise ConfigurationError(execution_reason)
                            rechecked = self._provider_data_egress_binding(
                                plan,
                                action,
                                connector,
                            )
                            if (
                                rechecked is None
                                or rechecked.fingerprint != egress.fingerprint
                            ):
                                raise ConfigurationError(
                                    "provider-data egress binding changed before "
                                    "result return"
                                )
                            result = sanitize_provider_result(result, egress)
                        except ConfigurationError as error:
                            recheck_error = error
                    report = ActionReport(
                        action_id=action.action_id,
                        capability=action.capability,
                        state=(
                            ActionState.FAILED
                            if recheck_error is not None
                            else ActionState.VERIFIED
                        ),
                        message=(
                            "provider-data egress binding changed before result return"
                            if recheck_error is not None
                            else "provider read independently verified"
                            if egress is not None
                            else verification.message
                        ),
                        result=None if recheck_error is not None else result,
                        egress=egress,
                    )
                    if _uses_idempotency(action):
                        self._audit.complete_action(
                            idempotency_key=action.idempotency_key,
                            action_fingerprint=action.effect_fingerprint,
                            claim_token=claim_token or "",
                            result=_idempotency_record(connector, action, result),
                        )
            except VersionConflictError as error:
                failure_persisted = result is None and claim_token is None
                if result is None and claim_token is not None:
                    failure_persisted = self._persist_idempotency_outcome(
                        action=action,
                        claim_token=claim_token,
                        state=IdempotencyClaimState.FAILED,
                        message=str(error),
                        result=None,
                        connector=connector,
                    )
                elif result is not None and claim_token is not None:
                    self._persist_idempotency_outcome(
                        action=action,
                        claim_token=claim_token,
                        state=IdempotencyClaimState.INDETERMINATE,
                        message=str(error),
                        result=result,
                        connector=connector,
                    )
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=(
                        ActionState.CONFLICTED
                        if failure_persisted
                        else ActionState.INDETERMINATE
                    ),
                    message=(
                        str(error)
                        + (
                            ""
                            if failure_persisted
                            else (
                                "; conflict occurred after connector execution"
                                if result is not None
                                else "; durable failure outcome could not be recorded"
                            )
                        )
                    ),
                    result=result,
                )
            except PreEffectError as error:
                failure_persisted = result is None and claim_token is None
                if result is None and claim_token is not None:
                    failure_persisted = self._persist_idempotency_outcome(
                        action=action,
                        claim_token=claim_token,
                        state=IdempotencyClaimState.FAILED,
                        message=f"{type(error).__name__}: {error}",
                        result=None,
                        connector=connector,
                    )
                elif result is not None and claim_token is not None:
                    self._persist_idempotency_outcome(
                        action=action,
                        claim_token=claim_token,
                        state=IdempotencyClaimState.INDETERMINATE,
                        message=f"{type(error).__name__}: {error}",
                        result=result,
                        connector=connector,
                    )
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=(
                        ActionState.FAILED
                        if failure_persisted
                        else ActionState.INDETERMINATE
                    ),
                    message=(
                        f"{type(error).__name__}: {error}"
                        + (
                            ""
                            if failure_persisted
                            else (
                                "; exception occurred after connector execution"
                                if result is not None
                                else "; durable failure outcome could not be recorded"
                            )
                        )
                    ),
                    result=result,
                )
            except (
                KeyError,
                MasterAgentError,
                OSError,
                OverflowError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as error:  # Connector boundary preserves partial state.
                outcome_persisted = self._persist_idempotency_outcome(
                    action=action,
                    claim_token=claim_token,
                    state=IdempotencyClaimState.INDETERMINATE,
                    message=f"{type(error).__name__}: {error}",
                    result=result,
                    connector=connector,
                )
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=(
                        ActionState.INDETERMINATE
                        if result is not None or claim_token is not None
                        else ActionState.FAILED
                    ),
                    message=(
                        f"{type(error).__name__}: {error}"
                        + (
                            ""
                            if outcome_persisted
                            else "; durable outcome could not be finalized"
                        )
                    ),
                    result=result,
                )

            if egress is not None and report.state is not ActionState.VERIFIED:
                report = ActionReport(
                    action_id=report.action_id,
                    capability=report.capability,
                    state=report.state,
                    message=(
                        "provider read failed after egress authorization: "
                        f"{report.state}"
                    ),
                    result=None,
                    compensation=None,
                    egress=egress,
                )
            reports.append(report)
            state_by_id[action.action_id] = report.state
            self._record_action(run_id, plan, action, report)

            if report.state in {
                ActionState.FAILED,
                ActionState.CONFLICTED,
                ActionState.PROHIBITED,
                ActionState.APPROVAL_REQUIRED,
                ActionState.INDETERMINATE,
            }:
                abort_remaining = self._maybe_compensate(
                    run_id=run_id,
                    plan=plan,
                    reports=reports,
                    executed=side_effects_may_have_occurred,
                    dry_run=dry_run,
                )

        systems_review = build_systems_post_execution_review(
            assessment=systems_assessment,
            decision=systems_decision,
            states=(item.state for item in reports),
            dry_run=dry_run,
        )
        self._audit.record(
            run_id=run_id,
            plan_id=plan.plan_id,
            action_id=None,
            event_type="plan_finished",
            payload={
                "states": {str(report.action_id): report.state for report in reports},
                "compensated": any(
                    report.state is ActionState.COMPENSATED for report in reports
                ),
                "systems_review": systems_review.to_dict(),
            },
        )

        return RunReport(
            run_id=run_id,
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            dry_run=dry_run,
            actions=tuple(reports),
            systems_review=systems_review,
        )

    def authenticated_approvals(
        self,
        plan: ChangePlan,
        approvals: Iterable[Approval],
    ) -> tuple[tuple[Approval, str], ...]:
        """Authenticate receipt evidence through the same policy authority."""

        snapshot = ChangePlan.from_dict(plan.to_dict())
        return self._policy.authenticated_approvals(snapshot, approvals)

    def _validate_capability(self, action: AgentAction) -> tuple[bool, str]:
        """Validate catalog enablement and organization governance."""

        if self._capabilities is not None:
            allowed, reason = self._capabilities.validate_action(action)
            if not allowed:
                return False, reason
        if self._governance is not None:
            allowed, reason = self._governance.validate_action(action)
            if not allowed:
                return False, reason
            if self._capabilities is not None:
                allowed, reason = self._governance.validate_external_model(
                    action,
                    self._capabilities.definition(action.capability),
                )
                if not allowed:
                    return False, reason
        return True, "capability passed catalog and governance checks"

    def _validate_execution_contract(
        self,
        plan: ChangePlan,
        action: AgentAction,
        connector: Connector,
    ) -> tuple[bool, str]:
        """Enforce approval-bound identity, scopes, auth, and reversibility."""

        if self._capabilities is None:
            return True, "no capability catalog was configured"
        context = plan.execution_context
        connector_mode = (
            context.runtime.connector_mode
            if context is not None and context.runtime is not None
            else "live"
        )
        definition = self._capabilities.definition(action.capability)
        provider_backed = definition.authentication != "local"
        if (
            provider_backed
            and connector_mode == "mock"
            and type(connector) is not MockConnector
        ):
            return False, "mock execution context requires a MockConnector"
        if (
            provider_backed
            and connector_mode == "live"
            and type(connector) is MockConnector
        ):
            return False, "live execution context cannot use a MockConnector"
        binding = self._execution_connector_binding(plan, action)
        return self._capabilities.validate_execution(
            action,
            connector,
            binding,
            connector_mode=connector_mode,
        )

    def _execution_connector_binding(
        self,
        plan: ChangePlan,
        action: AgentAction,
    ) -> ConnectorExecutionBinding | None:
        """Return the connector identity approved for one action, if present."""

        context = plan.execution_context
        binding_system = (
            "microsoft"
            if action.target.system
            in {"microsoft", "sharepoint", "outlook", "teams", "onenote"}
            else action.target.system
        )
        return next(
            (
                item
                for item in (context.connectors if context is not None else ())
                if item.system == binding_system
            ),
            None,
        )

    def _provider_data_egress_binding(
        self,
        plan: ChangePlan,
        action: AgentAction,
        connector: Connector,
    ) -> ProviderDataEgressBinding | None:
        """Bind a provider read independently of capability model-call flags."""

        if action.risk is not RiskLevel.READ_ONLY:
            return None
        if self._capabilities is None:
            if type(connector) is MockConnector:
                return None
            raise ConfigurationError(
                "provider reads require capability and governance policy"
            )
        definition = self._capabilities.definition(action.capability)
        if definition.authentication == "local":
            return None
        if self._governance is None:
            raise ConfigurationError(
                "provider reads require capability and governance policy"
            )
        if self._governance.model_context is None:
            raise ConfigurationError(
                "provider reads require configured model-context policy"
            )
        connector_mode = (
            "mock"
            if type(connector) is MockConnector
            else "local"
            if definition.authentication == "local"
            else "live"
        )
        audit_available = (
            implemented_audit_sink(self._governance.audit_sink) is not None
        )
        return bind_provider_data_egress(
            policy=self._governance.model_context,
            action=action,
            definition=definition,
            connector_binding=self._execution_connector_binding(plan, action),
            route=ProviderDataRoute.AUDITED,
            audit_available=audit_available,
            connector_mode=connector_mode,
        )

    def _minimum_approvers(self, action: AgentAction) -> int:
        """Return the governance-required number of distinct approvers."""

        if self._governance is None:
            return 0
        try:
            return self._governance.minimum_approvers(action.capability)
        except ConfigurationError:
            return 1

    def _maybe_compensate(
        self,
        *,
        run_id: UUID,
        plan: ChangePlan,
        reports: list[ActionReport],
        executed: list[_ExecutedAction],
        dry_run: bool,
    ) -> bool:
        """Compensate verified reversible actions after an atomic-plan failure."""

        if dry_run or not plan.compensate_on_failure or not executed:
            return False

        self._audit.record(
            run_id=run_id,
            plan_id=plan.plan_id,
            action_id=None,
            event_type="compensation_started",
            payload={"action_count": len(executed)},
        )
        for item in reversed(executed):
            action = item.action
            connector = item.connector
            try:
                item.result.validate_integrity()
            except ValidationError as error:
                reports[item.report_index] = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.COMPENSATION_FAILED,
                    message=f"compensation refused: {error}",
                    result=item.result,
                )
                self._record_action(
                    run_id,
                    plan,
                    action,
                    reports[item.report_index],
                )
                continue
            descriptor = item.result.compensation
            if descriptor is None:
                reports[item.report_index] = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.COMPENSATION_FAILED,
                    message="reversible result omitted its compensation descriptor",
                    result=item.result,
                )
                self._record_action(
                    run_id,
                    plan,
                    action,
                    reports[item.report_index],
                )
                continue
            if descriptor.mode is CompensationMode.MANUAL:
                reports[item.report_index] = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.COMPENSATION_FAILED,
                    message=(
                        "automatic compensation is unavailable: "
                        f"{descriptor.reason or descriptor.kind}"
                    ),
                    result=item.result,
                )
                self._record_action(
                    run_id,
                    plan,
                    action,
                    reports[item.report_index],
                )
                continue
            if not isinstance(connector, CompensatingConnector):
                reports[item.report_index] = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.COMPENSATION_FAILED,
                    message="connector does not implement verified compensation",
                    result=item.result,
                )
                self._record_action(
                    run_id,
                    plan,
                    action,
                    reports[item.report_index],
                )
                continue

            try:
                with activate_http_action_budget(item.http_budget):
                    postcondition = connector.verify(
                        action,
                        _copy_execution_result(item.result),
                    )
                    if not postcondition.verified:
                        raise VersionConflictError(
                            "automatic compensation refused because the target no "
                            "longer matches the agent's verified post-state"
                        )
                    compensation = connector.compensate(
                        action,
                        _copy_execution_result(item.result),
                    )
                    verification = connector.verify_compensation(
                        action,
                        _copy_execution_result(item.result),
                        _copy_execution_result(compensation),
                    )
                if not verification.verified:
                    raise RuntimeError(
                        f"compensation verification failed: {verification.message}"
                    )
                reports[item.report_index] = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.COMPENSATED,
                    message=f"compensated and verified: {verification.message}",
                    result=item.result,
                    compensation=compensation,
                )
                self._audit.clear_completed(
                    action.idempotency_key,
                    action_fingerprint=action.effect_fingerprint,
                )
            except (
                ConnectorError,
                KeyError,
                OSError,
                RuntimeError,
                TypeError,
                ValidationError,
                ValueError,
            ) as error:
                reports[item.report_index] = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.COMPENSATION_FAILED,
                    message=f"compensation failed: {type(error).__name__}: {error}",
                    result=item.result,
                )
            self._record_action(
                run_id,
                plan,
                action,
                reports[item.report_index],
            )

        self._audit.record(
            run_id=run_id,
            plan_id=plan.plan_id,
            action_id=None,
            event_type="compensation_finished",
            payload={
                "states": {
                    str(item.action.action_id): reports[item.report_index].state
                    for item in executed
                }
            },
        )
        executed.clear()
        return True

    def _record_action(
        self,
        run_id: UUID,
        plan: ChangePlan,
        action: AgentAction,
        report: ActionReport,
        extra: dict[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "capability": action.capability,
            "risk": action.risk,
            "authority_source": action.authority_source,
            "state": report.state,
            **audit_message_metadata(
                report.message,
                default_code=f"action_{report.state}",
            ),
        }
        governed_read = bool(
            action.risk is RiskLevel.READ_ONLY
            and self._governance is not None
            and self._governance.model_context is not None
        )
        if report.egress is not None or governed_read:
            payload["target_sha256"] = hashlib.sha256(
                action.target.uri.encode("utf-8")
            ).hexdigest()
        if report.egress is not None:
            payload["egress"] = report.egress.to_dict()
            payload["egress_fingerprint"] = report.egress.fingerprint
        elif not governed_read:
            payload["target"] = action.target.uri
        if report.result is not None:
            payload["result"] = (
                provider_result_audit_summary(report.result, report.egress)
                if report.egress is not None
                else result_audit_summary(report.result)
            )
        if report.compensation is not None:
            payload["compensation"] = result_audit_summary(report.compensation)
        if extra:
            payload.update(extra)
        self._audit.record(
            run_id=run_id,
            plan_id=plan.plan_id,
            action_id=action.action_id,
            event_type="action_state",
            payload=payload,
        )

    def _persist_idempotency_outcome(
        self,
        *,
        action: AgentAction,
        claim_token: str | None,
        state: IdempotencyClaimState,
        message: str,
        result: ExecutionResult | None,
        connector: Connector | None,
    ) -> bool:
        """Finalize one held claim without retaining provider content or errors."""

        if claim_token is None:
            return True
        outcome: dict[str, object] = {
            "error": audit_message_metadata(
                message,
                default_code=(
                    "action_failed"
                    if state is IdempotencyClaimState.FAILED
                    else "action_indeterminate"
                ),
            )
        }
        if result is not None:
            outcome["result"] = _idempotency_record(connector, action, result)
        try:
            if state is IdempotencyClaimState.FAILED:
                self._audit.fail_action(
                    idempotency_key=action.idempotency_key,
                    action_fingerprint=action.effect_fingerprint,
                    claim_token=claim_token,
                    outcome=outcome,
                )
            elif state is IdempotencyClaimState.INDETERMINATE:
                self._audit.mark_action_indeterminate(
                    idempotency_key=action.idempotency_key,
                    action_fingerprint=action.effect_fingerprint,
                    claim_token=claim_token,
                    outcome=outcome,
                )
            else:  # pragma: no cover - internal invariant.
                raise ValueError("unsupported idempotency outcome state")
        except (OSError, RuntimeError, sqlite3.Error, ConfigurationError):
            return False
        return True


def _idempotency_record(
    connector: Connector | None,
    action: AgentAction,
    result: ExecutionResult,
) -> dict[str, Any]:
    """Return connector reconciliation metadata or the content-free fallback."""

    if isinstance(connector, IdempotencyRecordingConnector):
        try:
            record = connector.idempotency_record(action, result)
            return _validate_idempotency_record(record)
        except (ConnectorError, KeyError, TypeError, ValueError):
            pass
    return result_audit_summary(result)


def _validate_idempotency_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Allow only bounded, flat identifiers and digests in retry metadata."""

    normalized: dict[str, Any] = {}
    allowed_suffixes = (
        "_accepted",
        "_count",
        "_digest",
        "_id",
        "_reference",
        "_status",
        "_version",
    )
    for key, value in record.items():
        if not isinstance(key, str) or (
            key != "schema" and not key.endswith(allowed_suffixes)
        ):
            raise StructuredDataTypeError(
                "idempotency record contains content-bearing metadata"
            )
        if not isinstance(value, (str, bool, int, type(None))):
            raise StructuredDataTypeError(
                "idempotency record values must be scalar metadata"
            )
        if isinstance(value, str) and len(value.encode("utf-8")) > 2048:
            raise StructuredDataTypeError("idempotency record value is too large")
        normalized[key] = value
    if len(normalized) > 32:
        raise StructuredDataTypeError("idempotency record has too many fields")
    return normalized


def _indeterminate_result(
    outcome: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    if outcome is None:
        return None
    result = outcome.get("result")
    return result if isinstance(result, Mapping) else None


def _validate_execution_result(
    action: AgentAction,
    result: ExecutionResult,
) -> None:
    """Bind a connector result to the action and its rollback contract."""

    if result.action_id != action.action_id:
        raise ConnectorError("connector result action ID did not match the action")
    result.validate_integrity()
    if result.state is not ActionState.SUCCEEDED:
        raise ConnectorError(
            "connector result must report succeeded before verification"
        )
    if action.risk is RiskLevel.REVERSIBLE_WRITE and result.compensation is None:
        raise ConnectorError(
            "reversible connector result omitted a typed compensation descriptor"
        )


def _copy_execution_result(result: ExecutionResult) -> ExecutionResult:
    """Return a validated private copy of connector-owned result evidence."""

    result.validate_integrity()
    return ExecutionResult(
        action_id=result.action_id,
        state=result.state,
        before=result.before,
        after=result.after,
        connector_reference=result.connector_reference,
        message=result.message,
        compensation=result.compensation,
    )


def _dependency_succeeded(
    state: ActionState | None,
    *,
    dry_run: bool,
) -> bool:
    """Require verified provider state for applied dependency edges."""

    if state in {ActionState.VERIFIED, ActionState.REUSED}:
        return True
    return dry_run and state is ActionState.PLANNED


def _topological_order(actions: tuple[AgentAction, ...]) -> tuple[AgentAction, ...]:
    by_id = {action.action_id: action for action in actions}
    ordered: list[AgentAction] = []
    visited: set[UUID] = set()

    def visit(action: AgentAction) -> None:
        if action.action_id in visited:
            return
        for dependency in action.dependencies:
            visit(by_id[dependency])
        visited.add(action.action_id)
        ordered.append(action)

    for candidate in actions:
        visit(candidate)
    return tuple(ordered)


def _uses_idempotency(action: AgentAction) -> bool:
    """Return whether durable duplicate suppression applies to an action.

    Reads and local generations must run again so recurring workflows receive
    fresh source data and regenerate current artifacts.
    """

    return action.risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}


def _strict_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise StructuredDataTypeError(f"{name} must be a boolean")
    return value
