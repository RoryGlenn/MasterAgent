"""Dependency-aware, policy-gated workflow execution."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from uuid import UUID, uuid4

from master_agent.audit import AuditLog, IdempotencyClaimState
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.connectors.base import (
    CompensatingConnector,
    Connector,
    IdempotencyVerifyingConnector,
)
from master_agent.errors import (
    ConfigurationError,
    ConnectorError,
    PreEffectError,
    StructuredDataTypeError,
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
    ExecutionResult,
    RiskLevel,
)
from master_agent.policy import PolicyEngine
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
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> ActionReport:
        """Create an action report from persisted JSON data."""

        result_data = data.get("result")
        compensation_data = data.get("compensation")
        if result_data is not None and not isinstance(result_data, Mapping):
            raise ValueError("action report result must be an object or null")
        if compensation_data is not None and not isinstance(compensation_data, Mapping):
            raise ValueError("action report compensation must be an object or null")
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
        )


@dataclass(frozen=True, slots=True)
class RunReport:
    """Final report for a plan execution attempt."""

    run_id: UUID
    plan_id: UUID
    plan_fingerprint: str
    dry_run: bool
    actions: tuple[ActionReport, ...]

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

        return {
            "run_id": str(self.run_id),
            "plan_id": str(self.plan_id),
            "plan_fingerprint": self.plan_fingerprint,
            "dry_run": self.dry_run,
            "successful": self.successful,
            "compensated": self.compensated,
            "actions": [item.to_dict() for item in self.actions],
        }

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
        return cls(
            run_id=UUID(str(data["run_id"])),
            plan_id=UUID(str(data["plan_id"])),
            plan_fingerprint=str(data["plan_fingerprint"]),
            dry_run=_strict_bool(data.get("dry_run"), "run report dry_run"),
            actions=tuple(actions),
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
        run_id = uuid4()
        approvals_tuple = tuple(approvals)
        reports: list[ActionReport] = []
        state_by_id: dict[UUID, ActionState] = {}
        verified_side_effects: list[_ExecutedAction] = []
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
                    executed=verified_side_effects,
                    dry_run=dry_run,
                )
                continue

            failed_dependencies = [
                dependency
                for dependency in action.dependencies
                if state_by_id.get(dependency)
                not in {
                    ActionState.PLANNED,
                    ActionState.VERIFIED,
                    ActionState.REUSED,
                }
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
                    executed=verified_side_effects,
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
                    executed=verified_side_effects,
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
            try:
                connector = self._connectors.resolve(
                    action.target.system,
                    action.capability,
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
                                executed=verified_side_effects,
                                dry_run=dry_run,
                            )
                            continue
                        with activate_http_action_budget(http_budget):
                            reuse_verification = connector.verify_completed(
                                action,
                                claim.result or {},
                            )
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
                                executed=verified_side_effects,
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
                            executed=verified_side_effects,
                            dry_run=dry_run,
                        )
                        continue
                    if claim.state is IdempotencyClaimState.IN_PROGRESS:
                        report = ActionReport(
                            action_id=action.action_id,
                            capability=action.capability,
                            state=ActionState.CONFLICTED,
                            message=(
                                "idempotent action is already in progress or has "
                                "an indeterminate prior side effect"
                            ),
                        )
                        reports.append(report)
                        state_by_id[action.action_id] = report.state
                        self._record_action(run_id, plan, action, report)
                        abort_remaining = self._maybe_compensate(
                            run_id=run_id,
                            plan=plan,
                            reports=reports,
                            executed=verified_side_effects,
                            dry_run=dry_run,
                        )
                        continue
                    claim_token = claim.token
                    if claim_token is None:  # pragma: no cover - invariant guard.
                        raise RuntimeError("idempotency claim omitted its token")
                with activate_http_action_budget(http_budget):
                    result = connector.execute(action)
                    verification = connector.verify(action, result)
                if not verification.verified:
                    report = ActionReport(
                        action_id=action.action_id,
                        capability=action.capability,
                        state=ActionState.INDETERMINATE,
                        message=(
                            "connector may have produced a side effect but "
                            f"verification failed: {verification.message}"
                        ),
                        result=result,
                    )
                else:
                    report = ActionReport(
                        action_id=action.action_id,
                        capability=action.capability,
                        state=ActionState.VERIFIED,
                        message=verification.message,
                        result=result,
                    )
                    if _uses_idempotency(action):
                        self._audit.complete_action(
                            idempotency_key=action.idempotency_key,
                            action_fingerprint=action.effect_fingerprint,
                            claim_token=claim_token or "",
                            result=result_audit_summary(result),
                        )
            except VersionConflictError as error:
                claim_released = result is None and claim_token is None
                if result is None and claim_token is not None:
                    try:
                        claim_released = self._audit.release_action_claim(
                            idempotency_key=action.idempotency_key,
                            action_fingerprint=action.effect_fingerprint,
                            claim_token=claim_token,
                        )
                    except (OSError, RuntimeError, sqlite3.Error, ConfigurationError):
                        claim_released = False
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=(
                        ActionState.CONFLICTED
                        if claim_released
                        else ActionState.INDETERMINATE
                    ),
                    message=(
                        str(error)
                        + (
                            ""
                            if claim_released
                            else (
                                "; conflict occurred after connector execution"
                                if result is not None
                                else "; idempotency claim could not be released"
                            )
                        )
                    ),
                    result=result,
                )
            except PreEffectError as error:
                claim_released = result is None and claim_token is None
                if result is None and claim_token is not None:
                    try:
                        claim_released = self._audit.release_action_claim(
                            idempotency_key=action.idempotency_key,
                            action_fingerprint=action.effect_fingerprint,
                            claim_token=claim_token,
                        )
                    except (OSError, RuntimeError, sqlite3.Error, ConfigurationError):
                        claim_released = False
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=(
                        ActionState.FAILED
                        if claim_released
                        else ActionState.INDETERMINATE
                    ),
                    message=(
                        f"{type(error).__name__}: {error}"
                        + (
                            ""
                            if claim_released
                            else (
                                "; exception occurred after connector execution"
                                if result is not None
                                else "; idempotency claim could not be released"
                            )
                        )
                    ),
                    result=result,
                )
            except (
                ConnectorError,
                KeyError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as error:  # Connector boundary preserves partial state.
                report = ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=(
                        ActionState.INDETERMINATE
                        if result is not None or claim_token is not None
                        else ActionState.FAILED
                    ),
                    message=f"{type(error).__name__}: {error}",
                    result=result,
                )

            reports.append(report)
            state_by_id[action.action_id] = report.state
            self._record_action(run_id, plan, action, report)

            if (
                connector is not None
                and action.risk is RiskLevel.REVERSIBLE_WRITE
                and result is not None
            ):
                verified_side_effects.append(
                    _ExecutedAction(
                        action=action,
                        connector=connector,
                        result=result,
                        report_index=len(reports) - 1,
                        http_budget=http_budget,
                    )
                )

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
                    executed=verified_side_effects,
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
            },
        )

        return RunReport(
            run_id=run_id,
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            dry_run=dry_run,
            actions=tuple(reports),
        )

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
        return True, "capability passed catalog and governance checks"

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
                    postcondition = connector.verify(action, item.result)
                    if not postcondition.verified:
                        raise VersionConflictError(
                            "automatic compensation refused because the target no "
                            "longer matches the agent's verified post-state"
                        )
                    compensation = connector.compensate(action, item.result)
                    verification = connector.verify_compensation(
                        action,
                        item.result,
                        compensation,
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
            "target": action.target.uri,
            "risk": action.risk,
            "authority_source": action.authority_source,
            "state": report.state,
            **audit_message_metadata(
                report.message,
                default_code=f"action_{report.state}",
            ),
        }
        if report.result is not None:
            payload["result"] = result_audit_summary(report.result)
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
