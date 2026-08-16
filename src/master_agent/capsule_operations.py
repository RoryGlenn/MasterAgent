"""Durable run-state coordination for promoted capability capsules."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID, uuid4

from master_agent.audit import AuditLog, RunCheckpoint
from master_agent.errors import ConfigurationError
from master_agent.models import ActionState, Approval, ChangePlan
from master_agent.orchestrator import RunReport, WorkflowOrchestrator
from master_agent.receipts import (
    ExecutionReceipt,
    ExternalReceiptSink,
    ReceiptSigner,
    TelemetrySink,
    build_execution_receipt,
    emit_receipt_telemetry,
    export_execution_receipt,
)


class CapsuleRunState(StrEnum):
    """Explicit recovery states for an exact capsule-bound plan."""

    PLANNED = "planned"
    AWAITING_CONNECTION = "awaiting_connection"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPENSATING = "compensating"
    TERMINAL = "terminal"


_TRANSITIONS: dict[CapsuleRunState, frozenset[CapsuleRunState]] = {
    CapsuleRunState.PLANNED: frozenset(
        {
            CapsuleRunState.AWAITING_CONNECTION,
            CapsuleRunState.AWAITING_APPROVAL,
            CapsuleRunState.EXECUTING,
            CapsuleRunState.VERIFYING,
        }
    ),
    CapsuleRunState.AWAITING_CONNECTION: frozenset(
        {
            CapsuleRunState.AWAITING_CONNECTION,
            CapsuleRunState.AWAITING_APPROVAL,
            CapsuleRunState.EXECUTING,
        }
    ),
    CapsuleRunState.AWAITING_APPROVAL: frozenset(
        {CapsuleRunState.AWAITING_APPROVAL, CapsuleRunState.EXECUTING}
    ),
    # A same-state transition marks an exact crash-recovery attempt. Existing
    # connector idempotency reservations decide whether calls may resume.
    CapsuleRunState.EXECUTING: frozenset(
        {CapsuleRunState.EXECUTING, CapsuleRunState.VERIFYING}
    ),
    CapsuleRunState.VERIFYING: frozenset(
        {
            CapsuleRunState.EXECUTING,
            CapsuleRunState.COMPENSATING,
            CapsuleRunState.TERMINAL,
        }
    ),
    CapsuleRunState.COMPENSATING: frozenset(
        {
            CapsuleRunState.EXECUTING,
            CapsuleRunState.COMPENSATING,
            CapsuleRunState.TERMINAL,
        }
    ),
    CapsuleRunState.TERMINAL: frozenset(),
}


@dataclass(frozen=True, slots=True)
class GovernedCapsuleRun:
    """Coordinator result, including a receipt only for terminal execution."""

    coordinator_run_id: UUID
    state: CapsuleRunState
    checkpoint: RunCheckpoint
    report: RunReport | None = None
    receipt: ExecutionReceipt | None = None
    external_receipt_locator: str | None = None


class CapsuleRunCoordinator:
    """Persist checkpoints, invoke the normal orchestrator, and sign evidence."""

    def __init__(
        self,
        *,
        orchestrator: WorkflowOrchestrator,
        audit: AuditLog,
        receipt_signer: ReceiptSigner,
        external_sink: ExternalReceiptSink | None = None,
        telemetry_sink: TelemetrySink | None = None,
        require_external_audit: bool = False,
    ) -> None:
        self._orchestrator = orchestrator
        self._audit = audit
        self._receipt_signer = receipt_signer
        self._external_sink = external_sink
        self._telemetry_sink = telemetry_sink
        self._require_external_audit = require_external_audit

    def run(
        self,
        plan: ChangePlan,
        *,
        approvals: Sequence[Approval] = (),
        dry_run: bool = False,
        connections_ready: bool = False,
        coordinator_run_id: UUID | None = None,
    ) -> GovernedCapsuleRun:
        """Start or resume only the exact capsule-bound plan."""

        context = plan.execution_context
        if context is None or not context.capsules:
            raise ConfigurationError(
                "capsule run requires exact capsule bindings in execution context"
            )
        capsule_digest = _capsule_bindings_sha256(plan)
        selected_run_id = coordinator_run_id or uuid4()
        checkpoint = self._audit.run_checkpoint(selected_run_id)
        if checkpoint is None:
            checkpoint = self._audit.checkpoint_run(
                run_id=selected_run_id,
                plan_id=plan.plan_id,
                plan_fingerprint=plan.fingerprint,
                state=str(CapsuleRunState.PLANNED),
                capsule_bindings_sha256=capsule_digest,
                expected_state=None,
            )
            self._record_state(checkpoint)
        else:
            _validate_resume(checkpoint, plan, capsule_digest)
            if checkpoint.state == CapsuleRunState.TERMINAL:
                raise ConfigurationError(
                    "capsule run is already terminal; replay is refused"
                )

        requires_connection = any(
            binding.credential_names for binding in context.capsules
        )
        if requires_connection and not connections_ready:
            checkpoint = self._transition(
                checkpoint,
                CapsuleRunState.AWAITING_CONNECTION,
                plan=plan,
                capsule_digest=capsule_digest,
            )
            return GovernedCapsuleRun(
                coordinator_run_id=selected_run_id,
                state=CapsuleRunState.AWAITING_CONNECTION,
                checkpoint=checkpoint,
            )

        if self._require_external_audit:
            sink = self._external_sink
            if (
                sink is None
                or not sink.external
                or not sink.tamper_resistant
                or not sink.healthy()
            ):
                raise ConfigurationError(
                    "production capsule run requires a healthy external "
                    "tamper-resistant audit sink"
                )

        authenticated_approvals = self._orchestrator.authenticated_approvals(
            plan,
            approvals,
        )
        policy_report = self._orchestrator.run(
            plan,
            approvals=approvals,
            dry_run=True,
        )
        if any(
            item.state is ActionState.APPROVAL_REQUIRED
            for item in policy_report.actions
        ):
            checkpoint = self._transition(
                checkpoint,
                CapsuleRunState.AWAITING_APPROVAL,
                plan=plan,
                capsule_digest=capsule_digest,
            )
            return GovernedCapsuleRun(
                coordinator_run_id=selected_run_id,
                state=CapsuleRunState.AWAITING_APPROVAL,
                checkpoint=checkpoint,
                report=policy_report,
            )

        if dry_run:
            report = policy_report
            checkpoint = self._transition(
                checkpoint,
                CapsuleRunState.VERIFYING,
                plan=plan,
                capsule_digest=capsule_digest,
            )
        else:
            checkpoint = self._transition(
                checkpoint,
                CapsuleRunState.EXECUTING,
                plan=plan,
                capsule_digest=capsule_digest,
            )
            report = self._orchestrator.run(
                plan,
                approvals=approvals,
                dry_run=False,
            )
            checkpoint = self._transition(
                checkpoint,
                CapsuleRunState.VERIFYING,
                plan=plan,
                capsule_digest=capsule_digest,
            )
            if report.compensated or any(
                item.state
                in {ActionState.COMPENSATING, ActionState.COMPENSATION_FAILED}
                for item in report.actions
            ):
                checkpoint = self._transition(
                    checkpoint,
                    CapsuleRunState.COMPENSATING,
                    plan=plan,
                    capsule_digest=capsule_digest,
                )

        result_sha256 = _report_sha256(report)
        anchor = self._audit.record(
            run_id=selected_run_id,
            plan_id=plan.plan_id,
            action_id=None,
            event_type="capsule_receipt_anchor",
            payload={
                "plan_fingerprint": plan.fingerprint,
                "capsule_bindings_sha256": capsule_digest,
                "result_sha256": result_sha256,
            },
        )
        receipt = build_execution_receipt(
            plan=plan,
            report=report,
            authenticated_approvals=authenticated_approvals,
            audit_anchor_sha256=anchor,
            signer=self._receipt_signer,
        )
        locator = None
        if self._external_sink is not None:
            locator = export_execution_receipt(receipt, sink=self._external_sink)
        if self._telemetry_sink is not None:
            emit_receipt_telemetry(receipt, sink=self._telemetry_sink)
        checkpoint = self._transition(
            checkpoint,
            CapsuleRunState.TERMINAL,
            plan=plan,
            capsule_digest=capsule_digest,
            result_sha256=receipt.receipt_sha256,
        )
        self._audit.record(
            run_id=selected_run_id,
            plan_id=plan.plan_id,
            action_id=None,
            event_type="capsule_execution_receipt",
            payload={
                "receipt_id": str(receipt.receipt_id),
                "receipt_sha256": receipt.receipt_sha256,
                "signer_key_id": receipt.signer_key_id,
                "external_sink": (
                    self._external_sink.sink_id
                    if self._external_sink is not None
                    else None
                ),
                "external_locator_sha256": (
                    hashlib.sha256(locator.encode()).hexdigest() if locator else None
                ),
            },
        )
        return GovernedCapsuleRun(
            coordinator_run_id=selected_run_id,
            state=CapsuleRunState.TERMINAL,
            checkpoint=checkpoint,
            report=report,
            receipt=receipt,
            external_receipt_locator=locator,
        )

    def _transition(
        self,
        checkpoint: RunCheckpoint,
        target: CapsuleRunState,
        *,
        plan: ChangePlan,
        capsule_digest: str,
        result_sha256: str | None = None,
    ) -> RunCheckpoint:
        current = CapsuleRunState(checkpoint.state)
        if target not in _TRANSITIONS[current]:
            raise ConfigurationError(
                f"capsule run transition {current} -> {target} is not allowed"
            )
        updated = self._audit.checkpoint_run(
            run_id=checkpoint.run_id,
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            state=str(target),
            capsule_bindings_sha256=capsule_digest,
            expected_state=str(current),
            result_sha256=result_sha256,
        )
        self._record_state(updated)
        return updated

    def _record_state(self, checkpoint: RunCheckpoint) -> None:
        self._audit.record(
            run_id=checkpoint.run_id,
            plan_id=checkpoint.plan_id,
            action_id=None,
            event_type="capsule_run_state",
            payload={
                "state": checkpoint.state,
                "sequence": checkpoint.sequence,
                "plan_fingerprint": checkpoint.plan_fingerprint,
                "capsule_bindings_sha256": checkpoint.capsule_bindings_sha256,
                "result_sha256": checkpoint.result_sha256,
            },
        )


def _validate_resume(
    checkpoint: RunCheckpoint,
    plan: ChangePlan,
    capsule_digest: str,
) -> None:
    if (
        checkpoint.plan_id != plan.plan_id
        or checkpoint.plan_fingerprint != plan.fingerprint
        or checkpoint.capsule_bindings_sha256 != capsule_digest
    ):
        raise ConfigurationError(
            "capsule run resume requires the exact captured plan and capsule bindings"
        )


def _capsule_bindings_sha256(plan: ChangePlan) -> str:
    context = plan.execution_context
    assert context is not None
    encoded = json.dumps(
        [item.to_dict() for item in context.capsules],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _report_sha256(report: RunReport) -> str:
    encoded = json.dumps(
        report.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
