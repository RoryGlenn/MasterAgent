"""Atomic workflow compensation tests."""

from __future__ import annotations

import sqlite3
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.audit import AuditLog, IdempotencyClaimState
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.errors import ConnectorError, PreEffectError
from master_agent.models import (
    ActionState,
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    CompensationDescriptor,
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry
from tests.helpers import govern_test_plan

ROOT = Path(__file__).resolve().parents[1]


class _CompensatingTestConnector:
    """Deterministic reversible connector with an injected second-action failure."""

    def __init__(
        self,
        *,
        inject_human_change: bool = False,
        compensation_mode: CompensationMode = CompensationMode.IN_PROCESS,
    ) -> None:
        self.state: dict[str, str] = {}
        self.inject_human_change = inject_human_change
        self.compensation_mode = compensation_mode
        self.compensation_calls = 0

    @property
    def system(self) -> str:
        return "test"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"test.resource.update"})

    def execute(self, action: AgentAction) -> ExecutionResult:
        if action.target.resource_id == "fail":
            if self.inject_human_change:
                self.state["first"] = "human change"
            raise PreEffectError("injected failure")
        before = {"value": self.state.get(action.target.resource_id)}
        value = str(action.parameters["value"])
        self.state[action.target.resource_id] = value
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after={"value": value},
            compensation=CompensationDescriptor(
                kind="restore_previous_value",
                mode=self.compensation_mode,
                reason=(
                    "test connector requires manual rollback"
                    if self.compensation_mode is CompensationMode.MANUAL
                    else "test connector retains the previous value in process"
                ),
            ),
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        return {"value": self.state.get(resource.resource_id)}

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        observed = self.read(action.target)
        return VerificationResult(
            action_id=action.action_id,
            verified=observed == result.after,
            observed=deepcopy(observed),
            message="test state verified",
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        self.compensation_calls += 1
        previous = (result.before or {}).get("value")
        if previous is None:
            self.state.pop(action.target.resource_id, None)
        else:
            self.state[action.target.resource_id] = str(previous)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=result.after,
            after={"value": previous},
            message="previous value restored",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        observed = self.read(action.target)
        return VerificationResult(
            action_id=action.action_id,
            verified=observed == compensation.after,
            observed=deepcopy(observed),
            message="rollback verified",
        )


class _VerificationRaisesConnector(_CompensatingTestConnector):
    """Prove the side-effect incident is durable before verification starts."""

    def __init__(self, audit_path: Path) -> None:
        super().__init__()
        self.audit_path = audit_path
        self.incident_was_durable = False

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        with sqlite3.connect(self.audit_path) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) FROM audit_events
                WHERE action_id = ? AND event_type = 'side_effect_may_have_occurred'
                """,
                (str(action.action_id),),
            ).fetchone()
        self.incident_was_durable = bool(row and row[0] == 1)
        assert result.after is not None
        result.after["value"] = "connector rewrote evidence"
        raise ConnectorError("verification transport failed")


class _CompensationVerificationFailsConnector(_CompensatingTestConnector):
    """Simulate a provider race after the compensation request returns."""

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        return VerificationResult(
            action_id=action.action_id,
            verified=False,
            observed={"value": "provider changed after rollback"},
            message="provider no longer matches the compensated state",
        )


class OrchestratorCompensationTests(unittest.TestCase):
    """Verify reverse-order, independently checked compensation."""

    def test_failure_compensates_prior_verified_write(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sources_path = root / "sources.toml"
            sources_path.write_text("", encoding="utf-8")
            connector = _CompensatingTestConnector()
            registry = ConnectorRegistry()
            registry.register(connector)
            first = _action("first", "changed")
            second = _action("fail", "never-written", dependencies=(first.action_id,))
            plan = ChangePlan(
                goal="Apply two writes atomically.",
                actions=(first, second),
                created_by="test",
                compensate_on_failure=True,
            )
            plan = govern_test_plan(plan)
            orchestrator, approval, audit = _runtime(root, sources_path, registry, plan)

            report = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )

            self.assertFalse(report.successful)
            self.assertTrue(report.compensated)
            self.assertEqual(report.actions[0].state, ActionState.COMPENSATED)
            self.assertEqual(report.actions[1].state, ActionState.FAILED)
            self.assertNotIn("first", connector.state)
            valid, _ = audit.verify_chain()
            self.assertTrue(valid)

    def test_human_change_blocks_compensation_without_overwrite(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sources_path = root / "sources.toml"
            sources_path.write_text("", encoding="utf-8")
            connector = _CompensatingTestConnector(inject_human_change=True)
            registry = ConnectorRegistry()
            registry.register(connector)
            first = _action("first", "agent change")
            second = _action("fail", "never-written", dependencies=(first.action_id,))
            plan = ChangePlan(
                goal="Preserve a concurrent human change.",
                actions=(first, second),
                created_by="test",
                compensate_on_failure=True,
            )
            plan = govern_test_plan(plan)
            orchestrator, approval, _ = _runtime(root, sources_path, registry, plan)

            report = orchestrator.run(plan, approvals=(approval,), dry_run=False)

            self.assertEqual(
                report.actions[0].state,
                ActionState.COMPENSATION_FAILED,
            )
            self.assertIn("VersionConflictError", report.actions[0].message)
            self.assertEqual(report.actions[1].state, ActionState.FAILED)
            self.assertEqual(connector.state["first"], "human change")
            self.assertEqual(connector.compensation_calls, 0)

    def test_manual_descriptor_prevents_automatic_connector_call(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sources_path = root / "sources.toml"
            sources_path.write_text("", encoding="utf-8")
            connector = _CompensatingTestConnector(
                compensation_mode=CompensationMode.MANUAL
            )
            registry = ConnectorRegistry()
            registry.register(connector)
            first = _action("first", "agent change")
            second = _action("fail", "never-written", dependencies=(first.action_id,))
            plan = ChangePlan(
                goal="Require manual rollback without an atomic precondition.",
                actions=(first, second),
                created_by="test",
                compensate_on_failure=True,
            )
            plan = govern_test_plan(plan)
            orchestrator, approval, _ = _runtime(
                root,
                sources_path,
                registry,
                plan,
            )

            report = orchestrator.run(plan, approvals=(approval,), dry_run=False)

            self.assertEqual(
                report.actions[0].state,
                ActionState.COMPENSATION_FAILED,
            )
            self.assertIn("requires manual rollback", report.actions[0].message)
            self.assertEqual(connector.state["first"], "agent change")
            self.assertEqual(connector.compensation_calls, 0)

    def test_failed_compensation_verification_preserves_idempotency_completion(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sources_path = root / "sources.toml"
            sources_path.write_text("", encoding="utf-8")
            connector = _CompensationVerificationFailsConnector()
            registry = ConnectorRegistry()
            registry.register(connector)
            first = _action("first", "agent change")
            second = _action("fail", "never-written", dependencies=(first.action_id,))
            plan = ChangePlan(
                goal="Retain idempotency evidence until rollback is verified.",
                actions=(first, second),
                created_by="test",
                compensate_on_failure=True,
            )
            plan = govern_test_plan(plan)
            orchestrator, approval, audit = _runtime(
                root,
                sources_path,
                registry,
                plan,
            )

            report = orchestrator.run(plan, approvals=(approval,), dry_run=False)

            self.assertEqual(
                report.actions[0].state,
                ActionState.COMPENSATION_FAILED,
            )
            self.assertEqual(
                audit.idempotency_outcome(
                    first.idempotency_key,
                    action_fingerprint=first.effect_fingerprint,
                ),
                IdempotencyClaimState.COMPLETED,
            )

    def test_verification_exception_preserves_result_and_incident_first(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sources_path = root / "sources.toml"
            sources_path.write_text("", encoding="utf-8")
            connector = _VerificationRaisesConnector(root / "audit.sqlite3")
            registry = ConnectorRegistry()
            registry.register(connector)
            action = _action("first", "agent change")
            plan = ChangePlan(
                goal="Record an indeterminate side effect.",
                actions=(action,),
                created_by="test",
            )
            plan = govern_test_plan(plan)
            orchestrator, approval, _ = _runtime(root, sources_path, registry, plan)

            report = orchestrator.run(plan, approvals=(approval,), dry_run=False)

            self.assertEqual(report.actions[0].state, ActionState.INDETERMINATE)
            self.assertIsNotNone(report.actions[0].result)
            assert report.actions[0].result is not None
            self.assertEqual(report.actions[0].result.after, {"value": "agent change"})
            self.assertTrue(connector.incident_was_durable)


def _runtime(
    root: Path,
    sources_path: Path,
    registry: ConnectorRegistry,
    plan: ChangePlan,
) -> tuple[WorkflowOrchestrator, Approval, AuditLog]:
    now = datetime.now(UTC)
    authenticator = HmacApprovalAuthenticator(
        {
            "rory": ApprovalAuthority(
                key_id="rory",
                subject="rory",
                issuer="master-agent.test",
                tenant="test-tenant",
                roles=("change-approver",),
                secret=b"rory-test-approval-secret-32-bytes!!",
            )
        }
    )
    approval = authenticator.issue(
        plan=plan,
        approved_action_ids=tuple(action.action_id for action in plan.actions),
        key_id="rory",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    audit = AuditLog(root / "audit.sqlite3")
    return (
        WorkflowOrchestrator(
            policy=PolicyEngine(
                PolicyConfig.from_toml(ROOT / "config/policy.toml"),
                approval_authenticator=authenticator,
            ),
            sources=SourceOfTruthRegistry.from_toml(sources_path),
            connectors=registry,
            audit=audit,
        ),
        approval,
        audit,
    )


def _action(
    resource_id: str,
    value: str,
    *,
    dependencies: tuple = (),
) -> AgentAction:
    return AgentAction(
        capability="test.resource.update",
        target=ResourceRef(
            system="test",
            resource_type="resource",
            resource_id=resource_id,
        ),
        parameters={"value": value},
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=f"test:update:{resource_id}",
        justification="Exercise verified compensation.",
        dependencies=dependencies,
    )


if __name__ == "__main__":
    unittest.main()
