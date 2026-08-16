"""Atomic workflow compensation tests."""

from __future__ import annotations

import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.errors import PreEffectError
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry

ROOT = Path(__file__).resolve().parents[1]


class _CompensatingTestConnector:
    """Deterministic reversible connector with an injected second-action failure."""

    def __init__(self) -> None:
        self.state: dict[str, str] = {}

    @property
    def system(self) -> str:
        return "test"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"test.resource.update"})

    def execute(self, action: AgentAction) -> ExecutionResult:
        if action.target.resource_id == "fail":
            raise PreEffectError("injected failure")
        before = {"value": self.state.get(action.target.resource_id)}
        value = str(action.parameters["value"])
        self.state[action.target.resource_id] = value
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after={"value": value},
            compensation={"kind": "restore_previous_value"},
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
                approved_action_ids=(first.action_id, second.action_id),
                key_id="rory",
                issued_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=5),
            )
            audit = AuditLog(root / "audit.sqlite3")
            orchestrator = WorkflowOrchestrator(
                policy=PolicyEngine(
                    PolicyConfig.from_toml(ROOT / "config/policy.toml"),
                    approval_authenticator=authenticator,
                ),
                sources=SourceOfTruthRegistry.from_toml(sources_path),
                connectors=registry,
                audit=audit,
            )

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
