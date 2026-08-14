"""End-to-end HTTP budgets across an orchestrated action lifecycle."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.errors import ConnectorError
from master_agent.http import SafeHttpClient
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
from tests.fakes import ExpectedRequest, QueueTransport


class _LifecycleConnector:
    """Synthetic live connector whose every lifecycle phase performs HTTP."""

    def __init__(self, transport: QueueTransport, *, max_pages: int) -> None:
        self._config = SimpleNamespace(
            max_pages=max_pages,
            max_response_bytes=4096,
        )
        self._client = SafeHttpClient(
            base_url="https://example.test/api",
            transport=transport,
            allowed_methods=frozenset({"GET", "POST"}),
            retry_attempts=0,
        )

    @property
    def system(self) -> str:
        return "budget"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"budget.resource.read", "budget.resource.update"})

    def execute(self, action: AgentAction) -> ExecutionResult:
        if action.target.resource_id == "fail":
            raise ConnectorError("injected second-action failure")
        self._client.request_json(
            "GET" if action.risk is RiskLevel.READ_ONLY else "POST",
            f"{action.target.resource_id}/execute",
            json_body=(
                None if action.risk is RiskLevel.READ_ONLY else {"value": "changed"}
            ),
        )
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={"value": "before"},
            after={"value": "changed"},
            compensation={"kind": "restore"},
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        return None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        self._client.request_json(
            "GET",
            f"{action.target.resource_id}/verify",
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=True,
            observed=result.after,
            message="verified",
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        self._client.request_json(
            "POST",
            f"{action.target.resource_id}/compensate",
            json_body={"value": "before"},
        )
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=result.after,
            after=result.before,
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        self._client.request_json(
            "GET",
            f"{action.target.resource_id}/verify-compensation",
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=True,
            observed=compensation.after,
            message="compensation verified",
        )


class HttpLifecycleBudgetTests(unittest.TestCase):
    """Prove max_pages cannot reset between lifecycle methods."""

    def test_execute_and_verify_share_one_max_pages_budget(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/one/execute", {"ok": True}),
            ExpectedRequest("GET", "/one/verify", {"ok": True}),
        )
        connector = _LifecycleConnector(transport, max_pages=1)
        action = _action("one", RiskLevel.READ_ONLY)

        with TemporaryDirectory() as directory:
            report = _orchestrator(Path(directory), connector).run(
                ChangePlan(
                    goal="Read with one lifecycle budget.",
                    actions=(action,),
                    created_by="test",
                ),
                dry_run=False,
            )

        self.assertEqual(report.actions[0].state, ActionState.INDETERMINATE)
        self.assertIn("request/page budget", report.actions[0].message)
        self.assertEqual(len(transport.requests), 1)

    def test_compensation_reuses_execute_and_verify_budget(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("POST", "/first/execute", {"ok": True}),
            ExpectedRequest("GET", "/first/verify", {"ok": True}),
            ExpectedRequest("GET", "/first/verify", {"ok": True}),
            ExpectedRequest("POST", "/first/compensate", {"ok": True}),
            ExpectedRequest(
                "GET",
                "/first/verify-compensation",
                {"ok": True},
            ),
        )
        connector = _LifecycleConnector(transport, max_pages=4)
        first = _action("first", RiskLevel.REVERSIBLE_WRITE)
        failed = _action(
            "fail",
            RiskLevel.REVERSIBLE_WRITE,
            dependencies=(first.action_id,),
        )

        with TemporaryDirectory() as directory:
            report = _orchestrator(Path(directory), connector).run(
                ChangePlan(
                    goal="Fail after one reversible write.",
                    actions=(first, failed),
                    created_by="test",
                    compensate_on_failure=True,
                ),
                dry_run=False,
            )

        self.assertEqual(report.actions[0].state, ActionState.COMPENSATION_FAILED)
        self.assertIn("request/page budget", report.actions[0].message)
        self.assertEqual(report.actions[1].state, ActionState.FAILED)
        self.assertEqual(len(transport.requests), 4)


def _action(
    resource_id: str,
    risk: RiskLevel,
    *,
    dependencies: tuple = (),
) -> AgentAction:
    return AgentAction(
        capability=(
            "budget.resource.read"
            if risk is RiskLevel.READ_ONLY
            else "budget.resource.update"
        ),
        target=ResourceRef(
            system="budget",
            resource_type="resource",
            resource_id=resource_id,
        ),
        parameters={},
        risk=risk,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"budget:{resource_id}",
        justification="Exercise a retained HTTP lifecycle budget.",
        dependencies=dependencies,
    )


def _orchestrator(
    root: Path,
    connector: _LifecycleConnector,
) -> WorkflowOrchestrator:
    registry = ConnectorRegistry()
    registry.register(connector)
    policy = PolicyConfig(
        auto_permit_risks=frozenset({RiskLevel.READ_ONLY, RiskLevel.REVERSIBLE_WRITE}),
        require_approval_risks=frozenset(),
        prohibit_risks=frozenset(),
        prohibited_capabilities=(),
        write_capability_patterns=("*.update",),
    )
    return WorkflowOrchestrator(
        policy=PolicyEngine(policy),
        sources=SourceOfTruthRegistry(()),
        connectors=registry,
        audit=AuditLog(root / "audit.sqlite3"),
    )


if __name__ == "__main__":
    unittest.main()
