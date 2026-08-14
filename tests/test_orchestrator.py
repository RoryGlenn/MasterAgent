"""Workflow orchestration tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.connectors.mock import MockConnector
from master_agent.models import ActionState
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.planners.static import build_weekly_status_plan
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry

ROOT = Path(__file__).resolve().parents[1]


class OrchestratorTests(unittest.TestCase):
    """Verify local workflow execution and idempotency."""

    def test_weekly_status_executes_and_verifies(self) -> None:
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(audit)
            plan = build_weekly_status_plan()
            report = orchestrator.run(plan, dry_run=False)
            self.assertTrue(report.successful)
            self.assertTrue(
                all(
                    action.state in {ActionState.VERIFIED, ActionState.SKIPPED}
                    for action in report.actions
                )
            )
            valid, _ = audit.verify_chain()
            self.assertTrue(valid)

    def test_recurring_reads_and_local_generation_run_fresh(self) -> None:
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(audit)
            plan = build_weekly_status_plan()
            first = orchestrator.run(plan, dry_run=False)
            second = orchestrator.run(plan, dry_run=False)
            self.assertTrue(first.successful)
            self.assertTrue(second.successful)
            self.assertTrue(
                all(action.state is ActionState.VERIFIED for action in second.actions)
            )


def _orchestrator(audit: AuditLog) -> WorkflowOrchestrator:
    registry = ConnectorRegistry()
    registry.register(
        MockConnector(
            "jira",
            {"PROJECT-SPRINT": {"version": "7", "summary": "healthy"}},
        )
    )
    registry.register(
        MockConnector(
            "bitbucket",
            {"open-prs": {"version": "4", "count": 1}},
        )
    )
    registry.register(
        MockConnector(
            "confluence",
            {"project-status": {"version": "12", "narrative": "on track"}},
        )
    )
    for system in ("powerpoint", "teams", "outlook"):
        registry.register(MockConnector(system))

    return WorkflowOrchestrator(
        policy=PolicyEngine(PolicyConfig.from_toml(ROOT / "config/policy.toml")),
        sources=SourceOfTruthRegistry.from_toml(ROOT / "config/sources_of_truth.toml"),
        connectors=registry,
        audit=audit,
    )


if __name__ == "__main__":
    unittest.main()
