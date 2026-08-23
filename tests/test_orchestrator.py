"""Workflow orchestration tests."""

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.connectors.mock import MockConnector
from master_agent.errors import ValidationError
from master_agent.models import (
    ActionState,
    ChangePlan,
    ComplexityItem,
    ComplexityKind,
    SystemsAssessment,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.planners.base import bind_systems_governance
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
            self.assertIsNotNone(report.systems_review)
            assert report.systems_review is not None
            self.assertTrue(report.systems_review.reassessment_required)
            self.assertFalse(report.systems_review.stop_condition_checked)

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

    def test_missing_systems_binding_fails_before_runtime_audit(self) -> None:
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            plan = replace(
                build_weekly_status_plan(),
                systems_assessment=None,
                systems_decision=None,
            )

            with self.assertRaisesRegex(ValidationError, "systems governance"):
                _orchestrator(audit).run(plan, dry_run=False)

            self.assertEqual(
                audit.verify_chain(),
                (False, "audit database contains no events"),
            )

    def test_over_budget_plan_requires_authenticated_whole_plan_review(self) -> None:
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            authenticator = HmacApprovalAuthenticator(
                {
                    "reviewer": ApprovalAuthority(
                        key_id="reviewer",
                        subject="Human Reviewer",
                        issuer="master-agent.test",
                        tenant="test-tenant",
                        roles=("change-approver",),
                        secret=b"systems-review-test-secret-32-bytes!!",
                    )
                }
            )
            orchestrator = _orchestrator(audit, authenticator=authenticator)
            plan = _over_budget_plan()

            with self.assertRaisesRegex(ValidationError, "authenticated human review"):
                orchestrator.run(plan, dry_run=True)
            self.assertEqual(
                audit.verify_chain(),
                (False, "audit database contains no events"),
            )

            now = datetime.now(UTC)
            partial = authenticator.issue(
                plan=plan,
                approved_action_ids=(plan.actions[0].action_id,),
                key_id="reviewer",
                issued_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=5),
            )
            with self.assertRaisesRegex(ValidationError, "authenticated human review"):
                orchestrator.run(plan, approvals=(partial,), dry_run=True)

            approval = authenticator.issue(
                plan=plan,
                approved_action_ids=tuple(action.action_id for action in plan.actions),
                key_id="reviewer",
                issued_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=5),
            )
            report = orchestrator.run(plan, approvals=(approval,), dry_run=True)
            self.assertTrue(report.successful)


def _orchestrator(
    audit: AuditLog,
    *,
    authenticator: HmacApprovalAuthenticator | None = None,
) -> WorkflowOrchestrator:
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
        policy=PolicyEngine(
            PolicyConfig.from_toml(ROOT / "config/policy.toml"),
            approval_authenticator=authenticator,
        ),
        sources=SourceOfTruthRegistry.from_toml(ROOT / "config/sources_of_truth.toml"),
        connectors=registry,
        audit=audit,
    )


def _over_budget_plan() -> ChangePlan:
    plan = replace(
        build_weekly_status_plan(),
        systems_assessment=None,
        systems_decision=None,
    )
    return bind_systems_governance(
        plan,
        SystemsAssessment(
            desired_outcome=plan.goal,
            current_behavior="the weekly report is not yet generated",
            constraint="the report requires multiple governed source reads",
            stocks=("source records",),
            flows=("records flow into the generated report",),
            feedback_loops=("review feedback updates the next report",),
            delays=("provider reads complete before generation",),
            leverage_point="the existing registered workflow",
            simplest_intervention="run the existing report plan",
            success_metric="the reviewed report is generated",
            failure_condition="the report is missing or unverified",
            unintended_consequences=("additional maintenance burden",),
            removable_complexity=("the test-only over-budget additions",),
            alternatives_considered=("reuse only the existing workflow",),
            added_complexity=(
                ComplexityItem(ComplexityKind.AGENT, "test planning agent"),
                ComplexityItem(ComplexityKind.STATE_STORE, "test state store"),
                ComplexityItem(
                    ComplexityKind.CONFIGURATION_SURFACE,
                    "test configuration surface",
                ),
            ),
            existing_mechanisms_insufficient_because=(
                "the test must exercise authenticated over-budget review"
            ),
            reversibility_strategy="remove the test-only additions",
            low_risk=False,
            reversible=True,
            well_understood=True,
        ),
    )


if __name__ == "__main__":
    unittest.main()
