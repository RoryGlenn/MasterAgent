"""Workflow orchestration tests."""

import hashlib
import unittest
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ComplexityItem,
    ComplexityKind,
    ResourceRef,
    RiskLevel,
    StrategyActionIntent,
    StrategyKernel,
    SystemsAssessment,
    SystemsMetricStatus,
    SystemsOutcomeEvidence,
)
from master_agent.orchestrator import RunReport, WorkflowOrchestrator
from master_agent.planners.base import (
    EvidenceBackedSystemsOutcomeObserver,
    SystemsOutcomeObserver,
    bind_static_intervention_governance,
)
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

    def test_fingerprint_bound_observer_closes_the_applied_run_loop(self) -> None:
        class Provider:
            def observe(self, *, assessment, decision, states):
                self.states = states
                return SystemsOutcomeEvidence(
                    assessment_fingerprint=assessment.fingerprint,
                    decision_fingerprint=decision.fingerprint,
                    success_metric_sha256=hashlib.sha256(
                        assessment.success_metric.encode("utf-8")
                    ).hexdigest(),
                    metric_status=SystemsMetricStatus.CONFIRMED_MOVED,
                    unintended_effects_detected=False,
                    observed_complexity_score=0,
                    removal_candidate_count=0,
                    stop_condition_checked=True,
                    stop_condition_triggered=False,
                    reason_codes=("workflow_metric_observed",),
                )

        provider = Provider()
        observer = EvidenceBackedSystemsOutcomeObserver(provider)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            report = _orchestrator(audit, outcome_observer=observer).run(
                build_weekly_status_plan(), dry_run=False
            )

        self.assertTrue(provider.states)
        self.assertEqual(
            report.systems_review.metric_status,
            SystemsMetricStatus.CONFIRMED_MOVED,
        )
        self.assertEqual(report.systems_review.complexity_growth, 0)
        self.assertFalse(report.systems_review.reassessment_required)
        restored = RunReport.from_dict(report.to_dict())
        self.assertEqual(restored.systems_review, report.systems_review)

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

    def test_effect_guard_runs_immediately_before_connector_dispatch(self) -> None:
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
                        secret=b"effect-fence-test-secret-32-bytes!",
                    )
                }
            )
            jira = MockConnector(
                "jira",
                {"PROJECT-SPRINT": {"version": "7", "summary": "healthy"}},
            )
            guarded: list[str] = []

            def reject_stale_claim(action: AgentAction) -> None:
                guarded.append(action.capability)
                self.assertEqual(
                    jira.read(action.target),
                    {"version": "7", "summary": "healthy"},
                )
                raise ConfigurationError("test occurrence fence was lost")

            orchestrator = _orchestrator(
                audit,
                authenticator=authenticator,
                pre_effect_guard=reject_stale_claim,
                jira_connector=jira,
            )
            source = build_weekly_status_plan()
            write = AgentAction(
                capability="jira.issue.update",
                target=ResourceRef(
                    system="jira",
                    resource_type="sprint",
                    resource_id="PROJECT-SPRINT",
                    expected_version="7",
                ),
                parameters={"summary": "changed"},
                risk=RiskLevel.REVERSIBLE_WRITE,
                authority_source=AuthoritySource.DIRECT_USER,
                requires_approval=True,
                idempotency_key="effect-fence-test",
                justification="Prove the final occurrence fence blocks dispatch.",
            )
            unbound = replace(
                source,
                actions=(write,),
                systems_assessment=None,
                systems_decision=None,
            )
            plan = bind_static_intervention_governance(
                unbound,
                SystemsAssessment.for_static_intervention(
                    desired_outcome=unbound.goal,
                    current_behavior="the sprint summary has not changed",
                    constraint="the write must keep its occurrence fence",
                    stocks=("the sprint record",),
                    flows=("approved updates reach the sprint record",),
                    feedback_loops=("verification confirms the final state",),
                    delays=("approval precedes provider dispatch",),
                    leverage_point="the orchestrator pre-effect boundary",
                    simplest_intervention="reject the stale fenced write",
                    success_metric="the provider receives no stale effect",
                    failure_condition="the provider state changes after fence loss",
                    unintended_consequences=("a duplicate provider effect",),
                    removable_complexity=("the test guard",),
                    strategy_kernel=_strategy_kernel_for_plan(unbound),
                    alternatives_considered=("connector-specific fencing",),
                    reversibility_strategy="retain the original provider state",
                    reversible=True,
                    well_understood=True,
                ),
            )
            now = datetime.now(UTC)
            approval = authenticator.issue(
                plan=plan,
                approved_action_ids=(write.action_id,),
                key_id="reviewer",
                issued_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=5),
            )

            report = orchestrator.run(plan, approvals=(approval,), dry_run=False)

            self.assertFalse(report.successful)
            self.assertEqual(guarded, ["jira.issue.update"])
            self.assertEqual(
                jira.read(write.target),
                {"version": "7", "summary": "healthy"},
            )


def _orchestrator(
    audit: AuditLog,
    *,
    authenticator: HmacApprovalAuthenticator | None = None,
    pre_effect_guard: Callable[[AgentAction], None] | None = None,
    jira_connector: MockConnector | None = None,
    outcome_observer: SystemsOutcomeObserver | None = None,
) -> WorkflowOrchestrator:
    registry = ConnectorRegistry()
    registry.register(
        jira_connector
        or MockConnector(
            "jira", {"PROJECT-SPRINT": {"version": "7", "summary": "healthy"}}
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
        pre_effect_guard=pre_effect_guard,
        systems_outcome_observer=outcome_observer,
    )


def _over_budget_plan() -> ChangePlan:
    plan = replace(
        build_weekly_status_plan(),
        systems_assessment=None,
        systems_decision=None,
    )
    return bind_static_intervention_governance(
        plan,
        SystemsAssessment.for_static_intervention(
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
            strategy_kernel=_strategy_kernel_for_plan(plan),
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
            reversible=True,
            well_understood=True,
        ),
    )


def _strategy_kernel_for_plan(plan: ChangePlan) -> StrategyKernel:
    return StrategyKernel(
        diagnosis="the requested test outcome has not reached verified state",
        guiding_policy="use only the existing governed test actions",
        proximate_objective="execute and verify the exact bounded test plan",
        tradeoffs=("prefer deterministic coverage over production breadth",),
        coherent_actions=tuple(
            StrategyActionIntent(
                intent_id=f"test_action_{index}",
                description=action.justification,
                expected_effect="the action reaches its independently verified state",
            )
            for index, action in enumerate(plan.actions, start=1)
        ),
    )


if __name__ == "__main__":
    unittest.main()
