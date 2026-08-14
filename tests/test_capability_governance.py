"""Capability catalog, governance, and multi-approval tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import unittest

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.capabilities import CapabilityCatalog
from master_agent.governance import ApprovalTier, GovernanceProfile
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.policy import PolicyConfig, PolicyEngine


ROOT = Path(__file__).resolve().parents[1]


class CapabilityGovernanceTests(unittest.TestCase):
    """Validate fail-closed capability and governance behavior."""

    def test_repository_catalog_has_governance_coverage(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        report = governance.coverage_report(catalog)
        self.assertTrue(report["ready"], report["errors"])
        self.assertGreater(len(report["covered"]), 20)

    def test_disabled_capability_is_rejected(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        action = AgentAction(
            capability="bitbucket.pull_request.merge",
            target=ResourceRef("bitbucket", "pull_request", "9"),
            parameters={"destination": "main"},
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="merge-disabled",
            justification="test",
        )
        allowed, reason = catalog.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("disabled", reason)

    def test_version_and_classification_contracts_fail_closed(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        action = AgentAction(
            capability="jira.issue.update",
            target=ResourceRef("jira", "issue", "X-1"),
            parameters={"fields": {"summary": "changed"}},
            risk=RiskLevel.REVERSIBLE_WRITE,
            data_classification=DataClassification.RESTRICTED,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="version-classification",
            justification="test",
        )

        allowed, reason = catalog.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("expected_version", reason)
        allowed, reason = governance.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("classification", reason)

    def test_dual_governance_requires_two_distinct_approvers(self) -> None:
        authenticator = HmacApprovalAuthenticator(
            {
                name: ApprovalAuthority(
                    key_id=name,
                    subject=name,
                    secret=(f"{name}-approval-secret-" + "x" * 32).encode(),
                )
                for name in ("alice", "bob")
            }
        )
        policy = PolicyEngine(
            PolicyConfig.from_toml(ROOT / "config/policy.toml"),
            approval_authenticator=authenticator,
        )
        action = AgentAction(
            capability="example.high_impact",
            target=ResourceRef("example", "resource", "1"),
            parameters={},
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="dual-test",
            justification="test",
        )
        plan = ChangePlan(goal="dual approval test", actions=(action,), created_by="test")
        now = datetime.now(UTC)

        def approval(name: str):
            return authenticator.issue(
                plan=plan,
                approved_action_ids=(action.action_id,),
                key_id=name,
                issued_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(minutes=10),
            )

        one = policy.evaluate(
            plan,
            action,
            approvals=(approval("alice"),),
            now=now,
            minimum_distinct_approvers=2,
        )
        self.assertFalse(one.permitted)
        two = policy.evaluate(
            plan,
            action,
            approvals=(approval("alice"), approval("bob")),
            now=now,
            minimum_distinct_approvers=2,
        )
        self.assertTrue(two.permitted)

    def test_governance_specific_rule_beats_catch_all(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        self.assertEqual(
            governance.approval_tier_for("outlook.email.send"),
            ApprovalTier.SINGLE,
        )
        self.assertEqual(
            governance.approval_tier_for("repository.permission.change"),
            ApprovalTier.PROHIBITED,
        )

    def test_governance_minimum_forces_approval_even_if_risk_is_auto_permitted(self) -> None:
        action = AgentAction(
            capability="example.high_impact",
            target=ResourceRef("example", "resource", "1"),
            parameters={},
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="governance-forces-approval",
            justification="test",
        )
        plan = ChangePlan(goal="governance approval", actions=(action,), created_by="test")
        policy = PolicyEngine(
            PolicyConfig(
                auto_permit_risks=frozenset({RiskLevel.HIGH_IMPACT}),
                require_approval_risks=frozenset(),
                prohibit_risks=frozenset(),
                prohibited_capabilities=(),
                write_capability_patterns=(),
            )
        )

        decision = policy.evaluate(
            plan,
            action,
            minimum_distinct_approvers=2,
        )

        self.assertFalse(decision.permitted)
        self.assertTrue(decision.approval_required)
        self.assertIn("2 distinct", decision.reason)


if __name__ == "__main__":
    unittest.main()
