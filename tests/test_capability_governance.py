"""Capability catalog, governance, and multi-approval tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from master_agent.capabilities import CapabilityCatalog
from master_agent.governance import ApprovalTier, GovernanceProfile
from master_agent.models import (
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
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

    def test_dual_governance_requires_two_distinct_approvers(self) -> None:
        policy = PolicyEngine(
            PolicyConfig.from_toml(ROOT / "config/policy.toml")
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

        def approval(name: str) -> Approval:
            return Approval(
                plan_fingerprint=plan.fingerprint,
                approved_action_ids=(action.action_id,),
                approved_by=name,
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


if __name__ == "__main__":
    unittest.main()
