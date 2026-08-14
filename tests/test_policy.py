"""Policy-engine tests."""

import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.policy import PolicyConfig, PolicyEngine

ROOT = Path(__file__).resolve().parents[1]


class PolicyEngineTests(unittest.TestCase):
    """Verify approval and trust boundaries."""

    def setUp(self) -> None:
        self.authenticator = HmacApprovalAuthenticator(
            {
                "rory": ApprovalAuthority(
                    key_id="rory",
                    subject="Rory",
                    secret=b"rory-test-approval-secret-32-bytes!!",
                )
            }
        )
        self.engine = PolicyEngine(
            PolicyConfig.from_toml(ROOT / "config/policy.toml"),
            approval_authenticator=self.authenticator,
        )

    def test_read_is_auto_permitted(self) -> None:
        action = _action(risk=RiskLevel.READ_ONLY, capability="jira.issue.search")
        plan = _plan(action)
        decision = self.engine.evaluate(plan, action)
        self.assertTrue(decision.permitted)
        self.assertFalse(decision.approval_required)

    def test_external_send_requires_exact_plan_approval(self) -> None:
        action = _action(
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            capability="outlook.email.send",
            requires_approval=True,
        )
        plan = _plan(action)
        denied = self.engine.evaluate(plan, action)
        self.assertFalse(denied.permitted)
        self.assertTrue(denied.approval_required)

        now = datetime.now(UTC)
        approval = self.authenticator.issue(
            plan=plan,
            approved_action_ids=(action.action_id,),
            key_id="rory",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )
        permitted = self.engine.evaluate(plan, action, approvals=(approval,), now=now)
        self.assertTrue(permitted.permitted)

    def test_mutated_plan_invalidates_approval(self) -> None:
        action = _action(
            risk=RiskLevel.REVERSIBLE_WRITE,
            capability="jira.issue.update",
            requires_approval=True,
        )
        original = _plan(action)
        now = datetime.now(UTC)
        approval = self.authenticator.issue(
            plan=original,
            approved_action_ids=(action.action_id,),
            key_id="rory",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )
        mutated = ChangePlan(
            goal="Different goal",
            actions=(action,),
            created_by=original.created_by,
        )
        decision = self.engine.evaluate(mutated, action, approvals=(approval,), now=now)
        self.assertFalse(decision.permitted)

    def test_retrieved_content_cannot_authorize_write(self) -> None:
        action = _action(
            risk=RiskLevel.REVERSIBLE_WRITE,
            capability="jira.issue.update",
            authority=AuthoritySource.RETRIEVED_INTERNAL_CONTENT,
        )
        plan = _plan(action)
        decision = self.engine.evaluate(plan, action)
        self.assertFalse(decision.permitted)
        self.assertIn("cannot authorize", decision.reason)

    def test_merge_is_prohibited_even_with_high_impact_tier(self) -> None:
        action = _action(
            risk=RiskLevel.HIGH_IMPACT,
            capability="bitbucket.pull_request.merge",
            requires_approval=True,
        )
        plan = _plan(action)
        decision = self.engine.evaluate(plan, action)
        self.assertFalse(decision.permitted)
        self.assertFalse(decision.approval_required)


def _action(
    *,
    risk: RiskLevel,
    capability: str,
    requires_approval: bool = False,
    authority: AuthoritySource = AuthoritySource.DIRECT_USER,
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef(system="jira", resource_type="issue", resource_id="X-1"),
        parameters={},
        risk=risk,
        authority_source=authority,
        requires_approval=requires_approval,
        idempotency_key=f"test:{capability}:{risk}",
        justification="Test action.",
    )


def _plan(action: AgentAction) -> ChangePlan:
    return ChangePlan(goal="Test", actions=(action,), created_by="test")


if __name__ == "__main__":
    unittest.main()
