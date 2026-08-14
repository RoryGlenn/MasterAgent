"""Approval-bound compensation-plan construction tests."""

from __future__ import annotations

from master_agent.compensation import build_compensation_plan
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    CompensationDescriptor,
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import ActionReport, RunReport
from uuid import uuid4
import unittest


class CompensationPlanTests(unittest.TestCase):
    """Verify persisted connector metadata becomes a new immutable plan."""

    def test_result_compensation_field_is_used(self) -> None:
        action = AgentAction(
            capability="example.resource.update",
            target=ResourceRef(
                system="example",
                resource_type="resource",
                resource_id="42",
            ),
            parameters={"value": "new"},
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="example:update:42",
            justification="Update test resource.",
        )
        original = ChangePlan(
            goal="Update one resource.",
            actions=(action,),
            created_by="test",
        )
        result = ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={"value": "old"},
            after={"value": "new"},
            compensation=CompensationDescriptor(
                kind="restore_previous_value",
                mode=CompensationMode.PLAN,
                capability="example.resource.restore",
                parameters={"value": "old"},
                expected_version="2",
                target_resource_id="provider-42",
            ).to_dict(),
        )
        report = RunReport(
            run_id=uuid4(),
            plan_id=original.plan_id,
            plan_fingerprint=original.fingerprint,
            dry_run=False,
            actions=(
                ActionReport(
                    action_id=action.action_id,
                    capability=action.capability,
                    state=ActionState.VERIFIED,
                    message="verified",
                    result=result,
                ),
            ),
        )

        compensation = build_compensation_plan(
            original,
            report,
            created_by="operator",
        )

        self.assertEqual(len(compensation.actions), 1)
        reverse = compensation.actions[0]
        self.assertEqual(reverse.capability, "example.resource.restore")
        self.assertEqual(reverse.parameters, {"value": "old"})
        self.assertEqual(reverse.target.expected_version, "2")
        self.assertEqual(reverse.target.resource_id, "provider-42")
        self.assertTrue(reverse.requires_approval)
        self.assertEqual(reverse.authority_source, AuthoritySource.DIRECT_USER)


if __name__ == "__main__":
    unittest.main()
