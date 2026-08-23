"""Approval-bound compensation-plan construction tests."""

from __future__ import annotations

import unittest
from uuid import uuid4

from master_agent.compensation import build_compensation_plan
from master_agent.errors import ValidationError
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
            ),
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

        persisted_report = RunReport.from_dict(report.to_dict())
        self.assertIsInstance(
            persisted_report.actions[0].result.compensation,
            CompensationDescriptor,
        )

        compensation = build_compensation_plan(
            original,
            persisted_report,
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

    def test_mixed_compensation_modes_fail_instead_of_returning_partial_plan(
        self,
    ) -> None:
        planned = _action("planned")
        in_process = _action("in-process")
        original = ChangePlan(
            goal="Update two resources.",
            actions=(planned, in_process),
            created_by="test",
        )
        report = RunReport(
            run_id=uuid4(),
            plan_id=original.plan_id,
            plan_fingerprint=original.fingerprint,
            dry_run=False,
            actions=(
                _report(planned, CompensationMode.PLAN),
                _report(in_process, CompensationMode.IN_PROCESS),
            ),
        )

        with self.assertRaisesRegex(ValidationError, "complete separately approvable"):
            build_compensation_plan(original, report, created_by="operator")

    def test_multiple_compensations_each_receive_a_strategy_trace(self) -> None:
        first = _action("first")
        second = _action("second")
        original = ChangePlan(
            goal="Update two resources.",
            actions=(first, second),
            created_by="test",
        )
        report = RunReport(
            run_id=uuid4(),
            plan_id=original.plan_id,
            plan_fingerprint=original.fingerprint,
            dry_run=False,
            actions=(
                _report(first, CompensationMode.PLAN),
                _report(second, CompensationMode.PLAN),
            ),
        )

        compensation = build_compensation_plan(
            original,
            report,
            created_by="operator",
        )

        self.assertEqual(len(compensation.actions), 2)
        self.assertEqual(len(compensation.strategy_traces), 2)
        assessment = compensation.systems_assessment
        assert assessment is not None and assessment.strategy_kernel is not None
        self.assertEqual(len(assessment.strategy_kernel.coherent_actions), 2)

    def test_unversioned_legacy_compensation_metadata_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "compensation descriptor must"):
            ExecutionResult.from_dict(
                {
                    "action_id": str(uuid4()),
                    "state": "succeeded",
                    "before": None,
                    "after": None,
                    "compensation": {
                        "capability": "example.resource.restore",
                        "value": "old",
                    },
                }
            )

    def test_execution_result_requires_typed_compensation_in_memory(self) -> None:
        with self.assertRaisesRegex(ValidationError, "CompensationDescriptor"):
            ExecutionResult(
                action_id=uuid4(),
                state=ActionState.SUCCEEDED,
                before=None,
                after={"value": "new"},
                compensation={"kind": "legacy"},  # type: ignore[arg-type]
            )

    def test_execution_result_rejects_snapshot_mutation(self) -> None:
        result = ExecutionResult(
            action_id=uuid4(),
            state=ActionState.SUCCEEDED,
            before={"value": "old"},
            after={"value": "new"},
        )
        assert result.after is not None
        result.after["value"] = "rewritten"

        with self.assertRaisesRegex(ValidationError, "after-state changed"):
            result.to_dict()


def _action(resource_id: str) -> AgentAction:
    return AgentAction(
        capability="example.resource.update",
        target=ResourceRef("example", "resource", resource_id),
        parameters={"value": "new"},
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=f"example:update:{resource_id}",
        justification="Update test resource.",
    )


def _report(action: AgentAction, mode: CompensationMode) -> ActionReport:
    descriptor = CompensationDescriptor(
        kind="restore_previous_value",
        mode=mode,
        capability=(
            "example.resource.restore" if mode is CompensationMode.PLAN else None
        ),
        parameters={"value": "old"},
        reason=(
            "requires originating connector"
            if mode is not CompensationMode.PLAN
            else None
        ),
    )
    return ActionReport(
        action_id=action.action_id,
        capability=action.capability,
        state=ActionState.VERIFIED,
        message="verified",
        result=ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=None,
            compensation=descriptor,
        ),
    )


if __name__ == "__main__":
    unittest.main()
