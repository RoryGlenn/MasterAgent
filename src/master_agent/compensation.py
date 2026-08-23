"""Build explicit, approval-gated compensation and correction plans."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from master_agent.errors import ValidationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    CompensationMode,
    ResourceRef,
    RiskLevel,
    SystemsAssessment,
)
from master_agent.orchestrator import RunReport
from master_agent.planners.base import bind_systems_governance


def build_compensation_plan(
    original: ChangePlan,
    report: RunReport,
    *,
    created_by: str,
) -> ChangePlan:
    """Create a reverse-ordered plan from connector compensation metadata.

    The function fails closed if any reported reversible effect cannot be
    represented in the returned plan. This prevents an operator from mistaking
    a silently partial rollback plan for complete compensation.
    """

    original_by_id = {action.action_id: action for action in original.actions}
    compensation_actions: list[AgentAction] = []
    unavailable: list[str] = []
    previous: UUID | None = None
    for item in reversed(report.actions):
        if item.result is None:
            continue
        source = original_by_id.get(item.action_id)
        if source is None:
            unavailable.append(f"{item.action_id}: original action is unavailable")
            continue
        if source.risk is not RiskLevel.REVERSIBLE_WRITE:
            continue
        descriptor = item.result.compensation
        if descriptor is None:
            unavailable.append(f"{item.action_id}: compensation descriptor is missing")
            continue
        if descriptor.mode is not CompensationMode.PLAN:
            unavailable.append(
                f"{item.action_id}: {descriptor.reason or descriptor.mode}"
            )
            continue
        capability = descriptor.capability or ""
        dependencies = (previous,) if previous is not None else ()
        action = AgentAction(
            capability=capability,
            target=ResourceRef(
                system=source.target.system,
                resource_type=source.target.resource_type,
                resource_id=(
                    descriptor.target_resource_id or source.target.resource_id
                ),
                expected_version=descriptor.expected_version,
            ),
            parameters=descriptor.parameters,
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key=(
                f"compensate:{original.fingerprint}:{source.action_id}:{capability}"
            ),
            justification=(
                f"Compensate approved action {source.action_id} from plan "
                f"{original.plan_id}."
            ),
            dependencies=dependencies,
        )
        compensation_actions.append(action)
        previous = action.action_id

    if unavailable:
        raise ValidationError(
            "run cannot produce a complete separately approvable compensation plan: "
            + "; ".join(unavailable)
        )
    if not compensation_actions:
        raise ValidationError(
            "run contains no separately approvable compensation operations"
        )
    plan = ChangePlan(
        goal=f"Compensate reversible effects of plan {original.plan_id}.",
        actions=tuple(compensation_actions),
        created_by=created_by,
    )
    return _bind_correction_governance(
        plan,
        current_behavior="verified reversible effects from the original run remain applied",
        simplest_intervention="execute the connector-provided reverse operations in reverse order",
        success_metric="every reversible effect is restored and independently verified",
        failure_condition="any compensation is unavailable, conflicts, or fails verification",
    )


def build_outlook_correction_plan(
    *,
    original_reference: str,
    to: tuple[str, ...],
    subject: str,
    body: str,
    created_by: str,
) -> ChangePlan:
    """Create an approval-gated correction email plan."""

    action = AgentAction(
        capability="outlook.email.send",
        target=ResourceRef(
            system="outlook",
            resource_type="correction_email",
            resource_id=f"correction:{original_reference}",
        ),
        parameters={
            "to": list(to),
            "subject": subject,
            "body": body,
            "content_type": "Text",
            "correlation_id": original_reference,
        },
        risk=RiskLevel.EXTERNAL_COMMUNICATION,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=f"outlook-correction:{original_reference}",
        justification="Send an explicit correction for a prior non-reversible email.",
    )
    plan = ChangePlan(
        goal=f"Send a correction for Outlook message {original_reference}.",
        actions=(action,),
        created_by=created_by,
    )
    return _bind_correction_governance(
        plan,
        current_behavior="a prior Outlook message requires an explicit correction",
        simplest_intervention="send one approval-gated correction email",
        success_metric="the correction is sent once and independently verified",
        failure_condition="approval, delivery, or verification does not succeed",
    )


def build_teams_correction_plan(
    *,
    original_reference: str,
    body: str,
    destination: Mapping[str, Any],
    created_by: str,
) -> ChangePlan:
    """Create an approval-gated Teams correction plan."""

    if destination.get("chat_id"):
        capability = "teams.chat.message.send"
    elif destination.get("team_id") and destination.get("channel_id"):
        capability = (
            "teams.channel.message.reply"
            if destination.get("parent_message_id")
            else "teams.channel.message.send"
        )
    else:
        raise ValidationError(
            "Teams correction destination requires chat_id or team_id/channel_id"
        )
    action = AgentAction(
        capability=capability,
        target=ResourceRef(
            system="teams",
            resource_type="correction_message",
            resource_id=f"correction:{original_reference}",
        ),
        parameters={
            **dict(destination),
            "body": body,
            "content_type": "text",
            "correlation_id": original_reference,
        },
        risk=RiskLevel.EXTERNAL_COMMUNICATION,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=f"teams-correction:{original_reference}",
        justification="Post an explicit correction for a prior non-reversible Teams message.",
    )
    plan = ChangePlan(
        goal=f"Post a correction for Teams message {original_reference}.",
        actions=(action,),
        created_by=created_by,
    )
    return _bind_correction_governance(
        plan,
        current_behavior="a prior Teams message requires an explicit correction",
        simplest_intervention="post one approval-gated correction message",
        success_metric="the correction is posted once and independently verified",
        failure_condition="approval, posting, or verification does not succeed",
    )


def _bind_correction_governance(
    plan: ChangePlan,
    *,
    current_behavior: str,
    simplest_intervention: str,
    success_metric: str,
    failure_condition: str,
) -> ChangePlan:
    """Bind the full systems assessment required for corrective effects."""

    return bind_systems_governance(
        plan,
        SystemsAssessment(
            desired_outcome=plan.goal,
            current_behavior=current_behavior,
            constraint="the prior provider state cannot be changed without a new effect",
            stocks=("the current provider state and its verified evidence",),
            flows=("an approval-gated corrective action to the provider",),
            feedback_loops=(
                "post-effect verification confirms or rejects the correction",
            ),
            delays=("approval, provider processing, and verification latency",),
            leverage_point="the smallest connector-supported corrective action",
            simplest_intervention=simplest_intervention,
            success_metric=success_metric,
            failure_condition=failure_condition,
            unintended_consequences=(
                "a transport failure could leave the correction outcome indeterminate",
            ),
            removable_complexity=("the one-use corrective plan",),
            low_risk=False,
            reversible=True,
            well_understood=True,
        ),
    )
