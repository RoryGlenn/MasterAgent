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
    CompensationDescriptor,
    CompensationMode,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import RunReport


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
        compensation = item.result.compensation
        if not isinstance(compensation, Mapping):
            after = item.result.after
            compensation = (
                after.get("compensation") if isinstance(after, Mapping) else None
            )
        if not isinstance(compensation, Mapping):
            unavailable.append(f"{item.action_id}: compensation descriptor is missing")
            continue
        descriptor = CompensationDescriptor.from_dict(compensation)
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
    return ChangePlan(
        goal=f"Compensate reversible effects of plan {original.plan_id}.",
        actions=tuple(compensation_actions),
        created_by=created_by,
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
    return ChangePlan(
        goal=f"Send a correction for Outlook message {original_reference}.",
        actions=(action,),
        created_by=created_by,
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
    return ChangePlan(
        goal=f"Post a correction for Teams message {original_reference}.",
        actions=(action,),
        created_by=created_by,
    )
