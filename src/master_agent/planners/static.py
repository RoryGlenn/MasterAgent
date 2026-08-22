"""Static planner used to prove the first governed workflow."""

from __future__ import annotations

from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)


def build_weekly_status_plan() -> ChangePlan:
    """Build the first safe vertical-slice workflow.

    Returns
    -------
    ChangePlan
        Read-only retrieval followed by local draft generation.
    """

    jira = AgentAction(
        capability="jira.issue.search",
        target=ResourceRef(
            system="jira",
            resource_type="sprint",
            resource_id="PROJECT-SPRINT",
            expected_version="7",
        ),
        parameters={"jql": "sprint in openSprints()", "limit": 100},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-status:jira:current-sprint:v1",
        justification="Collect canonical work-item status for the weekly package.",
    )

    bitbucket = AgentAction(
        capability="bitbucket.pull_request.search",
        target=ResourceRef(
            system="bitbucket",
            resource_type="pull_request_collection",
            resource_id="open-prs",
            expected_version="4",
        ),
        parameters={"state": "OPEN", "limit": 50},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-status:bitbucket:open-prs:v1",
        justification="Collect open pull requests and review state.",
    )

    confluence = AgentAction(
        capability="confluence.page.read",
        target=ResourceRef(
            system="confluence",
            resource_type="page",
            resource_id="project-status",
            expected_version="12",
        ),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-status:confluence:project-status:v1",
        justification="Read the canonical project-status narrative.",
    )

    dependencies = (jira.action_id, bitbucket.action_id, confluence.action_id)

    powerpoint = AgentAction(
        capability="powerpoint.presentation.generate",
        target=ResourceRef(
            system="powerpoint",
            resource_type="presentation",
            resource_id="weekly-status-preview",
        ),
        parameters={
            "title": "Weekly Project Status",
            "sections": [
                "Executive summary",
                "Sprint status",
                "Pull requests",
                "Blockers and decisions",
                "Next actions",
            ],
            "source_action_ids": [str(item) for item in dependencies],
        },
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-status:powerpoint:v1",
        justification="Generate a local presentation specification from canonical data.",
        dependencies=dependencies,
    )

    teams = AgentAction(
        capability="teams.message.draft",
        target=ResourceRef(
            system="teams",
            resource_type="message_draft",
            resource_id="weekly-status-preview-draft",
        ),
        parameters={
            "recipient_type": "team",
            "recipient_id": "project-team",
            "body": (
                "Weekly status draft: review the generated presentation for "
                "current progress, blockers, decisions, and next actions."
            ),
            "output_name": "weekly-status-teams.md",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-status:teams-draft:v1",
        justification="Prepare but do not send the weekly Teams summary.",
        dependencies=dependencies,
    )

    outlook = AgentAction(
        capability="outlook.email.draft",
        target=ResourceRef(
            system="outlook",
            resource_type="email_draft",
            resource_id="weekly-status-preview-draft",
        ),
        parameters={
            "to": ["stakeholders@example.invalid"],
            "subject": "Weekly project status",
            "body": (
                "The weekly project status package is ready for review. "
                "No content has been published or sent by this workflow."
            ),
            "output_name": "weekly-status-email.eml",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-status:outlook-draft:v1",
        justification="Prepare but do not send the stakeholder email summary.",
        dependencies=(powerpoint.action_id,),
    )

    return ChangePlan(
        goal="Prepare the weekly project status package without publishing or sending.",
        created_by="registered_workflow:weekly_status_v1",
        actions=(jira, bitbucket, confluence, powerpoint, teams, outlook),
    )
