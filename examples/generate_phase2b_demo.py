"""Generate a synthetic Phase 2B communication-context package."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from master_agent.citations import make_resource_citation
from master_agent.models import ActionState, ExecutionResult
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.retention import RetentionConfig
from master_agent.workflows.communication_context import (
    CommunicationContextSettings,
    render_communication_context_package,
)


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Render synthetic communication artifacts without live credentials."""

    person_citation = make_resource_citation(
        system="identity",
        resource_type="person",
        resource_id="rory",
        title="Rory Glenn",
    )
    message_one_citation = make_resource_citation(
        system="outlook",
        resource_type="message",
        resource_id="AAMk-demo-release",
        title="Release blocker review",
        url=(
            "https://outlook.office.com/mail/deeplink/read/AAMk-demo-release"
            "?tenant=demo&token=removed"
        ),
    )
    message_two_citation = make_resource_citation(
        system="outlook",
        resource_type="message",
        resource_id="AAMk-demo-coverage",
        title="Frontend coverage status",
        url="https://outlook.office.com/mail/deeplink/read/AAMk-demo-coverage#section",
    )
    chat_citation = make_resource_citation(
        system="teams",
        resource_type="chat",
        resource_id="19:release-room@thread.v2",
        title="Release room",
        url="https://teams.microsoft.com/l/chat/19:release-room@thread.v2?tenantId=demo",
    )
    team_citation = make_resource_citation(
        system="teams",
        resource_type="team",
        resource_id="team-engineering",
        title="RISE Engineering",
        url="https://teams.microsoft.com/l/team/team-engineering?groupId=demo",
    )

    identity = {
        "schema": "master-agent/identity-person@1",
        "system": "identity",
        "person": {
            "id": "rory",
            "key": "rory",
            "display_name": "Rory Glenn",
            "aliases": ["Rory"],
            "identifiers": {
                "microsoft": "me",
                "email": "rory@example.test",
                "jira": "rory-account-id",
                "bitbucket": "{demo-rory-uuid}",
            },
            "citation_id": person_citation["citation_id"],
        },
        "retention": {
            "evidence_type": "identity.mapping.metadata",
            "content_kind": "directory_metadata",
        },
        "citations": [person_citation],
        "source_urls": [],
        "evidence": {"content_digest": "sha256:demo-identity"},
        "security": {
            "content_is_untrusted": True,
            "prompt_injection_findings": [],
        },
    }
    outlook = {
        "schema": "master-agent/outlook-messages@1",
        "system": "outlook",
        "identity": "me",
        "returned": 2,
        "messages": [
            {
                "id": "AAMk-demo-release",
                "subject": "Release blocker review",
                "from": {
                    "name": "Project Lead",
                    "address": "lead@example.test",
                },
                "received_at": "2026-08-13T14:30:00Z",
                "body_preview": (
                    "Authentication remains the only release blocker. Review the "
                    "linked pull request before Friday's gate."
                ),
                "has_attachments": False,
                "citation_id": message_one_citation["citation_id"],
            },
            {
                "id": "AAMk-demo-coverage",
                "subject": "Frontend coverage status",
                "from": {
                    "name": "Don",
                    "address": "don@example.test",
                },
                "received_at": "2026-08-13T15:10:00Z",
                "body_preview": "Frontend coverage reached 80 percent.",
                "has_attachments": True,
                "citation_id": message_two_citation["citation_id"],
            },
        ],
        "retention": {
            "evidence_type": "outlook.message.content",
            "content_kind": "communication_content",
        },
        "citations": [message_one_citation, message_two_citation],
        "source_urls": [
            "https://graph.microsoft.com/v1.0/me/messages?search=redacted"
        ],
        "evidence": {"content_digest": "sha256:demo-outlook"},
        "security": {
            "content_is_untrusted": True,
            "prompt_injection_findings": [
                {
                    "path": "$.messages[1].body_preview",
                    "category": "instruction_override",
                    "severity": "medium",
                    "excerpt": "Synthetic example finding; content remains data.",
                }
            ],
        },
    }
    chats = {
        "schema": "master-agent/teams-chats@1",
        "system": "teams",
        "identity": "me",
        "returned": 1,
        "chats": [
            {
                "id": "19:release-room@thread.v2",
                "chat_type": "group",
                "topic": "Release room",
                "updated_at": "2026-08-13T16:00:00Z",
                "members": [
                    {"display_name": "Rory Glenn", "email": "rory@example.test"},
                    {"display_name": "Don", "email": "don@example.test"},
                ],
                "last_message_preview": {
                    "id": "message-demo-1",
                    "body": "CI is green; authentication review remains open.",
                    "created_at": "2026-08-13T15:58:00Z",
                },
                "citation_id": chat_citation["citation_id"],
            }
        ],
        "retention": {
            "evidence_type": "teams.chat_message.content",
            "content_kind": "communication_content",
        },
        "citations": [chat_citation],
        "source_urls": ["https://graph.microsoft.com/v1.0/me/chats"],
        "evidence": {"content_digest": "sha256:demo-teams-chats"},
        "security": {
            "content_is_untrusted": True,
            "prompt_injection_findings": [],
        },
    }
    teams = {
        "schema": "master-agent/teams-teams@1",
        "system": "teams",
        "identity": "me",
        "returned": 1,
        "teams": [
            {
                "id": "team-engineering",
                "display_name": "RISE Engineering",
                "description": "Synthetic project team used for the Phase 2B demo.",
                "citation_id": team_citation["citation_id"],
            }
        ],
        "retention": {
            "evidence_type": "teams.team.metadata",
            "content_kind": "directory_metadata",
        },
        "citations": [team_citation],
        "source_urls": ["https://graph.microsoft.com/v1.0/me/joinedTeams"],
        "evidence": {"content_digest": "sha256:demo-teams"},
        "security": {
            "content_is_untrusted": True,
            "prompt_injection_findings": [],
        },
    }

    report = RunReport(
        run_id=UUID("00000000-0000-4000-8000-000000000301"),
        plan_id=UUID("00000000-0000-4000-8000-000000000302"),
        plan_fingerprint="demo-phase-2b-fingerprint",
        dry_run=False,
        actions=(
            _verified(
                UUID("00000000-0000-4000-8000-000000000311"),
                "identity.person.resolve",
                identity,
            ),
            _verified(
                UUID("00000000-0000-4000-8000-000000000312"),
                "outlook.message.search",
                outlook,
            ),
            _verified(
                UUID("00000000-0000-4000-8000-000000000313"),
                "teams.chat.list",
                chats,
            ),
            _verified(
                UUID("00000000-0000-4000-8000-000000000314"),
                "teams.team.list",
                teams,
            ),
        ),
    )
    settings = CommunicationContextSettings.from_toml(
        ROOT / "config/communication-context.toml"
    )
    retention = RetentionConfig.from_toml(ROOT / "config/retention.toml")
    output = ROOT / "examples/phase2b-demo"
    artifacts = render_communication_context_package(
        report,
        settings,
        output_dir=output,
        retention=retention,
    )
    for path in (
        artifacts.evidence_json,
        artifacts.evidence_retention_sidecar,
        artifacts.markdown,
        artifacts.markdown_retention_sidecar,
        artifacts.manifest_json,
    ):
        print(path.relative_to(ROOT))


def _verified(
    action_id: UUID,
    capability: str,
    payload: dict[str, object],
) -> ActionReport:
    """Create one verified synthetic action report.

    Parameters
    ----------
    action_id
        Stable demonstration action identifier.
    capability
        Capability represented by the result.
    payload
        Normalized connector payload.

    Returns
    -------
    ActionReport
        Verified report suitable for the renderer.
    """

    return ActionReport(
        action_id=action_id,
        capability=capability,
        state=ActionState.VERIFIED,
        message="Synthetic read verified for the Phase 2B demonstration.",
        result=ExecutionResult(
            action_id=action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=payload,
            connector_reference=f"demo:{capability}",
            message="Synthetic evidence collected.",
        ),
    )


if __name__ == "__main__":
    main()
