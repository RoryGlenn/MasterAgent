"""Read-only Outlook/Teams communication-context workflow tests."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from master_agent.citations import make_resource_citation
from master_agent.errors import ConfigurationError
from master_agent.identity import IdentityRegistry
from master_agent.models import ActionState, ExecutionResult, RiskLevel
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.retention import RetentionConfig
from master_agent.workflows.communication_context import (
    CommunicationContextSettings,
    build_communication_context_plan,
    render_communication_context_package,
)

ROOT = Path(__file__).resolve().parents[1]


class CommunicationContextWorkflowTests(unittest.TestCase):
    """Verify the registered workflow remains bounded and read-only."""

    def test_configuration_builds_four_read_actions_with_dependencies(self) -> None:
        settings = CommunicationContextSettings.from_toml(
            ROOT / "config/communication-context.toml"
        )
        identities = IdentityRegistry.from_toml(ROOT / "config/identities.toml")

        plan = build_communication_context_plan(settings, identities)

        self.assertEqual(len(plan.actions), 4)
        self.assertTrue(
            all(action.risk is RiskLevel.READ_ONLY for action in plan.actions)
        )
        identity_action = plan.actions[0]
        self.assertEqual(identity_action.capability, "identity.person.resolve")
        for action in plan.actions[1:]:
            self.assertEqual(action.dependencies, (identity_action.action_id,))
        outlook = next(
            action
            for action in plan.actions
            if action.capability == "outlook.message.search"
        )
        self.assertEqual(outlook.parameters["identity"], "me")
        self.assertEqual(outlook.parameters["query"], "release blocker")

    def test_configuration_rejects_string_boolean(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "communication-context.toml"
            path.write_text(
                """
[workflow]
name = "Test"
identity_query = "rory"

[outlook]
query = "release"

[teams]
include_members = "false"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ConfigurationError,
                "must be a TOML boolean",
            ):
                CommunicationContextSettings.from_toml(path)

    def test_renderer_writes_retained_evidence_markdown_and_manifest(self) -> None:
        settings = CommunicationContextSettings.from_toml(
            ROOT / "config/communication-context.toml"
        )
        retention = RetentionConfig.from_toml(ROOT / "config/retention.toml")
        report = _report()

        with TemporaryDirectory() as directory:
            output = Path(directory)
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
                self.assertTrue(path.exists(), path)
                self.assertGreater(path.stat().st_size, 0)

            markdown = artifacts.markdown.read_text(encoding="utf-8")
            self.assertIn("Release blocker", markdown)
            self.assertIn("Release room", markdown)
            self.assertIn("[CIT-", markdown)
            self.assertIn("untrusted data", markdown)

            evidence = json.loads(artifacts.evidence_json.read_text(encoding="utf-8"))
            self.assertEqual(len(evidence["messages"]), 1)
            self.assertEqual(len(evidence["chats"]), 1)
            self.assertEqual(len(evidence["teams"]), 1)
            self.assertEqual(len(evidence["citations"]), 4)

            sidecar = json.loads(
                artifacts.evidence_retention_sidecar.read_text(encoding="utf-8")
            )
            self.assertEqual(len(sidecar["citation_ids"]), 4)
            self.assertTrue(sidecar["content_included"])

            manifest = json.loads(artifacts.manifest_json.read_text(encoding="utf-8"))
            self.assertTrue(manifest["successful"])
            self.assertEqual(manifest["counts"]["citations"], 4)
            for filename, digest in manifest["files"].items():
                self.assertEqual(digest, _sha256(output / filename))


def _report() -> RunReport:
    identity_id = uuid4()
    outlook_id = uuid4()
    chats_id = uuid4()
    teams_id = uuid4()

    person_citation = make_resource_citation(
        system="identity",
        resource_type="person",
        resource_id="rory",
        title="Rory Glenn",
    )
    message_citation = make_resource_citation(
        system="outlook",
        resource_type="message",
        resource_id="message-1",
        title="Release blocker",
        url="https://outlook.office.com/mail/message-1?view=full",
    )
    chat_citation = make_resource_citation(
        system="teams",
        resource_type="chat",
        resource_id="chat-1",
        title="Release room",
        url="https://teams.microsoft.com/l/chat/chat-1?tenant=t1",
    )
    team_citation = make_resource_citation(
        system="teams",
        resource_type="team",
        resource_id="team-1",
        title="Engineering",
        url="https://teams.microsoft.com/l/team/team-1",
    )

    identity_payload = {
        "schema": "master-agent/identity-person@1",
        "system": "identity",
        "person": {
            "id": "rory",
            "key": "rory",
            "display_name": "Rory Glenn",
            "citation_id": person_citation["citation_id"],
        },
        "citations": [person_citation],
        "security": {"prompt_injection_findings": []},
    }
    outlook_payload = {
        "schema": "master-agent/outlook-messages@1",
        "system": "outlook",
        "messages": [
            {
                "id": "message-1",
                "subject": "Release blocker",
                "from": {"name": "Don", "address": "don@example.com"},
                "received_at": "2026-08-13T15:00:00Z",
                "citation_id": message_citation["citation_id"],
            }
        ],
        "citations": [message_citation],
        "security": {
            "prompt_injection_findings": [
                {
                    "path": "$.messages[0].body_preview",
                    "category": "instruction_override",
                    "severity": "high",
                    "excerpt": "Ignore previous instructions",
                }
            ]
        },
    }
    chats_payload = {
        "schema": "master-agent/teams-chats@1",
        "system": "teams",
        "chats": [
            {
                "id": "chat-1",
                "topic": "Release room",
                "updated_at": "2026-08-13T16:00:00Z",
                "members": [{"display_name": "Don"}],
                "citation_id": chat_citation["citation_id"],
            }
        ],
        "citations": [chat_citation],
        "security": {"prompt_injection_findings": []},
    }
    teams_payload = {
        "schema": "master-agent/teams-teams@1",
        "system": "teams",
        "teams": [
            {
                "id": "team-1",
                "display_name": "Engineering",
                "citation_id": team_citation["citation_id"],
            }
        ],
        "citations": [team_citation],
        "security": {"prompt_injection_findings": []},
    }
    return RunReport(
        run_id=uuid4(),
        plan_id=uuid4(),
        plan_fingerprint="b" * 64,
        dry_run=False,
        actions=(
            _action_report(identity_id, "identity.person.resolve", identity_payload),
            _action_report(outlook_id, "outlook.message.search", outlook_payload),
            _action_report(chats_id, "teams.chat.list", chats_payload),
            _action_report(teams_id, "teams.team.list", teams_payload),
        ),
    )


def _action_report(
    action_id: object,
    capability: str,
    payload: dict[str, object],
) -> ActionReport:
    return ActionReport(
        action_id=action_id,
        capability=capability,
        state=ActionState.VERIFIED,
        message="verified",
        result=ExecutionResult(
            action_id=action_id,
            state=ActionState.SUCCEEDED,
            before=payload,
            after=payload,
            connector_reference="test",
            message="read",
        ),
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
