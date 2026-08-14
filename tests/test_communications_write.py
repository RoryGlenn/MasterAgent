"""Contract tests for approval-bound external communications."""

from __future__ import annotations

import unittest

from master_agent.connectors.communications import OutlookSendConnector, TeamsSendConnector
from master_agent.errors import ConnectorError
from master_agent.models import RiskLevel
from tests.fakes import ScriptedTransport
from tests.helpers import action_for, resolved_config


class OutlookSendConnectorTests(unittest.TestCase):
    """Validate immutable preflight draft comparison before sending."""

    def test_exact_draft_is_verified_before_send(self) -> None:
        transport = ScriptedTransport()
        draft_collection = "/v1.0/me/messages"
        draft_item = "/v1.0/me/messages/draft-1"
        transport.add_json("POST", draft_collection, {"id": "draft-1"}, status=201)
        transport.add_json(
            "GET",
            draft_item,
            {
                "subject": "Release status",
                "body": {"contentType": "Text", "content": "Release is ready."},
                "toRecipients": [
                    {"emailAddress": {"address": "don@example.com"}}
                ],
                "ccRecipients": [],
                "bccRecipients": [],
            },
        )
        transport.add_bytes("POST", draft_item + "/send", b"", status=202)
        connector = OutlookSendConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = action_for(
            "outlook.email.send",
            system="outlook",
            resource_type="message",
            resource_id="me",
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={
                "identity": "me",
                "to": ["don@example.com"],
                "subject": "Release status",
                "body": "Release is ready.",
                "content_type": "Text",
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertTrue(result.after["non_reversible"])
        self.assertEqual(result.after["provider_status"], 202)
        self.assertEqual([item.method for item in transport.requests], ["POST", "GET", "POST"])

    def test_provider_draft_mismatch_blocks_send(self) -> None:
        transport = ScriptedTransport()
        transport.add_json("POST", "/v1.0/me/messages", {"id": "draft-1"}, status=201)
        transport.add_json(
            "GET",
            "/v1.0/me/messages/draft-1",
            {
                "subject": "Changed by provider",
                "body": {"contentType": "Text", "content": "Release is ready."},
                "toRecipients": [
                    {"emailAddress": {"address": "don@example.com"}}
                ],
                "ccRecipients": [],
                "bccRecipients": [],
            },
        )
        connector = OutlookSendConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = action_for(
            "outlook.email.send",
            system="outlook",
            resource_type="message",
            resource_id="me",
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={
                "to": ["don@example.com"],
                "subject": "Release status",
                "body": "Release is ready.",
            },
        )
        with self.assertRaises(ConnectorError):
            connector.execute(action)
        self.assertEqual([item.method for item in transport.requests], ["POST", "GET"])


class TeamsSendConnectorTests(unittest.TestCase):
    """Validate Teams delegated post and provider re-read."""

    def test_chat_message_send_and_verify(self) -> None:
        transport = ScriptedTransport()
        collection = "/v1.0/chats/chat-1/messages"
        item = collection + "/message-1"
        transport.add_json("POST", collection, {"id": "message-1"}, status=201)
        transport.add_json(
            "GET",
            item,
            {
                "id": "message-1",
                "body": {"contentType": "text", "content": "Release is ready."},
            },
        )
        connector = TeamsSendConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = action_for(
            "teams.chat.message.send",
            system="teams",
            resource_type="chat_message",
            resource_id="chat-1",
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={
                "chat_id": "chat-1",
                "body": "Release is ready.",
                "content_type": "text",
            },
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["message_id"], "message-1")
        self.assertTrue(result.after["non_reversible"])

    def test_application_mode_is_rejected_before_network(self) -> None:
        transport = ScriptedTransport()
        connector = TeamsSendConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={
                    "identity_mode": "application",
                    "allow_application_message_send": True,
                },
            ),
            transport=transport,
        )
        action = action_for(
            "teams.chat.message.send",
            system="teams",
            resource_type="chat_message",
            resource_id="chat-1",
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={"chat_id": "chat-1", "body": "Hello"},
        )
        with self.assertRaises(ConnectorError):
            connector.execute(action)
        self.assertEqual(transport.requests, [])


if __name__ == "__main__":
    unittest.main()
