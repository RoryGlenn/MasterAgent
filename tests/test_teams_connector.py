"""Contract tests for read-only Microsoft Teams context."""

from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlparse

from master_agent.connectors.teams import TeamsConnector
from master_agent.errors import ConnectorError
from tests.fakes import ScriptedTransport
from tests.helpers import read_action, resolved_config


class TeamsConnectorTests(unittest.TestCase):
    """Verify bounded discovery, local filtering, and attachment metadata safety."""

    def test_chat_list_expands_members_and_last_message(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/me/chats",
            {
                "value": [
                    {
                        "id": "chat-1",
                        "topic": "Release room",
                        "chatType": "group",
                        "lastUpdatedDateTime": "2026-08-13T15:00:00Z",
                        "webUrl": "https://teams.microsoft.com/l/chat/chat-1?tenantId=t1",
                        "members": [
                            {
                                "id": "member-1",
                                "displayName": "Don",
                                "userId": "user-don",
                                "email": "don@example.com",
                            }
                        ],
                        "lastMessagePreview": {
                            "id": "message-1",
                            "createdDateTime": "2026-08-13T14:59:00Z",
                            "from": {"user": {"id": "user-don", "displayName": "Don"}},
                            "body": {
                                "contentType": "html",
                                "content": "<p>CI is green.</p>",
                            },
                        },
                    }
                ]
            },
        )
        connector = TeamsConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = read_action(
            "teams.chat.list",
            system="teams",
            resource_type="chat_collection",
            resource_id="my-chats",
            parameters={"limit": 10},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        chat = result.after["chats"][0]
        self.assertEqual(chat["members"][0]["user_id"], "user-don")
        self.assertEqual(chat["last_message_preview"]["body"], "CI is green.")
        self.assertTrue(str(chat["citation_id"]).startswith("CIT-"))
        query = parse_qs(urlparse(transport.requests[0].url).query)
        self.assertEqual(query["$expand"], ["members,lastMessagePreview"])
        self.assertEqual(query["$top"], ["10"])

    def test_chat_message_query_is_a_bounded_local_filter(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/chats/chat-2/messages",
            {
                "value": [
                    {
                        "id": "message-release",
                        "lastModifiedDateTime": "2026-08-13T15:00:00Z",
                        "from": {"user": {"id": "u1", "displayName": "Melanie"}},
                        "body": {
                            "contentType": "html",
                            "content": "<p>The release blocker is resolved.</p>",
                        },
                        "webUrl": "https://teams.microsoft.com/l/message/chat-2/message-release",
                    },
                    {
                        "id": "message-lunch",
                        "lastModifiedDateTime": "2026-08-13T14:00:00Z",
                        "from": {"user": {"id": "u2", "displayName": "Don"}},
                        "body": {"contentType": "text", "content": "Lunch at noon."},
                    },
                ]
            },
        )
        connector = TeamsConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = read_action(
            "teams.chat.message.list",
            system="teams",
            resource_type="message_collection",
            resource_id="chat-2",
            parameters={"query": "release blocker", "limit": 5, "scan_limit": 20},
        )

        result = connector.execute(action)

        self.assertEqual(result.after["returned"], 1)
        self.assertEqual(result.after["messages"][0]["id"], "message-release")
        self.assertEqual(result.after["query"]["mode"], "bounded_local_filter")
        request_url = transport.requests[0].url
        self.assertNotIn("release", request_url.lower())
        query = parse_qs(urlparse(request_url).query)
        self.assertEqual(query["$top"], ["20"])

    def test_channel_message_attachments_remain_metadata_only(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/teams/team-1/channels/channel-1/messages",
            {
                "value": [
                    {
                        "id": "message-3",
                        "createdDateTime": "2026-08-13T15:00:00Z",
                        "body": {
                            "contentType": "text",
                            "content": "See attached status.",
                        },
                        "attachments": [
                            {
                                "id": "attachment-1",
                                "name": "status.docx",
                                "contentType": "reference",
                                "contentUrl": "https://tenant.sharepoint.com/status.docx?token=temp",
                                "thumbnailUrl": "https://tenant.sharepoint.com/thumb?token=temp",
                                "content": '{"providerType":"oneDriveBusiness"}',
                            }
                        ],
                    }
                ]
            },
        )
        connector = TeamsConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = read_action(
            "teams.channel.message.list",
            system="teams",
            resource_type="message_collection",
            resource_id="channel-1",
            parameters={"team_id": "team-1", "limit": 10},
        )

        result = connector.execute(action)

        attachment = result.after["messages"][0]["attachments"][0]
        self.assertEqual(attachment["name"], "status.docx")
        self.assertEqual(
            attachment["content_url"],
            "https://tenant.sharepoint.com/status.docx",
        )
        self.assertEqual(
            attachment["thumbnail_url"],
            "https://tenant.sharepoint.com/thumb",
        )
        self.assertNotIn("token=temp", json.dumps(attachment))
        self.assertNotIn("content", attachment)
        self.assertNotIn("content_excerpt", attachment)
        self.assertNotIn("oneDriveBusiness", json.dumps(attachment))
        self.assertNotIn("content_bytes", attachment)
        self.assertEqual(len(transport.requests), 1)

    def test_channel_reply_list_uses_explicit_replies_endpoint(self) -> None:
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/teams/team-2/channels/channel-2/messages/root-message/replies",
            {
                "value": [
                    {
                        "id": "reply-1",
                        "replyToId": "root-message",
                        "body": {"contentType": "text", "content": "Acknowledged."},
                    }
                ]
            },
        )
        connector = TeamsConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "delegated"},
            ),
            transport=transport,
        )
        action = read_action(
            "teams.channel.message.replies.list",
            system="teams",
            resource_type="message_collection",
            resource_id="root-message",
            parameters={"team_id": "team-2", "channel_id": "channel-2"},
        )

        result = connector.execute(action)

        self.assertEqual(result.after["messages"][0]["reply_to_id"], "root-message")
        self.assertEqual(result.after["parent_message_id"], "root-message")

    def test_application_mode_requires_explicit_identity_for_user_collections(
        self,
    ) -> None:
        transport = ScriptedTransport()
        connector = TeamsConnector(
            resolved_config(
                "microsoft",
                base_url="https://graph.microsoft.com/v1.0",
                extra={"identity_mode": "application", "default_identity": "me"},
            ),
            transport=transport,
        )
        action = read_action(
            "teams.chat.list",
            system="teams",
            resource_type="chat_collection",
            resource_id="chats",
        )

        with self.assertRaisesRegex(ConnectorError, "requires delegated"):
            connector.execute(action)
        self.assertEqual(transport.requests, [])


if __name__ == "__main__":
    unittest.main()
