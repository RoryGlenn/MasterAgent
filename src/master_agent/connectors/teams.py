"""Read-only Microsoft Teams connector through Microsoft Graph."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.microsoft_graph import (
    graph_client,
    graph_paged_values,
    graph_user_root,
)
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    boolean_parameter,
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport
from master_agent.models import AgentAction
from master_agent.text import excerpt, html_to_text


class TeamsConnector(ReadOnlyConnector):
    """Discover and read Teams chats, teams, channels, and messages."""

    _CAPABILITIES = frozenset(
        {
            "teams.chat.list",
            "teams.chat.message.list",
            "teams.chat.message.read",
            "teams.team.list",
            "teams.channel.list",
            "teams.channel.message.list",
            "teams.channel.message.read",
            "teams.channel.message.replies.list",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="teams", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = graph_client(config, transport=transport)

    def probe(self) -> Mapping[str, Any]:
        """Verify bounded Teams access using the configured probe resource."""

        root, identity = graph_user_root(self._config, None)
        probe_resource = str(self._config.extra.get("teams_probe", "chats")).lower()
        if probe_resource == "teams":
            path = f"{root}/joinedTeams"
            data, response = self._client.request_json("GET", path)
        else:
            path = f"{root}/chats"
            data, response = self._client.request_json(
                "GET",
                path,
                query={"$top": 1},
            )
        if not isinstance(data, Mapping) or not isinstance(data.get("value", []), list):
            raise ConnectorError(
                "Microsoft Graph Teams probe response must be a collection"
            )
        return {
            "reachable": True,
            "identity": identity,
            "probe_resource": probe_resource,
            "returned": len(data.get("value", [])),
            "reference": response.url,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        capability = action.capability
        if capability == "teams.chat.list":
            return self._list_chats(action)
        if capability == "teams.chat.message.list":
            return self._list_chat_messages(action)
        if capability == "teams.chat.message.read":
            return self._read_chat_message(action)
        if capability == "teams.team.list":
            return self._list_teams(action)
        if capability == "teams.channel.list":
            return self._list_channels(action)
        if capability == "teams.channel.message.list":
            return self._list_channel_messages(action)
        if capability == "teams.channel.message.read":
            return self._read_channel_message(action)
        if capability == "teams.channel.message.replies.list":
            return self._list_channel_message_replies(action)
        raise ConnectorError(f"unsupported Teams capability: {capability}")

    def _list_chats(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=25,
            maximum=min(self._config.max_items, 50),
        )
        include_members = boolean_parameter(
            action.parameters,
            "include_members",
            default=True,
        )
        include_last_message = boolean_parameter(
            action.parameters,
            "include_last_message",
            default=True,
        )
        expansions: list[str] = []
        if include_members:
            expansions.append("members")
        if include_last_message:
            expansions.append("lastMessagePreview")
        query: dict[str, Any] = {"$top": limit}
        if expansions:
            query["$expand"] = ",".join(expansions)
        chats, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"{root}/chats",
            query=query,
            limit=limit,
            normalizer=_normalize_chat,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-chats@1",
                "system": "teams",
                "identity": identity,
                "returned": len(chats),
                "members_may_be_truncated": include_members,
                "chats": chats,
                "retention": {
                    "evidence_type": (
                        "teams.chat_message.content"
                        if include_last_message
                        else "teams.chat.metadata"
                    ),
                    "content_kind": (
                        "communication_content"
                        if include_last_message
                        else "communication_metadata"
                    ),
                    "persistence_requires_explicit_output": include_last_message,
                },
                "source_urls": [
                    reference,
                    *[str(chat["web_url"]) for chat in chats if chat.get("web_url")],
                ],
            },
            connector_reference=reference,
        )

    def _list_chat_messages(self, action: AgentAction) -> RetrievedPayload:
        chat_id = action.target.resource_id
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=25,
            maximum=min(self._config.max_items, 50),
        )
        scan_limit = integer_parameter(
            action.parameters,
            "scan_limit",
            default=limit,
            maximum=min(self._config.max_items, 50),
        )
        scan_limit = max(limit, scan_limit)
        query_text = _bounded_local_query(
            string_parameter(action.parameters, "query"),
        )
        messages, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"chats/{quote_segment(chat_id)}/messages",
            query={
                "$top": scan_limit,
                "$orderby": "lastModifiedDateTime desc",
            },
            limit=scan_limit,
            normalizer=lambda item: _normalize_message(item, chat_id=chat_id),
        )
        filtered = _filter_messages(messages, query_text)[:limit]
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-chat-messages@1",
                "system": "teams",
                "chat_id": chat_id,
                "query": {
                    "free_text": query_text or None,
                    "mode": "bounded_local_filter" if query_text else None,
                    "scanned": len(messages),
                },
                "returned": len(filtered),
                "messages": filtered,
                "retention": {
                    "evidence_type": "teams.chat_message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [
                    reference,
                    *[
                        str(message["web_url"])
                        for message in filtered
                        if message.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _read_chat_message(self, action: AgentAction) -> RetrievedPayload:
        chat_id = string_parameter(action.parameters, "chat_id", required=True)
        message_id = action.target.resource_id
        data, response = self._client.request_json(
            "GET",
            (f"chats/{quote_segment(chat_id)}/messages/{quote_segment(message_id)}"),
        )
        if not isinstance(data, Mapping):
            raise ConnectorError(
                "Microsoft Graph chat message response must be an object"
            )
        message = _normalize_message(data, chat_id=chat_id)
        enforce_expected_version(
            action,
            message.get("etag") or message.get("updated_at"),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-chat-message@1",
                "system": "teams",
                "chat_id": chat_id,
                "message": message,
                "retention": {
                    "evidence_type": "teams.chat_message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [response.url, message.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _list_teams(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=self._config.max_items,
        )
        teams, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"{root}/joinedTeams",
            query=None,
            limit=limit,
            normalizer=_normalize_team,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-teams@1",
                "system": "teams",
                "identity": identity,
                "returned": len(teams),
                "teams": teams,
                "retention": {
                    "evidence_type": "teams.team.metadata",
                    "content_kind": "metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _list_channels(self, action: AgentAction) -> RetrievedPayload:
        team_id = action.target.resource_id
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=self._config.max_items,
        )
        channels, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"teams/{quote_segment(team_id)}/channels",
            query={
                "$select": (
                    "id,displayName,description,membershipType,createdDateTime,"
                    "isArchived,webUrl,tenantId"
                )
            },
            limit=limit,
            normalizer=lambda item: _normalize_channel(item, team_id=team_id),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-channels@1",
                "system": "teams",
                "team_id": team_id,
                "returned": len(channels),
                "channels": channels,
                "retention": {
                    "evidence_type": "teams.channel.metadata",
                    "content_kind": "metadata",
                },
                "source_urls": [
                    reference,
                    *[
                        str(channel["web_url"])
                        for channel in channels
                        if channel.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _list_channel_messages(self, action: AgentAction) -> RetrievedPayload:
        team_id = string_parameter(action.parameters, "team_id", required=True)
        channel_id = action.target.resource_id
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=20,
            maximum=min(self._config.max_items, 50),
        )
        scan_limit = integer_parameter(
            action.parameters,
            "scan_limit",
            default=limit,
            maximum=min(self._config.max_items, 50),
        )
        scan_limit = max(limit, scan_limit)
        include_replies = boolean_parameter(
            action.parameters,
            "include_replies",
            default=False,
        )
        query_text = _bounded_local_query(
            string_parameter(action.parameters, "query"),
        )
        query: dict[str, Any] = {"$top": scan_limit}
        if include_replies:
            query["$expand"] = "replies"
        messages, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=(
                f"teams/{quote_segment(team_id)}/channels/"
                f"{quote_segment(channel_id)}/messages"
            ),
            query=query,
            limit=scan_limit,
            normalizer=lambda item: _normalize_message(
                item,
                team_id=team_id,
                channel_id=channel_id,
                include_replies=include_replies,
            ),
        )
        filtered = _filter_messages(messages, query_text)[:limit]
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-channel-messages@1",
                "system": "teams",
                "team_id": team_id,
                "channel_id": channel_id,
                "query": {
                    "free_text": query_text or None,
                    "mode": "bounded_local_filter" if query_text else None,
                    "scanned": len(messages),
                },
                "returned": len(filtered),
                "messages": filtered,
                "retention": {
                    "evidence_type": "teams.channel_message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [
                    reference,
                    *[
                        str(message["web_url"])
                        for message in filtered
                        if message.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _read_channel_message(self, action: AgentAction) -> RetrievedPayload:
        team_id = string_parameter(action.parameters, "team_id", required=True)
        channel_id = string_parameter(action.parameters, "channel_id", required=True)
        message_id = action.target.resource_id
        data, response = self._client.request_json(
            "GET",
            (
                f"teams/{quote_segment(team_id)}/channels/"
                f"{quote_segment(channel_id)}/messages/{quote_segment(message_id)}"
            ),
        )
        if not isinstance(data, Mapping):
            raise ConnectorError(
                "Microsoft Graph channel message response must be an object"
            )
        message = _normalize_message(
            data,
            team_id=team_id,
            channel_id=channel_id,
        )
        enforce_expected_version(
            action,
            message.get("etag") or message.get("updated_at"),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-channel-message@1",
                "system": "teams",
                "team_id": team_id,
                "channel_id": channel_id,
                "message": message,
                "retention": {
                    "evidence_type": "teams.channel_message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [response.url, message.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _list_channel_message_replies(self, action: AgentAction) -> RetrievedPayload:
        team_id = string_parameter(action.parameters, "team_id", required=True)
        channel_id = string_parameter(action.parameters, "channel_id", required=True)
        message_id = action.target.resource_id
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=25,
            maximum=min(self._config.max_items, 50),
        )
        replies, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=(
                f"teams/{quote_segment(team_id)}/channels/"
                f"{quote_segment(channel_id)}/messages/"
                f"{quote_segment(message_id)}/replies"
            ),
            query={"$top": limit},
            limit=limit,
            normalizer=lambda item: _normalize_message(
                item,
                team_id=team_id,
                channel_id=channel_id,
            ),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/teams-channel-message-replies@1",
                "system": "teams",
                "team_id": team_id,
                "channel_id": channel_id,
                "parent_message_id": message_id,
                "returned": len(replies),
                "messages": replies,
                "retention": {
                    "evidence_type": "teams.channel_message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [
                    reference,
                    *[
                        str(reply["web_url"])
                        for reply in replies
                        if reply.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _root(self, action: AgentAction) -> tuple[str, str]:
        identity = string_parameter(action.parameters, "identity")
        return graph_user_root(self._config, identity or None)


def _normalize_chat(chat: Mapping[str, Any]) -> dict[str, Any]:
    members = chat.get("members")
    last_message = chat.get("lastMessagePreview")
    meeting = chat.get("onlineMeetingInfo")
    meeting = meeting if isinstance(meeting, Mapping) else {}
    return {
        "id": chat.get("id"),
        "topic": chat.get("topic"),
        "chat_type": chat.get("chatType"),
        "created_at": chat.get("createdDateTime"),
        "updated_at": chat.get("lastUpdatedDateTime"),
        "tenant_id": chat.get("tenantId"),
        "web_url": chat.get("webUrl"),
        "meeting_join_web_url": meeting.get("joinWebUrl"),
        "members": [
            _normalize_member(item) for item in members if isinstance(item, Mapping)
        ]
        if isinstance(members, list)
        else [],
        "last_message_preview": (
            _normalize_message(last_message, chat_id=str(chat.get("id") or ""))
            if isinstance(last_message, Mapping)
            else None
        ),
    }


def _normalize_member(member: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": member.get("id"),
        "display_name": member.get("displayName"),
        "user_id": member.get("userId"),
        "email": member.get("email"),
        "tenant_id": member.get("tenantId"),
        "roles": list(member.get("roles", []))
        if isinstance(member.get("roles"), list)
        else [],
    }


def _normalize_team(team: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": team.get("id"),
        "display_name": team.get("displayName"),
        "description": team.get("description"),
        "is_archived": team.get("isArchived"),
        "tenant_id": team.get("tenantId"),
        "web_url": team.get("webUrl"),
        "updated_at": team.get("lastUpdatedDateTime"),
    }


def _normalize_channel(
    channel: Mapping[str, Any],
    *,
    team_id: str,
) -> dict[str, Any]:
    return {
        "id": channel.get("id"),
        "team_id": team_id,
        "display_name": channel.get("displayName"),
        "description": channel.get("description"),
        "membership_type": channel.get("membershipType"),
        "created_at": channel.get("createdDateTime"),
        "updated_at": channel.get("lastModifiedDateTime"),
        "is_archived": channel.get("isArchived"),
        "tenant_id": channel.get("tenantId"),
        "web_url": channel.get("webUrl"),
    }


def _normalize_message(
    message: Mapping[str, Any],
    *,
    chat_id: str | None = None,
    team_id: str | None = None,
    channel_id: str | None = None,
    include_replies: bool = False,
) -> dict[str, Any]:
    body = message.get("body")
    body = body if isinstance(body, Mapping) else {}
    body_text = _body_text(body)
    channel_identity = message.get("channelIdentity")
    channel_identity = channel_identity if isinstance(channel_identity, Mapping) else {}
    effective_team_id = team_id or _optional_text(channel_identity.get("teamId"))
    effective_channel_id = channel_id or _optional_text(
        channel_identity.get("channelId")
    )
    replies = message.get("replies")
    normalized_replies = (
        [
            _normalize_message(
                reply,
                team_id=effective_team_id,
                channel_id=effective_channel_id,
            )
            for reply in replies
            if isinstance(reply, Mapping)
        ]
        if include_replies and isinstance(replies, list)
        else []
    )
    return {
        "id": message.get("id"),
        "etag": message.get("etag") or message.get("@odata.etag"),
        "reply_to_id": message.get("replyToId"),
        "chat_id": chat_id,
        "team_id": effective_team_id,
        "channel_id": effective_channel_id,
        "message_type": message.get("messageType"),
        "subject": message.get("subject"),
        "summary": message.get("summary"),
        "importance": message.get("importance"),
        "locale": message.get("locale"),
        "created_at": message.get("createdDateTime"),
        "updated_at": message.get("lastModifiedDateTime"),
        "deleted_at": message.get("deletedDateTime"),
        "from": _normalize_sender(message.get("from")),
        "body": body_text,
        "body_excerpt": excerpt(body_text, limit=500),
        "web_url": message.get("webUrl"),
        "attachments": _normalize_attachments(message.get("attachments")),
        "mentions": _normalize_mentions(message.get("mentions")),
        "reactions": _normalize_reactions(message.get("reactions")),
        "replies": normalized_replies,
    }


def _normalize_sender(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    for identity_type in ("user", "application", "device"):
        candidate = value.get(identity_type)
        if isinstance(candidate, Mapping):
            return {
                "identity_type": identity_type,
                "id": candidate.get("id"),
                "display_name": candidate.get("displayName"),
                "tenant_id": candidate.get("tenantId"),
                "user_identity_type": candidate.get("userIdentityType"),
            }
    return None


def _normalize_attachments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        {
            "id": item.get("id"),
            "name": item.get("name"),
            "content_type": item.get("contentType"),
            "content_url": _safe_reference_url(item.get("contentUrl")),
            "thumbnail_url": _safe_reference_url(item.get("thumbnailUrl")),
        }
        for item in value
        if isinstance(item, Mapping)
    ]


def _safe_reference_url(value: Any) -> str | None:
    """Return a query-free HTTPS reference suitable for retained evidence."""

    if not isinstance(value, str) or not value.strip():
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return parsed._replace(query="", fragment="").geturl()


def _normalize_mentions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        {
            "id": item.get("id"),
            "mention_text": item.get("mentionText"),
            "mentioned": _normalize_sender(item.get("mentioned")),
        }
        for item in value
        if isinstance(item, Mapping)
    ]


def _normalize_reactions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        {
            "reaction_type": item.get("reactionType"),
            "created_at": item.get("createdDateTime"),
            "user": _normalize_sender(item.get("user")),
        }
        for item in value
        if isinstance(item, Mapping)
    ]


def _body_text(body: Mapping[str, Any]) -> str:
    content = str(body.get("content") or "")
    content_type = str(body.get("contentType") or "").lower()
    return html_to_text(content) if content_type == "html" else content.strip()


def _filter_messages(
    messages: list[dict[str, Any]],
    query_text: str,
) -> list[dict[str, Any]]:
    if not query_text:
        return messages
    needle = query_text.casefold()
    matched: list[dict[str, Any]] = []
    for message in messages:
        sender = message.get("from")
        sender_name = (
            str(sender.get("display_name") or "") if isinstance(sender, Mapping) else ""
        )
        haystack = "\n".join(
            (
                str(message.get("subject") or ""),
                str(message.get("summary") or ""),
                str(message.get("body") or ""),
                sender_name,
            )
        ).casefold()
        if needle in haystack:
            matched.append(message)
    return matched


def _bounded_local_query(value: str) -> str:
    rendered = " ".join(value.split())
    if len(rendered) > 300:
        raise ConnectorError("Teams local message query exceeds 300 characters")
    return rendered


def _optional_text(value: Any) -> str | None:
    return str(value) if value not in {None, ""} else None
