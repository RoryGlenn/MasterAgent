"""Approval-bound Outlook and Microsoft Teams communication connectors."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.microsoft_graph import graph_client, graph_user_root
from master_agent.connectors.utils import quote_segment
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport
from master_agent.models import (
    ActionState,
    AgentAction,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)


class OutlookSendConnector:
    """Create, verify, and send an Outlook draft through Microsoft Graph."""

    _CAPABILITIES = frozenset({"outlook.email.send"})

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        self._config = config
        self._client = graph_client(
            config,
            transport=transport,
            allowed_methods=frozenset({"GET", "POST"}),
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "outlook"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Send exactly the recipients, subject, and body in the approved plan."""

        self._validate(action)
        identity = str(action.parameters.get("identity", action.target.resource_id)).strip()
        root, normalized_identity = graph_user_root(self._config, identity or None)
        payload = _mail_payload(action.parameters)
        approved = _canonical_mail(payload)
        approved_digest = _digest(approved)

        draft_data, draft_response = self._client.request_json(
            "POST",
            f"{root}/messages",
            json_body=payload,
            safe_to_retry=False,
        )
        if not isinstance(draft_data, Mapping) or not draft_data.get("id"):
            raise ConnectorError("Outlook draft response omitted a message ID")
        draft_id = str(draft_data["id"])
        observed = self._read_draft(root, draft_id)
        observed_digest = _digest(_canonical_mail(observed))
        if observed_digest != approved_digest:
            raise ConnectorError(
                "Outlook provider draft did not match the approval-bound content"
            )

        send_response = self._client.request_bytes(
            "POST",
            f"{root}/messages/{quote_segment(draft_id)}/send",
            body=b"",
            content_type="application/json",
            safe_to_retry=False,
        )
        after = {
            "identity": normalized_identity,
            "draft_id": draft_id,
            "approved_digest": approved_digest,
            "provider_draft_digest": observed_digest,
            "preflight_verified": True,
            "provider_accepted": send_response.status == 202,
            "provider_status": send_response.status,
            "recipients": approved["to"] + approved["cc"] + approved["bcc"],
            "subject": approved["subject"],
            "content_type": approved["content_type"],
            "non_reversible": True,
            "correction_capability": "outlook.email.draft",
        }
        self._last[action.idempotency_key] = dict(after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={"draft_id": draft_id, "draft_reference": draft_response.url},
            after=after,
            connector_reference=send_response.url,
            message="Outlook accepted the approval-bound message for sending",
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Communication delivery has no durable resource read by target ID."""

        return None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify exact preflight content and provider acceptance."""

        after = result.after or {}
        expected = _digest(_canonical_mail(_mail_payload(action.parameters)))
        verified = bool(
            after.get("preflight_verified")
            and after.get("provider_accepted")
            and after.get("approved_digest") == expected
            and after.get("provider_draft_digest") == expected
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed={
                "approved_digest": after.get("approved_digest"),
                "provider_draft_digest": after.get("provider_draft_digest"),
                "provider_status": after.get("provider_status"),
            },
            message=(
                "verified exact Outlook draft content before provider acceptance"
                if verified
                else "Outlook send preflight or provider acceptance failed"
            ),
        )

    def _read_draft(self, root: str, message_id: str) -> dict[str, Any]:
        data, _ = self._client.request_json(
            "GET",
            f"{root}/messages/{quote_segment(message_id)}",
            query={
                "$select": "subject,body,toRecipients,ccRecipients,bccRecipients"
            },
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Outlook draft read response must be an object")
        body = data.get("body") if isinstance(data.get("body"), Mapping) else {}
        return {
            "subject": str(data.get("subject", "")),
            "body": {
                "contentType": str(body.get("contentType", "Text")),
                "content": str(body.get("content", "")),
            },
            "toRecipients": data.get("toRecipients", []),
            "ccRecipients": data.get("ccRecipients", []),
            "bccRecipients": data.get("bccRecipients", []),
        }

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system or action.capability not in self.capabilities:
            raise ConnectorError("unsupported Outlook communication action")
        if action.risk is not RiskLevel.EXTERNAL_COMMUNICATION:
            raise ConnectorError("Outlook send must use external_communication risk")
        if not action.requires_approval:
            raise ConnectorError("Outlook send must be explicitly approval-bound")
        mode = str(self._config.extra.get("identity_mode", "delegated")).lower()
        if mode != "delegated" and self._config.extra.get(
            "allow_application_mail_send",
            False,
        ) is not True:
            raise ConnectorError(
                "application-mode Outlook sending is disabled by connector policy"
            )


class TeamsSendConnector:
    """Post to an existing Teams chat/channel and verify returned content."""

    _CAPABILITIES = frozenset(
        {
            "teams.chat.message.send",
            "teams.channel.message.send",
            "teams.channel.message.reply",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        self._config = config
        self._client = graph_client(
            config,
            transport=transport,
            allowed_methods=frozenset({"GET", "POST"}),
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "teams"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Post exactly one approval-bound message to an existing destination."""

        self._validate(action)
        body_text = _required(action.parameters, "body")
        content_type = str(action.parameters.get("content_type", "text")).lower()
        if content_type not in {"text", "html"}:
            raise ConnectorError("Teams content_type must be text or html")
        path = self._path(action)
        payload = {"body": {"contentType": content_type, "content": body_text}}
        approved_digest = _digest(payload)
        data, response = self._client.request_json(
            "POST",
            path,
            json_body=payload,
            safe_to_retry=False,
        )
        if not isinstance(data, Mapping) or not data.get("id"):
            raise ConnectorError("Teams message response omitted a message ID")
        message_id = str(data["id"])
        read_path = self._read_path(action, message_id)
        observed, read_response = self._client.request_json("GET", read_path)
        if not isinstance(observed, Mapping):
            raise ConnectorError("Teams message read response must be an object")
        observed_body = (
            observed.get("body")
            if isinstance(observed.get("body"), Mapping)
            else {}
        )
        provider_payload = {
            "body": {
                "contentType": str(observed_body.get("contentType", "")).lower(),
                "content": str(observed_body.get("content", "")),
            }
        }
        provider_digest = _digest(provider_payload)
        after = {
            "message_id": message_id,
            "approved_digest": approved_digest,
            "provider_digest": provider_digest,
            "provider_status": response.status,
            "provider_accepted": response.status == 201,
            "body": provider_payload["body"],
            "reference": read_response.url,
            "non_reversible": True,
            "correction_capability": "teams.message.draft",
        }
        self._last[message_id] = dict(after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=after,
            connector_reference=response.url,
            message="Teams posted the approval-bound message",
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return the normalized message from the latest send operation."""

        value = self._last.get(resource.resource_id)
        return dict(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify returned Teams message content matches the immutable action."""

        after = result.after or {}
        expected = _digest(
            {
                "body": {
                    "contentType": str(
                        action.parameters.get("content_type", "text")
                    ).lower(),
                    "content": _required(action.parameters, "body"),
                }
            }
        )
        verified = bool(
            after.get("provider_accepted")
            and after.get("approved_digest") == expected
            and after.get("provider_digest") == expected
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=after,
            message=(
                "verified Teams message content by provider re-read"
                if verified
                else "Teams message content did not match the approved action"
            ),
        )

    def _path(self, action: AgentAction) -> str:
        parameters = action.parameters
        if action.capability == "teams.chat.message.send":
            chat_id = _required(parameters, "chat_id")
            return f"chats/{quote_segment(chat_id)}/messages"
        team_id = _required(parameters, "team_id")
        channel_id = _required(parameters, "channel_id")
        root = (
            f"teams/{quote_segment(team_id)}/channels/"
            f"{quote_segment(channel_id)}/messages"
        )
        if action.capability == "teams.channel.message.reply":
            parent_id = _required(parameters, "parent_message_id")
            return f"{root}/{quote_segment(parent_id)}/replies"
        return root

    def _read_path(self, action: AgentAction, message_id: str) -> str:
        parameters = action.parameters
        if action.capability == "teams.chat.message.send":
            chat_id = _required(parameters, "chat_id")
            return (
                f"chats/{quote_segment(chat_id)}/messages/"
                f"{quote_segment(message_id)}"
            )
        team_id = _required(parameters, "team_id")
        channel_id = _required(parameters, "channel_id")
        root = (
            f"teams/{quote_segment(team_id)}/channels/"
            f"{quote_segment(channel_id)}/messages"
        )
        if action.capability == "teams.channel.message.reply":
            parent_id = _required(parameters, "parent_message_id")
            return (
                f"{root}/{quote_segment(parent_id)}/replies/"
                f"{quote_segment(message_id)}"
            )
        return f"{root}/{quote_segment(message_id)}"

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system or action.capability not in self.capabilities:
            raise ConnectorError("unsupported Teams communication action")
        if action.risk is not RiskLevel.EXTERNAL_COMMUNICATION:
            raise ConnectorError("Teams send must use external_communication risk")
        if not action.requires_approval:
            raise ConnectorError("Teams send must be explicitly approval-bound")
        mode = str(self._config.extra.get("identity_mode", "delegated")).lower()
        if mode != "delegated":
            raise ConnectorError(
                "Microsoft Graph Teams message sending requires delegated identity; "
                "bot identity must use a separate Teams bot connector"
            )


def _mail_payload(parameters: Mapping[str, Any]) -> dict[str, Any]:
    content_type = str(parameters.get("content_type", "Text")).strip().title()
    if content_type not in {"Text", "Html"}:
        raise ConnectorError("Outlook content_type must be Text or Html")
    return {
        "subject": _required(parameters, "subject"),
        "body": {
            "contentType": content_type,
            "content": _required(parameters, "body"),
        },
        "toRecipients": _recipients(parameters.get("to"), required=True),
        "ccRecipients": _recipients(parameters.get("cc")),
        "bccRecipients": _recipients(parameters.get("bcc")),
    }


def _canonical_mail(payload: Mapping[str, Any]) -> dict[str, Any]:
    body = payload.get("body") if isinstance(payload.get("body"), Mapping) else {}
    return {
        "subject": str(payload.get("subject", "")),
        "body": str(body.get("content", "")),
        "content_type": str(body.get("contentType", "Text")).title(),
        "to": _recipient_addresses(payload.get("toRecipients")),
        "cc": _recipient_addresses(payload.get("ccRecipients")),
        "bcc": _recipient_addresses(payload.get("bccRecipients")),
    }


def _recipients(value: Any, *, required: bool = False) -> list[dict[str, Any]]:
    if value is None:
        values: list[str] = []
    elif isinstance(value, str):
        values = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, list):
        values = [str(part).strip() for part in value if str(part).strip()]
    else:
        raise ConnectorError("recipient fields must be strings or lists")
    if required and not values:
        raise ConnectorError("at least one primary recipient is required")
    for address in values:
        if "@" not in address or any(character.isspace() for character in address):
            raise ConnectorError("recipient address is invalid")
    return [{"emailAddress": {"address": address}} for address in values]


def _recipient_addresses(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    addresses: list[str] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        email = item.get("emailAddress")
        if isinstance(email, Mapping) and email.get("address"):
            addresses.append(str(email["address"]).lower())
    return sorted(addresses)


def _required(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip()
    if not value:
        raise ConnectorError(f"missing required parameter: {key}")
    return value


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
