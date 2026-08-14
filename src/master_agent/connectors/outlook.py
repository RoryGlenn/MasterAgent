"""Read-only Outlook mail connector through Microsoft Graph."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.microsoft_graph import (
    graph_client,
    graph_paged_values,
    graph_user_root,
)
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport
from master_agent.models import AgentAction
from master_agent.text import excerpt, html_to_text


_IMMUTABLE_ID_PREFER = 'IdType="ImmutableId"'
_TEXT_AND_IMMUTABLE_PREFER = (
    'outlook.body-content-type="text", IdType="ImmutableId"'
)


class OutlookConnector(ReadOnlyConnector):
    """Search and read Outlook mailbox content without write permissions."""

    _CAPABILITIES = frozenset(
        {
            "outlook.mail_folder.list",
            "outlook.message.search",
            "outlook.message.read",
            "outlook.attachment.list",
            "outlook.attachment.text.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="outlook", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = graph_client(config, transport=transport)

    def probe(self) -> Mapping[str, Any]:
        """Verify mailbox access through bounded Inbox metadata."""

        root, identity = graph_user_root(self._config, None)
        data, response = self._client.request_json(
            "GET",
            f"{root}/mailFolders/inbox",
            query={
                "$select": "id,displayName,totalItemCount,unreadItemCount,childFolderCount"
            },
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph mail folder response must be an object")
        folder = _normalize_mail_folder(data)
        return {
            "reachable": True,
            "identity": identity,
            "folder_id": folder.get("id"),
            "display_name": folder.get("display_name"),
            "total_item_count": folder.get("total_item_count"),
            "unread_item_count": folder.get("unread_item_count"),
            "reference": response.url,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        capability = action.capability
        if capability == "outlook.mail_folder.list":
            return self._list_mail_folders(action)
        if capability == "outlook.message.search":
            return self._search_messages(action)
        if capability == "outlook.message.read":
            return self._read_message(action)
        if capability == "outlook.attachment.list":
            return self._list_attachments(action)
        if capability == "outlook.attachment.text.read":
            return self._read_text_attachment(action)
        raise ConnectorError(f"unsupported Outlook capability: {capability}")

    def _list_mail_folders(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        parent_folder_id = string_parameter(action.parameters, "parent_folder_id")
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=50,
            maximum=self._config.max_items,
        )
        path = (
            f"{root}/mailFolders/{quote_segment(parent_folder_id)}/childFolders"
            if parent_folder_id
            else f"{root}/mailFolders"
        )
        folders, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=path,
            query={
                "$select": (
                    "id,displayName,parentFolderId,childFolderCount,"
                    "totalItemCount,unreadItemCount,isHidden"
                ),
                "$top": min(limit, 100),
                "includeHiddenFolders": "false",
            },
            limit=limit,
            normalizer=_normalize_mail_folder,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/outlook-mail-folders@1",
                "system": "outlook",
                "identity": identity,
                "parent_folder_id": parent_folder_id or None,
                "returned": len(folders),
                "folders": folders,
                "retention": {
                    "evidence_type": "outlook.mail_folder.metadata",
                    "content_kind": "metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _search_messages(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        query_text = _bounded_query(
            string_parameter(action.parameters, "query"),
            maximum=500,
        )
        folder_id = string_parameter(action.parameters, "folder_id")
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=25,
            maximum=min(self._config.max_items, 1000),
        )
        path = (
            f"{root}/mailFolders/{quote_segment(folder_id)}/messages"
            if folder_id
            else f"{root}/messages"
        )
        query: dict[str, Any] = {
            "$select": (
                "id,conversationId,internetMessageId,subject,from,sender,"
                "toRecipients,ccRecipients,receivedDateTime,sentDateTime,"
                "lastModifiedDateTime,isRead,hasAttachments,importance,"
                "bodyPreview,webLink"
            ),
            "$top": min(limit, 100),
        }
        if query_text:
            query["$search"] = f'"{_escape_search_phrase(query_text)}"'
        else:
            query["$orderby"] = "receivedDateTime desc"

        messages, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=path,
            query=query,
            limit=limit,
            normalizer=_normalize_message_summary,
            headers={"Prefer": _TEXT_AND_IMMUTABLE_PREFER},
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/outlook-messages@1",
                "system": "outlook",
                "identity": identity,
                "folder_id": folder_id or None,
                "query": {"free_text": query_text or None},
                "returned": len(messages),
                "messages": messages,
                "retention": {
                    "evidence_type": "outlook.message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [
                    reference,
                    *[
                        str(message["web_url"])
                        for message in messages
                        if message.get("web_url")
                    ],
                ],
            },
            connector_reference=reference,
        )

    def _read_message(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        message_id = quote_segment(action.target.resource_id)
        data, response = self._client.request_json(
            "GET",
            f"{root}/messages/{message_id}",
            query={
                "$select": (
                    "id,conversationId,internetMessageId,subject,from,sender,"
                    "toRecipients,ccRecipients,bccRecipients,replyTo,receivedDateTime,"
                    "sentDateTime,lastModifiedDateTime,isRead,hasAttachments,importance,"
                    "bodyPreview,body,uniqueBody,webLink"
                )
            },
            headers={"Prefer": _TEXT_AND_IMMUTABLE_PREFER},
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph message response must be an object")
        message = _normalize_message(data, include_body=True)
        enforce_expected_version(
            action,
            message.get("etag") or message.get("updated_at"),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/outlook-message@1",
                "system": "outlook",
                "identity": identity,
                "message": message,
                "retention": {
                    "evidence_type": "outlook.message.content",
                    "content_kind": "communication_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [response.url, message.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _list_attachments(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        message_id = string_parameter(
            action.parameters,
            "message_id",
            default=action.target.resource_id,
            required=True,
        )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=50,
            maximum=self._config.max_items,
        )
        attachments, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"{root}/messages/{quote_segment(message_id)}/attachments",
            query={"$top": min(limit, 100)},
            limit=limit,
            normalizer=lambda item: _normalize_attachment(item, message_id=message_id),
            headers={"Prefer": _IMMUTABLE_ID_PREFER},
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/outlook-attachments@1",
                "system": "outlook",
                "identity": identity,
                "message_id": message_id,
                "returned": len(attachments),
                "attachments": attachments,
                "retention": {
                    "evidence_type": "outlook.attachment.metadata",
                    "content_kind": "attachment_metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _read_text_attachment(self, action: AgentAction) -> RetrievedPayload:
        root, identity = self._root(action)
        message_id = string_parameter(
            action.parameters,
            "message_id",
            required=True,
        )
        attachment_id = quote_segment(action.target.resource_id)
        max_bytes = integer_parameter(
            action.parameters,
            "max_bytes",
            default=int(
                self._config.extra.get(
                    "max_mail_attachment_bytes",
                    self._config.extra.get("max_attachment_text_bytes", 250_000),
                )
            ),
            maximum=min(self._config.max_response_bytes, 2_000_000),
        )
        attachment_path = (
            f"{root}/messages/{quote_segment(message_id)}/attachments/"
            f"{attachment_id}"
        )
        data, metadata_response = self._client.request_json(
            "GET",
            attachment_path,
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph attachment response must be an object")
        attachment = _normalize_attachment(data, message_id=message_id)
        odata_type = str(data.get("@odata.type", ""))
        if odata_type and not odata_type.endswith("fileAttachment"):
            raise ConnectorError("only Outlook file attachments support text extraction")
        if attachment.get("is_inline"):
            raise ConnectorError(
                "inline Outlook attachments are not eligible for text extraction"
            )

        name = str(attachment.get("name", ""))
        extension = PurePosixPath(name).suffix.lower()
        allowed_extensions = tuple(
            str(item).lower()
            for item in self._config.extra.get(
                "allowed_mail_attachment_extensions",
                self._config.extra.get(
                    "allowed_attachment_text_extensions",
                    [".txt", ".md", ".json", ".csv", ".yaml", ".yml", ".log"],
                ),
            )
        )
        if extension not in allowed_extensions:
            raise ConnectorError(
                f"Outlook attachment text read rejected unsupported extension: {extension}"
            )
        content_type = str(attachment.get("content_type") or "").lower()
        allowed_mime_types = tuple(
            str(item).lower()
            for item in self._config.extra.get(
                "allowed_mail_attachment_mime_types",
                [
                    "text/plain",
                    "text/markdown",
                    "text/csv",
                    "application/json",
                    "application/yaml",
                    "application/x-yaml",
                    "text/yaml",
                ],
            )
        )
        if content_type and content_type not in allowed_mime_types:
            raise ConnectorError(
                "Outlook attachment text read rejected unsupported content type: "
                f"{content_type}"
            )
        declared_size = attachment.get("size")
        if isinstance(declared_size, int) and declared_size > max_bytes:
            raise ConnectorError(
                f"Outlook attachment size {declared_size} exceeds text-read limit {max_bytes}"
            )

        content_response = self._client.request_bytes(
            "GET",
            f"{attachment_path}/$value",
            max_response_bytes=max_bytes,
        )
        try:
            content = content_response.body.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ConnectorError("Outlook text attachment is not valid UTF-8") from error
        enforce_expected_version(action, attachment.get("updated_at"))
        return RetrievedPayload(
            data={
                "schema": "master-agent/outlook-text-attachment@1",
                "system": "outlook",
                "identity": identity,
                "message_id": message_id,
                "attachment": attachment,
                "content": content,
                "content_excerpt": excerpt(content, limit=1000),
                "retention": {
                    "evidence_type": "outlook.attachment.content",
                    "content_kind": "attachment_content",
                    "persistence_requires_explicit_output": True,
                },
                "source_urls": [metadata_response.url, content_response.url],
            },
            connector_reference=metadata_response.url,
        )

    def _root(self, action: AgentAction) -> tuple[str, str]:
        identity = string_parameter(action.parameters, "identity")
        return graph_user_root(self._config, identity or None)


def _normalize_mail_folder(folder: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": folder.get("id"),
        "display_name": folder.get("displayName"),
        "parent_folder_id": folder.get("parentFolderId"),
        "child_folder_count": folder.get("childFolderCount"),
        "total_item_count": folder.get("totalItemCount"),
        "unread_item_count": folder.get("unreadItemCount"),
        "is_hidden": folder.get("isHidden"),
    }


def _normalize_message_summary(message: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_message(message, include_body=False)


def _normalize_message(
    message: Mapping[str, Any],
    *,
    include_body: bool,
) -> dict[str, Any]:
    body = message.get("body")
    body = body if isinstance(body, Mapping) else {}
    unique_body = message.get("uniqueBody")
    unique_body = unique_body if isinstance(unique_body, Mapping) else {}
    body_content = _body_text(body)
    unique_content = _body_text(unique_body)
    preview = str(message.get("bodyPreview") or "")
    result = {
        "id": message.get("id"),
        "etag": message.get("@odata.etag"),
        "conversation_id": message.get("conversationId"),
        "internet_message_id": message.get("internetMessageId"),
        "subject": message.get("subject"),
        "from": _normalize_recipient(message.get("from")),
        "sender": _normalize_recipient(message.get("sender")),
        "to": _normalize_recipients(message.get("toRecipients")),
        "cc": _normalize_recipients(message.get("ccRecipients")),
        "bcc": _normalize_recipients(message.get("bccRecipients")),
        "reply_to": _normalize_recipients(message.get("replyTo")),
        "received_at": message.get("receivedDateTime"),
        "sent_at": message.get("sentDateTime"),
        "updated_at": message.get("lastModifiedDateTime"),
        "is_read": message.get("isRead"),
        "has_attachments": message.get("hasAttachments"),
        "importance": message.get("importance"),
        "body_preview": preview,
        "body_excerpt": excerpt(body_content or preview, limit=500),
        "web_url": message.get("webLink"),
    }
    if include_body:
        result["body"] = body_content
        result["unique_body"] = unique_content
    return result


def _normalize_recipient(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    address = value.get("emailAddress")
    if not isinstance(address, Mapping):
        return None
    return {
        "name": address.get("name"),
        "address": address.get("address"),
    }


def _normalize_recipients(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in (_normalize_recipient(candidate) for candidate in value)
        if item is not None
    ]


def _body_text(body: Mapping[str, Any]) -> str:
    content = str(body.get("content") or "")
    content_type = str(body.get("contentType") or "").lower()
    return html_to_text(content) if content_type == "html" else content.strip()


def _normalize_attachment(
    attachment: Mapping[str, Any],
    *,
    message_id: str,
) -> dict[str, Any]:
    return {
        "id": attachment.get("id"),
        "message_id": message_id,
        "odata_type": attachment.get("@odata.type"),
        "name": attachment.get("name"),
        "content_type": attachment.get("contentType"),
        "size": attachment.get("size"),
        "is_inline": attachment.get("isInline"),
        "content_id": attachment.get("contentId"),
        "updated_at": attachment.get("lastModifiedDateTime"),
    }


def _bounded_query(value: str, *, maximum: int) -> str:
    if any(ord(character) < 32 and character not in {"\t", "\n", "\r"} for character in value):
        raise ConnectorError("Outlook query contains unsupported control characters")
    rendered = " ".join(value.split())
    if len(rendered) > maximum:
        raise ConnectorError(f"Outlook query exceeds {maximum} characters")
    return rendered


def _escape_search_phrase(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
