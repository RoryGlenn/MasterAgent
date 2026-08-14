"""Delegated Microsoft OneNote page create and update capabilities."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

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
from master_agent.errors import (
    ConnectorError,
    ResourceNotFoundError,
    VersionConflictError,
)
from master_agent.http import HttpTransport
from master_agent.models import (
    ActionState,
    AgentAction,
    CompensationDescriptor,
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)


class OneNoteReadConnector(ReadOnlyConnector):
    """Read delegated OneNote notebooks, sections, and pages through Graph."""

    _CAPABILITIES = frozenset(
        {
            "onenote.notebook.list",
            "onenote.section.list",
            "onenote.page.list",
            "onenote.page.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        mode = str(config.extra.get("identity_mode", "delegated")).lower()
        if mode != "delegated":
            raise ConnectorError(
                "OneNote Graph operations require delegated identity mode"
            )
        super().__init__(system="onenote", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = graph_client(config, transport=transport)

    def probe(self) -> Mapping[str, Any]:
        """Verify delegated OneNote access without retaining page content."""

        root, identity = graph_user_root(self._config, None)
        data, response = self._client.request_json(
            "GET",
            f"{root}/onenote/notebooks",
            query={"$top": 1, "$select": "id,displayName,lastModifiedDateTime"},
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("OneNote notebook response must be an object")
        values = data.get("value", [])
        return {
            "reachable": True,
            "identity": identity,
            "notebook_count_in_probe": len(values) if isinstance(values, list) else 0,
            "reference": response.url,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        identity = string_parameter(action.parameters, "identity") or None
        root, normalized_identity = graph_user_root(self._config, identity)
        capability = action.capability
        if capability == "onenote.notebook.list":
            return self._list_collection(
                action,
                root=root,
                identity=normalized_identity,
                kind="notebooks",
                schema="master-agent/onenote-notebooks@1",
                normalizer=_normalize_notebook,
            )
        if capability == "onenote.section.list":
            return self._list_collection(
                action,
                root=root,
                identity=normalized_identity,
                kind="sections",
                schema="master-agent/onenote-sections@1",
                normalizer=_normalize_section,
            )
        if capability == "onenote.page.list":
            return self._list_pages(action, root, normalized_identity)
        if capability == "onenote.page.read":
            return self._read_page(action, root, normalized_identity)
        raise ConnectorError(f"unsupported OneNote read capability: {capability}")

    def _list_collection(
        self,
        action: AgentAction,
        *,
        root: str,
        identity: str,
        kind: str,
        schema: str,
        normalizer: Any,
    ) -> RetrievedPayload:
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=50,
            maximum=min(self._config.max_items, 100),
        )
        values, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"{root}/onenote/{kind}",
            query={"$top": min(limit, 100)},
            limit=limit,
            normalizer=normalizer,
        )
        return RetrievedPayload(
            data={
                "schema": schema,
                "system": "onenote",
                "identity": identity,
                "returned": len(values),
                kind: values,
                "retention": {
                    "evidence_type": f"onenote.{kind}.metadata",
                    "content_kind": "metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _list_pages(
        self,
        action: AgentAction,
        root: str,
        identity: str,
    ) -> RetrievedPayload:
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=50,
            maximum=min(self._config.max_items, 100),
        )
        query_text = string_parameter(action.parameters, "query").casefold()
        pages, reference = graph_paged_values(
            self._client,
            config=self._config,
            path=f"{root}/onenote/pages",
            query={
                "$top": min(limit, 100),
                "$select": (
                    "id,title,createdDateTime,lastModifiedDateTime,links,parentSection"
                ),
                "$orderby": "lastModifiedDateTime desc",
            },
            limit=min(self._config.max_items, max(limit, 100 if query_text else limit)),
            normalizer=_normalize_page,
        )
        if query_text:
            pages = [
                page
                for page in pages
                if query_text in str(page.get("title", "")).casefold()
            ][:limit]
        else:
            pages = pages[:limit]
        return RetrievedPayload(
            data={
                "schema": "master-agent/onenote-pages@1",
                "system": "onenote",
                "identity": identity,
                "query": query_text or None,
                "returned": len(pages),
                "pages": pages,
                "retention": {
                    "evidence_type": "onenote.page.metadata",
                    "content_kind": "metadata",
                },
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _read_page(
        self,
        action: AgentAction,
        root: str,
        identity: str,
    ) -> RetrievedPayload:
        page_id = quote_segment(action.target.resource_id)
        metadata, response = self._client.request_json(
            "GET",
            f"{root}/onenote/pages/{page_id}",
            query={
                "$select": (
                    "id,title,createdDateTime,lastModifiedDateTime,links,parentSection"
                )
            },
        )
        if not isinstance(metadata, Mapping):
            raise ConnectorError("OneNote page metadata must be an object")
        enforce_expected_version(action, metadata.get("lastModifiedDateTime"))
        content_response = self._client.request_bytes(
            "GET",
            f"{root}/onenote/pages/{page_id}/content",
            query={"includeIDs": "true"},
            max_response_bytes=min(
                self._config.max_response_bytes,
                int(self._config.extra.get("max_onenote_html_bytes", 1_000_000)),
            ),
        )
        content_html = content_response.text()
        page = _normalize_page(metadata)
        page["content_html"] = content_html
        page["content_sha256"] = hashlib.sha256(
            content_html.encode("utf-8")
        ).hexdigest()
        return RetrievedPayload(
            data={
                "schema": "master-agent/onenote-page@1",
                "system": "onenote",
                "identity": identity,
                "page": page,
                "retention": {
                    "evidence_type": "onenote.page.content",
                    "content_kind": "untrusted_document_content",
                },
                "source_urls": [response.url, content_response.url],
            },
            connector_reference=response.url,
        )


class OneNoteWriteConnector:
    """Create or patch OneNote pages using delegated Graph identity."""

    _CAPABILITIES = frozenset({"onenote.page.create", "onenote.page.update"})

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        mode = str(config.extra.get("identity_mode", "delegated")).lower()
        if mode != "delegated":
            raise ConnectorError(
                "OneNote write capabilities require delegated identity mode"
            )
        self._config = config
        self._client = graph_client(
            config,
            transport=transport,
            allowed_methods=frozenset({"GET", "POST", "PATCH", "DELETE"}),
        )
        self._last: dict[str, dict[str, Any]] = {}
        self._previous_html: dict[str, str] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "onenote"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Create or patch one OneNote page."""

        self._validate(action)
        identity = str(action.parameters.get("identity", "me"))
        root, _ = graph_user_root(self._config, identity)
        if action.capability == "onenote.page.create":
            section_id = string_parameter(
                action.parameters, "section_id", required=True
            )
            html = string_parameter(action.parameters, "html", required=True)
            data, response = self._client.request_json(
                "POST",
                f"{root}/onenote/sections/{quote_segment(section_id)}/pages",
                body=html.encode("utf-8"),
                content_type="text/html",
            )
            if not isinstance(data, Mapping) or not data.get("id"):
                raise ConnectorError("OneNote create response omitted a page ID")
            page_id = str(data["id"])
            observed = self._read_page(root, page_id, include_content=True)
            after = {**observed, "created": True}
            self._last[page_id] = deepcopy(after)
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before=None,
                after=after,
                connector_reference=str(observed.get("web_url") or response.url),
                message="OneNote page created",
                compensation=CompensationDescriptor(
                    kind="delete_created_page",
                    mode=CompensationMode.IN_PROCESS,
                    target_resource_id=page_id,
                    reason=(
                        "created-page deletion is available only through the "
                        "originating connector run"
                    ),
                ).to_dict(),
            )

        page_id = action.target.resource_id
        before = self._read_page(root, page_id, include_content=True)
        enforce_expected_version(action, before.get("version"))
        commands = action.parameters.get("commands")
        if (
            not isinstance(commands, Sequence)
            or isinstance(commands, (str, bytes))
            or not commands
        ):
            raise ConnectorError("OneNote update commands must be a non-empty list")
        normalized: list[dict[str, str]] = []
        for item in commands:
            if not isinstance(item, Mapping):
                raise ConnectorError("each OneNote update command must be an object")
            target = string_parameter(item, "target", required=True)
            operation = string_parameter(item, "action", required=True)
            if operation not in {"append", "prepend", "replace", "insert", "delete"}:
                raise ConnectorError("unsupported OneNote patch action")
            command = {"target": target, "action": operation}
            if operation != "delete":
                command["content"] = string_parameter(item, "content", required=True)
            normalized.append(command)
        previous_html = str(before.get("content_html", ""))
        self._previous_html[str(action.action_id)] = previous_html
        self._client.request_bytes(
            "PATCH",
            f"{root}/onenote/pages/{quote_segment(page_id)}/content",
            json_body=normalized,
            safe_to_retry=False,
        )
        observed = self._read_page(root, page_id, include_content=True)
        self._last[page_id] = deepcopy(observed)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={
                key: value for key, value in before.items() if key != "content_html"
            },
            after={
                **observed,
                "expected_fragments": [
                    item.get("content", "")
                    for item in normalized
                    if item.get("content")
                ],
            },
            connector_reference=str(observed.get("web_url") or page_id),
            message="OneNote page update accepted",
            compensation=CompensationDescriptor(
                kind="restore_previous_page_html",
                mode=CompensationMode.IN_PROCESS,
                reason=(
                    "prior page HTML is held only by the originating connector "
                    "and is not persisted in the run report"
                ),
                parameters={
                    "available": bool(previous_html),
                    "previous_content_sha256": hashlib.sha256(
                        previous_html.encode("utf-8")
                    ).hexdigest(),
                },
            ).to_dict(),
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return last normalized state."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify created page identity or patched content fragments."""

        identity = str(action.parameters.get("identity", "me"))
        root, _ = graph_user_root(self._config, identity)
        after = result.after or {}
        page_id = str(after.get("id", action.target.resource_id))
        observed = self._read_page(root, page_id, include_content=True)
        if action.capability == "onenote.page.create":
            verified = observed.get("id") == page_id
        else:
            content = str(observed.get("content_html", ""))
            fragments = after.get("expected_fragments", [])
            verified = isinstance(fragments, list) and all(
                str(fragment) in content for fragment in fragments
            )
        return VerificationResult(
            action_id=action.action_id,
            verified=bool(verified),
            observed={
                key: value for key, value in observed.items() if key != "content_html"
            },
            message=(
                "verified OneNote page by independent re-read"
                if verified
                else "OneNote page content did not match the approved change"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Delete a created page or restore retained pre-update HTML."""

        identity = str(action.parameters.get("identity", "me"))
        root, _ = graph_user_root(self._config, identity)
        if action.capability == "onenote.page.create":
            page_id = str((result.after or {}).get("id", "")).strip()
            if not page_id:
                raise ConnectorError("OneNote create rollback has no page ID")
            current = self._read_page(root, page_id, include_content=False)
            if current.get("version") != (result.after or {}).get("version"):
                raise VersionConflictError(
                    "OneNote page changed after creation; deletion is refused"
                )
            response = self._client.request_bytes(
                "DELETE",
                f"{root}/onenote/pages/{quote_segment(page_id)}",
                safe_to_retry=False,
            )
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before=result.after,
                after={"id": page_id, "deleted": True},
                connector_reference=response.url,
                message="deleted OneNote page created by rolled-back workflow",
            )
        if action.capability != "onenote.page.update":
            raise ConnectorError("unsupported OneNote compensation action")
        previous = self._previous_html.get(str(action.action_id))
        if previous is None:
            raise ConnectorError("OneNote previous content is unavailable")
        page_id = action.target.resource_id
        current = self._read_page(root, page_id, include_content=False)
        if current.get("version") != (result.after or {}).get("version"):
            raise VersionConflictError(
                "OneNote page changed after update; rollback is refused"
            )
        self._client.request_bytes(
            "PATCH",
            f"{root}/onenote/pages/{quote_segment(page_id)}/content",
            json_body=[{"target": "body", "action": "replace", "content": previous}],
            safe_to_retry=False,
        )
        observed = self._read_page(root, page_id, include_content=True)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after=observed,
            connector_reference=str(observed.get("web_url") or page_id),
            message="restored previous OneNote page body",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Verify restored HTML equals the retained content."""

        observed = compensation.after or {}
        if action.capability == "onenote.page.create":
            identity = str(action.parameters.get("identity", "me"))
            root, _ = graph_user_root(self._config, identity)
            page_id = str(observed.get("id", ""))
            try:
                self._read_page(root, page_id, include_content=False)
                verified = False
            except ResourceNotFoundError:
                verified = True
        else:
            previous = self._previous_html.get(str(action.action_id))
            verified = previous is not None and observed.get("content_html") == previous
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed={
                key: value for key, value in observed.items() if key != "content_html"
            },
            message=(
                "verified OneNote rollback"
                if verified
                else "OneNote rollback did not match the prior state"
            ),
        )

    def _read_page(
        self,
        root: str,
        page_id: str,
        *,
        include_content: bool,
    ) -> dict[str, Any]:
        metadata, response = self._client.request_json(
            "GET",
            f"{root}/onenote/pages/{quote_segment(page_id)}",
        )
        if not isinstance(metadata, Mapping):
            raise ConnectorError("OneNote page metadata must be an object")
        content = ""
        if include_content:
            content_response = self._client.request_bytes(
                "GET",
                f"{root}/onenote/pages/{quote_segment(page_id)}/content",
                query={"includeIDs": "true"},
            )
            content = content_response.body.decode("utf-8", errors="strict")
        links = metadata.get("links")
        links = links if isinstance(links, Mapping) else {}
        one_note_web = links.get("oneNoteWebUrl")
        one_note_web = one_note_web if isinstance(one_note_web, Mapping) else {}
        return {
            "id": str(metadata.get("id", page_id)),
            "title": str(metadata.get("title", "")),
            "version": metadata.get("lastModifiedDateTime"),
            "created_at": metadata.get("createdDateTime"),
            "last_modified": metadata.get("lastModifiedDateTime"),
            "web_url": one_note_web.get("href"),
            "content_html": content,
            "reference": response.url,
        }

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("OneNote connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(f"unsupported OneNote capability: {action.capability}")
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("OneNote writes must use reversible_write risk")


def _normalize_notebook(value: Mapping[str, Any]) -> dict[str, Any]:
    links = _as_mapping(value.get("links"))
    web = _as_mapping(links.get("oneNoteWebUrl"))
    return {
        "id": str(value.get("id", "")),
        "display_name": str(value.get("displayName", "")),
        "created_at": value.get("createdDateTime"),
        "last_modified": value.get("lastModifiedDateTime"),
        "web_url": web.get("href"),
    }


def _normalize_section(value: Mapping[str, Any]) -> dict[str, Any]:
    links = _as_mapping(value.get("links"))
    web = _as_mapping(links.get("oneNoteWebUrl"))
    parent = _as_mapping(value.get("parentNotebook"))
    return {
        "id": str(value.get("id", "")),
        "display_name": str(value.get("displayName", "")),
        "notebook_id": parent.get("id"),
        "created_at": value.get("createdDateTime"),
        "last_modified": value.get("lastModifiedDateTime"),
        "web_url": web.get("href"),
    }


def _normalize_page(value: Mapping[str, Any]) -> dict[str, Any]:
    links = _as_mapping(value.get("links"))
    web = _as_mapping(links.get("oneNoteWebUrl"))
    parent = _as_mapping(value.get("parentSection"))
    return {
        "id": str(value.get("id", "")),
        "title": str(value.get("title", "")),
        "section_id": parent.get("id"),
        "created_at": value.get("createdDateTime"),
        "last_modified": value.get("lastModifiedDateTime"),
        "version": value.get("lastModifiedDateTime"),
        "web_url": web.get("href"),
    }


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
