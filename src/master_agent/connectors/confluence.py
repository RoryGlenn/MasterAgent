"""Read-only Confluence Cloud and Data Center connector."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    absolute_web_url,
    boolean_parameter,
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport, SafeHttpClient
from master_agent.models import AgentAction
from master_agent.text import excerpt, html_to_text


class ConfluenceConnector(ReadOnlyConnector):
    """Search and read Confluence pages without write permissions."""

    _CAPABILITIES = frozenset(
        {
            "confluence.page.search",
            "confluence.page.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="confluence", capabilities=self._CAPABILITIES)
        self._config = config
        self._web_base_url = (config.web_base_url or config.base_url).rstrip("/")
        self._client = SafeHttpClient(
            base_url=config.base_url,
            header_provider=config.auth.headers,
            transport=transport,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            ca_bundle_data=config.ca_bundle_data,
            proxy_url=config.proxy_url,
            proxy_username=config.proxy_username,
            proxy_password=config.proxy_password,
        )

    def probe(self) -> Mapping[str, Any]:
        """Verify read access with a one-page CQL query."""

        path = self._search_path
        data, response = self._client.request_json(
            "GET",
            path,
            query={"cql": "type=page", "limit": 1},
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Confluence search response must be an object")
        return {
            "reachable": True,
            "deployment": self._config.deployment,
            "result_count": len(data.get("results", []))
            if isinstance(data.get("results"), list)
            else 0,
            "reference": response.url,
        }

    @property
    def _search_path(self) -> str:
        return (
            "wiki/rest/api/content/search"
            if self._config.deployment is DeploymentType.CLOUD
            else "rest/api/content/search"
        )

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "confluence.page.search":
            return self._search_pages(action)
        if action.capability == "confluence.page.read":
            return self._read_page_action(action)
        raise ConnectorError(f"unsupported Confluence capability: {action.capability}")

    def _search_pages(self, action: AgentAction) -> RetrievedPayload:
        cql = string_parameter(action.parameters, "cql", required=True)
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=10,
            maximum=self._config.max_items,
        )
        include_body = boolean_parameter(
            action.parameters,
            "include_body",
            default=False,
        )

        raw_pages: list[Mapping[str, Any]] = []
        next_url: str | None = None
        start = 0
        reference = ""
        for _ in range(self._config.max_pages):
            remaining = limit - len(raw_pages)
            if remaining <= 0:
                break
            if next_url:
                data, response = self._client.request_json("GET", next_url)
            else:
                data, response = self._client.request_json(
                    "GET",
                    self._search_path,
                    query={
                        "cql": cql,
                        "limit": min(remaining, 50),
                        "start": start,
                        "expand": "version,space,history.lastUpdated",
                    },
                )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Confluence search response must be an object")
            page = data.get("results", [])
            if not isinstance(page, list):
                raise ConnectorError("Confluence results must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            raw_pages.extend(mapped)
            links = data.get("_links")
            links = links if isinstance(links, Mapping) else {}
            next_value = links.get("next")
            next_url = str(next_value) if next_value else None
            start += len(mapped)
            if not mapped or not next_url:
                break

        pages: list[dict[str, Any]] = []
        for item in raw_pages[:limit]:
            page_id = str(item.get("id", ""))
            if include_body and page_id:
                normalized, _ = self._read_page(page_id)
                pages.append(normalized)
            else:
                pages.append(self._normalize_search_page(item))

        source_urls = [reference]
        source_urls.extend(
            str(page["web_url"]) for page in pages if page.get("web_url")
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/confluence-pages@1",
                "system": "confluence",
                "deployment": self._config.deployment,
                "query": {"cql": cql, "include_body": include_body},
                "returned": len(pages),
                "pages": pages,
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=reference,
        )

    def _read_page_action(self, action: AgentAction) -> RetrievedPayload:
        page, reference = self._read_page(action.target.resource_id)
        enforce_expected_version(action, page.get("version"))
        source_urls = [reference]
        if page.get("web_url"):
            source_urls.append(str(page["web_url"]))
        return RetrievedPayload(
            data={
                "schema": "master-agent/confluence-page@1",
                "system": "confluence",
                "deployment": self._config.deployment,
                "page": page,
                "source_urls": source_urls,
            },
            connector_reference=reference,
        )

    def _read_page(self, page_id: str) -> tuple[dict[str, Any], str]:
        encoded = quote_segment(page_id)
        if self._config.deployment is DeploymentType.CLOUD:
            data, response = self._client.request_json(
                "GET",
                f"wiki/api/v2/pages/{encoded}",
                query={"body-format": "storage"},
            )
            if not isinstance(data, Mapping):
                raise ConnectorError("Confluence page response must be an object")
            page = self._normalize_cloud_page(data)
        else:
            data, response = self._client.request_json(
                "GET",
                f"rest/api/content/{encoded}",
                query={"expand": "body.storage,version,space,history.lastUpdated"},
            )
            if not isinstance(data, Mapping):
                raise ConnectorError("Confluence page response must be an object")
            page = self._normalize_data_center_page(data)
        return page, response.url

    def _normalize_search_page(self, page: Mapping[str, Any]) -> dict[str, Any]:
        version = page.get("version")
        version = version if isinstance(version, Mapping) else {}
        space = page.get("space")
        space = space if isinstance(space, Mapping) else {}
        history = page.get("history")
        history = history if isinstance(history, Mapping) else {}
        last_updated = history.get("lastUpdated")
        last_updated = last_updated if isinstance(last_updated, Mapping) else {}
        links = page.get("_links")
        links = links if isinstance(links, Mapping) else {}
        return {
            "id": str(page.get("id", "")),
            "title": str(page.get("title", "")),
            "status": page.get("status"),
            "version": version.get("number"),
            "space_id": space.get("id"),
            "space_key": space.get("key"),
            "updated_at": last_updated.get("when"),
            "body_text": None,
            "body_excerpt": None,
            "web_url": self._approved_web_url(
                str(links.get("webui")) if links.get("webui") else None,
            ),
        }

    def _normalize_cloud_page(self, page: Mapping[str, Any]) -> dict[str, Any]:
        body = page.get("body")
        body = body if isinstance(body, Mapping) else {}
        storage = body.get("storage")
        storage = storage if isinstance(storage, Mapping) else {}
        html = str(storage.get("value", ""))
        text = html_to_text(html)
        version = page.get("version")
        version = version if isinstance(version, Mapping) else {}
        links = page.get("_links")
        links = links if isinstance(links, Mapping) else {}
        return {
            "id": str(page.get("id", "")),
            "title": str(page.get("title", "")),
            "status": page.get("status"),
            "version": version.get("number"),
            "space_id": page.get("spaceId"),
            "space_key": None,
            "updated_at": version.get("createdAt"),
            "body_text": text,
            "body_excerpt": excerpt(text),
            "web_url": self._approved_web_url(
                str(links.get("webui")) if links.get("webui") else None,
            ),
        }

    def _normalize_data_center_page(
        self,
        page: Mapping[str, Any],
    ) -> dict[str, Any]:
        body = page.get("body")
        body = body if isinstance(body, Mapping) else {}
        storage = body.get("storage")
        storage = storage if isinstance(storage, Mapping) else {}
        html = str(storage.get("value", ""))
        text = html_to_text(html)
        version = page.get("version")
        version = version if isinstance(version, Mapping) else {}
        space = page.get("space")
        space = space if isinstance(space, Mapping) else {}
        links = page.get("_links")
        links = links if isinstance(links, Mapping) else {}
        return {
            "id": str(page.get("id", "")),
            "title": str(page.get("title", "")),
            "status": page.get("status"),
            "version": version.get("number"),
            "space_id": space.get("id"),
            "space_key": space.get("key"),
            "updated_at": version.get("when"),
            "body_text": text,
            "body_excerpt": excerpt(text),
            "web_url": self._approved_web_url(
                str(links.get("webui")) if links.get("webui") else None,
            ),
        }

    def _approved_web_url(self, candidate: str | None) -> str | None:
        """Resolve a provider web link only on the approved browser origin."""

        resolved = absolute_web_url(self._web_base_url, candidate)
        if resolved is None:
            return None
        approved = urlparse(self._web_base_url)
        parsed = urlparse(resolved)
        try:
            approved_origin = (
                approved.scheme.casefold(),
                (approved.hostname or "").casefold(),
                approved.port or 443,
            )
            candidate_origin = (
                parsed.scheme.casefold(),
                (parsed.hostname or "").casefold(),
                parsed.port or 443,
            )
        except ValueError:
            return None
        if approved_origin != candidate_origin:
            return None
        return parsed._replace(
            scheme=approved.scheme,
            netloc=approved.netloc,
            fragment="",
        ).geturl()
