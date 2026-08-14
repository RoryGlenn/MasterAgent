"""Shared Microsoft Graph connector helpers."""

from __future__ import annotations

from typing import Any, Mapping

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.utils import quote_segment
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport, SafeHttpClient


def graph_client(
    config: ResolvedConnectorConfig,
    *,
    transport: HttpTransport | None,
    allowed_methods: frozenset[str] = frozenset({"GET", "HEAD"}),
) -> SafeHttpClient:
    """Build an origin-bound Microsoft Graph client."""

    return SafeHttpClient(
        base_url=config.base_url,
        header_provider=config.auth.headers,
        transport=transport,
        timeout_seconds=config.timeout_seconds,
        max_response_bytes=config.max_response_bytes,
        ca_bundle=config.ca_bundle,
        allowed_methods=allowed_methods,
    )


def graph_user_root(
    config: ResolvedConnectorConfig,
    identity: str | None,
) -> tuple[str, str]:
    """Return a Graph user root and normalized identity reference.

    ``me`` is accepted only in delegated identity mode. Application mode must
    name an explicit user object ID or user principal name.
    """

    selected = (identity or str(config.extra.get("default_identity", "me"))).strip()
    if not selected:
        raise ConnectorError("Microsoft Graph identity must not be empty")
    mode = str(config.extra.get("identity_mode", "delegated")).lower()
    if selected == "me":
        if mode != "delegated":
            raise ConnectorError(
                "Microsoft Graph /me requires delegated identity mode; "
                "configure an explicit user ID for app-only access"
            )
        return "me", "me"
    return f"users/{quote_segment(selected)}", selected


def graph_paged_values(
    client: SafeHttpClient,
    *,
    config: ResolvedConnectorConfig,
    path: str,
    query: Mapping[str, Any] | None,
    limit: int,
    normalizer: Any,
    headers: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Read a bounded Microsoft Graph ``value`` collection."""

    values: list[dict[str, Any]] = []
    next_url: str | None = None
    reference = ""
    for _ in range(config.max_pages):
        if len(values) >= limit:
            break
        if next_url:
            data, response = client.request_json("GET", next_url, headers=headers)
        else:
            data, response = client.request_json(
                "GET",
                path,
                query=query,
                headers=headers,
            )
        reference = response.url
        if not isinstance(data, Mapping):
            raise ConnectorError("Microsoft Graph collection must be an object")
        page = data.get("value", [])
        if not isinstance(page, list):
            raise ConnectorError("Microsoft Graph value must be a list")
        mapped = [item for item in page if isinstance(item, Mapping)]
        values.extend(normalizer(item) for item in mapped)
        next_value = data.get("@odata.nextLink")
        next_url = str(next_value) if next_value else None
        if not mapped or not next_url:
            break
    return values[:limit], reference
