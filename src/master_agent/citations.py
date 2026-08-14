"""Deterministic resource-level citations for retrieved enterprise evidence."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, MutableMapping
from urllib.parse import urlparse

from master_agent.models import AgentAction


_COLLECTION_SPECS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "issues": ("issue", ("key", "id"), ("summary", "key"), ("web_url",), ("updated_at", "version")),
    "pages": ("page", ("id",), ("title",), ("web_url",), ("version", "updated_at")),
    "pull_requests": ("pull_request", ("id",), ("title",), ("web_url", "source_urls"), ("version", "updated_at")),
    "repositories": ("repository", ("slug", "id", "name"), ("name", "slug"), ("web_url",), ("updated_at",)),
    "sites": ("site", ("id",), ("display_name", "name"), ("web_url",), ("updated_at",)),
    "drives": ("drive", ("id",), ("name",), ("web_url",), ("updated_at",)),
    "items": ("drive_item", ("id",), ("name",), ("web_url",), ("etag", "updated_at")),
    "users": ("identity", ("id", "user_principal_name", "mail"), ("display_name", "mail"), (), ()),
    "chats": ("chat", ("id",), ("topic", "chat_type", "id"), ("web_url",), ("updated_at",)),
    "teams": ("team", ("id",), ("display_name", "id"), ("web_url",), ("updated_at",)),
    "channels": ("channel", ("id",), ("display_name", "id"), ("web_url",), ("updated_at",)),
    "messages": ("message", ("id",), ("subject", "body_excerpt", "id"), ("web_url",), ("etag", "updated_at")),
    "attachments": ("attachment", ("id",), ("name", "id"), ("web_url",), ("updated_at", "size")),
    "folders": ("mail_folder", ("id",), ("display_name", "id"), ("web_url",), ()),
    "people": ("person", ("key", "id"), ("display_name", "key"), (), ()),
}

_SINGULAR_SPECS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "issue": _COLLECTION_SPECS["issues"],
    "page": _COLLECTION_SPECS["pages"],
    "pull_request": _COLLECTION_SPECS["pull_requests"],
    "repository": _COLLECTION_SPECS["repositories"],
    "site": _COLLECTION_SPECS["sites"],
    "file": _COLLECTION_SPECS["items"],
    "identity": _COLLECTION_SPECS["users"],
    "chat": _COLLECTION_SPECS["chats"],
    "team": _COLLECTION_SPECS["teams"],
    "channel": _COLLECTION_SPECS["channels"],
    "message": _COLLECTION_SPECS["messages"],
    "attachment": _COLLECTION_SPECS["attachments"],
    "folder": _COLLECTION_SPECS["folders"],
    "person": _COLLECTION_SPECS["people"],
}


def enrich_resource_citations(
    payload: MutableMapping[str, Any],
    *,
    action: AgentAction,
    connector_reference: str,
) -> tuple[dict[str, Any], ...]:
    """Add deterministic citations and per-record citation IDs to a payload.

    Parameters
    ----------
    payload
        Mutable normalized connector payload.
    action
        Action that produced the payload.
    connector_reference
        Exact API reference used for the retrieval.

    Returns
    -------
    tuple[dict[str, Any], ...]
        Citations in stable insertion order.
    """

    existing = payload.get("citations")
    citations: list[dict[str, Any]] = []
    if isinstance(existing, list):
        citations.extend(
            dict(item) for item in existing if isinstance(item, Mapping)
        )

    known = {str(item.get("citation_id")) for item in citations}
    system = str(payload.get("system") or action.target.system)

    for key, spec in _COLLECTION_SPECS.items():
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, MutableMapping):
                continue
            citation = _citation_from_record(
                system=system,
                record=item,
                spec=spec,
                fallback_url=connector_reference,
            )
            if citation is None:
                continue
            item["citation_id"] = citation["citation_id"]
            if citation["citation_id"] not in known:
                citations.append(citation)
                known.add(citation["citation_id"])

    for key, spec in _SINGULAR_SPECS.items():
        value = payload.get(key)
        if not isinstance(value, MutableMapping):
            continue
        citation = _citation_from_record(
            system=system,
            record=value,
            spec=spec,
            fallback_url=connector_reference,
        )
        if citation is None:
            continue
        value["citation_id"] = citation["citation_id"]
        if citation["citation_id"] not in known:
            citations.append(citation)
            known.add(citation["citation_id"])

    if not citations:
        citation = make_resource_citation(
            system=action.target.system,
            resource_type=action.target.resource_type,
            resource_id=action.target.resource_id,
            title=action.target.uri,
            url=connector_reference,
            version=action.target.expected_version,
        )
        citations.append(citation)

    payload["citations"] = citations
    payload["citation_ids"] = [item["citation_id"] for item in citations]
    return tuple(citations)


def make_resource_citation(
    *,
    system: str,
    resource_type: str,
    resource_id: str,
    title: object | None = None,
    url: object | None = None,
    version: object | None = None,
    parent_resource_id: object | None = None,
) -> dict[str, Any]:
    """Build one query-free, credential-safe resource citation."""

    identity = f"{system}\0{resource_type}\0{resource_id}".encode("utf-8")
    citation_id = "CIT-" + hashlib.sha256(identity).hexdigest()[:12].upper()
    safe_url = _safe_url(url)
    rendered_title = _first_text((title, resource_id))[:300]
    parent = _optional_scalar_text(parent_resource_id)
    rendered_version = _optional_scalar_text(version)
    return {
        "citation_id": citation_id,
        "marker": f"[{citation_id}]",
        "system": system,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "parent_resource_id": parent,
        "title": rendered_title,
        "url": safe_url,
        "version": rendered_version,
    }


def citation_index(payloads: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Collect and de-duplicate citations from normalized evidence payloads."""

    by_id: dict[str, dict[str, Any]] = {}
    for payload in payloads:
        values = payload.get("citations")
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, Mapping):
                continue
            citation_id = value.get("citation_id")
            if isinstance(citation_id, str) and citation_id:
                by_id.setdefault(citation_id, dict(value))
    return list(by_id.values())


def _citation_from_record(
    *,
    system: str,
    record: Mapping[str, Any],
    spec: tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]],
    fallback_url: str,
) -> dict[str, Any] | None:
    resource_type, id_keys, title_keys, url_keys, version_keys = spec
    resource_id = _first_text(record.get(key) for key in id_keys)
    if not resource_id:
        return None
    title = _first_text(record.get(key) for key in title_keys)
    url = _first_url(record.get(key) for key in url_keys) or fallback_url
    version = _first_text(record.get(key) for key in version_keys)
    parent = _first_text(
        record.get(key)
        for key in ("parent_id", "team_id", "channel_id", "chat_id", "message_id")
    )
    return make_resource_citation(
        system=system,
        resource_type=resource_type,
        resource_id=resource_id,
        title=title,
        url=url,
        version=version,
        parent_resource_id=parent,
    )


def _first_text(values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)):
            return str(value)
    return ""


def _first_url(values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value:
            safe = _safe_url(value)
            if safe:
                return safe
        elif isinstance(value, list):
            for item in value:
                safe = _safe_url(item)
                if safe:
                    return safe
    return None


def _optional_scalar_text(value: object | None) -> str | None:
    if value is None or isinstance(value, (Mapping, list, tuple, set)):
        return None
    rendered = str(value).strip()
    return rendered or None


def _safe_url(value: object | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return parsed._replace(query="", fragment="").geturl()


def find_citations(value: Any) -> list[dict[str, Any]]:
    """Recursively collect de-duplicated citations from an arbitrary JSON value."""

    found: dict[str, dict[str, Any]] = {}

    def visit(current: Any) -> None:
        if isinstance(current, Mapping):
            citations = current.get("citations")
            if isinstance(citations, list):
                for citation in citations:
                    if not isinstance(citation, Mapping):
                        continue
                    citation_id = citation.get("citation_id")
                    if isinstance(citation_id, str) and citation_id:
                        found.setdefault(citation_id, dict(citation))
            for item in current.values():
                visit(item)
        elif isinstance(current, list):
            for item in current:
                visit(item)

    visit(value)
    return list(found.values())
