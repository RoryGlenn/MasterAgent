"""Read-only Jira Cloud and Data Center connector."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from master_agent.config import (
    DeploymentType,
    JiraReviewFieldConfiguration,
    ResolvedConnectorConfig,
)
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_list_parameter,
    string_parameter,
)
from master_agent.errors import ConnectorError, ValidationError
from master_agent.http import HttpTransport, SafeHttpClient
from master_agent.models import AgentAction
from master_agent.resource_limits import measure_json_resources

_REVIEW_CONTEXT_SCHEMA = "master-agent/jira-issue-review-context@1"
_MAX_REVIEW_LINKS = 100
_MAX_REVIEW_TEXT_BYTES = 64 * 1024
_MAX_REVIEW_CONTEXT_BYTES = 256 * 1024
_REVIEW_OUTPUT_FIELDS = frozenset(
    {
        "id",
        "key",
        "summary",
        "status",
        "status_category",
        "assignee",
        "priority",
        "issue_type",
        "project_key",
        "labels",
        "blocked",
        "updated_at",
        "resolved_at",
        "web_url",
        "description",
        "acceptance_criteria",
        "issue_links",
        "external_relations",
    }
)


class JiraConnector(ReadOnlyConnector):
    """Retrieve Jira issues using deployment-specific REST APIs."""

    _CAPABILITIES = frozenset(
        {
            "jira.issue.search",
            "jira.issue.read",
            "jira.issue.review_context.read",
            "jira.server.info",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="jira", capabilities=self._CAPABILITIES)
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
            allowed_methods=frozenset({"GET", "HEAD", "POST"}),
        )

    def probe(self) -> Mapping[str, Any]:
        """Retrieve server metadata using a read-only endpoint."""

        path = (
            "rest/api/3/serverInfo"
            if self._config.deployment is DeploymentType.CLOUD
            else "rest/api/2/serverInfo"
        )
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError("Jira serverInfo response must be an object")
        return {
            "reachable": True,
            "deployment": self._config.deployment,
            "base_url": self._web_base_url,
            "version": data.get("version"),
            "deployment_type": data.get("deploymentType"),
            "reference": response.url,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "jira.issue.search":
            return self._search_issues(action)
        if action.capability == "jira.issue.read":
            return self._read_issue(action)
        if action.capability == "jira.issue.review_context.read":
            return self._read_review_context(action)
        if action.capability == "jira.server.info":
            result = dict(self.probe())
            reference = str(result.pop("reference"))
            return RetrievedPayload(
                data={"schema": "master-agent/jira-server@1", **result},
                connector_reference=reference,
            )
        raise ConnectorError(f"unsupported Jira capability: {action.capability}")

    def _search_issues(self, action: AgentAction) -> RetrievedPayload:
        jql = string_parameter(action.parameters, "jql", required=True)
        requested_limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=self._config.max_items,
        )
        fields = string_list_parameter(
            action.parameters,
            "fields",
            default=(
                "summary",
                "status",
                "assignee",
                "priority",
                "issuetype",
                "project",
                "labels",
                "updated",
                "resolutiondate",
            ),
        )
        if self._config.deployment is DeploymentType.CLOUD:
            raw_issues, total, reference = self._search_cloud(
                jql=jql,
                fields=fields,
                limit=requested_limit,
            )
        else:
            raw_issues, total, reference = self._search_data_center(
                jql=jql,
                fields=fields,
                limit=requested_limit,
            )

        issues = [self._normalize_issue(item) for item in raw_issues]
        source_urls = [reference]
        source_urls.extend(
            issue["web_url"]
            for issue in issues
            if isinstance(issue.get("web_url"), str)
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/jira-issues@1",
                "system": "jira",
                "deployment": self._config.deployment,
                "query": {"jql": jql, "fields": list(fields)},
                "total": total,
                "returned": len(issues),
                "issues": issues,
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=reference,
        )

    def _search_cloud(
        self,
        *,
        jql: str,
        fields: tuple[str, ...],
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], int, str]:
        issues: list[Mapping[str, Any]] = []
        next_page_token: str | None = None
        reference = ""
        total = 0
        for _ in range(self._config.max_pages):
            remaining = limit - len(issues)
            if remaining <= 0:
                break
            body: dict[str, Any] = {
                "jql": jql,
                "fields": list(fields),
                "maxResults": min(remaining, 100),
            }
            if next_page_token:
                body["nextPageToken"] = next_page_token
            data, response = self._client.request_json(
                "POST",
                "rest/api/3/search/jql",
                json_body=body,
                safe_to_retry=True,
            )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Jira search response must be an object")
            page = data.get("issues", [])
            if not isinstance(page, list):
                raise ConnectorError("Jira issues response must be a list")
            issues.extend(item for item in page if isinstance(item, Mapping))
            total_value = data.get("total")
            if isinstance(total_value, int):
                total = total_value
            else:
                total = max(total, len(issues))
            token = data.get("nextPageToken")
            next_page_token = str(token) if token else None
            if bool(data.get("isLast")) or not next_page_token:
                break
        return issues[:limit], total, reference

    def _search_data_center(
        self,
        *,
        jql: str,
        fields: tuple[str, ...],
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], int, str]:
        issues: list[Mapping[str, Any]] = []
        start_at = 0
        reference = ""
        total = 0
        for _ in range(self._config.max_pages):
            remaining = limit - len(issues)
            if remaining <= 0:
                break
            body = {
                "jql": jql,
                "fields": list(fields),
                "maxResults": min(remaining, 100),
                "startAt": start_at,
            }
            data, response = self._client.request_json(
                "POST",
                "rest/api/2/search",
                json_body=body,
                safe_to_retry=True,
            )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Jira search response must be an object")
            page = data.get("issues", [])
            if not isinstance(page, list):
                raise ConnectorError("Jira issues response must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            issues.extend(mapped)
            total = int(data.get("total", len(issues)))
            start_at += len(mapped)
            if not mapped or start_at >= total:
                break
        return issues[:limit], total, reference

    def _read_issue(self, action: AgentAction) -> RetrievedPayload:
        issue_key = action.target.resource_id
        fields = string_list_parameter(action.parameters, "fields")
        api_version = "3" if self._config.deployment is DeploymentType.CLOUD else "2"
        query = {"fields": ",".join(fields)} if fields else None
        data, response = self._client.request_json(
            "GET",
            f"rest/api/{api_version}/issue/{quote_segment(issue_key)}",
            query=query,
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Jira issue response must be an object")
        issue = self._normalize_issue(data)
        enforce_expected_version(action, issue.get("updated_at"))
        return RetrievedPayload(
            data={
                "schema": "master-agent/jira-issue@1",
                "system": "jira",
                "deployment": self._config.deployment,
                "issue": issue,
                "source_urls": [response.url, issue["web_url"]],
            },
            connector_reference=response.url,
        )

    def _read_review_context(self, action: AgentAction) -> RetrievedPayload:
        """Read the fixed work-item fields used by the Tier-1 review."""

        issue_key = action.target.resource_id
        requested = string_list_parameter(action.parameters, "fields")
        if not requested:
            raise ConnectorError(
                "Jira review context requires an explicit normalized field list"
            )
        if len(requested) != len(set(requested)):
            raise ConnectorError("Jira review context fields must be unique")
        unknown = sorted(set(requested) - _REVIEW_OUTPUT_FIELDS)
        if unknown:
            raise ConnectorError(
                "Jira review context requested unsupported fields: "
                + ", ".join(unknown)
            )

        review_fields = JiraReviewFieldConfiguration.from_extra(self._config.extra)
        raw_fields = _raw_review_fields(requested, review_fields)
        api_version = "3" if self._config.deployment is DeploymentType.CLOUD else "2"
        data, response = self._client.request_json(
            "GET",
            f"rest/api/{api_version}/issue/{quote_segment(issue_key)}",
            query={"fields": ",".join(raw_fields)},
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Jira review-context response must be an object")
        issue = self._normalize_issue(data)
        if issue.get("key") != issue_key:
            raise ConnectorError(
                "Jira returned an issue identity different from the exact requested key"
            )
        raw_issue_fields = data.get("fields")
        if not isinstance(raw_issue_fields, Mapping):
            raise ConnectorError("Jira review-context fields must be an object")

        if "description" in requested:
            issue["description"] = _review_text(
                raw_issue_fields.get("description"),
                field_name="description",
            )
        if "acceptance_criteria" in requested:
            issue["acceptance_criteria"] = [
                {
                    "field_id": field_id,
                    "text": _review_text(
                        raw_issue_fields.get(field_id),
                        field_name=field_id,
                    ),
                }
                for field_id in review_fields.acceptance_field_ids
                if field_id in raw_issue_fields
            ]
        if "issue_links" in requested:
            issue["issue_links"] = _normalize_issue_links(
                raw_issue_fields.get("issuelinks")
            )

        references = [response.url, issue["web_url"]]
        if "external_relations" in requested:
            remote_links, remote_reference = self._read_remote_links(
                issue_key,
                api_version=api_version,
            )
            references.append(remote_reference)
            issue["external_relations"] = _normalize_external_relations(
                action,
                remote_links=remote_links,
                raw_issue_fields=raw_issue_fields,
                field_configuration=review_fields,
            )

        projected_issue = {name: issue.get(name) for name in requested}
        try:
            measure_json_resources(
                projected_issue,
                context="Jira review context",
                max_bytes=_MAX_REVIEW_CONTEXT_BYTES,
            )
        except ValidationError as error:
            raise ConnectorError(
                "Jira review context exceeds its bounded contract"
            ) from error
        enforce_expected_version(action, issue.get("updated_at"))
        return RetrievedPayload(
            data={
                "schema": _REVIEW_CONTEXT_SCHEMA,
                "system": "jira",
                "deployment": self._config.deployment,
                "issue": projected_issue,
                "source_urls": list(dict.fromkeys(references)),
            },
            connector_reference=response.url,
        )

    def _read_remote_links(
        self,
        issue_key: str,
        *,
        api_version: str,
    ) -> tuple[list[Mapping[str, Any]], str]:
        data, response = self._client.request_json(
            "GET",
            f"rest/api/{api_version}/issue/{quote_segment(issue_key)}/remotelink",
        )
        if not isinstance(data, list) or not all(
            isinstance(item, Mapping) for item in data
        ):
            raise ConnectorError("Jira remote-link response must be an object list")
        if len(data) > _MAX_REVIEW_LINKS:
            raise ConnectorError("Jira remote links exceed the 100-link limit")
        return list(data), response.url

    def _normalize_issue(self, issue: Mapping[str, Any]) -> dict[str, Any]:
        fields = issue.get("fields")
        if not isinstance(fields, Mapping):
            fields = {}
        status = fields.get("status")
        status = status if isinstance(status, Mapping) else {}
        status_category = status.get("statusCategory")
        status_category = (
            status_category if isinstance(status_category, Mapping) else {}
        )
        assignee = fields.get("assignee")
        assignee = assignee if isinstance(assignee, Mapping) else {}
        priority = fields.get("priority")
        priority = priority if isinstance(priority, Mapping) else {}
        issue_type = fields.get("issuetype")
        issue_type = issue_type if isinstance(issue_type, Mapping) else {}
        project = fields.get("project")
        project = project if isinstance(project, Mapping) else {}
        labels_value = fields.get("labels", [])
        labels = (
            [str(item) for item in labels_value]
            if isinstance(labels_value, list)
            else []
        )
        key = str(issue.get("key", issue.get("id", "")))
        status_name = str(status.get("name", ""))
        blocked = "block" in status_name.lower() or any(
            "block" in label.lower() for label in labels
        )
        return {
            "id": str(issue.get("id", "")),
            "key": key,
            "summary": str(fields.get("summary", "")),
            "status": status_name,
            "status_category": str(status_category.get("name", "")),
            "assignee": (
                assignee.get("displayName")
                or assignee.get("name")
                or assignee.get("emailAddress")
            ),
            "priority": priority.get("name"),
            "issue_type": issue_type.get("name"),
            "project_key": project.get("key"),
            "labels": labels,
            "blocked": blocked,
            "updated_at": fields.get("updated"),
            "resolved_at": fields.get("resolutiondate"),
            "web_url": f"{self._web_base_url}/browse/{quote_segment(key)}",
        }


def _raw_review_fields(
    requested: tuple[str, ...],
    configuration: JiraReviewFieldConfiguration,
) -> tuple[str, ...]:
    standard: dict[str, tuple[str, ...]] = {
        "summary": ("summary",),
        "status": ("status",),
        "status_category": ("status",),
        "assignee": ("assignee",),
        "priority": ("priority",),
        "issue_type": ("issuetype",),
        "project_key": ("project",),
        "labels": ("labels",),
        "blocked": ("status", "labels"),
        "updated_at": ("updated",),
        "resolved_at": ("resolutiondate",),
        "description": ("description",),
        "issue_links": ("issuelinks",),
    }
    selected: set[str] = set()
    for field_name in requested:
        selected.update(standard.get(field_name, ()))
    if "acceptance_criteria" in requested:
        selected.update(configuration.acceptance_field_ids)
    if "external_relations" in requested:
        selected.update(configuration.relation_field_kinds)
    return tuple(sorted(selected))


def _review_text(value: Any, *, field_name: str) -> str:
    if value is None:
        return ""
    try:
        measure_json_resources(
            value,
            context=f"Jira review field {field_name}",
            max_bytes=_MAX_REVIEW_TEXT_BYTES,
        )
    except ValidationError as error:
        raise ConnectorError("Jira review text exceeds its field bound") from error
    if isinstance(value, str):
        return value
    if not isinstance(value, Mapping) or value.get("type") != "doc":
        raise ConnectorError("Jira review text must be plain text or Atlassian ADF")

    parts: list[str] = []
    rendered_bytes = 0
    stack: list[tuple[bool, Any]] = [(False, value)]
    while stack:
        exiting, current = stack.pop()
        if exiting:
            if isinstance(current, Mapping) and current.get("type") in {
                "paragraph",
                "heading",
                "listItem",
            }:
                parts.append("\n")
                rendered_bytes += 1
            continue
        if not isinstance(current, Mapping):
            raise ConnectorError("Jira ADF content contains an unsupported node")
        node_type = current.get("type")
        if not isinstance(node_type, str) or not node_type:
            raise ConnectorError("Jira ADF content contains an invalid node type")
        if node_type == "text":
            text = current.get("text")
            if not isinstance(text, str):
                raise ConnectorError("Jira ADF text node is invalid")
            rendered_bytes += len(text.encode("utf-8"))
            if rendered_bytes > _MAX_REVIEW_TEXT_BYTES:
                raise ConnectorError("Jira review text exceeds its field bound")
            parts.append(text)
        elif node_type == "hardBreak":
            rendered_bytes += 1
            parts.append("\n")
        content = current.get("content", [])
        if not isinstance(content, list):
            raise ConnectorError("Jira ADF content must be a list")
        stack.append((True, current))
        for child in reversed(content):
            stack.append((False, child))
    return "".join(parts).rstrip()


def _normalize_issue_links(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise ConnectorError("Jira issue links must be an object list")
    if len(value) > _MAX_REVIEW_LINKS:
        raise ConnectorError("Jira issue links exceed the 100-link limit")
    normalized: list[dict[str, str]] = []
    for item in value:
        link_type = item.get("type")
        link_type = link_type if isinstance(link_type, Mapping) else {}
        inward = item.get("inwardIssue")
        outward = item.get("outwardIssue")
        if isinstance(inward, Mapping) == isinstance(outward, Mapping):
            raise ConnectorError("Jira issue link must have one exact direction")
        linked = inward if isinstance(inward, Mapping) else outward
        assert isinstance(linked, Mapping)
        normalized.append(
            {
                "link_id": str(item.get("id", "")),
                "relation_type": str(link_type.get("name", "")),
                "direction": "inward" if isinstance(inward, Mapping) else "outward",
                "linked_issue_id": str(linked.get("id", "")),
                "linked_issue_key": str(linked.get("key", "")),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["relation_type"],
            item["direction"],
            item["linked_issue_key"],
            item["link_id"],
        ),
    )


def _normalize_external_relations(
    action: AgentAction,
    *,
    remote_links: list[Mapping[str, Any]],
    raw_issue_fields: Mapping[str, Any],
    field_configuration: JiraReviewFieldConfiguration,
) -> list[dict[str, str]]:
    candidates: list[tuple[str, str, str]] = []
    for remote_link in remote_links:
        remote_object = remote_link.get("object")
        if not isinstance(remote_object, Mapping):
            raise ConnectorError("Jira remote link object is invalid")
        url = remote_object.get("url")
        if url is None:
            continue
        if not isinstance(url, str):
            raise ConnectorError("Jira remote link URL is invalid")
        candidates.append(("remote_link", str(remote_link.get("id", "")), url))
    for field_id, kind in field_configuration.relation_field_kinds.items():
        if field_id not in raw_issue_fields:
            continue
        raw_value = raw_issue_fields[field_id]
        values = [raw_value] if isinstance(raw_value, str) else raw_value
        if not isinstance(values, list) or not all(
            isinstance(item, str) for item in values
        ):
            raise ConnectorError("Jira configured relation field must contain URLs")
        if len(values) > _MAX_REVIEW_LINKS:
            raise ConnectorError("Jira configured relation field exceeds its limit")
        candidates.extend((kind, field_id, item) for item in values)
    if len(candidates) > _MAX_REVIEW_LINKS:
        raise ConnectorError("Jira external relations exceed the 100-link limit")

    relations: dict[str, dict[str, str]] = {}
    for provenance, source_id, candidate in sorted(candidates):
        relation = _relation_from_url(action, candidate, kind_hint=provenance)
        if relation is None:
            continue
        identity = json.dumps(relation, sort_keys=True, separators=(",", ":"))
        relation["provenance"] = (
            "remote_link" if provenance == "remote_link" else "configured_field"
        )
        relation["source_id"] = source_id
        relations.setdefault(identity, relation)
    return [relations[key] for key in sorted(relations)]


def _relation_from_url(
    action: AgentAction,
    candidate: str,
    *,
    kind_hint: str,
) -> dict[str, str] | None:
    parsed = _safe_relation_url(candidate)
    if parsed is None:
        return None
    origin, segments = parsed
    if kind_hint in {"remote_link", "bitbucket_pull_request_url"}:
        bitbucket = _bitbucket_relation(action, origin=origin, segments=segments)
        if bitbucket is not None:
            return bitbucket
    if kind_hint in {"remote_link", "confluence_page_url"}:
        return _confluence_relation(action, origin=origin, segments=segments)
    return None


def _safe_relation_url(candidate: str) -> tuple[str, tuple[str, ...]] | None:
    if len(candidate) > 4096 or "%" in candidate:
        return None
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = parsed.hostname.casefold().rstrip(".")
    rendered_host = f"[{host}]" if ":" in host else host
    if port not in {None, 443}:
        rendered_host = f"{rendered_host}:{port}"
    segments = tuple(item for item in parsed.path.split("/") if item)
    return f"https://{rendered_host}", segments


def _expected_origin(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ConnectorError(f"Jira review relation scope requires {name}")
    parsed = _safe_relation_url(value.rstrip("/"))
    if parsed is None or parsed[1]:
        raise ConnectorError(f"Jira review relation scope {name} is invalid")
    return parsed[0]


def _bitbucket_relation(
    action: AgentAction,
    *,
    origin: str,
    segments: tuple[str, ...],
) -> dict[str, str] | None:
    expected_origin = _expected_origin(
        action.parameters.get("bitbucket_origin"),
        "bitbucket_origin",
    )
    string_parameter(action.parameters, "bitbucket_owner", required=True)
    string_parameter(
        action.parameters,
        "bitbucket_repository",
        required=True,
    )
    accepted_origins = {expected_origin}
    if expected_origin in {"https://api.bitbucket.org", "https://bitbucket.org"}:
        accepted_origins.update({"https://api.bitbucket.org", "https://bitbucket.org"})
    if origin not in accepted_origins:
        return None
    owner_or_project = ""
    repository = ""
    pull_request_id = ""
    if len(segments) == 4 and segments[2] == "pull-requests":
        owner_or_project = segments[0]
        repository = segments[1]
        pull_request_id = segments[3]
    elif (
        len(segments) == 6
        and segments[:2] == ("2.0", "repositories")
        and segments[4] == "pullrequests"
    ):
        owner_or_project = segments[2]
        repository = segments[3]
        pull_request_id = segments[5]
    elif (
        len(segments) in {6, 7}
        and segments[0] == "projects"
        and segments[2] == "repos"
        and segments[4] == "pull-requests"
        and (len(segments) == 6 or segments[6] == "overview")
    ):
        owner_or_project = segments[1]
        repository = segments[3]
        pull_request_id = segments[5]
    if (
        not pull_request_id.isdecimal()
        or str(int(pull_request_id)) != pull_request_id
        or int(pull_request_id) <= 0
    ):
        return None
    return {
        "provider": "bitbucket",
        "resource_type": "pull_request",
        "canonical_origin": expected_origin,
        "owner_or_project": owner_or_project,
        "repository": repository,
        "pull_request_id": pull_request_id,
    }


def _confluence_relation(
    action: AgentAction,
    *,
    origin: str,
    segments: tuple[str, ...],
) -> dict[str, str] | None:
    expected_origin = _expected_origin(
        action.parameters.get("confluence_origin"),
        "confluence_origin",
    )
    configured_space = string_parameter(action.parameters, "confluence_space_key")
    if origin != expected_origin:
        return None
    observed_space = configured_space
    page_id = ""
    if (
        len(segments) >= 5
        and segments[:2] == ("wiki", "spaces")
        and segments[3] == "pages"
    ):
        observed_space = segments[2]
        page_id = segments[4]
    elif len(segments) >= 4 and segments[0] == "spaces" and segments[2] == "pages":
        observed_space = segments[1]
        page_id = segments[3]
    elif len(segments) == 2 and segments[0] == "pages":
        page_id = segments[1]
    if not page_id.isdecimal() or str(int(page_id)) != page_id or int(page_id) <= 0:
        return None
    return {
        "provider": "confluence",
        "resource_type": "page",
        "canonical_origin": expected_origin,
        "space": observed_space,
        "page_id": page_id,
    }
