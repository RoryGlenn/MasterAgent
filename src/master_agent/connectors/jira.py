"""Read-only Jira Cloud and Data Center connector."""

from __future__ import annotations

from typing import Any, Mapping

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_list_parameter,
    string_parameter,
)
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport, SafeHttpClient
from master_agent.models import AgentAction


class JiraConnector(ReadOnlyConnector):
    """Retrieve Jira issues using deployment-specific REST APIs."""

    _CAPABILITIES = frozenset(
        {
            "jira.issue.search",
            "jira.issue.read",
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
        self._client = SafeHttpClient(
            base_url=config.base_url,
            header_provider=config.auth.headers,
            transport=transport,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            ca_bundle=config.ca_bundle,
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
            "base_url": data.get("baseUrl", self._config.base_url),
            "version": data.get("version"),
            "deployment_type": data.get("deploymentType"),
            "reference": response.url,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "jira.issue.search":
            return self._search_issues(action)
        if action.capability == "jira.issue.read":
            return self._read_issue(action)
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
            "web_url": f"{self._config.base_url}/browse/{quote_segment(key)}",
        }
