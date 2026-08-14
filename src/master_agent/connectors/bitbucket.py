"""Read-only Bitbucket Cloud and Data Center connector."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    boolean_parameter,
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConnectorError
from master_agent.http import HttpTransport, SafeHttpClient
from master_agent.models import AgentAction


class BitbucketConnector(ReadOnlyConnector):
    """Read repositories, pull requests, diffs, and CI status."""

    _CAPABILITIES = frozenset(
        {
            "bitbucket.instance.read",
            "bitbucket.repository.read",
            "bitbucket.pull_request.search",
            "bitbucket.pull_request.read",
            "bitbucket.pull_request.diffstat",
            "bitbucket.build_status.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        super().__init__(system="bitbucket", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = SafeHttpClient(
            base_url=config.base_url,
            header_provider=config.auth.headers,
            transport=transport,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            ca_bundle=config.ca_bundle,
        )

    def probe(self) -> Mapping[str, Any]:
        """Verify authentication and return minimal instance metadata."""

        payload = self._read_instance()
        instance = payload.data.get("instance", {})
        if not isinstance(instance, Mapping):
            instance = {}
        return {
            "reachable": True,
            "deployment": self._config.deployment,
            "display_name": instance.get("display_name"),
            "version": instance.get("version"),
            "reference": payload.connector_reference,
        }

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "bitbucket.instance.read":
            return self._read_instance()
        if action.capability == "bitbucket.repository.read":
            return self._read_repository(action)
        if action.capability == "bitbucket.pull_request.search":
            return self._search_pull_requests(action)
        if action.capability == "bitbucket.pull_request.read":
            return self._read_pull_request(action)
        if action.capability == "bitbucket.pull_request.diffstat":
            return self._read_diffstat(action)
        if action.capability == "bitbucket.build_status.read":
            return self._read_build_status(action)
        raise ConnectorError(f"unsupported Bitbucket capability: {action.capability}")

    def _read_instance(self) -> RetrievedPayload:
        if self._config.deployment is DeploymentType.CLOUD:
            data, response = self._client.request_json("GET", "user")
            if not isinstance(data, Mapping):
                raise ConnectorError("Bitbucket Cloud user response must be an object")
            instance = {
                "display_name": data.get("display_name"),
                "version": None,
                "authenticated_user": {
                    "id": data.get("uuid") or data.get("account_id"),
                    "display_name": data.get("display_name"),
                    "nickname": data.get("nickname"),
                    "username": data.get("username"),
                },
            }
        else:
            data, response = self._client.request_json(
                "GET",
                "rest/api/latest/projects",
                query={"limit": 1},
            )
            if not isinstance(data, Mapping):
                raise ConnectorError(
                    "Bitbucket Data Center project response must be an object"
                )
            instance = {
                "display_name": "Bitbucket Data Center",
                "version": None,
                "visible_project_count": data.get("size"),
                "is_last_page": data.get("isLastPage"),
            }
        return RetrievedPayload(
            data={
                "schema": "master-agent/bitbucket-instance@1",
                "system": "bitbucket",
                "deployment": self._config.deployment,
                "instance": instance,
                "source_urls": [response.url],
            },
            connector_reference=response.url,
        )

    def _read_repository(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        if self._config.deployment is DeploymentType.CLOUD:
            path = f"repositories/{quote_segment(owner)}/{quote_segment(repository)}"
        else:
            path = self._dc_repo_path(owner, repository)
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError("Bitbucket repository response must be an object")
        repository_data = self._normalize_repository(data, owner, repository)
        enforce_expected_version(
            action,
            repository_data.get("updated_at") or repository_data.get("id"),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/bitbucket-repository@1",
                "system": "bitbucket",
                "deployment": self._config.deployment,
                "repository": repository_data,
                "source_urls": [response.url, repository_data.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _search_pull_requests(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        state = string_parameter(action.parameters, "state", default="OPEN")
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=50,
            maximum=self._config.max_items,
        )
        include_statuses = boolean_parameter(
            action.parameters,
            "include_statuses",
            default=True,
        )
        include_diffstat = boolean_parameter(
            action.parameters,
            "include_diffstat",
            default=False,
        )
        enrichment_limit = integer_parameter(
            action.parameters,
            "enrichment_limit",
            default=20,
            maximum=limit,
        )

        if self._config.deployment is DeploymentType.CLOUD:
            raw, reference = self._list_cloud_pull_requests(
                owner=owner,
                repository=repository,
                state=state,
                limit=limit,
            )
        else:
            raw, reference = self._list_dc_pull_requests(
                owner=owner,
                repository=repository,
                state=state,
                limit=limit,
            )

        pull_requests: list[dict[str, Any]] = []
        for index, item in enumerate(raw):
            normalized = self._normalize_pull_request(item, owner, repository)
            pull_request_id = str(normalized["id"])
            if index < enrichment_limit and include_statuses:
                statuses, status_reference = self._statuses_for_pull_request(
                    owner=owner,
                    repository=repository,
                    raw_pull_request=item,
                    pull_request_id=pull_request_id,
                )
                normalized["build_statuses"] = statuses
                normalized["ci_summary"] = _summarize_statuses(statuses)
                normalized.setdefault("source_urls", []).append(status_reference)
            else:
                normalized["build_statuses"] = []
                normalized["ci_summary"] = _summarize_statuses([])
            if index < enrichment_limit and include_diffstat:
                changes, diff_reference = self._diffstat_for_pull_request(
                    owner=owner,
                    repository=repository,
                    pull_request_id=pull_request_id,
                )
                normalized["changes"] = changes
                normalized["diff_summary"] = _summarize_changes(changes)
                normalized.setdefault("source_urls", []).append(diff_reference)
            pull_requests.append(normalized)

        source_urls = [reference]
        for pull_request in pull_requests:
            source_urls.extend(
                str(url) for url in pull_request.get("source_urls", []) if url
            )
        return RetrievedPayload(
            data={
                "schema": "master-agent/bitbucket-pull-requests@1",
                "system": "bitbucket",
                "deployment": self._config.deployment,
                "repository": {"owner": owner, "slug": repository},
                "query": {
                    "state": state,
                    "include_statuses": include_statuses,
                    "include_diffstat": include_diffstat,
                },
                "returned": len(pull_requests),
                "pull_requests": pull_requests,
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=reference,
        )

    def _read_pull_request(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        pull_request_id = action.target.resource_id
        path = self._pull_request_path(owner, repository, pull_request_id)
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError("Bitbucket pull-request response must be an object")
        normalized = self._normalize_pull_request(data, owner, repository)
        version = normalized.get("version") or normalized.get("updated_at")
        enforce_expected_version(action, version)
        return RetrievedPayload(
            data={
                "schema": "master-agent/bitbucket-pull-request@1",
                "system": "bitbucket",
                "deployment": self._config.deployment,
                "pull_request": normalized,
                "source_urls": [response.url, *normalized.get("source_urls", [])],
            },
            connector_reference=response.url,
        )

    def _read_diffstat(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        changes, reference = self._diffstat_for_pull_request(
            owner=owner,
            repository=repository,
            pull_request_id=action.target.resource_id,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/bitbucket-diffstat@1",
                "system": "bitbucket",
                "deployment": self._config.deployment,
                "pull_request_id": action.target.resource_id,
                "returned": len(changes),
                "changes": changes,
                "summary": _summarize_changes(changes),
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _read_build_status(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        commit = string_parameter(
            action.parameters,
            "commit",
            default=action.target.resource_id,
            required=True,
        )
        statuses, reference = self._statuses_for_commit(
            owner=owner,
            repository=repository,
            commit=commit,
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/bitbucket-build-status@1",
                "system": "bitbucket",
                "deployment": self._config.deployment,
                "commit": commit,
                "returned": len(statuses),
                "statuses": statuses,
                "summary": _summarize_statuses(statuses),
                "source_urls": [reference],
            },
            connector_reference=reference,
        )

    def _coordinates(self, parameters: Mapping[str, Any]) -> tuple[str, str]:
        if self._config.deployment is DeploymentType.CLOUD:
            owner = string_parameter(parameters, "workspace", required=True)
        else:
            owner = string_parameter(
                parameters,
                "project",
                default=string_parameter(parameters, "workspace"),
                required=True,
            )
        repository = string_parameter(parameters, "repository", required=True)
        return owner, repository

    def _list_cloud_pull_requests(
        self,
        *,
        owner: str,
        repository: str,
        state: str,
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], str]:
        results: list[Mapping[str, Any]] = []
        next_url: str | None = None
        reference = ""
        path = (
            f"repositories/{quote_segment(owner)}/{quote_segment(repository)}"
            "/pullrequests"
        )
        for _ in range(self._config.max_pages):
            remaining = limit - len(results)
            if remaining <= 0:
                break
            if next_url:
                data, response = self._client.request_json("GET", next_url)
            else:
                data, response = self._client.request_json(
                    "GET",
                    path,
                    query={"state": state, "pagelen": min(remaining, 50)},
                )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Bitbucket PR list response must be an object")
            page = data.get("values", [])
            if not isinstance(page, list):
                raise ConnectorError("Bitbucket PR values must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            results.extend(mapped)
            next_value = data.get("next")
            next_url = str(next_value) if next_value else None
            if not mapped or not next_url:
                break
        return results[:limit], reference

    def _list_dc_pull_requests(
        self,
        *,
        owner: str,
        repository: str,
        state: str,
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], str]:
        results: list[Mapping[str, Any]] = []
        start = 0
        reference = ""
        path = f"{self._dc_repo_path(owner, repository)}/pull-requests"
        for _ in range(self._config.max_pages):
            remaining = limit - len(results)
            if remaining <= 0:
                break
            data, response = self._client.request_json(
                "GET",
                path,
                query={
                    "state": state,
                    "limit": min(remaining, 100),
                    "start": start,
                },
            )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Bitbucket PR list response must be an object")
            page = data.get("values", [])
            if not isinstance(page, list):
                raise ConnectorError("Bitbucket PR values must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            results.extend(mapped)
            if bool(data.get("isLastPage")) or not mapped:
                break
            next_start = data.get("nextPageStart")
            start = (
                int(next_start) if isinstance(next_start, int) else start + len(mapped)
            )
        return results[:limit], reference

    def _statuses_for_pull_request(
        self,
        *,
        owner: str,
        repository: str,
        raw_pull_request: Mapping[str, Any],
        pull_request_id: str,
    ) -> tuple[list[dict[str, Any]], str]:
        if self._config.deployment is DeploymentType.CLOUD:
            path = (
                f"{self._pull_request_path(owner, repository, pull_request_id)}"
                "/statuses"
            )
            return self._list_status_endpoint(path)
        source = raw_pull_request.get("fromRef")
        source = source if isinstance(source, Mapping) else {}
        commit = str(source.get("latestCommit", ""))
        if not commit:
            return [], self._pull_request_path(owner, repository, pull_request_id)
        return self._statuses_for_commit(
            owner=owner,
            repository=repository,
            commit=commit,
        )

    def _statuses_for_commit(
        self,
        *,
        owner: str,
        repository: str,
        commit: str,
    ) -> tuple[list[dict[str, Any]], str]:
        if self._config.deployment is DeploymentType.CLOUD:
            path = (
                f"repositories/{quote_segment(owner)}/{quote_segment(repository)}"
                f"/commit/{quote_segment(commit)}/statuses"
            )
        else:
            path = f"rest/build-status/latest/commits/{quote_segment(commit)}"
        return self._list_status_endpoint(path)

    def _list_status_endpoint(
        self,
        path: str,
    ) -> tuple[list[dict[str, Any]], str]:
        statuses: list[dict[str, Any]] = []
        next_url: str | None = None
        start = 0
        reference = ""
        for _ in range(self._config.max_pages):
            if next_url:
                data, response = self._client.request_json("GET", next_url)
            else:
                query = (
                    {"pagelen": 50}
                    if self._config.deployment is DeploymentType.CLOUD
                    else {"limit": 100, "start": start}
                )
                data, response = self._client.request_json(
                    "GET",
                    path,
                    query=query,
                )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError(
                    "Bitbucket build-status response must be an object"
                )
            page = data.get("values", [])
            if not isinstance(page, list):
                raise ConnectorError("Bitbucket build statuses must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            statuses.extend(self._normalize_status(item) for item in mapped)
            if self._config.deployment is DeploymentType.CLOUD:
                next_value = data.get("next")
                next_url = str(next_value) if next_value else None
                if not mapped or not next_url:
                    break
            else:
                if bool(data.get("isLastPage")) or not mapped:
                    break
                next_start = data.get("nextPageStart")
                start = (
                    int(next_start)
                    if isinstance(next_start, int)
                    else start + len(mapped)
                )
        return statuses[: self._config.max_items], reference

    def _diffstat_for_pull_request(
        self,
        *,
        owner: str,
        repository: str,
        pull_request_id: str,
    ) -> tuple[list[dict[str, Any]], str]:
        suffix = (
            "diffstat" if self._config.deployment is DeploymentType.CLOUD else "changes"
        )
        path = f"{self._pull_request_path(owner, repository, pull_request_id)}/{suffix}"
        changes: list[dict[str, Any]] = []
        next_url: str | None = None
        start = 0
        reference = ""
        for _ in range(self._config.max_pages):
            if next_url:
                data, response = self._client.request_json("GET", next_url)
            else:
                query = (
                    {"pagelen": 50}
                    if self._config.deployment is DeploymentType.CLOUD
                    else {"limit": 100, "start": start}
                )
                data, response = self._client.request_json(
                    "GET",
                    path,
                    query=query,
                )
            reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("Bitbucket diffstat response must be an object")
            page = data.get("values", [])
            if not isinstance(page, list):
                raise ConnectorError("Bitbucket diffstat values must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            changes.extend(self._normalize_change(item) for item in mapped)
            if self._config.deployment is DeploymentType.CLOUD:
                next_value = data.get("next")
                next_url = str(next_value) if next_value else None
                if not mapped or not next_url:
                    break
            else:
                if bool(data.get("isLastPage")) or not mapped:
                    break
                next_start = data.get("nextPageStart")
                start = (
                    int(next_start)
                    if isinstance(next_start, int)
                    else start + len(mapped)
                )
        return changes[: self._config.max_items], reference

    def _pull_request_path(
        self,
        owner: str,
        repository: str,
        pull_request_id: str,
    ) -> str:
        if self._config.deployment is DeploymentType.CLOUD:
            return (
                f"repositories/{quote_segment(owner)}/{quote_segment(repository)}"
                f"/pullrequests/{quote_segment(pull_request_id)}"
            )
        return (
            f"{self._dc_repo_path(owner, repository)}/pull-requests/"
            f"{quote_segment(pull_request_id)}"
        )

    @staticmethod
    def _dc_repo_path(owner: str, repository: str) -> str:
        return (
            f"rest/api/latest/projects/{quote_segment(owner)}/repos/"
            f"{quote_segment(repository)}"
        )

    def _normalize_repository(
        self,
        repository_data: Mapping[str, Any],
        owner: str,
        repository: str,
    ) -> dict[str, Any]:
        links = repository_data.get("links")
        links = links if isinstance(links, Mapping) else {}
        html_link = links.get("html")
        html_link = html_link if isinstance(html_link, Mapping) else {}
        project = repository_data.get("project")
        project = project if isinstance(project, Mapping) else {}
        web_url = html_link.get("href")
        if not web_url and self._config.deployment is DeploymentType.DATA_CENTER:
            web_url = (
                f"{self._config.base_url}/projects/{quote_segment(owner)}/repos/"
                f"{quote_segment(repository)}/browse"
            )
        return {
            "id": repository_data.get("uuid") or repository_data.get("id"),
            "name": repository_data.get("name"),
            "slug": repository_data.get("slug", repository),
            "owner_or_project": owner,
            "project_name": project.get("name"),
            "is_private": repository_data.get("is_private"),
            "scm": repository_data.get("scm"),
            "main_branch": _nested_name(repository_data.get("mainbranch")),
            "updated_at": repository_data.get("updated_on"),
            "web_url": web_url,
        }

    def _normalize_pull_request(
        self,
        pull_request: Mapping[str, Any],
        owner: str,
        repository: str,
    ) -> dict[str, Any]:
        if self._config.deployment is DeploymentType.CLOUD:
            return self._normalize_cloud_pull_request(pull_request)
        return self._normalize_dc_pull_request(pull_request, owner, repository)

    @staticmethod
    def _normalize_cloud_pull_request(
        pull_request: Mapping[str, Any],
    ) -> dict[str, Any]:
        author = pull_request.get("author")
        author = author if isinstance(author, Mapping) else {}
        source = pull_request.get("source")
        source = source if isinstance(source, Mapping) else {}
        destination = pull_request.get("destination")
        destination = destination if isinstance(destination, Mapping) else {}
        links = pull_request.get("links")
        links = links if isinstance(links, Mapping) else {}
        html_link = links.get("html")
        html_link = html_link if isinstance(html_link, Mapping) else {}
        reviewers = pull_request.get("reviewers", [])
        participants = pull_request.get("participants", [])
        return {
            "id": pull_request.get("id"),
            "version": None,
            "title": pull_request.get("title"),
            "description": pull_request.get("description"),
            "state": pull_request.get("state"),
            "draft": bool(pull_request.get("draft", False)),
            "author": author.get("display_name") or author.get("nickname"),
            "source_branch": _branch_name(source),
            "destination_branch": _branch_name(destination),
            "source_commit": _commit_hash(source),
            "reviewers": [
                _person_name(item) for item in reviewers if isinstance(item, Mapping)
            ],
            "participants": [
                {
                    "name": _person_name(item.get("user"))
                    if isinstance(item.get("user"), Mapping)
                    else None,
                    "approved": item.get("approved"),
                    "state": item.get("state"),
                }
                for item in participants
                if isinstance(item, Mapping)
            ],
            "comment_count": pull_request.get("comment_count"),
            "task_count": pull_request.get("task_count"),
            "created_at": pull_request.get("created_on"),
            "updated_at": pull_request.get("updated_on"),
            "source_urls": [html_link.get("href")] if html_link.get("href") else [],
        }

    def _normalize_dc_pull_request(
        self,
        pull_request: Mapping[str, Any],
        owner: str,
        repository: str,
    ) -> dict[str, Any]:
        author = pull_request.get("author")
        author = author if isinstance(author, Mapping) else {}
        author_user = author.get("user")
        author_user = author_user if isinstance(author_user, Mapping) else {}
        from_ref = pull_request.get("fromRef")
        from_ref = from_ref if isinstance(from_ref, Mapping) else {}
        to_ref = pull_request.get("toRef")
        to_ref = to_ref if isinstance(to_ref, Mapping) else {}
        reviewers = pull_request.get("reviewers", [])
        pull_request_id = pull_request.get("id")
        web_url = (
            f"{self._config.base_url}/projects/{quote_segment(owner)}/repos/"
            f"{quote_segment(repository)}/pull-requests/{pull_request_id}/overview"
        )
        return {
            "id": pull_request_id,
            "version": pull_request.get("version"),
            "title": pull_request.get("title"),
            "description": pull_request.get("description"),
            "state": pull_request.get("state"),
            "draft": bool(pull_request.get("draft", False)),
            "author": _person_name(author_user),
            "source_branch": _display_ref(from_ref),
            "destination_branch": _display_ref(to_ref),
            "source_commit": from_ref.get("latestCommit"),
            "reviewers": [
                _person_name(item.get("user"))
                for item in reviewers
                if isinstance(item, Mapping) and isinstance(item.get("user"), Mapping)
            ],
            "participants": [
                {
                    "name": _person_name(item.get("user"))
                    if isinstance(item.get("user"), Mapping)
                    else None,
                    "approved": item.get("approved"),
                    "state": item.get("status"),
                }
                for item in reviewers
                if isinstance(item, Mapping)
            ],
            "comment_count": pull_request.get("openTaskCount"),
            "task_count": pull_request.get("openTaskCount"),
            "created_at": pull_request.get("createdDate"),
            "updated_at": pull_request.get("updatedDate"),
            "source_urls": [web_url],
        }

    def _normalize_status(self, status: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "key": status.get("key"),
            "name": status.get("name"),
            "state": status.get("state"),
            "description": status.get("description"),
            "url": status.get("url"),
            "created_at": status.get("created_on") or status.get("createdDate"),
            "updated_at": status.get("updated_on") or status.get("updatedDate"),
        }

    def _normalize_change(self, change: Mapping[str, Any]) -> dict[str, Any]:
        if self._config.deployment is DeploymentType.CLOUD:
            old = change.get("old")
            old = old if isinstance(old, Mapping) else {}
            new = change.get("new")
            new = new if isinstance(new, Mapping) else {}
            return {
                "status": change.get("status"),
                "old_path": old.get("path"),
                "new_path": new.get("path"),
                "lines_added": int(change.get("lines_added", 0) or 0),
                "lines_removed": int(change.get("lines_removed", 0) or 0),
            }
        path = change.get("path")
        path = path if isinstance(path, Mapping) else {}
        source = change.get("srcPath")
        source = source if isinstance(source, Mapping) else {}
        return {
            "status": change.get("type"),
            "old_path": source.get("toString") or source.get("name"),
            "new_path": path.get("toString") or path.get("name"),
            "lines_added": None,
            "lines_removed": None,
        }


def _nested_name(value: object) -> object:
    return value.get("name") if isinstance(value, Mapping) else None


def _branch_name(reference: Mapping[str, Any]) -> object:
    branch = reference.get("branch")
    return branch.get("name") if isinstance(branch, Mapping) else None


def _commit_hash(reference: Mapping[str, Any]) -> object:
    commit = reference.get("commit")
    return commit.get("hash") if isinstance(commit, Mapping) else None


def _display_ref(reference: Mapping[str, Any]) -> object:
    display = reference.get("displayId")
    if display:
        return display
    ref_id = reference.get("id")
    if isinstance(ref_id, str):
        return ref_id.removeprefix("refs/heads/")
    return None


def _person_name(value: object) -> object:
    if not isinstance(value, Mapping):
        return None
    return (
        value.get("display_name")
        or value.get("displayName")
        or value.get("nickname")
        or value.get("name")
        or value.get("username")
    )


def _summarize_statuses(statuses: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(statuses),
        "successful": 0,
        "failed": 0,
        "in_progress": 0,
        "other": 0,
    }
    for status in statuses:
        state = str(status.get("state", "")).upper()
        if state in {"SUCCESSFUL", "SUCCESS"}:
            summary["successful"] += 1
        elif state in {"FAILED", "FAILURE", "ERROR"}:
            summary["failed"] += 1
        elif state in {"INPROGRESS", "IN_PROGRESS", "PENDING"}:
            summary["in_progress"] += 1
        else:
            summary["other"] += 1
    return summary


def _summarize_changes(changes: list[dict[str, Any]]) -> dict[str, int | None]:
    added_values = [item.get("lines_added") for item in changes]
    removed_values = [item.get("lines_removed") for item in changes]
    numeric_added = [int(value) for value in added_values if isinstance(value, int)]
    numeric_removed = [int(value) for value in removed_values if isinstance(value, int)]
    return {
        "files": len(changes),
        "lines_added": sum(numeric_added) if numeric_added else None,
        "lines_removed": sum(numeric_removed) if numeric_removed else None,
    }
