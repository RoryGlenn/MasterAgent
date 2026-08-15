"""Read-only GitHub Cloud connector."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    enforce_expected_version,
    integer_parameter,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConfigurationError, ConnectorError
from master_agent.http import HttpTransport, SafeHttpClient
from master_agent.models import AgentAction

_REPOSITORY_COORDINATE = re.compile(r"^[A-Za-z0-9_.-]+$")
_PULL_REQUEST_STATES = frozenset({"open", "closed", "all"})
_REPOSITORY_VISIBILITIES = frozenset({"all", "public", "private"})
_REPOSITORY_AFFILIATIONS = "owner,collaborator,organization_member"


@dataclass(frozen=True, slots=True)
class GitHubPrincipalAttestation:
    """Provider-verified identity for the bearer token used by GitHub."""

    user_id: int
    login: str
    reference: str

    @property
    def identity(self) -> str:
        """Return the stable, secret-free identity bound into approvals."""

        return f"github:user:{self.user_id}"


class GitHubConnector(ReadOnlyConnector):
    """Read repositories, pull requests, and commit check runs from GitHub."""

    _CAPABILITIES = frozenset(
        {
            "github.public_repository.list",
            "github.repository.list",
            "github.repository.read",
            "github.pull_request.search",
            "github.pull_request.read",
            "github.checks.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        if config.system != "github":
            raise ConfigurationError("GitHub connector requires github configuration")
        if config.deployment is not DeploymentType.CLOUD:
            raise ConfigurationError("GitHub connector currently supports cloud only")
        super().__init__(system="github", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = SafeHttpClient(
            base_url=config.base_url,
            default_headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            header_provider=config.auth.headers,
            transport=transport,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            ca_bundle_data=config.ca_bundle_data,
        )

    def probe(self) -> Mapping[str, Any]:
        """Verify GitHub authentication without exposing token material."""

        principal = self.attest_principal()
        return {
            "reachable": True,
            "deployment": self._config.deployment,
            "authenticated_user": principal.login,
            "user_id": principal.user_id,
            "reference": principal.reference,
        }

    def attest_principal(self) -> GitHubPrincipalAttestation:
        """Resolve the token's immutable user identity through GitHub."""

        data, response = self._client.request_json("GET", "user")
        if not isinstance(data, Mapping):
            raise ConnectorError("GitHub user response must be an object")
        login = data.get("login")
        user_id = data.get("id")
        if not isinstance(login, str) or not login.strip():
            raise ConnectorError("GitHub user response has no authenticated login")
        if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
            raise ConnectorError("GitHub user response has no valid numeric identity")
        return GitHubPrincipalAttestation(
            user_id=user_id,
            login=login,
            reference=response.url,
        )

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "github.public_repository.list":
            return self._list_public_user_repositories(action)
        if action.capability == "github.repository.list":
            return self._list_authenticated_repositories(action)
        if action.capability == "github.repository.read":
            return self._read_repository(action)
        if action.capability == "github.pull_request.search":
            return self._search_pull_requests(action)
        if action.capability == "github.pull_request.read":
            return self._read_pull_request(action)
        if action.capability == "github.checks.read":
            return self._read_checks(action)
        raise ConnectorError(f"unsupported GitHub capability: {action.capability}")

    def _list_public_user_repositories(
        self,
        action: AgentAction,
    ) -> RetrievedPayload:
        username = _repository_coordinate(
            string_parameter(action.parameters, "username", required=True),
            name="username",
        )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=self._config.max_items,
            maximum=self._config.max_items,
        )
        raw, reference = self._list_public_repositories(
            username=username,
            limit=limit,
        )
        repositories: list[dict[str, Any]] = []
        for item in raw:
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConnectorError("GitHub repository response has no valid name")
            repository = self._normalize_repository(item, username, name)
            if (
                repository.get("is_private") is not False
                or repository.get("visibility") != "public"
            ):
                raise ConnectorError(
                    "GitHub public-user repository response was not public"
                )
            repositories.append(repository)
        source_urls = [reference]
        source_urls.extend(
            str(item["web_url"]) for item in repositories if item.get("web_url")
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/github-public-repositories@1",
                "system": "github",
                "deployment": self._config.deployment,
                "query": {
                    "username": username,
                    "type": "owner",
                    "visibility": "public",
                    "sort": "updated",
                    "direction": "desc",
                },
                "returned": len(repositories),
                "repositories": repositories,
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=reference,
        )

    def _list_authenticated_repositories(self, action: AgentAction) -> RetrievedPayload:
        visibility = string_parameter(
            action.parameters,
            "visibility",
            default="all",
        ).casefold()
        if visibility not in _REPOSITORY_VISIBILITIES:
            raise ConnectorError(
                "GitHub repository visibility must be all, public, or private"
            )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=self._config.max_items,
            maximum=self._config.max_items,
        )
        raw, reference = self._list_repositories(
            visibility=visibility,
            limit=limit,
        )
        repositories = [self._normalize_repository(item) for item in raw]
        source_urls = [reference]
        source_urls.extend(
            str(item["web_url"]) for item in repositories if item.get("web_url")
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/github-repositories@1",
                "system": "github",
                "deployment": self._config.deployment,
                "query": {
                    "visibility": visibility,
                    "affiliation": _REPOSITORY_AFFILIATIONS,
                    "sort": "updated",
                    "direction": "desc",
                },
                "returned": len(repositories),
                "repositories": repositories,
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=reference,
        )

    def _read_repository(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        path = self._repository_path(owner, repository)
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError("GitHub repository response must be an object")
        normalized = self._normalize_repository(data, owner, repository)
        enforce_expected_version(
            action,
            normalized.get("updated_at") or normalized.get("pushed_at"),
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/github-repository@1",
                "system": "github",
                "deployment": self._config.deployment,
                "repository": normalized,
                "source_urls": [response.url, normalized.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _search_pull_requests(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        state = string_parameter(
            action.parameters,
            "state",
            default="open",
        ).casefold()
        if state not in _PULL_REQUEST_STATES:
            raise ConnectorError(
                "GitHub pull-request state must be open, closed, or all"
            )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=50,
            maximum=self._config.max_items,
        )
        path = f"{self._repository_path(owner, repository)}/pulls"
        raw, reference = self._list_pull_requests(
            path=path,
            state=state,
            limit=limit,
        )
        pull_requests = [
            self._normalize_pull_request(item, owner, repository) for item in raw
        ]
        source_urls = [reference]
        source_urls.extend(
            str(item["web_url"]) for item in pull_requests if item.get("web_url")
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/github-pull-requests@1",
                "system": "github",
                "deployment": self._config.deployment,
                "repository": {"owner": owner, "name": repository},
                "query": {"state": state},
                "returned": len(pull_requests),
                "pull_requests": pull_requests,
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=reference,
        )

    def _read_pull_request(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        number = _positive_pull_request_number(action.target.resource_id)
        path = (
            f"{self._repository_path(owner, repository)}/pulls/"
            f"{quote_segment(str(number))}"
        )
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError("GitHub pull-request response must be an object")
        normalized = self._normalize_pull_request(data, owner, repository)
        if normalized.get("id") != number:
            raise ConnectorError("GitHub pull-request response identity did not match")
        enforce_expected_version(action, normalized.get("version"))
        return RetrievedPayload(
            data={
                "schema": "master-agent/github-pull-request@1",
                "system": "github",
                "deployment": self._config.deployment,
                "repository": {"owner": owner, "name": repository},
                "pull_request": normalized,
                "source_urls": [response.url, normalized.get("web_url")],
            },
            connector_reference=response.url,
        )

    def _read_checks(self, action: AgentAction) -> RetrievedPayload:
        owner, repository = self._coordinates(action.parameters)
        reference = _git_reference(
            string_parameter(
                action.parameters,
                "ref",
                default=action.target.resource_id,
                required=True,
            )
        )
        limit = integer_parameter(
            action.parameters,
            "limit",
            default=100,
            maximum=self._config.max_items,
        )
        path = (
            f"{self._repository_path(owner, repository)}/commits/"
            f"{quote_segment(reference)}/check-runs"
        )
        raw, connector_reference = self._list_check_runs(path=path, limit=limit)
        checks = [self._normalize_check_run(item) for item in raw]
        raw_head_shas = [item.get("head_sha") for item in checks]
        if checks and (
            not all(isinstance(value, str) and value for value in raw_head_shas)
            or len(set(raw_head_shas)) != 1
        ):
            raise ConnectorError("GitHub check-runs did not prove one commit identity")
        head_sha = str(raw_head_shas[0]) if raw_head_shas else None
        enforce_expected_version(action, head_sha)
        source_urls = [connector_reference]
        source_urls.extend(
            str(item["web_url"]) for item in checks if item.get("web_url")
        )
        return RetrievedPayload(
            data={
                "schema": "master-agent/github-checks@1",
                "system": "github",
                "deployment": self._config.deployment,
                "repository": {"owner": owner, "name": repository},
                "ref": reference,
                "head_sha": head_sha,
                "returned": len(checks),
                "checks": checks,
                "summary": _summarize_checks(checks),
                "source_urls": list(dict.fromkeys(source_urls)),
            },
            connector_reference=connector_reference,
        )

    def _list_pull_requests(
        self,
        *,
        path: str,
        state: str,
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], str]:
        results: list[Mapping[str, Any]] = []
        connector_reference = path
        for page_number in range(1, self._config.max_pages + 1):
            remaining = limit - len(results)
            if remaining <= 0:
                break
            page_size = min(remaining, 100)
            data, response = self._client.request_json(
                "GET",
                path,
                query={
                    "state": state,
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": page_size,
                    "page": page_number,
                },
            )
            connector_reference = response.url
            if not isinstance(data, list):
                raise ConnectorError("GitHub pull-request list response must be a list")
            mapped = [item for item in data if isinstance(item, Mapping)]
            results.extend(mapped)
            if len(data) < page_size:
                break
        return results[:limit], connector_reference

    def _list_repositories(
        self,
        *,
        visibility: str,
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], str]:
        results: list[Mapping[str, Any]] = []
        connector_reference = "user/repos"
        for page_number in range(1, self._config.max_pages + 1):
            remaining = limit - len(results)
            if remaining <= 0:
                break
            page_size = min(remaining, 100)
            data, response = self._client.request_json(
                "GET",
                "user/repos",
                query={
                    "visibility": visibility,
                    "affiliation": _REPOSITORY_AFFILIATIONS,
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": page_size,
                    "page": page_number,
                },
            )
            connector_reference = response.url
            if not isinstance(data, list):
                raise ConnectorError("GitHub repository list response must be a list")
            mapped = [item for item in data if isinstance(item, Mapping)]
            if len(mapped) != len(data):
                raise ConnectorError(
                    "GitHub repository list contains a non-object item"
                )
            results.extend(mapped)
            if len(data) < page_size:
                break
        return results[:limit], connector_reference

    def _list_public_repositories(
        self,
        *,
        username: str,
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], str]:
        results: list[Mapping[str, Any]] = []
        path = f"users/{quote_segment(username)}/repos"
        connector_reference = path
        for page_number in range(1, self._config.max_pages + 1):
            remaining = limit - len(results)
            if remaining <= 0:
                break
            page_size = min(remaining, 100)
            data, response = self._client.request_json(
                "GET",
                path,
                query={
                    "type": "owner",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": page_size,
                    "page": page_number,
                },
            )
            connector_reference = response.url
            if not isinstance(data, list):
                raise ConnectorError(
                    "GitHub public-user repository list response must be a list"
                )
            mapped = [item for item in data if isinstance(item, Mapping)]
            if len(mapped) != len(data):
                raise ConnectorError(
                    "GitHub public-user repository list contains a non-object item"
                )
            results.extend(mapped)
            if len(data) < page_size:
                break
        return results[:limit], connector_reference

    def _list_check_runs(
        self,
        *,
        path: str,
        limit: int,
    ) -> tuple[list[Mapping[str, Any]], str]:
        results: list[Mapping[str, Any]] = []
        connector_reference = path
        for page_number in range(1, self._config.max_pages + 1):
            remaining = limit - len(results)
            if remaining <= 0:
                break
            page_size = min(remaining, 100)
            data, response = self._client.request_json(
                "GET",
                path,
                query={"per_page": page_size, "page": page_number},
            )
            connector_reference = response.url
            if not isinstance(data, Mapping):
                raise ConnectorError("GitHub check-runs response must be an object")
            page = data.get("check_runs")
            if not isinstance(page, list):
                raise ConnectorError("GitHub check-runs value must be a list")
            mapped = [item for item in page if isinstance(item, Mapping)]
            results.extend(mapped)
            if len(page) < page_size:
                break
        return results[:limit], connector_reference

    @staticmethod
    def _coordinates(parameters: Mapping[str, Any]) -> tuple[str, str]:
        owner = _repository_coordinate(
            string_parameter(parameters, "owner", required=True),
            name="owner",
        )
        repository = _repository_coordinate(
            string_parameter(parameters, "repository", required=True),
            name="repository",
        )
        return owner, repository

    @staticmethod
    def _repository_path(owner: str, repository: str) -> str:
        return f"repos/{quote_segment(owner)}/{quote_segment(repository)}"

    @staticmethod
    def _normalize_repository(
        data: Mapping[str, Any],
        owner: str | None = None,
        repository: str | None = None,
    ) -> dict[str, Any]:
        raw_owner = data.get("owner")
        raw_owner = raw_owner if isinstance(raw_owner, Mapping) else {}
        topics = data.get("topics")
        full_name = data.get("full_name")
        name = data.get("name")
        owner_login = raw_owner.get("login")
        if (
            not isinstance(full_name, str)
            or not isinstance(name, str)
            or not name.strip()
            or not isinstance(owner_login, str)
            or not owner_login.strip()
            or full_name.casefold() != f"{owner_login}/{name}".casefold()
            or (
                owner is not None
                and repository is not None
                and full_name.casefold() != f"{owner}/{repository}".casefold()
            )
        ):
            raise ConnectorError("GitHub repository response identity did not match")
        return {
            "id": data.get("id"),
            "node_id": data.get("node_id"),
            "name": name,
            "full_name": full_name,
            "owner": owner_login,
            "description": data.get("description"),
            "is_private": data.get("private"),
            "visibility": data.get("visibility"),
            "fork": data.get("fork"),
            "archived": data.get("archived"),
            "disabled": data.get("disabled"),
            "default_branch": data.get("default_branch"),
            "topics": [str(item) for item in topics]
            if isinstance(topics, list)
            else [],
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "pushed_at": data.get("pushed_at"),
            "web_url": data.get("html_url"),
        }

    @staticmethod
    def _normalize_pull_request(
        data: Mapping[str, Any],
        owner: str,
        repository: str,
    ) -> dict[str, Any]:
        user = data.get("user")
        user = user if isinstance(user, Mapping) else {}
        head = data.get("head")
        head = head if isinstance(head, Mapping) else {}
        base = data.get("base")
        base = base if isinstance(base, Mapping) else {}
        base_repository = base.get("repo")
        base_repository = (
            base_repository if isinstance(base_repository, Mapping) else {}
        )
        head_repository = head.get("repo")
        head_repository = (
            head_repository if isinstance(head_repository, Mapping) else {}
        )
        reviewers = data.get("requested_reviewers")
        labels = data.get("labels")
        updated_at = data.get("updated_at")
        number = data.get("number")
        destination_repository = base_repository.get("full_name")
        if (
            not isinstance(number, int)
            or isinstance(number, bool)
            or number <= 0
            or not isinstance(destination_repository, str)
            or destination_repository.casefold() != f"{owner}/{repository}".casefold()
        ):
            raise ConnectorError("GitHub pull-request response identity did not match")
        return {
            "id": number,
            "node_id": data.get("node_id"),
            "version": updated_at,
            "title": data.get("title"),
            "description": data.get("body"),
            "state": data.get("state"),
            "draft": bool(data.get("draft", False)),
            "author": user.get("login"),
            "source_branch": head.get("ref"),
            "source_commit": head.get("sha"),
            "source_repository": head_repository.get("full_name"),
            "destination_branch": base.get("ref"),
            "destination_commit": base.get("sha"),
            "destination_repository": destination_repository,
            "requested_reviewers": [
                item.get("login")
                for item in reviewers
                if isinstance(item, Mapping) and item.get("login")
            ]
            if isinstance(reviewers, list)
            else [],
            "labels": [
                item.get("name")
                for item in labels
                if isinstance(item, Mapping) and item.get("name")
            ]
            if isinstance(labels, list)
            else [],
            "mergeable": data.get("mergeable"),
            "mergeable_state": data.get("mergeable_state"),
            "merged": data.get("merged"),
            "comments": data.get("comments"),
            "review_comments": data.get("review_comments"),
            "commits": data.get("commits"),
            "additions": data.get("additions"),
            "deletions": data.get("deletions"),
            "changed_files": data.get("changed_files"),
            "created_at": data.get("created_at"),
            "updated_at": updated_at,
            "closed_at": data.get("closed_at"),
            "merged_at": data.get("merged_at"),
            "web_url": data.get("html_url"),
        }

    @staticmethod
    def _normalize_check_run(data: Mapping[str, Any]) -> dict[str, Any]:
        app = data.get("app")
        app = app if isinstance(app, Mapping) else {}
        output = data.get("output")
        output = output if isinstance(output, Mapping) else {}
        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "status": data.get("status"),
            "conclusion": data.get("conclusion"),
            "head_sha": data.get("head_sha"),
            "app": app.get("slug") or app.get("name"),
            "external_id": data.get("external_id"),
            "started_at": data.get("started_at"),
            "completed_at": data.get("completed_at"),
            "output_title": output.get("title"),
            "output_summary": output.get("summary"),
            "web_url": data.get("details_url") or data.get("html_url"),
        }


def _repository_coordinate(value: str, *, name: str) -> str:
    if (
        value in {".", ".."}
        or len(value) > 100
        or _REPOSITORY_COORDINATE.fullmatch(value) is None
    ):
        raise ConnectorError(f"unsafe GitHub {name}")
    return value


def _positive_pull_request_number(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise ConnectorError(
            "GitHub pull-request ID must be a positive integer"
        ) from error
    if number <= 0:
        raise ConnectorError("GitHub pull-request ID must be a positive integer")
    return number


def _git_reference(value: str) -> str:
    if (
        value in {".", ".."}
        or len(value) > 255
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ConnectorError("unsafe GitHub commit reference")
    return value


def _summarize_checks(checks: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(checks),
        "successful": 0,
        "failed": 0,
        "in_progress": 0,
        "other": 0,
    }
    failed = {
        "action_required",
        "cancelled",
        "failure",
        "startup_failure",
        "stale",
        "timed_out",
    }
    for check in checks:
        status = str(check.get("status", "")).casefold()
        conclusion = str(check.get("conclusion", "")).casefold()
        if status != "completed":
            summary["in_progress"] += 1
        elif conclusion == "success":
            summary["successful"] += 1
        elif conclusion in failed:
            summary["failed"] += 1
        else:
            summary["other"] += 1
    return summary
