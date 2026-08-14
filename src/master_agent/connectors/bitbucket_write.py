"""Approved Bitbucket pull-request writes with verified decline compensation."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.utils import quote_segment, string_parameter
from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.http import HttpTransport, SafeHttpClient
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


class BitbucketWriteConnector:
    """Create pull requests and independently verify provider state."""

    _CAPABILITIES = frozenset({"bitbucket.pull_request.create"})

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        self._config = config
        self._client = SafeHttpClient(
            base_url=config.base_url,
            header_provider=config.auth.headers,
            transport=transport,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            ca_bundle_data=config.ca_bundle_data,
            allowed_methods=frozenset({"GET", "POST"}),
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "bitbucket"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Create a pull request from explicitly named branches."""

        self._validate(action)
        title = string_parameter(action.parameters, "title", required=True)
        source = _safe_branch(
            string_parameter(action.parameters, "source_branch", required=True)
        )
        destination = _safe_branch(
            string_parameter(action.parameters, "destination_branch", required=True)
        )
        description = str(action.parameters.get("description", ""))
        if self._config.deployment is DeploymentType.CLOUD:
            workspace = string_parameter(action.parameters, "workspace", required=True)
            repository = string_parameter(
                action.parameters,
                "repository",
                required=True,
            )
            path = (
                f"repositories/{quote_segment(workspace)}/"
                f"{quote_segment(repository)}/pullrequests"
            )
            data, response = self._client.request_json(
                "POST",
                path,
                json_body={
                    "title": title,
                    "description": description,
                    "source": {"branch": {"name": source}},
                    "destination": {"branch": {"name": destination}},
                    "close_source_branch": _boolean_parameter(
                        action.parameters,
                        "close_source_branch",
                        default=False,
                    ),
                },
            )
            context = {"workspace": workspace, "repository": repository}
        else:
            project = string_parameter(action.parameters, "project_key", required=True)
            repository = string_parameter(
                action.parameters,
                "repository_slug",
                required=True,
            )
            path = (
                f"rest/api/1.0/projects/{quote_segment(project)}/repos/"
                f"{quote_segment(repository)}/pull-requests"
            )
            data, response = self._client.request_json(
                "POST",
                path,
                json_body={
                    "title": title,
                    "description": description,
                    "fromRef": {
                        "id": f"refs/heads/{source}",
                        "repository": {
                            "slug": repository,
                            "project": {"key": project},
                        },
                    },
                    "toRef": {
                        "id": f"refs/heads/{destination}",
                        "repository": {
                            "slug": repository,
                            "project": {"key": project},
                        },
                    },
                },
            )
            context = {"project_key": project, "repository_slug": repository}
        if not isinstance(data, Mapping) or data.get("id") is None:
            raise ConnectorError("Bitbucket pull-request response omitted an ID")
        pr_id = str(data["id"])
        observed = self._read_pull_request(pr_id, context)
        after = {
            **observed,
            **context,
            "source_branch": source,
            "destination_branch": destination,
        }
        self._last[pr_id] = deepcopy(after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=after,
            connector_reference=str(observed.get("web_url") or response.url),
            message="Bitbucket pull request created",
            compensation=CompensationDescriptor(
                kind="decline_pull_request",
                mode=CompensationMode.IN_PROCESS,
                target_resource_id=pr_id,
                reason=(
                    "decline requires connector-held provider context and is "
                    "available only during the originating run"
                ),
            ).to_dict(),
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return cached normalized state."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Re-read the created pull request."""

        after = result.after or {}
        pr_id = str(after.get("id", ""))
        observed = self._read_pull_request(pr_id, after)
        verified = bool(
            observed.get("id") == pr_id
            and observed.get("state") in {"OPEN", "OPENED", "open", "OPENING"}
            and observed.get("title") == after.get("title")
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified Bitbucket pull request by independent re-read"
                if verified
                else "Bitbucket pull request did not match approved fields"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Decline the pull request created by the action."""

        after = result.after or {}
        pr_id = str(after.get("id", ""))
        if not pr_id:
            raise ConnectorError("pull-request compensation requires a provider ID")
        current = self._read_pull_request(pr_id, after)
        if any(
            current.get(key) != after.get(key)
            for key in ("id", "title", "state", "version")
        ):
            raise VersionConflictError(
                "Bitbucket pull request changed after creation; decline is refused"
            )
        if self._config.deployment is DeploymentType.CLOUD:
            workspace = str(after.get("workspace", ""))
            repository = str(after.get("repository", ""))
            path = (
                f"repositories/{quote_segment(workspace)}/"
                f"{quote_segment(repository)}/pullrequests/{quote_segment(pr_id)}/decline"
            )
        else:
            project = str(after.get("project_key", ""))
            repository = str(after.get("repository_slug", ""))
            path = (
                f"rest/api/1.0/projects/{quote_segment(project)}/repos/"
                f"{quote_segment(repository)}/pull-requests/{quote_segment(pr_id)}/decline"
            )
        self._client.request_bytes("POST", path, safe_to_retry=False)
        observed = self._read_pull_request(pr_id, after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=after,
            after=observed,
            connector_reference=str(observed.get("web_url") or path),
            message="Bitbucket pull request declined",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Verify the pull request is no longer open."""

        observed = compensation.after or {}
        state = str(observed.get("state", "")).upper()
        verified = state in {"DECLINED", "SUPERSEDED", "CLOSED"}
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified declined Bitbucket pull request"
                if verified
                else "Bitbucket pull request remains open after compensation"
            ),
        )

    def _read_pull_request(
        self,
        pr_id: str,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not pr_id:
            raise ConnectorError("Bitbucket pull-request ID must not be empty")
        if self._config.deployment is DeploymentType.CLOUD:
            workspace = str(context.get("workspace", ""))
            repository = str(context.get("repository", ""))
            path = (
                f"repositories/{quote_segment(workspace)}/"
                f"{quote_segment(repository)}/pullrequests/{quote_segment(pr_id)}"
            )
        else:
            project = str(context.get("project_key", ""))
            repository = str(context.get("repository_slug", ""))
            path = (
                f"rest/api/1.0/projects/{quote_segment(project)}/repos/"
                f"{quote_segment(repository)}/pull-requests/{quote_segment(pr_id)}"
            )
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError("Bitbucket pull-request response must be an object")
        links = data.get("links")
        links = links if isinstance(links, Mapping) else {}
        html = links.get("html")
        html = html if isinstance(html, Mapping) else {}
        self_links = links.get("self")
        self_url: str | None = None
        if isinstance(self_links, Mapping):
            candidate = self_links.get("href")
            self_url = str(candidate) if candidate else None
        elif isinstance(self_links, list) and self_links:
            first = self_links[0]
            if isinstance(first, Mapping) and first.get("href"):
                self_url = str(first["href"])
        return {
            "id": str(data.get("id", pr_id)),
            "title": str(data.get("title", "")),
            "state": data.get("state") or data.get("status"),
            "version": data.get("version") or data.get("updated_on"),
            "web_url": html.get("href") or self_url,
            "reference": response.url,
        }

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("Bitbucket write connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported Bitbucket write capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("pull-request creation must use reversible_write risk")


def _safe_branch(value: str) -> str:
    if (
        not value
        or value.startswith("-")
        or ".." in value
        or value.endswith("/")
        or any(character.isspace() for character in value)
        or any(token in value for token in ("~", "^", ":", "?", "*", "[", "\\"))
    ):
        raise ConnectorError("unsafe branch name")
    return value


def _boolean_parameter(
    parameters: Mapping[str, Any],
    key: str,
    *,
    default: bool,
) -> bool:
    value = parameters.get(key, default)
    if not isinstance(value, bool):
        raise ConnectorError(f"{key} must be a boolean")
    return value
