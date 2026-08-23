"""Approved Bitbucket pull-request writes with verified manual recovery."""

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
            proxy_url=config.proxy_url,
            proxy_username=config.proxy_username,
            proxy_password=config.proxy_password,
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
        approved = _approved_pull_request(action, self._config.deployment)
        title = str(approved["title"])
        source = str(approved["source_branch"])
        destination = str(approved["destination_branch"])
        description = str(approved["description"])
        if self._config.deployment is DeploymentType.CLOUD:
            context = _pull_request_context(action, self._config.deployment)
            workspace = str(context["workspace"])
            repository = str(context["repository"])
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
                    "close_source_branch": approved["close_source_branch"],
                },
            )
        else:
            context = _pull_request_context(action, self._config.deployment)
            project = str(context["project_key"])
            repository = str(context["repository_slug"])
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
        if not isinstance(data, Mapping) or data.get("id") is None:
            raise ConnectorError("Bitbucket pull-request response omitted an ID")
        pr_id = str(data["id"])
        observed = self._read_pull_request(pr_id, context)
        if not _pull_request_matches(observed, approved, pr_id):
            raise ConnectorError(
                "Bitbucket provider poststate did not match the approved pull request"
            )
        after = {**observed, **context}
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
                mode=CompensationMode.MANUAL,
                target_resource_id=pr_id,
                reason=(
                    "the decline adapter has no atomic provider precondition, so "
                    "a human must re-read and decline the pull request manually"
                ),
            ),
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
        context = _pull_request_context(action, self._config.deployment)
        approved = _approved_pull_request(action, self._config.deployment)
        observed = self._read_pull_request(pr_id, context)
        verified = _pull_request_matches(observed, approved, pr_id)
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
        context = _pull_request_context(action, self._config.deployment)
        approved = _approved_pull_request(action, self._config.deployment)
        current = self._read_pull_request(pr_id, context)
        if not _pull_request_matches(current, approved, pr_id) or current.get(
            "version"
        ) != after.get("version"):
            raise VersionConflictError(
                "Bitbucket pull request changed after creation; decline is refused"
            )
        if self._config.deployment is DeploymentType.CLOUD:
            workspace = context["workspace"]
            repository = context["repository"]
            path = (
                f"repositories/{quote_segment(workspace)}/"
                f"{quote_segment(repository)}/pullrequests/{quote_segment(pr_id)}/decline"
            )
        else:
            project = context["project_key"]
            repository = context["repository_slug"]
            path = (
                f"rest/api/1.0/projects/{quote_segment(project)}/repos/"
                f"{quote_segment(repository)}/pull-requests/{quote_segment(pr_id)}/decline"
            )
        self._client.request_bytes("POST", path, safe_to_retry=False)
        observed = self._read_pull_request(pr_id, context)
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

        after = original.after or {}
        pr_id = str(after.get("id", ""))
        context = _pull_request_context(action, self._config.deployment)
        approved = _approved_pull_request(action, self._config.deployment)
        observed = self._read_pull_request(pr_id, context)
        state = str(observed.get("state", "")).upper()
        verified = bool(
            pr_id
            and observed.get("id") == pr_id
            and state in {"DECLINED", "SUPERSEDED", "CLOSED"}
            and all(observed.get(key) == value for key, value in approved.items())
        )
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
            "id": str(data["id"]) if data.get("id") is not None else "",
            "title": data.get("title") if isinstance(data.get("title"), str) else None,
            "description": (
                data.get("description")
                if isinstance(data.get("description"), str)
                else None
            ),
            "source_branch": _provider_branch(data, source=True),
            "destination_branch": _provider_branch(data, source=False),
            "close_source_branch": (
                data.get("close_source_branch")
                if self._config.deployment is DeploymentType.CLOUD
                and isinstance(data.get("close_source_branch"), bool)
                else None
            ),
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


def _approved_pull_request(
    action: AgentAction,
    deployment: DeploymentType,
) -> dict[str, object]:
    """Return only provider fields whose values are bound to the action."""

    description = action.parameters.get("description", "")
    if not isinstance(description, str):
        raise ConnectorError("description must be a string")
    approved: dict[str, object] = {
        "title": string_parameter(action.parameters, "title", required=True),
        "description": description,
        "source_branch": _safe_branch(
            string_parameter(action.parameters, "source_branch", required=True)
        ),
        "destination_branch": _safe_branch(
            string_parameter(action.parameters, "destination_branch", required=True)
        ),
    }
    if deployment is DeploymentType.CLOUD:
        approved["close_source_branch"] = _boolean_parameter(
            action.parameters,
            "close_source_branch",
            default=False,
        )
    elif "close_source_branch" in action.parameters:
        raise ConnectorError(
            "close_source_branch is not supported for Bitbucket Data Center"
        )
    return approved


def _pull_request_context(
    action: AgentAction,
    deployment: DeploymentType,
) -> dict[str, str]:
    """Derive the provider path solely from approval-bound action fields."""

    if deployment is DeploymentType.CLOUD:
        return {
            "workspace": string_parameter(
                action.parameters,
                "workspace",
                required=True,
            ),
            "repository": string_parameter(
                action.parameters,
                "repository",
                required=True,
            ),
        }
    return {
        "project_key": string_parameter(
            action.parameters,
            "project_key",
            required=True,
        ),
        "repository_slug": string_parameter(
            action.parameters,
            "repository_slug",
            required=True,
        ),
    }


def _pull_request_matches(
    observed: Mapping[str, Any],
    approved: Mapping[str, object],
    pr_id: str,
) -> bool:
    """Require the open provider PR to equal every approved mutable field."""

    return bool(
        pr_id
        and observed.get("id") == pr_id
        and str(observed.get("state", "")).upper() in {"OPEN", "OPENED", "OPENING"}
        and observed.get("version")
        and all(observed.get(key) == value for key, value in approved.items())
    )


def _provider_branch(data: Mapping[str, Any], *, source: bool) -> str | None:
    """Normalize Cloud and Data Center branch response shapes."""

    cloud_name = "source" if source else "destination"
    cloud = data.get(cloud_name)
    if isinstance(cloud, Mapping):
        branch = cloud.get("branch")
        if isinstance(branch, Mapping):
            name = branch.get("name")
            return name if isinstance(name, str) and name else None

    server_name = "fromRef" if source else "toRef"
    server = data.get(server_name)
    if not isinstance(server, Mapping):
        return None
    raw_ref = server.get("id")
    if not isinstance(raw_ref, str):
        return None
    ref = raw_ref
    prefix = "refs/heads/"
    return ref[len(prefix) :] if ref.startswith(prefix) else None


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
