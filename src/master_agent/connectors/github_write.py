"""Bounded GitHub write and administration capabilities."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.utils import (
    enforce_expected_version,
    quote_segment,
    string_parameter,
)
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

_COORDINATE = re.compile(r"^[A-Za-z0-9_.-]+$")
_REPOSITORY_SETTINGS = frozenset(
    {
        "has_issues",
        "has_projects",
        "has_wiki",
        "has_discussions",
        "allow_squash_merge",
        "allow_merge_commit",
        "allow_rebase_merge",
        "allow_auto_merge",
        "delete_branch_on_merge",
        "web_commit_signoff_required",
    }
)
_COLLABORATOR_ROLES = frozenset({"pull", "triage", "push", "maintain", "admin"})


class GitHubWriteConnector:
    """Create GitHub issues and pull requests with verified manual recovery."""

    _CAPABILITIES = frozenset({"github.issue.create", "github.pull_request.create"})

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        _validate_config(config)
        self._config = config
        self._client = _client(config, transport, frozenset({"GET", "POST", "PATCH"}))
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        return "github"

    @property
    def capabilities(self) -> frozenset[str]:
        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        self._validate(action)
        owner, repository = _coordinates(action.parameters)
        repository_path = _repository_path(owner, repository)
        if action.capability == "github.issue.create":
            approved = _approved_issue(action)
            data, response = self._client.request_json(
                "POST", f"{repository_path}/issues", json_body=approved
            )
            kind = "issue"
        else:
            approved = _approved_pull_request(action)
            data, response = self._client.request_json(
                "POST", f"{repository_path}/pulls", json_body=approved
            )
            kind = "pull_request"
        if not isinstance(data, Mapping):
            raise ConnectorError(f"GitHub {kind} create response must be an object")
        number = _positive_number(data.get("number"), name=f"{kind} number")
        observed = self._read_created(kind, owner, repository, number)
        if not _created_matches(kind, observed, approved, number, require_open=True):
            raise ConnectorError(
                f"GitHub provider poststate did not match the approved {kind}"
            )
        after = {**observed, "owner": owner, "repository": repository}
        self._last[str(number)] = deepcopy(after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=after,
            connector_reference=str(observed.get("web_url") or response.url),
            message=f"GitHub {kind.replace('_', ' ')} created",
            compensation=CompensationDescriptor(
                kind=f"close_{kind}",
                mode=CompensationMode.MANUAL,
                target_resource_id=str(number),
                reason=(
                    "GitHub close has no adapter-enforced atomic precondition, so a "
                    "human must re-read and close the created resource manually"
                ),
            ),
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self, action: AgentAction, result: ExecutionResult
    ) -> VerificationResult:
        after = result.after or {}
        number = _positive_number(after.get("number"), name="created resource number")
        owner, repository = _coordinates(action.parameters)
        kind = "issue" if action.capability == "github.issue.create" else "pull_request"
        approved = (
            _approved_issue(action)
            if kind == "issue"
            else _approved_pull_request(action)
        )
        observed = self._read_created(kind, owner, repository, number)
        verified = _created_matches(kind, observed, approved, number, require_open=True)
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                f"verified GitHub {kind.replace('_', ' ')} by independent re-read"
                if verified
                else f"GitHub {kind.replace('_', ' ')} did not match approved fields"
            ),
        )

    def compensate(
        self, action: AgentAction, result: ExecutionResult
    ) -> ExecutionResult:
        after = result.after or {}
        number = _positive_number(after.get("number"), name="created resource number")
        owner, repository = _coordinates(action.parameters)
        kind = "issue" if action.capability == "github.issue.create" else "pull_request"
        approved = (
            _approved_issue(action)
            if kind == "issue"
            else _approved_pull_request(action)
        )
        current = self._read_created(kind, owner, repository, number)
        if not _created_matches(
            kind, current, approved, number, require_open=True
        ) or current.get("version") != after.get("version"):
            raise VersionConflictError(
                f"GitHub {kind.replace('_', ' ')} changed after creation; close is refused"
            )
        endpoint = "issues" if kind == "issue" else "pulls"
        path = f"{_repository_path(owner, repository)}/{endpoint}/{number}"
        self._client.request_json("PATCH", path, json_body={"state": "closed"})
        observed = self._read_created(kind, owner, repository, number)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=after,
            after=observed,
            connector_reference=str(observed.get("web_url") or path),
            message=f"GitHub {kind.replace('_', ' ')} closed",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        after = original.after or {}
        number = _positive_number(after.get("number"), name="created resource number")
        owner, repository = _coordinates(action.parameters)
        kind = "issue" if action.capability == "github.issue.create" else "pull_request"
        approved = (
            _approved_issue(action)
            if kind == "issue"
            else _approved_pull_request(action)
        )
        observed = self._read_created(kind, owner, repository, number)
        verified = bool(
            observed.get("state") == "closed"
            and _created_matches(kind, observed, approved, number, require_open=False)
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                f"verified closed GitHub {kind.replace('_', ' ')}"
                if verified
                else f"GitHub {kind.replace('_', ' ')} remains open after compensation"
            ),
        )

    def _read_created(
        self, kind: str, owner: str, repository: str, number: int
    ) -> dict[str, Any]:
        endpoint = "issues" if kind == "issue" else "pulls"
        data, response = self._client.request_json(
            "GET", f"{_repository_path(owner, repository)}/{endpoint}/{number}"
        )
        if not isinstance(data, Mapping):
            raise ConnectorError(f"GitHub {kind} response must be an object")
        if kind == "issue" and "pull_request" in data:
            raise ConnectorError("GitHub issue endpoint returned a pull request")
        return _normalize_created(kind, data, response.url)

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("GitHub write connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported GitHub write capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("GitHub creation must use reversible_write risk")


class GitHubAdminConnector:
    """Update bounded repository settings or an existing collaborator's role."""

    _CAPABILITIES = frozenset(
        {"github.repository.settings.update", "github.collaborator.access.update"}
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        _validate_config(config)
        self._config = config
        self._client = _client(
            config, transport, frozenset({"GET", "PUT", "PATCH", "DELETE"})
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        return "github"

    @property
    def capabilities(self) -> frozenset[str]:
        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        self._validate(action)
        if action.capability == "github.repository.settings.update":
            result = self._update_settings(action)
        else:
            result = self._update_collaborator(action)
        if result.after is not None:
            self._last[action.target.resource_id] = deepcopy(dict(result.after))
        return result

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self, action: AgentAction, result: ExecutionResult
    ) -> VerificationResult:
        owner, repository = _coordinates(action.parameters)
        if action.capability == "github.repository.settings.update":
            observed = self._read_settings(owner, repository)
            approved = _approved_settings(action)
            verified = _settings_match(observed, approved)
        else:
            username = _coordinate(
                string_parameter(action.parameters, "username", required=True),
                "username",
            )
            observed = self._read_collaborator(owner, repository, username)
            role = _approved_role(action)
            verified = _collaborator_matches(observed, username, role)
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified GitHub administration change by independent re-read"
                if verified
                else "GitHub administration state did not match the approved change"
            ),
        )

    def compensate(
        self, action: AgentAction, result: ExecutionResult
    ) -> ExecutionResult:
        if action.capability != "github.repository.settings.update":
            raise ConnectorError(
                "collaborator access has no automatic rollback because GitHub reports "
                "only the highest effective role"
            )
        owner, repository = _coordinates(action.parameters)
        approved = _approved_settings(action)
        current = self._read_settings(owner, repository)
        if not _settings_match(current, approved):
            raise VersionConflictError(
                "GitHub repository settings changed after update; rollback is refused"
            )
        before = result.before or {}
        prior = before.get("settings")
        if not isinstance(prior, Mapping) or set(prior) != set(approved):
            raise ConnectorError("GitHub settings rollback has no exact prior values")
        path = _repository_path(owner, repository)
        self._client.request_json("PATCH", path, json_body=dict(prior))
        observed = self._read_settings(owner, repository)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=result.after,
            after=observed,
            connector_reference=str(observed["reference"]),
            message="GitHub repository settings restored",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        owner, repository = _coordinates(action.parameters)
        observed = self._read_settings(owner, repository)
        before = original.before or {}
        prior = before.get("settings")
        verified = isinstance(prior, Mapping) and _settings_match(observed, prior)
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified restored GitHub repository settings"
                if verified
                else "GitHub repository settings were not restored"
            ),
        )

    def _update_settings(self, action: AgentAction) -> ExecutionResult:
        owner, repository = _coordinates(action.parameters)
        approved = _approved_settings(action)
        before = self._read_settings(owner, repository)
        enforce_expected_version(action, before.get("version"))
        missing = set(approved) - set(before["settings"])
        if missing:
            raise ConnectorError(
                "GitHub repository response omitted approved settings: "
                + ", ".join(sorted(missing))
            )
        prior = {key: before["settings"][key] for key in approved}
        path = _repository_path(owner, repository)
        self._client.request_json("PATCH", path, json_body=approved)
        observed = self._read_settings(owner, repository)
        if not _settings_match(observed, approved):
            raise ConnectorError("GitHub repository settings poststate did not match")
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before={**before, "settings": prior},
            after=observed,
            connector_reference=str(observed["reference"]),
            message="GitHub repository settings updated",
            compensation=CompensationDescriptor(
                kind="restore_repository_settings",
                mode=CompensationMode.MANUAL,
                target_resource_id=f"{owner}/{repository}",
                reason=(
                    "repository-settings restore has no atomic provider precondition "
                    "and requires manual re-review"
                ),
            ),
        )

    def _update_collaborator(self, action: AgentAction) -> ExecutionResult:
        owner, repository = _coordinates(action.parameters)
        username = _coordinate(
            string_parameter(action.parameters, "username", required=True), "username"
        )
        role = _approved_role(action)
        before = self._read_collaborator(owner, repository, username)
        if before.get("role_name") in {None, "none"}:
            raise ConnectorError(
                "GitHub collaborator access update requires an existing collaborator; "
                "invitations are not supported"
            )
        path = (
            f"{_repository_path(owner, repository)}/collaborators/"
            f"{quote_segment(username)}"
        )
        response = self._client.request_bytes(
            "PUT",
            path,
            json_body={"permission": role},
        )
        if response.status != 204:
            invitation = response.json()
            invitation_id = (
                invitation.get("id") if isinstance(invitation, Mapping) else None
            )
            if not isinstance(invitation_id, int) or isinstance(invitation_id, bool):
                raise ConnectorError(
                    "GitHub returned an unexpected collaborator invitation response"
                )
            self._client.request_bytes(
                "DELETE",
                f"{_repository_path(owner, repository)}/invitations/{invitation_id}",
            )
            raise VersionConflictError(
                "GitHub collaborator disappeared during update; the resulting "
                "invitation was cancelled and the role change failed"
            )
        observed = self._read_collaborator(owner, repository, username)
        if not _collaborator_matches(observed, username, role):
            raise ConnectorError("GitHub collaborator role poststate did not match")
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=observed,
            connector_reference=str(observed["reference"]),
            message="GitHub existing collaborator role updated",
            compensation=CompensationDescriptor(
                kind="manual_collaborator_role_review",
                mode=CompensationMode.MANUAL,
                target_resource_id=username,
                reason=(
                    "GitHub exposes the highest effective role, so the source grant "
                    "cannot be safely restored automatically"
                ),
            ),
        )

    def _read_settings(self, owner: str, repository: str) -> dict[str, Any]:
        data, response = self._client.request_json(
            "GET", _repository_path(owner, repository)
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("GitHub repository response must be an object")
        full_name = data.get("full_name")
        if not isinstance(full_name, str) or full_name.casefold() != (
            f"{owner}/{repository}".casefold()
        ):
            raise ConnectorError("GitHub repository response identity did not match")
        settings: dict[str, bool] = {}
        for key in _REPOSITORY_SETTINGS:
            value = data.get(key)
            if isinstance(value, bool):
                settings[key] = value
        return {
            "owner": owner,
            "repository": repository,
            "settings": settings,
            "version": data.get("updated_at"),
            "reference": response.url,
        }

    def _read_collaborator(
        self, owner: str, repository: str, username: str
    ) -> dict[str, Any]:
        path = (
            f"{_repository_path(owner, repository)}/collaborators/"
            f"{quote_segment(username)}/permission"
        )
        data, response = self._client.request_json("GET", path)
        if not isinstance(data, Mapping):
            raise ConnectorError(
                "GitHub collaborator permission response must be an object"
            )
        user = data.get("user")
        login = user.get("login") if isinstance(user, Mapping) else None
        if not isinstance(login, str) or login.casefold() != username.casefold():
            raise ConnectorError("GitHub collaborator response identity did not match")
        role_name = data.get("role_name")
        if not isinstance(role_name, str) or not role_name:
            raise ConnectorError("GitHub collaborator response omitted role_name")
        return {
            "owner": owner,
            "repository": repository,
            "username": login,
            "role_name": role_name,
            "permission": data.get("permission"),
            "reference": response.url,
        }

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("GitHub admin connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported GitHub admin capability: {action.capability}"
            )
        expected_risk = (
            RiskLevel.REVERSIBLE_WRITE
            if action.capability == "github.repository.settings.update"
            else RiskLevel.HIGH_IMPACT
        )
        if action.risk is not expected_risk:
            raise ConnectorError(
                f"GitHub administration must use {expected_risk.value} risk"
            )


def _client(
    config: ResolvedConnectorConfig,
    transport: HttpTransport | None,
    methods: frozenset[str],
) -> SafeHttpClient:
    return SafeHttpClient(
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
        allowed_methods=methods,
    )


def _validate_config(config: ResolvedConnectorConfig) -> None:
    if config.system != "github":
        raise ConnectorError("GitHub connector requires github configuration")
    if config.deployment is not DeploymentType.CLOUD:
        raise ConnectorError("GitHub connector currently supports cloud only")


def _coordinate(value: str, name: str) -> str:
    if not _COORDINATE.fullmatch(value):
        raise ConnectorError(f"unsafe GitHub {name}")
    return value


def _coordinates(parameters: Mapping[str, Any]) -> tuple[str, str]:
    return (
        _coordinate(string_parameter(parameters, "owner", required=True), "owner"),
        _coordinate(
            string_parameter(parameters, "repository", required=True), "repository"
        ),
    )


def _repository_path(owner: str, repository: str) -> str:
    return f"repos/{quote_segment(owner)}/{quote_segment(repository)}"


def _positive_number(value: object, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConnectorError(f"GitHub {name} must be a positive integer")
    return value


def _optional_string(parameters: Mapping[str, Any], key: str, default: str = "") -> str:
    value = parameters.get(key, default)
    if not isinstance(value, str):
        raise ConnectorError(f"{key} must be a string")
    return value


def _approved_issue(action: AgentAction) -> dict[str, object]:
    return {
        "title": string_parameter(action.parameters, "title", required=True),
        "body": _optional_string(action.parameters, "body"),
    }


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


def _approved_pull_request(action: AgentAction) -> dict[str, object]:
    draft = action.parameters.get("draft", False)
    if not isinstance(draft, bool):
        raise ConnectorError("draft must be a boolean")
    return {
        "title": string_parameter(action.parameters, "title", required=True),
        "body": _optional_string(action.parameters, "body"),
        "head": _safe_branch(
            string_parameter(action.parameters, "head", required=True)
        ),
        "base": _safe_branch(
            string_parameter(action.parameters, "base", required=True)
        ),
        "draft": draft,
    }


def _normalize_created(
    kind: str, data: Mapping[str, Any], reference: str
) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "number": _positive_number(data.get("number"), name=f"{kind} number"),
        "title": data.get("title"),
        "body": data.get("body") if isinstance(data.get("body"), str) else "",
        "state": data.get("state"),
        "version": data.get("updated_at"),
        "web_url": data.get("html_url"),
        "reference": reference,
    }
    if kind == "pull_request":
        for key in ("head", "base"):
            value = data.get(key)
            normalized[key] = value.get("ref") if isinstance(value, Mapping) else None
        normalized["draft"] = data.get("draft")
    return normalized


def _created_matches(
    kind: str,
    observed: Mapping[str, Any],
    approved: Mapping[str, object],
    number: int,
    *,
    require_open: bool,
) -> bool:
    fields = (
        ("title", "body")
        if kind == "issue"
        else ("title", "body", "head", "base", "draft")
    )
    return bool(
        observed.get("number") == number
        and observed.get("version")
        and (not require_open or observed.get("state") == "open")
        and all(observed.get(key) == approved[key] for key in fields)
    )


def _approved_settings(action: AgentAction) -> dict[str, bool]:
    raw = action.parameters.get("settings")
    if not isinstance(raw, Mapping) or not raw:
        raise ConnectorError("settings must be a non-empty object")
    unknown = set(raw) - _REPOSITORY_SETTINGS
    if unknown:
        raise ConnectorError(
            "unsupported GitHub repository settings: " + ", ".join(sorted(unknown))
        )
    if not all(isinstance(value, bool) for value in raw.values()):
        raise ConnectorError("GitHub repository settings must be booleans")
    return {str(key): bool(value) for key, value in raw.items()}


def _settings_match(observed: Mapping[str, Any], approved: Mapping[str, Any]) -> bool:
    settings = observed.get("settings")
    return isinstance(settings, Mapping) and all(
        settings.get(key) == value for key, value in approved.items()
    )


def _approved_role(action: AgentAction) -> str:
    role = string_parameter(action.parameters, "role", required=True).casefold()
    if role not in _COLLABORATOR_ROLES:
        raise ConnectorError(
            "GitHub collaborator role must be pull, triage, push, maintain, or admin"
        )
    return role


def _collaborator_matches(
    observed: Mapping[str, Any], username: str, role: object
) -> bool:
    return bool(
        isinstance(role, str)
        and str(observed.get("username", "")).casefold() == username.casefold()
        and observed.get("role_name") == role
    )
