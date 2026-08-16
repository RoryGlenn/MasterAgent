"""Approved reversible Confluence space and page writes for Phase 4."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.base import CompensatingConnector
from master_agent.connectors.utils import enforce_expected_version, quote_segment
from master_agent.errors import (
    ConnectorError,
    ResourceNotFoundError,
    VersionConflictError,
)
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
from master_agent.text import html_to_text


class ConfluenceWriteConnector(CompensatingConnector):
    """Create spaces and create or update pages with exact verification."""

    _CAPABILITIES = frozenset(
        {
            "confluence.page.create",
            "confluence.page.update",
            "confluence.page.compensate",
            "confluence.space.create",
        }
    )

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
            allowed_methods=frozenset({"GET", "POST", "PUT", "DELETE"}),
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "confluence"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Execute one approved page mutation."""

        self._validate(action)
        if action.capability == "confluence.space.create":
            result = self._create_space(action)
        elif action.capability == "confluence.page.create":
            result = self._create(action)
        elif action.capability == "confluence.page.update":
            result = self._update(action, compensating=False)
        elif action.capability == "confluence.page.compensate":
            result = self._update(action, compensating=True)
        else:  # pragma: no cover
            raise ConnectorError(
                f"unsupported Confluence capability: {action.capability}"
            )
        if result.after is not None:
            resource_id = str(result.after.get("id", action.target.resource_id))
            self._last[resource_id] = deepcopy(dict(result.after))
            if action.capability == "confluence.space.create":
                self._last[action.target.resource_id] = deepcopy(dict(result.after))
        return result

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return most recently written state."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Re-read the page and compare the exact approved poststate."""

        after = result.after or {}
        if action.capability == "confluence.space.create":
            expected = _approved_space_poststate(action, after)
            observed = self._read_space(str(expected["id"]))
            verified = _space_matches(after, expected) and _space_matches(
                observed, expected
            )
            return VerificationResult(
                action_id=action.action_id,
                verified=verified,
                observed=observed,
                message=(
                    "verified Confluence space by independent re-read"
                    if verified
                    else "Confluence space did not match approved identity"
                ),
            )
        try:
            expected = self._approved_result_poststate(action, result)
        except ConnectorError:
            return VerificationResult(
                action_id=action.action_id,
                verified=False,
                observed=None,
                message="Confluence result did not identify an approved poststate",
            )
        page_id = str(expected["id"])
        observed = self._read_page(
            page_id,
            representation=str(expected["representation"]),
        )
        verified = _poststate_matches(after, expected) and _poststate_matches(
            observed,
            expected,
        )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified Confluence page by independent re-read"
                if verified
                else "Confluence page did not match approved content"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Delete a created page or restore the exact pre-update page body."""

        after = result.after or {}
        if action.capability == "confluence.space.create":
            return self._delete_created_space(action, after)
        page_id = str(after.get("id", action.target.resource_id))
        if result.before is None:
            before = self._read_page(
                page_id,
                representation=str(after.get("representation", "storage")),
            )
            if not _page_matches(before, after):
                raise VersionConflictError(
                    "Confluence page changed after creation; deletion is refused"
                )
            path = (
                f"wiki/api/v2/pages/{quote_segment(page_id)}"
                if self._config.deployment is DeploymentType.CLOUD
                else f"rest/api/content/{quote_segment(page_id)}"
            )
            response = self._client.request_bytes(
                "DELETE",
                path,
                safe_to_retry=False,
            )
            observed = {"id": page_id, "deleted": True}
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before=before,
                after=observed,
                connector_reference=response.url,
                message="deleted Confluence page created by rolled-back workflow",
            )

        current = self._read_page(
            page_id,
            representation=str(after.get("representation", "storage")),
        )
        if not _page_matches(current, after):
            raise VersionConflictError(
                "Confluence page changed after update; rollback is refused"
            )
        prior = result.before
        replacement = AgentAction(
            capability="confluence.page.compensate",
            target=ResourceRef(
                system="confluence",
                resource_type="page",
                resource_id=page_id,
                expected_version=str(current.get("version")),
            ),
            parameters={
                "title": prior.get("title"),
                "body": prior.get("body"),
                "representation": prior.get("representation", "storage"),
                "space_key": prior.get("space_key"),
                "status": prior.get("status") or "current",
                "version_message": "Master Agent verified rollback",
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=action.authority_source,
            requires_approval=False,
            idempotency_key=f"rollback:{action.idempotency_key}",
            justification="Restore the state captured before this action.",
            action_id=action.action_id,
        )
        return self._update(replacement, compensating=True)

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Verify created-page deletion or exact prior content restoration."""

        observed = compensation.after or {}
        if action.capability == "confluence.space.create":
            space_id = str(observed.get("id", ""))
            try:
                self._read_space(space_id)
                verified = False
            except ResourceNotFoundError:
                verified = True
            return VerificationResult(
                action_id=action.action_id,
                verified=verified,
                observed=observed,
                message=(
                    "verified Confluence space rollback"
                    if verified
                    else "Confluence space still exists after rollback"
                ),
            )
        if original.before is None:
            verified = bool(observed.get("deleted"))
        else:
            prior = original.before
            verified = observed.get("title") == prior.get("title") and observed.get(
                "body"
            ) == prior.get("body")
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified Confluence rollback"
                if verified
                else "Confluence rollback did not restore prior state"
            ),
        )

    def _create_space(self, action: AgentAction) -> ExecutionResult:
        if self._config.deployment is not DeploymentType.CLOUD:
            raise ConnectorError("Confluence space creation currently requires Cloud")
        key = _required_text(action.parameters, "key").upper()
        if action.target.resource_type != "space" or action.target.resource_id != key:
            raise ConnectorError(
                "Confluence space creation target must equal the approved space key"
            )
        if len(key) > 255 or not key.isalnum():
            raise ConnectorError(
                "Confluence space key must contain only letters and digits"
            )
        name = _required_text(action.parameters, "name")
        payload: dict[str, Any] = {"key": key, "name": name}
        description = str(action.parameters.get("description", "")).strip()
        if description:
            payload["description"] = {
                "value": description,
                "representation": "plain",
            }
        data, response = self._client.request_json(
            "POST",
            "wiki/api/v2/spaces",
            json_body=payload,
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Confluence create-space response must be an object")
        space_id = _provider_space_id(data)
        observed = self._read_space(space_id)
        expected = _approved_space_poststate(action, {"id": space_id})
        if not _space_matches(observed, expected):
            raise ConnectorError(
                "Confluence create-space provider poststate did not match approved identity"
            )
        observed["compensation"] = {
            "capability": "confluence.space.delete_created",
            "space_id": space_id,
            "space_key": key,
            "created_by_action": True,
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=observed,
            connector_reference=response.url,
            message="Confluence space created",
            compensation=CompensationDescriptor(
                kind="delete_created_space",
                mode=CompensationMode.IN_PROCESS,
                target_resource_id=space_id,
                reason=(
                    "created-space deletion is available only through the "
                    "originating connector run"
                ),
            ).to_dict(),
        )

    def _delete_created_space(
        self,
        action: AgentAction,
        after: Mapping[str, Any],
    ) -> ExecutionResult:
        expected = _approved_space_poststate(action, after)
        space_id = str(expected["id"])
        current = self._read_space(space_id)
        if not _space_matches(current, expected):
            raise VersionConflictError(
                "Confluence space changed after creation; deletion is refused"
            )
        homepage_id = str(current.get("homepage_id", "")).strip()
        page_ids = self._read_space_page_ids(space_id)
        if any(page_id != homepage_id for page_id in page_ids):
            raise VersionConflictError(
                "Confluence space contains another page; deletion is refused"
            )
        response = self._client.request_bytes(
            "DELETE",
            f"wiki/rest/api/space/{quote_segment(str(expected['key']))}",
            safe_to_retry=False,
        )
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=current,
            after={"id": space_id, "key": expected["key"], "deleted": True},
            connector_reference=response.url,
            message="deleted Confluence space created by rolled-back workflow",
        )

    def _create(self, action: AgentAction) -> ExecutionResult:
        title = _required_text(action.parameters, "title")
        body = _required_text(action.parameters, "body")
        representation = _representation_for_deployment(
            action.parameters,
            self._config.deployment,
        )
        if self._config.deployment is DeploymentType.CLOUD:
            space_id = str(action.parameters.get("space_id", "")).strip()
            if not space_id:
                space_key = _required_text(action.parameters, "space_key").upper()
                space_id = self._resolve_cloud_space_id(space_key)
            payload: dict[str, Any] = {
                "spaceId": space_id,
                "status": str(action.parameters.get("status", "draft")),
                "title": title,
                "body": {"representation": representation, "value": body},
            }
            parent_id = str(action.parameters.get("parent_id", "")).strip()
            if parent_id:
                payload["parentId"] = parent_id
            data, response = self._client.request_json(
                "POST",
                "wiki/api/v2/pages",
                json_body=payload,
            )
        else:
            space_key = _required_text(action.parameters, "space_key")
            payload = {
                "type": "page",
                "title": title,
                "space": {"key": space_key},
                "body": {"storage": {"value": body, "representation": "storage"}},
            }
            parent_id = str(action.parameters.get("parent_id", "")).strip()
            if parent_id:
                payload["ancestors"] = [{"id": parent_id}]
            data, response = self._client.request_json(
                "POST",
                "rest/api/content",
                json_body=payload,
            )
        if not isinstance(data, Mapping) or not data.get("id"):
            raise ConnectorError("Confluence create response omitted a page ID")
        page_id = _provider_page_id(data)
        after = self._read_page(page_id, representation=representation)
        if (
            self._config.deployment is DeploymentType.CLOUD
            and str(after.get("space_id", "")) != space_id
        ):
            raise ConnectorError(
                "Confluence create provider poststate used another space"
            )
        expected = _approved_poststate(
            action,
            page_id=page_id,
            version=1,
            deployment=self._config.deployment,
        )
        _require_poststate(after, expected, "create")
        after["compensation"] = {
            "capability": "confluence.page.delete_created",
            "page_id": page_id,
            "created_by_action": True,
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=after,
            connector_reference=response.url,
            message="Confluence page created",
            compensation=CompensationDescriptor(
                kind="delete_created_page",
                mode=CompensationMode.IN_PROCESS,
                target_resource_id=page_id,
                reason=(
                    "created-page deletion is available only through the "
                    "originating connector run"
                ),
            ).to_dict(),
        )

    def _update(self, action: AgentAction, *, compensating: bool) -> ExecutionResult:
        page_id = action.target.resource_id
        title = _required_text(action.parameters, "title")
        body = _required_text(action.parameters, "body")
        representation = _representation_for_deployment(
            action.parameters,
            self._config.deployment,
        )
        next_version = _expected_updated_version(action)
        before = self._read_page(page_id)
        if before.get("id") != page_id:
            raise ConnectorError(
                "Confluence update prestate did not match the approved resource ID"
            )
        enforce_expected_version(action, before.get("version"))
        message = str(action.parameters.get("version_message", "")).strip()

        if self._config.deployment is DeploymentType.CLOUD:
            payload: dict[str, Any] = {
                "id": page_id,
                "status": str(
                    action.parameters.get("status", before.get("status") or "current")
                ),
                "title": title,
                "body": {"representation": representation, "value": body},
                "version": {"number": next_version},
            }
            if message:
                payload["version"]["message"] = message
            _, response = self._client.request_json(
                "PUT",
                f"wiki/api/v2/pages/{quote_segment(page_id)}",
                json_body=payload,
            )
        else:
            space_key = str(
                action.parameters.get("space_key", before.get("space_key") or "")
            ).strip()
            if not space_key:
                raise ConnectorError("Confluence Data Center update requires space_key")
            payload = {
                "id": page_id,
                "type": "page",
                "title": title,
                "space": {"key": space_key},
                "body": {"storage": {"value": body, "representation": "storage"}},
                "version": {"number": next_version},
            }
            if message:
                payload["version"]["message"] = message
            _, response = self._client.request_json(
                "PUT",
                f"rest/api/content/{quote_segment(page_id)}",
                json_body=payload,
            )

        observed = self._read_page(page_id, representation=representation)
        expected = _approved_poststate(
            action,
            page_id=page_id,
            version=next_version,
            deployment=self._config.deployment,
        )
        _require_poststate(observed, expected, "update")
        observed["compensation"] = {
            "capability": "confluence.page.compensate",
            "title": before.get("title"),
            "body": before.get("body"),
            "representation": before.get("representation", "storage"),
            "space_key": before.get("space_key"),
            "expected_version": observed.get("version"),
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=observed,
            connector_reference=response.url,
            message=(
                "Confluence compensation update accepted"
                if compensating
                else "Confluence page update accepted"
            ),
            compensation=CompensationDescriptor.from_dict(
                observed["compensation"]
            ).to_dict(),
        )

    def _approved_result_poststate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> dict[str, Any]:
        if action.capability == "confluence.page.create":
            page_id = _provider_page_id(result.after or {})
            version = 1
        else:
            page_id = action.target.resource_id
            version = _expected_updated_version(action)
        return _approved_poststate(
            action,
            page_id=page_id,
            version=version,
            deployment=self._config.deployment,
        )

    def _read_page(
        self,
        page_id: str,
        *,
        representation: str = "storage",
    ) -> dict[str, Any]:
        encoded = quote_segment(page_id)
        if self._config.deployment is DeploymentType.CLOUD:
            data, response = self._client.request_json(
                "GET",
                f"wiki/api/v2/pages/{encoded}",
                query={"body-format": representation},
            )
            if not isinstance(data, Mapping):
                raise ConnectorError("Confluence page response must be an object")
            body_value, observed_representation = _cloud_body(
                data,
                preferred_representation=representation,
            )
            version = data.get("version")
            version = version if isinstance(version, Mapping) else {}
            return {
                "id": _provider_page_id(data),
                "title": str(data.get("title", "")),
                "status": data.get("status"),
                "version": _provider_version(version.get("number")),
                "space_id": data.get("spaceId"),
                "space_key": None,
                "body": body_value,
                "body_text": html_to_text(body_value)
                if observed_representation == "storage"
                else body_value,
                "representation": observed_representation,
                "reference": response.url,
            }

        data, response = self._client.request_json(
            "GET",
            f"rest/api/content/{encoded}",
            query={"expand": "body.storage,version,space"},
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Confluence page response must be an object")
        body = data.get("body")
        body = body if isinstance(body, Mapping) else {}
        storage = body.get("storage")
        storage = storage if isinstance(storage, Mapping) else {}
        version = data.get("version")
        version = version if isinstance(version, Mapping) else {}
        space = data.get("space")
        space = space if isinstance(space, Mapping) else {}
        body_value = str(storage.get("value", ""))
        return {
            "id": _provider_page_id(data),
            "title": str(data.get("title", "")),
            "status": data.get("status"),
            "version": _provider_version(version.get("number")),
            "space_id": space.get("id"),
            "space_key": space.get("key"),
            "body": body_value,
            "body_text": html_to_text(body_value),
            "representation": "storage",
            "reference": response.url,
        }

    def _read_space(self, space_id: str) -> dict[str, Any]:
        data, response = self._client.request_json(
            "GET",
            f"wiki/api/v2/spaces/{quote_segment(space_id)}",
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Confluence space response must be an object")
        return {
            "id": _provider_space_id(data),
            "key": str(data.get("key", "")),
            "name": str(data.get("name", "")),
            "type": data.get("type"),
            "status": data.get("status"),
            "homepage_id": data.get("homepageId"),
            "reference": response.url,
        }

    def _resolve_cloud_space_id(self, space_key: str) -> str:
        data, _ = self._client.request_json(
            "GET",
            "wiki/api/v2/spaces",
            query={"keys": space_key, "limit": 2},
        )
        if not isinstance(data, Mapping) or not isinstance(data.get("results"), list):
            raise ConnectorError(
                "Confluence space lookup response must contain results"
            )
        matches = [
            item
            for item in data["results"]
            if isinstance(item, Mapping)
            and str(item.get("key", "")).upper() == space_key
        ]
        if len(matches) != 1:
            raise ConnectorError(
                "Confluence space key did not resolve to exactly one visible space"
            )
        return _provider_space_id(matches[0])

    def _read_space_page_ids(self, space_id: str) -> tuple[str, ...]:
        data, _ = self._client.request_json(
            "GET",
            f"wiki/api/v2/spaces/{quote_segment(space_id)}/pages",
            query={"limit": 2},
        )
        if not isinstance(data, Mapping) or not isinstance(data.get("results"), list):
            raise ConnectorError("Confluence space-page response must contain results")
        return tuple(
            _provider_page_id(item)
            for item in data["results"]
            if isinstance(item, Mapping)
        )

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("Confluence write connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported Confluence write capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("Confluence writes must use reversible_write risk")
        if (
            action.capability == "confluence.space.create"
            and self._config.deployment is not DeploymentType.CLOUD
        ):
            raise ConnectorError("Confluence space creation currently requires Cloud")


def _cloud_body(
    page: Mapping[str, Any],
    *,
    preferred_representation: str,
) -> tuple[str, str]:
    body = page.get("body")
    body = body if isinstance(body, Mapping) else {}
    fallback = (
        "atlas_doc_format" if preferred_representation == "storage" else "storage"
    )
    for representation in (preferred_representation, fallback):
        value = body.get(representation)
        if isinstance(value, Mapping):
            return str(value.get("value", "")), representation
    return "", "storage"


def _page_matches(observed: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(
        observed.get(key) == expected.get(key)
        for key in ("id", "title", "body", "representation", "version")
    )


def _approved_poststate(
    action: AgentAction,
    *,
    page_id: str,
    version: int,
    deployment: DeploymentType,
) -> dict[str, Any]:
    return {
        "id": page_id,
        "title": _required_text(action.parameters, "title"),
        "body": _required_text(action.parameters, "body"),
        "representation": _representation_for_deployment(
            action.parameters,
            deployment,
        ),
        "version": version,
    }


def _poststate_matches(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> bool:
    for key in ("id", "title", "body", "representation", "version"):
        actual = observed.get(key)
        approved = expected.get(key)
        if type(actual) is not type(approved) or actual != approved:
            return False
    return True


def _require_poststate(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
    operation: str,
) -> None:
    if not _poststate_matches(observed, expected):
        raise ConnectorError(
            f"Confluence {operation} provider poststate did not match approved content"
        )


def _provider_page_id(data: Mapping[str, Any]) -> str:
    value = data.get("id")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ConnectorError("Confluence page response omitted a page ID")
    rendered = str(value).strip()
    if not rendered:
        raise ConnectorError("Confluence page response omitted a page ID")
    return rendered


def _provider_space_id(data: Mapping[str, Any]) -> str:
    value = data.get("id")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ConnectorError("Confluence space response omitted a space ID")
    rendered = str(value).strip()
    if not rendered:
        raise ConnectorError("Confluence space response omitted a space ID")
    return rendered


def _approved_space_poststate(
    action: AgentAction,
    observed: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": _provider_space_id(observed),
        "key": _required_text(action.parameters, "key").upper(),
        "name": _required_text(action.parameters, "name"),
        "type": "global",
        "status": "current",
    }


def _space_matches(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> bool:
    return all(
        type(observed.get(key)) is type(expected.get(key))
        and observed.get(key) == expected.get(key)
        for key in ("id", "key", "name", "type", "status")
    )


def _provider_version(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConnectorError("Confluence page response has an invalid version")
    return value


def _expected_updated_version(action: AgentAction) -> int:
    expected = action.target.expected_version
    if expected is None or not expected.isdecimal():
        raise ConnectorError(
            "Confluence update requires a numeric approved expected_version"
        )
    current = int(expected)
    if current < 1 or str(current) != expected:
        raise ConnectorError(
            "Confluence update requires a normalized positive expected_version"
        )
    return current + 1


def _required_text(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip()
    if not value:
        raise ConnectorError(f"missing required parameter: {key}")
    return value


def _representation(parameters: Mapping[str, Any]) -> str:
    value = str(parameters.get("representation", "storage")).strip()
    if value not in {"storage", "atlas_doc_format"}:
        raise ConnectorError("representation must be storage or atlas_doc_format")
    return value


def _representation_for_deployment(
    parameters: Mapping[str, Any],
    deployment: DeploymentType,
) -> str:
    value = _representation(parameters)
    if deployment is DeploymentType.DATA_CENTER and value != "storage":
        raise ConnectorError(
            "Confluence Data Center writes require storage representation"
        )
    return value
