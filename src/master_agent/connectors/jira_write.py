"""Approved reversible Jira write capabilities for Phase 4."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.base import CompensatingConnector
from master_agent.connectors.utils import (
    enforce_expected_version,
    quote_segment,
    string_parameter,
)
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


class JiraWriteConnector(CompensatingConnector):
    """Perform version-checked Jira updates, comments, and transitions."""

    _CAPABILITIES = frozenset(
        {
            "jira.issue.update",
            "jira.issue.comment.create",
            "jira.issue.transition",
            "jira.issue.compensate",
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
            proxy_url=config.proxy_url,
            proxy_username=config.proxy_username,
            proxy_password=config.proxy_password,
            allowed_methods=frozenset({"GET", "POST", "PUT", "DELETE"}),
        )
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return connector system."""

        return "jira"

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported write capabilities."""

        return self._CAPABILITIES

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Execute one policy-approved Jira write."""

        self._validate(action)
        if action.capability == "jira.issue.update":
            result = self._update_issue(action)
        elif action.capability == "jira.issue.comment.create":
            result = self._create_comment(action)
        elif action.capability == "jira.issue.transition":
            result = self._transition_issue(action)
        elif action.capability == "jira.issue.compensate":
            result = self._compensate(action)
        else:  # pragma: no cover - guarded by _validate.
            raise ConnectorError(f"unsupported Jira capability: {action.capability}")
        if result.after is not None:
            self._last[action.target.resource_id] = deepcopy(dict(result.after))
        return result

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return the most recently written normalized state."""

        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Re-read Jira and verify the expected mutation."""

        if action.capability == "jira.issue.comment.create":
            after = result.after or {}
            comment_id = after.get("comment_id")
            if not isinstance(comment_id, str) or not comment_id:
                return VerificationResult(
                    action_id=action.action_id,
                    verified=False,
                    observed=None,
                    message="Jira comment response omitted an ID",
                )
            observed = self._read_comment(action.target.resource_id, comment_id)
            expected_body = string_parameter(action.parameters, "body", required=True)
            expected_payload: object = (
                _text_to_adf(expected_body)
                if self._config.deployment is DeploymentType.CLOUD
                else expected_body
            )
            verified = bool(
                observed.get("comment_id") == comment_id
                and _json_values_equal(observed.get("body"), expected_payload)
            )
            return VerificationResult(
                action_id=action.action_id,
                verified=verified,
                observed=observed,
                message=(
                    "verified Jira comment by independent re-read"
                    if verified
                    else "Jira comment body did not match"
                ),
            )

        observed = self._read_issue(action.target.resource_id)
        after = result.after or {}
        if action.capability in {"jira.issue.update", "jira.issue.compensate"}:
            expected_fields = _mapping_parameter(action.parameters, "fields")
            verified = _issue_poststate_matches(
                action,
                observed,
                expected_version=after.get("version"),
                expected_fields=expected_fields,
            )
        else:
            target_status = string_parameter(
                action.parameters,
                "target_status",
                required=True,
            )
            verified = _issue_poststate_matches(
                action,
                observed,
                expected_version=after.get("version"),
                expected_status=target_status,
            )
        return VerificationResult(
            action_id=action.action_id,
            verified=bool(verified),
            observed=observed,
            message=(
                "verified Jira mutation by independent re-read"
                if verified
                else "Jira state did not match the approved mutation"
            ),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Restore fields, remove a created comment, or run an explicit reverse transition."""

        before_state = self._read_issue(action.target.resource_id)
        if action.capability == "jira.issue.update":
            expected_after = result.after or {}
            approved_fields = _mapping_parameter(action.parameters, "fields")
            if before_state.get("version") != expected_after.get(
                "version"
            ) or not _fields_match(
                before_state.get("fields"),
                approved_fields,
            ):
                raise VersionConflictError(
                    "Jira issue changed after update; rollback is refused"
                )
            fields = _previous_values(
                (result.before or {}).get("fields"),
                approved_fields,
            )
            rollback = AgentAction(
                capability="jira.issue.compensate",
                target=ResourceRef(
                    system="jira",
                    resource_type="issue",
                    resource_id=action.target.resource_id,
                    expected_version=str(before_state.get("version")),
                ),
                parameters={"fields": dict(fields)},
                risk=RiskLevel.REVERSIBLE_WRITE,
                authority_source=action.authority_source,
                requires_approval=False,
                idempotency_key=f"rollback:{action.idempotency_key}",
                justification="Restore Jira fields captured before this action.",
                action_id=action.action_id,
            )
            return self._compensate(rollback)

        if action.capability == "jira.issue.comment.create":
            raw_comment_id = (result.after or {}).get("comment_id")
            if not isinstance(raw_comment_id, str) or not raw_comment_id.strip():
                raise ConnectorError("Jira comment rollback has no comment ID")
            comment_id = raw_comment_id.strip()
            expected_body = string_parameter(
                action.parameters,
                "body",
                required=True,
            )
            expected_payload: object = (
                _text_to_adf(expected_body)
                if self._config.deployment is DeploymentType.CLOUD
                else expected_body
            )
            current_comment = self._read_comment(
                action.target.resource_id,
                comment_id,
            )
            if current_comment.get(
                "comment_id"
            ) != comment_id or not _json_values_equal(
                current_comment.get("body"),
                expected_payload,
            ):
                raise VersionConflictError(
                    "Jira comment changed after creation; deletion is refused"
                )
            response = self._client.request_bytes(
                "DELETE",
                (
                    f"rest/api/{self._api}/issue/"
                    f"{quote_segment(action.target.resource_id)}/comment/"
                    f"{quote_segment(comment_id)}"
                ),
                safe_to_retry=False,
            )
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before={"comment_id": comment_id},
                after={"comment_id": comment_id, "deletion_requested": True},
                connector_reference=response.url,
                message="Jira comment deletion request accepted",
            )

        if action.capability == "jira.issue.transition":
            expected_after = result.after or {}
            if before_state.get("version") != expected_after.get(
                "version"
            ) or before_state.get("status") != expected_after.get("status"):
                raise VersionConflictError(
                    "Jira issue changed after transition; reversal is refused"
                )
            reverse_id = string_parameter(
                action.parameters,
                "reverse_transition_id",
                required=True,
            )
            previous_status = (result.before or {}).get("status")
            if not isinstance(previous_status, str) or not previous_status:
                raise ConnectorError("Jira transition prior status is unavailable")
            response = self._client.request_bytes(
                "POST",
                (
                    f"rest/api/{self._api}/issue/"
                    f"{quote_segment(action.target.resource_id)}/transitions"
                ),
                json_body={"transition": {"id": reverse_id}},
                safe_to_retry=False,
            )
            observed = self._read_issue(action.target.resource_id)
            if not _issue_poststate_matches(
                action,
                observed,
                prior_version=before_state.get("version"),
                expected_status=previous_status,
            ):
                raise ConnectorError(
                    "Jira provider poststate did not match the captured prior status"
                )
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before=before_state,
                after=observed,
                connector_reference=response.url,
                message="applied configured reverse Jira transition",
            )
        raise ConnectorError("unsupported Jira compensation action")

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Independently verify rollback against the captured original state."""

        if action.capability == "jira.issue.comment.create":
            raw_comment_id = (original.after or {}).get("comment_id")
            if not isinstance(raw_comment_id, str) or not raw_comment_id.strip():
                return VerificationResult(
                    action_id=action.action_id,
                    verified=False,
                    observed=None,
                    message="Jira comment rollback has no provider ID",
                )
            comment_id = raw_comment_id.strip()
            try:
                observed = self._read_comment(
                    action.target.resource_id,
                    comment_id,
                )
            except ResourceNotFoundError:
                return VerificationResult(
                    action_id=action.action_id,
                    verified=True,
                    observed={"comment_id": comment_id, "exists": False},
                    message="verified Jira comment deletion by provider not-found",
                )
            return VerificationResult(
                action_id=action.action_id,
                verified=False,
                observed=observed,
                message="Jira comment still exists after rollback",
            )

        observed = self._read_issue(action.target.resource_id)
        expected_version = (compensation.after or {}).get("version")
        if action.capability == "jira.issue.update":
            previous = original.before or {}
            requested = _mapping_parameter(action.parameters, "fields")
            expected = _previous_values(previous.get("fields"), requested)
            verified = bool(
                expected_version
                and _issue_poststate_matches(
                    action,
                    observed,
                    expected_version=expected_version,
                    expected_fields=expected,
                )
            )
        elif action.capability == "jira.issue.transition":
            previous_status = (original.before or {}).get("status")
            verified = bool(
                expected_version
                and isinstance(previous_status, str)
                and previous_status
                and _issue_poststate_matches(
                    action,
                    observed,
                    expected_version=expected_version,
                    expected_status=previous_status,
                )
            )
        else:
            raise ConnectorError(
                f"unsupported Jira compensation verification: {action.capability}"
            )
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified Jira rollback"
                if verified
                else "Jira rollback did not restore prior state"
            ),
        )

    def _update_issue(self, action: AgentAction) -> ExecutionResult:
        before = self._read_issue(action.target.resource_id)
        enforce_expected_version(action, before.get("version"))
        fields = _mapping_parameter(action.parameters, "fields")
        body: dict[str, Any] = {"fields": fields}
        api = self._api
        self._client.request_bytes(
            "PUT",
            f"rest/api/{api}/issue/{quote_segment(action.target.resource_id)}",
            json_body=body,
            safe_to_retry=False,
        )
        observed = self._read_issue(action.target.resource_id)
        if not _issue_poststate_matches(
            action,
            observed,
            prior_version=before.get("version"),
            expected_fields=fields,
        ):
            raise ConnectorError(
                "Jira provider poststate did not match the approved field update"
            )
        after = {
            **observed,
            "requested_fields": fields,
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=f"jira:{action.target.resource_id}",
            message="Jira issue update accepted",
            compensation=CompensationDescriptor(
                kind="restore_previous_issue_fields",
                mode=CompensationMode.MANUAL,
                parameters={
                    "fields": _previous_values(before.get("fields"), fields),
                },
                target_resource_id=action.target.resource_id,
                reason=(
                    "Jira issue restore has no adapter-enforced atomic precondition "
                    "and requires manual re-review"
                ),
            ),
        )

    def _create_comment(self, action: AgentAction) -> ExecutionResult:
        before = self._read_issue(action.target.resource_id)
        enforce_expected_version(action, before.get("version"))
        body_text = string_parameter(action.parameters, "body", required=True)
        body_payload: Any = (
            _text_to_adf(body_text)
            if self._config.deployment is DeploymentType.CLOUD
            else body_text
        )
        data, response = self._client.request_json(
            "POST",
            f"rest/api/{self._api}/issue/{quote_segment(action.target.resource_id)}/comment",
            json_body={"body": body_payload},
        )
        if not isinstance(data, Mapping) or not data.get("id"):
            raise ConnectorError("Jira comment creation response omitted an ID")
        after = {
            "comment_id": str(data["id"]),
            "body_text": body_text,
            "created": data.get("created"),
            "compensation": {
                "capability": "jira.issue.comment.delete_created",
                "comment_id": str(data["id"]),
                "created_by_action": True,
            },
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=response.url,
            message="Jira comment created",
            compensation=CompensationDescriptor(
                kind="delete_created_comment",
                mode=CompensationMode.MANUAL,
                target_resource_id=str(data["id"]),
                reason=(
                    "Jira comment deletion has no adapter-enforced atomic "
                    "precondition and requires manual re-review"
                ),
            ),
        )

    def _transition_issue(self, action: AgentAction) -> ExecutionResult:
        before = self._read_issue(action.target.resource_id)
        enforce_expected_version(action, before.get("version"))
        transition_id = string_parameter(
            action.parameters,
            "transition_id",
            required=True,
        )
        target_status = string_parameter(
            action.parameters,
            "target_status",
            required=True,
        )
        reverse_transition_id = string_parameter(
            action.parameters,
            "reverse_transition_id",
            required=True,
        )
        payload: dict[str, Any] = {"transition": {"id": transition_id}}
        self._client.request_bytes(
            "POST",
            f"rest/api/{self._api}/issue/{quote_segment(action.target.resource_id)}/transitions",
            json_body=payload,
            safe_to_retry=False,
        )
        observed = self._read_issue(action.target.resource_id)
        if not _issue_poststate_matches(
            action,
            observed,
            prior_version=before.get("version"),
            expected_status=target_status,
        ):
            raise ConnectorError(
                "Jira provider poststate did not match the approved transition"
            )
        after = {
            **observed,
            "target_status": target_status,
            "transition_id": transition_id,
        }
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=after,
            connector_reference=f"jira:{action.target.resource_id}",
            message="Jira transition accepted",
            compensation=CompensationDescriptor(
                kind="reverse_issue_transition",
                mode=CompensationMode.MANUAL,
                target_resource_id=action.target.resource_id,
                parameters={
                    "previous_status": before.get("status"),
                    "reverse_transition_id": reverse_transition_id,
                },
                reason=(
                    "Jira transition reversal has no adapter-enforced atomic "
                    "precondition and requires manual re-review"
                ),
            ),
        )

    def _compensate(self, action: AgentAction) -> ExecutionResult:
        before = self._read_issue(action.target.resource_id)
        enforce_expected_version(action, before.get("version"))
        fields = _mapping_parameter(action.parameters, "fields")
        self._client.request_bytes(
            "PUT",
            f"rest/api/{self._api}/issue/{quote_segment(action.target.resource_id)}",
            json_body={"fields": fields},
            safe_to_retry=False,
        )
        observed = self._read_issue(action.target.resource_id)
        if not _issue_poststate_matches(
            action,
            observed,
            prior_version=before.get("version"),
            expected_fields=fields,
        ):
            raise ConnectorError(
                "Jira provider poststate did not match the approved compensation"
            )
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after={**observed, "requested_fields": fields},
            connector_reference=f"jira:{action.target.resource_id}",
            message="Jira compensation update accepted",
        )

    def _read_issue(self, issue_key: str) -> dict[str, Any]:
        data, response = self._client.request_json(
            "GET",
            f"rest/api/{self._api}/issue/{quote_segment(issue_key)}",
            query={"fields": "*all"},
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Jira issue response must be an object")
        fields = data.get("fields")
        fields = fields if isinstance(fields, Mapping) else {}
        status = fields.get("status")
        status = status if isinstance(status, Mapping) else {}
        return {
            "id": str(data.get("id", "")),
            "key": str(data.get("key", "")),
            "version": str(fields.get("updated")) if fields.get("updated") else None,
            "updated_at": fields.get("updated"),
            "status": status.get("name"),
            "fields": deepcopy(dict(fields)),
            "reference": response.url,
        }

    def _read_comment(self, issue_key: str, comment_id: str) -> dict[str, Any]:
        data, response = self._client.request_json(
            "GET",
            (
                f"rest/api/{self._api}/issue/{quote_segment(issue_key)}/comment/"
                f"{quote_segment(comment_id)}"
            ),
        )
        if not isinstance(data, Mapping):
            raise ConnectorError("Jira comment response must be an object")
        return {
            "comment_id": str(data.get("id", "")),
            "body": deepcopy(data.get("body")),
            "body_text": _adf_to_text(data.get("body")),
            "created": data.get("created"),
            "updated": data.get("updated"),
            "reference": response.url,
        }

    @property
    def _api(self) -> str:
        return "3" if self._config.deployment is DeploymentType.CLOUD else "2"

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError("Jira write connector received another system")
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"unsupported Jira write capability: {action.capability}"
            )
        if action.risk is not RiskLevel.REVERSIBLE_WRITE:
            raise ConnectorError("Jira writes must use reversible_write risk")
        if action.capability in {"jira.issue.update", "jira.issue.compensate"}:
            _mapping_parameter(action.parameters, "fields")
            if (
                action.capability == "jira.issue.update"
                and "update" in action.parameters
            ):
                raise ConnectorError(
                    "Jira update operators are disabled until their exact poststate "
                    "can be derived"
                )
        if action.capability == "jira.issue.comment.create":
            string_parameter(action.parameters, "body", required=True)
        if action.capability == "jira.issue.transition":
            string_parameter(action.parameters, "transition_id", required=True)
            string_parameter(action.parameters, "target_status", required=True)
            string_parameter(action.parameters, "reverse_transition_id", required=True)
            if "fields" in action.parameters:
                raise ConnectorError(
                    "Jira transition fields are disabled until their exact rollback "
                    "and poststate can be proven"
                )


def _mapping_parameter(parameters: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = parameters.get(key)
    if not isinstance(value, Mapping) or not value:
        raise ConnectorError(f"parameter must be a non-empty object: {key}")
    return deepcopy(dict(value))


def _previous_values(current: Any, requested: Mapping[str, Any]) -> dict[str, Any]:
    mapping = current if isinstance(current, Mapping) else {}
    return {key: deepcopy(mapping.get(key)) for key in requested}


def _fields_match(observed: Any, expected: Any) -> bool:
    if not isinstance(observed, Mapping) or not isinstance(expected, Mapping):
        return False
    return all(
        key in observed and _json_values_equal(observed[key], value)
        for key, value in expected.items()
    )


def _json_values_equal(observed: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool/int equality coercion."""

    if isinstance(expected, Mapping):
        return (
            isinstance(observed, Mapping)
            and observed.keys() == expected.keys()
            and all(
                _json_values_equal(observed[key], value)
                for key, value in expected.items()
            )
        )
    if isinstance(expected, (list, tuple)):
        return (
            isinstance(observed, (list, tuple))
            and len(observed) == len(expected)
            and all(
                _json_values_equal(observed_item, expected_item)
                for observed_item, expected_item in zip(observed, expected, strict=True)
            )
        )
    return type(observed) is type(expected) and bool(observed == expected)


def _issue_poststate_matches(
    action: AgentAction,
    observed: Mapping[str, Any],
    *,
    prior_version: object | None = None,
    expected_version: object | None = None,
    expected_fields: Mapping[str, Any] | None = None,
    expected_status: str | None = None,
) -> bool:
    """Match issue identity, version, and every action-derived expected field."""

    version = observed.get("version")
    if observed.get("key") != action.target.resource_id or not version:
        return False
    if prior_version is not None and version == prior_version:
        return False
    if expected_version is not None and version != expected_version:
        return False
    if expected_fields is not None and not _fields_match(
        observed.get("fields"),
        expected_fields,
    ):
        return False
    return expected_status is None or observed.get("status") == expected_status


def _text_to_adf(text: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": line}] if line else [],
            }
            for line in text.splitlines() or [text]
        ],
    }


def _adf_to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, Mapping):
        return ""
    parts: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            if node.get("type") == "text" and isinstance(node.get("text"), str):
                parts.append(str(node["text"]))
            content = node.get("content")
            if isinstance(content, list):
                for child in content:
                    walk(child)
                if node.get("type") == "paragraph":
                    parts.append("\n")
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return "".join(parts).rstrip()
