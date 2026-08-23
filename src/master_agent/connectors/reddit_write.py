"""Approval-bound Reddit posting and interaction capabilities."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from master_agent.config import ResolvedConnectorConfig
from master_agent.connectors.reddit import (
    _client,
    _content_reference,
    _fullname,
    _subreddit,
    _validate_config,
)
from master_agent.connectors.utils import enforce_expected_version, string_parameter
from master_agent.errors import ConnectorError, RateLimitError, ResourceNotFoundError
from master_agent.http import HttpTransport
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


class RedditWriteConnector:
    """Execute exactly approved Reddit mutations with independent verification."""

    _CAPABILITIES = frozenset(
        {
            "reddit.post.create",
            "reddit.comment.create",
            "reddit.comment.reply",
            "reddit.content.edit",
            "reddit.content.delete",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
        include_writes: bool = True,
        include_communications: bool = True,
    ) -> None:
        _validate_config(config)
        self._config = config
        self._client = _client(
            config,
            transport,
            retry_attempts=0,
            allowed_methods=frozenset({"GET", "POST"}),
        )
        capabilities: set[str] = set()
        if include_communications and _enabled(config, "posts_enabled"):
            capabilities.add("reddit.post.create")
        if include_communications and _enabled(config, "comments_enabled"):
            capabilities.update({"reddit.comment.create", "reddit.comment.reply"})
        if include_writes and _enabled(config, "edits_enabled"):
            capabilities.add("reddit.content.edit")
        if include_writes and _enabled(config, "deletes_enabled"):
            capabilities.add("reddit.content.delete")
        self._capabilities = frozenset(capabilities)
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        return "reddit"

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    def execute(self, action: AgentAction) -> ExecutionResult:
        self._validate(action)
        if action.capability == "reddit.post.create":
            return self._create_post(action)
        if action.capability in {"reddit.comment.create", "reddit.comment.reply"}:
            return self._create_comment(action)
        if action.capability == "reddit.content.edit":
            return self._edit(action)
        return self._delete(action)

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        value = self._last.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self, action: AgentAction, result: ExecutionResult
    ) -> VerificationResult:
        after = result.after or {}
        fullname = _fullname(str(after.get("fullname", action.target.resource_id)))
        if action.capability == "reddit.content.delete":
            observed = self._read_item(fullname, missing_ok=True)
            verified = observed is None
        else:
            observed = self._read_item(fullname)
            verified = observed is not None and _matches(action, observed)
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified Reddit provider poststate by independent re-read"
                if verified
                else "Reddit provider poststate did not match the approved mutation"
            ),
        )

    def compensate(
        self, action: AgentAction, result: ExecutionResult
    ) -> ExecutionResult:
        raise ConnectorError(
            "Reddit mutations require manual recovery after a fresh ownership review"
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        return VerificationResult(
            action_id=action.action_id,
            verified=False,
            observed=None,
            message="Reddit connector has no automatic compensation",
        )

    def _create_post(self, action: AgentAction) -> ExecutionResult:
        subreddit = _subreddit(
            string_parameter(action.parameters, "subreddit", required=True)
        )
        title = string_parameter(action.parameters, "title", required=True)
        kind = string_parameter(action.parameters, "kind", default="self").casefold()
        if kind not in {"self", "link"}:
            raise ConnectorError("Reddit post kind must be self or link")
        form: dict[str, Any] = {
            "api_type": "json",
            "kind": kind,
            "sr": subreddit,
            "title": title,
            "resubmit": "true",
            "sendreplies": "true",
        }
        if kind == "self":
            form["text"] = string_parameter(action.parameters, "body", default="")
        else:
            form["url"] = string_parameter(action.parameters, "url", required=True)
        fullname, reference = self._submit("api/submit", form)
        observed = self._read_item(fullname)
        if observed is None:  # pragma: no cover - missing_ok is false.
            raise ConnectorError("Reddit post was not found after creation")
        if not _matches(action, observed):
            raise ConnectorError("Reddit post did not match the approved fields")
        return self._created_result(action, observed, reference, "post")

    def _create_comment(self, action: AgentAction) -> ExecutionResult:
        expected_kind = "t3" if action.capability == "reddit.comment.create" else "t1"
        parent = _content_reference(
            string_parameter(action.parameters, "parent_fullname", required=True),
            expected_kind=expected_kind,
        )
        body = string_parameter(action.parameters, "body", required=True)
        fullname, reference = self._submit(
            "api/comment",
            {"api_type": "json", "thing_id": parent, "text": body},
        )
        observed = self._read_item(fullname)
        if observed is None:  # pragma: no cover - missing_ok is false.
            raise ConnectorError("Reddit comment was not found after creation")
        if not _matches(action, observed):
            raise ConnectorError("Reddit comment did not match the approved fields")
        return self._created_result(action, observed, reference, "comment")

    def _edit(self, action: AgentAction) -> ExecutionResult:
        fullname = _content_reference(action.target.resource_id)
        before = self._owned_item(fullname)
        enforce_expected_version(action, before.get("version"))
        body = string_parameter(action.parameters, "body", required=True)
        self._submit(
            "api/editusertext",
            {"api_type": "json", "thing_id": fullname, "text": body},
            expected_fullname=fullname,
        )
        observed = self._read_item(fullname)
        if observed is None:  # pragma: no cover - missing_ok is false.
            raise ConnectorError("Reddit content was not found after editing")
        if observed.get("body") != body:
            raise ConnectorError("Reddit edit did not match the approved body")
        self._last[fullname] = deepcopy(observed)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=observed,
            connector_reference=str(observed.get("web_url") or fullname),
            message="Reddit content edited",
            compensation=CompensationDescriptor(
                kind="restore_reddit_content",
                mode=CompensationMode.MANUAL,
                target_resource_id=fullname,
                reason="Reddit does not provide an atomic edit precondition for safe rollback",
            ),
        )

    def _delete(self, action: AgentAction) -> ExecutionResult:
        fullname = _content_reference(action.target.resource_id)
        before = self._owned_item(fullname)
        enforce_expected_version(action, before.get("version"))
        self._client.request_form("POST", "api/del", form={"id": fullname})
        if self._read_item(fullname, missing_ok=True) is not None:
            raise ConnectorError("Reddit deletion could not be independently verified")
        self._last.pop(fullname, None)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after={"fullname": fullname, "deleted": True},
            connector_reference=str(before.get("web_url") or fullname),
            message="Reddit content deleted",
        )

    def _created_result(
        self,
        action: AgentAction,
        observed: dict[str, Any],
        reference: str,
        kind: str,
    ) -> ExecutionResult:
        fullname = str(observed["fullname"])
        self._last[fullname] = deepcopy(observed)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=observed,
            connector_reference=str(observed.get("web_url") or reference),
            message=f"Reddit {kind} created",
            compensation=CompensationDescriptor(
                kind="delete_reddit_content",
                mode=CompensationMode.MANUAL,
                target_resource_id=fullname,
                reason="Reddit deletion has no provider-side atomic precondition",
            ),
        )

    def _submit(
        self,
        path: str,
        form: Mapping[str, Any],
        *,
        expected_fullname: str | None = None,
    ) -> tuple[str, str]:
        data, response = self._client.request_form("POST", path, form=form)
        if not isinstance(data, Mapping):
            raise ConnectorError("Reddit mutation response must be an object")
        errors = _reddit_errors(data)
        if errors:
            if "RATELIMIT" in errors:
                raise RateLimitError(
                    "Reddit rate limit exceeded",
                    retry_after_seconds=_reddit_retry_after(data),
                )
            raise ConnectorError(
                "Reddit rejected the approved mutation: " + ", ".join(errors)
            )
        fullname = expected_fullname or _response_fullname(data)
        return _fullname(fullname), response.url

    def _read_item(
        self,
        fullname: str,
        *,
        missing_ok: bool = False,
    ) -> dict[str, Any] | None:
        data, response = self._client.request_json(
            "GET", "api/info", query={"id": fullname, "raw_json": 1}
        )
        if not isinstance(data, Mapping) or not isinstance(data.get("data"), Mapping):
            raise ConnectorError("Reddit content response is invalid")
        children = data["data"].get("children")
        if not isinstance(children, list):
            raise ConnectorError("Reddit content listing is invalid")
        if not children:
            if missing_ok:
                return None
            raise ResourceNotFoundError("Reddit content was not found")
        if len(children) != 1 or not isinstance(children[0], Mapping):
            raise ConnectorError("Reddit content response was ambiguous")
        child = children[0]
        raw = child.get("data")
        if not isinstance(raw, Mapping) or raw.get("name") != fullname:
            raise ConnectorError("Reddit content response did not match its target")
        permalink = raw.get("permalink")
        body = raw.get("body") if child.get("kind") == "t1" else raw.get("selftext")
        version_source = raw.get("edited")
        if version_source is False or version_source is None:
            version_source = raw.get("created_utc")
        return {
            "fullname": fullname,
            "kind": child.get("kind"),
            "author": raw.get("author") if isinstance(raw.get("author"), str) else None,
            "subreddit": raw.get("subreddit")
            if isinstance(raw.get("subreddit"), str)
            else None,
            "parent_fullname": (
                raw.get("parent_id") if isinstance(raw.get("parent_id"), str) else None
            ),
            "title": raw.get("title") if isinstance(raw.get("title"), str) else None,
            "body": body if isinstance(body, str) else None,
            "url": raw.get("url") if isinstance(raw.get("url"), str) else None,
            "permalink": permalink if isinstance(permalink, str) else None,
            "web_url": (
                f"{self._config.web_base_url}{permalink}"
                if isinstance(permalink, str) and permalink.startswith("/")
                else response.url
            ),
            "version": _version(version_source),
        }

    def _owned_item(self, fullname: str) -> dict[str, Any]:
        item = self._read_item(fullname)
        if item is None:  # pragma: no cover - missing_ok is false.
            raise ConnectorError("Reddit owned content was not found")
        identity, _ = self._client.request_json("GET", "api/v1/me")
        if not isinstance(identity, Mapping) or not isinstance(
            identity.get("name"), str
        ):
            raise ConnectorError("Reddit identity response is invalid")
        if item.get("author", "").casefold() != identity["name"].casefold():
            raise ConnectorError(
                "Reddit mutation is limited to authenticated-user content"
            )
        return item

    def _validate(self, action: AgentAction) -> None:
        if action.target.system != "reddit":
            raise ConnectorError("Reddit write connector received another system")
        if action.capability not in self._capabilities:
            raise ConnectorError(f"Reddit capability is disabled: {action.capability}")
        if not action.requires_approval:
            raise ConnectorError("every Reddit mutation requires exact approval")
        expected_risk = (
            RiskLevel.HIGH_IMPACT
            if action.capability == "reddit.content.delete"
            else RiskLevel.EXTERNAL_COMMUNICATION
        )
        if action.risk is not expected_risk:
            raise ConnectorError(f"Reddit mutation requires {expected_risk.value} risk")
        if (
            action.capability in {"reddit.content.edit", "reddit.content.delete"}
            and not action.target.expected_version
        ):
            raise ConnectorError("Reddit edit and delete require expected_version")


def _enabled(config: ResolvedConnectorConfig, key: str) -> bool:
    value = config.extra.get(key, False)
    if not isinstance(value, bool):
        raise ConnectorError(f"Reddit {key} must be true or false")
    return value


def _reddit_errors(data: Mapping[str, Any]) -> list[str]:
    payload = data.get("json")
    if not isinstance(payload, Mapping):
        return []
    raw_errors = payload.get("errors", [])
    if not isinstance(raw_errors, list):
        raise ConnectorError("Reddit mutation errors are malformed")
    names: list[str] = []
    for item in raw_errors:
        if (
            isinstance(item, list)
            and item
            and isinstance(item[0], str)
            and re.fullmatch(r"[A-Za-z0-9_]{1,64}", item[0]) is not None
        ):
            names.append(item[0])
    if raw_errors and not names:
        raise ConnectorError("Reddit mutation errors are malformed")
    return names


def _reddit_retry_after(data: Mapping[str, Any]) -> int | None:
    payload = data.get("json")
    if not isinstance(payload, Mapping):
        return None
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        return None
    unit_seconds = {"second": 1, "minute": 60, "hour": 3600}
    for item in raw_errors:
        if (
            not isinstance(item, list)
            or len(item) < 2
            or item[0] != "RATELIMIT"
            or not isinstance(item[1], str)
        ):
            continue
        match = re.search(
            r"\b(\d{1,6})\s*(second|minute|hour)s?\b",
            item[1],
            flags=re.IGNORECASE,
        )
        if match is not None:
            return min(
                int(match.group(1)) * unit_seconds[match.group(2).casefold()], 86400
            )
    return None


def _response_fullname(data: Mapping[str, Any]) -> str:
    payload = data.get("json")
    if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), Mapping):
        raise ConnectorError("Reddit mutation response has no data")
    response_data = payload["data"]
    name = response_data.get("name")
    if isinstance(name, str):
        return name
    things = response_data.get("things")
    if isinstance(things, list):
        for thing in things:
            if isinstance(thing, Mapping) and isinstance(thing.get("data"), Mapping):
                candidate = thing["data"].get("name")
                if isinstance(candidate, str):
                    return candidate
    raise ConnectorError("Reddit mutation response has no content fullname")


def _version(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConnectorError("Reddit content has no stable version")
    return format(float(value), ".6f")


def _matches(action: AgentAction, observed: Mapping[str, Any]) -> bool:
    if action.capability == "reddit.post.create":
        if observed.get("title") != action.parameters.get("title"):
            return False
        if (
            str(observed.get("subreddit", "")).casefold()
            != str(action.parameters.get("subreddit", "")).casefold()
        ):
            return False
        kind = str(action.parameters.get("kind", "self")).casefold()
        return (
            observed.get("body") == action.parameters.get("body", "")
            if kind == "self"
            else observed.get("url") == action.parameters.get("url")
        )
    if observed.get("body") != action.parameters.get("body"):
        return False
    if action.capability in {"reddit.comment.create", "reddit.comment.reply"}:
        expected_kind = "t3" if action.capability == "reddit.comment.create" else "t1"
        approved_parent = _content_reference(
            str(action.parameters.get("parent_fullname", "")),
            expected_kind=expected_kind,
        )
        return observed.get("parent_fullname") == approved_parent
    return True
