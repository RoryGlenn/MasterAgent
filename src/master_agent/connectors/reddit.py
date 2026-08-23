"""Bounded read-only Reddit OAuth connector."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.connectors.utils import (
    integer_parameter,
    quote_segment,
    string_parameter,
)
from master_agent.errors import ConfigurationError, ConnectorError
from master_agent.http import HttpResponse, HttpTransport, SafeHttpClient
from master_agent.models import AgentAction

_CONTENT_FULLNAME = re.compile(r"^t[13]_[a-z0-9]{1,16}$")
_READ_FULLNAME = re.compile(r"^t[134]_[a-z0-9]{1,64}$")
_CONTENT_ID = re.compile(r"^[a-z0-9]{1,16}$")
_REDDIT_CONTENT_PATH = re.compile(
    r"^/(?:r/[A-Za-z0-9_]{2,21}/)?comments/([a-z0-9]+)/[^/]+"
    r"(?:/([a-z0-9]+))?/?$",
    re.IGNORECASE,
)
_REDDIT_WEB_HOSTS = frozenset(
    {"reddit.com", "www.reddit.com", "old.reddit.com", "np.reddit.com"}
)
_REDDIT_USER_ID = re.compile(r"^[a-z0-9]{1,32}$")
_REDDIT_USERNAME = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
_SUBREDDIT = re.compile(r"^[A-Za-z0-9_]{2,21}$")
_SORTS = frozenset({"relevance", "hot", "top", "new", "comments"})
_TIME_WINDOWS = frozenset({"hour", "day", "week", "month", "year", "all"})


@dataclass(frozen=True, slots=True)
class RedditPrincipalAttestation:
    """Provider-verified Reddit identity and delegated scopes."""

    user_id: str
    username: str
    reference: str
    scopes: tuple[str, ...] = ()

    @property
    def identity(self) -> str:
        """Return the immutable secret-free identity used by approvals."""

        return f"reddit:user:{self.user_id}"


class RedditConnector(ReadOnlyConnector):
    """Search and read Reddit through its official OAuth API."""

    _CAPABILITIES = frozenset(
        {
            "reddit.search",
            "reddit.content.read",
            "reddit.subreddit.rules.read",
            "reddit.user.submitted.read",
            "reddit.user.comments.read",
            "reddit.inbox.read",
        }
    )

    def __init__(
        self,
        config: ResolvedConnectorConfig,
        *,
        transport: HttpTransport | None = None,
    ) -> None:
        _validate_config(config)
        super().__init__(system="reddit", capabilities=self._CAPABILITIES)
        self._config = config
        self._client = _client(
            config,
            transport,
            retry_attempts=2,
            allowed_methods=frozenset({"GET"}),
        )

    def probe(self) -> Mapping[str, Any]:
        """Verify Reddit authentication without exposing token material."""

        principal = self.attest_principal()
        return {
            "reachable": True,
            "deployment": self._config.deployment,
            "authenticated_user": principal.username,
            "user_id": principal.user_id,
            "reference": principal.reference,
            "scopes": list(principal.scopes),
        }

    def attest_principal(self) -> RedditPrincipalAttestation:
        """Resolve the immutable user ID authenticated by the bearer token."""

        data, response = self._client.request_json("GET", "api/v1/me")
        if not isinstance(data, Mapping):
            raise ConnectorError("Reddit identity response must be an object")
        user_id = data.get("id")
        username = data.get("name")
        if (
            not isinstance(user_id, str)
            or _REDDIT_USER_ID.fullmatch(user_id.casefold()) is None
        ):
            raise ConnectorError("Reddit identity response has no stable user ID")
        if (
            not isinstance(username, str)
            or _REDDIT_USERNAME.fullmatch(username) is None
        ):
            raise ConnectorError("Reddit identity response has no username")
        provider = self._config.auth.token_provider
        scopes = provider.get_token().scopes if provider is not None else ()
        return RedditPrincipalAttestation(
            user_id=user_id.casefold(),
            username=username,
            reference=response.url,
            scopes=tuple(sorted(scopes)),
        )

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        if action.capability == "reddit.search":
            return self._search(action)
        if action.capability == "reddit.content.read":
            return self._read_content(action)
        if action.capability == "reddit.subreddit.rules.read":
            return self._read_rules(action)
        if action.capability == "reddit.user.submitted.read":
            return self._read_user_listing(action, listing="submitted")
        if action.capability == "reddit.user.comments.read":
            return self._read_user_listing(action, listing="comments")
        if action.capability == "reddit.inbox.read":
            return self._read_inbox(action)
        raise ConnectorError(f"unsupported Reddit capability: {action.capability}")

    def _search(self, action: AgentAction) -> RetrievedPayload:
        query = string_parameter(action.parameters, "query", required=True)
        subreddit_raw = string_parameter(action.parameters, "subreddit", default="")
        subreddit = _subreddit(subreddit_raw) if subreddit_raw else None
        sort = string_parameter(
            action.parameters, "sort", default="relevance"
        ).casefold()
        time_window = string_parameter(
            action.parameters, "time", default="all"
        ).casefold()
        if sort not in _SORTS:
            raise ConnectorError("Reddit search sort is unsupported")
        if time_window not in _TIME_WINDOWS:
            raise ConnectorError("Reddit search time window is unsupported")
        limit = _limit(action, self._config.max_items)
        path = f"r/{quote_segment(subreddit)}/search" if subreddit else "search"
        items, response = self._listing(
            path,
            limit=limit,
            query={
                "q": query,
                "sort": sort,
                "t": time_window,
                "restrict_sr": "true" if subreddit else "false",
                "raw_json": 1,
            },
        )
        return self._payload(
            schema="master-agent/reddit-search@1",
            items=items,
            response=response,
            query={
                "query": query,
                "subreddit": subreddit,
                "sort": sort,
                "time": time_window,
            },
        )

    def _read_content(self, action: AgentAction) -> RetrievedPayload:
        reference = _content_parameter(action)
        fullname = _content_reference(
            reference,
            expected_kind=_content_kind_parameter(action),
        )
        items, response = self._listing(
            "api/info", limit=1, query={"id": fullname, "raw_json": 1}
        )
        if len(items) != 1 or items[0].get("fullname") != fullname:
            raise ConnectorError("Reddit content was not found")
        return self._payload(
            schema="master-agent/reddit-content@1",
            items=items,
            response=response,
            query={"reference": reference, "fullname": fullname},
        )

    def _read_rules(self, action: AgentAction) -> RetrievedPayload:
        subreddit = _subreddit(
            string_parameter(action.parameters, "subreddit", required=True)
        )
        data, response = self._client.request_json(
            "GET", f"r/{quote_segment(subreddit)}/about/rules", query={"raw_json": 1}
        )
        if not isinstance(data, Mapping) or not isinstance(data.get("rules"), list):
            raise ConnectorError("Reddit rules response is invalid")
        rules = []
        for raw in data["rules"][: self._config.max_items]:
            if not isinstance(raw, Mapping):
                raise ConnectorError("Reddit rule must be an object")
            rules.append(
                {
                    "kind": _optional_text(raw.get("kind")),
                    "short_name": _optional_text(raw.get("short_name")),
                    "description": _optional_text(raw.get("description")),
                    "violation_reason": _optional_text(raw.get("violation_reason")),
                }
            )
        return RetrievedPayload(
            data={
                "schema": "master-agent/reddit-subreddit-rules@1",
                "system": "reddit",
                "subreddit": subreddit,
                "returned": len(rules),
                "rules": rules,
                "source_urls": [
                    response.url,
                    f"{self._config.web_base_url}/r/{subreddit}/about/rules",
                ],
            },
            connector_reference=response.url,
        )

    def _read_user_listing(
        self, action: AgentAction, *, listing: str
    ) -> RetrievedPayload:
        username = string_parameter(action.parameters, "username", default="me")
        if username == "me":
            resolved_username = self.attest_principal().username
        elif _REDDIT_USERNAME.fullmatch(username) is None:
            raise ConnectorError("Reddit username is invalid")
        else:
            resolved_username = username
        limit = _limit(action, self._config.max_items)
        items, response = self._listing(
            f"user/{quote_segment(resolved_username)}/{listing}",
            limit=limit,
            query={"raw_json": 1},
        )
        return self._payload(
            schema=f"master-agent/reddit-user-{listing}@1",
            items=items,
            response=response,
            query={"username": username, "resolved_username": resolved_username},
        )

    def _read_inbox(self, action: AgentAction) -> RetrievedPayload:
        limit = _limit(action, self._config.max_items)
        items, response = self._listing(
            "message/inbox", limit=limit, query={"raw_json": 1}
        )
        return self._payload(
            schema="master-agent/reddit-inbox@1",
            items=items,
            response=response,
            query={},
        )

    def _listing(
        self,
        path: str,
        *,
        limit: int,
        query: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], HttpResponse]:
        items: list[dict[str, Any]] = []
        after: str | None = None
        response: HttpResponse | None = None
        for _ in range(self._config.max_pages):
            remaining = limit - len(items)
            if remaining <= 0:
                break
            data, response = self._client.request_json(
                "GET",
                path,
                query={**query, "limit": min(100, remaining), "after": after},
            )
            if not isinstance(data, Mapping):
                raise ConnectorError("Reddit listing response must be an object")
            listing = data.get("data")
            if not isinstance(listing, Mapping) or not isinstance(
                listing.get("children"), list
            ):
                raise ConnectorError("Reddit listing response is invalid")
            for child in listing["children"]:
                items.append(
                    _normalize_child(
                        child,
                        self._config.web_base_url or "https://www.reddit.com",
                    )
                )
                if len(items) >= limit:
                    break
            next_after = listing.get("after")
            after = next_after if isinstance(next_after, str) and next_after else None
            if after is None:
                break
        if response is None:
            raise ConnectorError("Reddit listing produced no response")
        return items, response

    def _payload(
        self,
        *,
        schema: str,
        items: list[dict[str, Any]],
        response: HttpResponse,
        query: Mapping[str, Any],
    ) -> RetrievedPayload:
        sources = [response.url]
        sources.extend(str(item["web_url"]) for item in items if item.get("web_url"))
        return RetrievedPayload(
            data={
                "schema": schema,
                "system": "reddit",
                "deployment": self._config.deployment,
                "query": dict(query),
                "returned": len(items),
                "items": items,
                "source_urls": list(dict.fromkeys(sources)),
            },
            connector_reference=response.url,
        )


def _client(
    config: ResolvedConnectorConfig,
    transport: HttpTransport | None,
    *,
    retry_attempts: int,
    allowed_methods: frozenset[str],
) -> SafeHttpClient:
    user_agent = str(config.extra.get("user_agent", "")).strip()
    if not user_agent or any(character in user_agent for character in "\r\n\x00"):
        raise ConfigurationError("Reddit connector requires a valid User-Agent")
    return SafeHttpClient(
        base_url=config.base_url,
        default_headers={"Accept": "application/json", "User-Agent": user_agent},
        header_provider=config.auth.headers,
        transport=transport,
        timeout_seconds=config.timeout_seconds,
        max_response_bytes=config.max_response_bytes,
        retry_attempts=retry_attempts,
        ca_bundle_data=config.ca_bundle_data,
        proxy_url=config.proxy_url,
        proxy_username=config.proxy_username,
        proxy_password=config.proxy_password,
        allowed_methods=allowed_methods,
    )


def _validate_config(config: ResolvedConnectorConfig) -> None:
    if config.system != "reddit":
        raise ConfigurationError("Reddit connector requires reddit configuration")
    if config.deployment is not DeploymentType.CLOUD:
        raise ConfigurationError("Reddit connector supports cloud only")
    if config.base_url.rstrip("/") != "https://oauth.reddit.com":
        raise ConfigurationError("Reddit connector requires the fixed OAuth API origin")


def _normalize_child(raw: Any, web_base_url: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or not isinstance(raw.get("data"), Mapping):
        raise ConnectorError("Reddit listing child is invalid")
    data = raw["data"]
    fullname = data.get("name")
    if not isinstance(fullname, str) or _READ_FULLNAME.fullmatch(fullname) is None:
        raise ConnectorError("Reddit content has no valid fullname")
    permalink = _optional_text(data.get("permalink"))
    return {
        "fullname": fullname,
        "kind": _optional_text(raw.get("kind")),
        "id": _optional_text(data.get("id")),
        "author": _optional_text(data.get("author")),
        "subreddit": _optional_text(data.get("subreddit")),
        "title": _optional_text(data.get("title")),
        "body": _optional_text(data.get("body"))
        or _optional_text(data.get("selftext")),
        "parent_fullname": _optional_text(data.get("parent_id")),
        "url": _optional_text(data.get("url")),
        "permalink": permalink,
        "web_url": f"{web_base_url}{permalink}"
        if permalink and permalink.startswith("/")
        else None,
        "created_utc": data.get("created_utc")
        if isinstance(data.get("created_utc"), (int, float))
        else None,
        "edited": data.get("edited")
        if isinstance(data.get("edited"), (bool, int, float))
        else None,
        "score": data.get("score") if isinstance(data.get("score"), int) else None,
        "num_comments": data.get("num_comments")
        if isinstance(data.get("num_comments"), int)
        else None,
    }


def _fullname(value: str) -> str:
    normalized = value.casefold()
    if _CONTENT_FULLNAME.fullmatch(normalized) is None:
        raise ConnectorError("Reddit fullname must identify a post or comment")
    return normalized


def _content_reference(value: str, *, expected_kind: str | None = None) -> str:
    """Normalize one approved Reddit fullname, bare ID, or canonical web URL."""

    rendered = value.strip()
    normalized = rendered.casefold()
    if _CONTENT_FULLNAME.fullmatch(normalized) is not None:
        return _require_content_kind(normalized, expected_kind)
    if _CONTENT_ID.fullmatch(normalized) is not None:
        return _require_content_kind(
            f"{expected_kind or 't3'}_{normalized}", expected_kind
        )
    try:
        parsed = urlparse(rendered)
        port = parsed.port
    except ValueError as error:
        raise ConnectorError("Reddit content reference is invalid") from error
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or port is not None
        or parsed.fragment
    ):
        raise ConnectorError("Reddit content reference must be a safe HTTPS URL")
    segments = tuple(segment for segment in parsed.path.split("/") if segment)
    if hostname == "redd.it" and len(segments) == 1:
        identifier = segments[0].casefold()
        if _CONTENT_ID.fullmatch(identifier) is not None:
            return _require_content_kind(f"t3_{identifier}", expected_kind)
    if hostname in _REDDIT_WEB_HOSTS:
        match = _REDDIT_CONTENT_PATH.fullmatch(parsed.path)
        if match is not None:
            post_id = match.group(1).casefold()
            raw_comment_id = match.group(2)
            comment_id = raw_comment_id.casefold() if raw_comment_id else None
            fullname = f"t1_{comment_id}" if comment_id else f"t3_{post_id}"
            return _require_content_kind(fullname, expected_kind)
    raise ConnectorError("Reddit content reference is not a supported Reddit URL")


def _require_content_kind(fullname: str, expected_kind: str | None) -> str:
    if expected_kind is not None and not fullname.startswith(f"{expected_kind}_"):
        label = "post" if expected_kind == "t3" else "comment"
        raise ConnectorError(f"Reddit content reference must identify a {label}")
    return fullname


def _content_parameter(action: AgentAction) -> str:
    reference = action.parameters.get("reference")
    legacy = action.parameters.get("fullname")
    if reference is not None and legacy is not None:
        raise ConnectorError("provide reference or fullname, not both")
    selected = reference if reference is not None else legacy
    return string_parameter({"reference": selected}, "reference", required=True)


def _content_kind_parameter(action: AgentAction) -> str | None:
    kind = string_parameter(action.parameters, "kind", default="").casefold()
    if not kind:
        return None
    if kind not in {"post", "comment"}:
        raise ConnectorError("Reddit content kind must be post or comment")
    return "t3" if kind == "post" else "t1"


def _subreddit(value: str) -> str:
    if _SUBREDDIT.fullmatch(value) is None:
        raise ConnectorError("Reddit subreddit name is invalid")
    return value


def _limit(action: AgentAction, maximum: int) -> int:
    return integer_parameter(
        action.parameters, "limit", default=min(25, maximum), maximum=maximum
    )


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) else None
