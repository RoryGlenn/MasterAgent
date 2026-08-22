"""Restricted HTTP transport for live read-only connectors."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from email.message import Message
from http.client import HTTPMessage
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import ParseResult, unquote, urlencode, urljoin, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from master_agent.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ConnectorError,
    ConnectorHttpError,
    RateLimitError,
    ResourceNotFoundError,
)
from master_agent.trust_store import capture_ca_bundle, create_ssl_context


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """HTTP response returned by a transport."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str

    def json(self) -> Any:
        """Decode the response body as JSON."""

        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConnectorHttpError(
                f"response from {_safe_url(self.url)} was not valid JSON"
            ) from error

    def text(self, encoding: str = "utf-8") -> str:
        """Decode the response body as text."""

        try:
            return self.body.decode(encoding)
        except UnicodeDecodeError as error:
            raise ConnectorHttpError(
                f"response from {_safe_url(self.url)} was not valid {encoding} text"
            ) from error


@dataclass(slots=True)
class HttpActionBudget:
    """One shared request/response budget for a connector action."""

    max_requests: int
    max_response_bytes: int
    requests_used: int = 0
    response_bytes_used: int = 0

    @property
    def remaining_response_bytes(self) -> int:
        """Return bytes still available to every nested request."""

        return self.max_response_bytes - self.response_bytes_used

    def reserve_request(self) -> None:
        """Reserve one network attempt, including retries."""

        if self.requests_used >= self.max_requests:
            raise ConnectorHttpError(
                "connector action exceeded its global request/page budget"
            )
        self.requests_used += 1

    def record_response(self, size: int) -> None:
        """Account for response bytes and reject aggregate overages."""

        if size < 0 or size > self.remaining_response_bytes:
            raise ConnectorHttpError(
                "connector action exceeded its global response-byte budget"
            )
        self.response_bytes_used += size


_ACTION_BUDGET: ContextVar[HttpActionBudget | None] = ContextVar(
    "master_agent_http_action_budget",
    default=None,
)


@contextmanager
def http_action_budget(
    *,
    max_requests: int,
    max_response_bytes: int,
) -> Iterator[HttpActionBudget]:
    """Apply one budget across pagination, enrichment, downloads, and retries."""

    if max_requests <= 0 or max_response_bytes <= 0:
        raise ConfigurationError("HTTP action budgets must be positive")
    existing = _ACTION_BUDGET.get()
    if existing is not None:
        yield existing
        return
    budget = HttpActionBudget(
        max_requests=max_requests,
        max_response_bytes=max_response_bytes,
    )
    token = _ACTION_BUDGET.set(budget)
    try:
        yield budget
    finally:
        _ACTION_BUDGET.reset(token)


@contextmanager
def activate_http_action_budget(
    budget: HttpActionBudget | None,
) -> Iterator[HttpActionBudget | None]:
    """Activate a retained budget for another phase of the same action.

    The orchestrator retains one mutable budget from execution through
    verification and any later compensation. Nested connector helpers reuse
    that same object, so entering another phase cannot reset page, request, or
    response-byte counters.
    """

    if budget is None:
        yield None
        return
    existing = _ACTION_BUDGET.get()
    if existing is budget:
        yield budget
        return
    if existing is not None:
        raise ConfigurationError("cannot replace an active HTTP action budget")
    token = _ACTION_BUDGET.set(budget)
    try:
        yield budget
    finally:
        _ACTION_BUDGET.reset(token)


def connector_http_action_budget(connector: object) -> HttpActionBudget | None:
    """Create the production lifecycle budget for one configured connector.

    Local-only connectors have no resolved integration configuration and do
    not receive an HTTP budget. Every live read or write connector stores its
    validated ``ResolvedConnectorConfig`` as ``_config``.
    """

    config = getattr(connector, "_config", None)
    if config is None:
        return None
    max_requests = getattr(config, "max_pages", None)
    max_response_bytes = getattr(config, "max_response_bytes", None)
    if (
        not isinstance(max_requests, int)
        or isinstance(max_requests, bool)
        or max_requests <= 0
        or not isinstance(max_response_bytes, int)
        or isinstance(max_response_bytes, bool)
        or max_response_bytes <= 0
    ):
        raise ConfigurationError(
            "live connector HTTP action budgets must be positive integers"
        )
    return HttpActionBudget(
        max_requests=max_requests,
        max_response_bytes=max_response_bytes,
    )


class HttpTransport(Protocol):
    """Low-level transport protocol used by ``SafeHttpClient``."""

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HttpResponse:
        """Perform one HTTP request."""


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    """Reject redirects that would carry credentials outside an API root."""

    def __init__(self, *, allowed_base_url: str | None = None) -> None:
        super().__init__()
        self._allowed_origin: tuple[str, str, int] | None = None
        self._allowed_path: str | None = None
        if allowed_base_url is None:
            return
        parsed = urlparse(allowed_base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigurationError("redirect confinement requires an HTTPS base URL")
        allowed_path = _decoded_safe_path(parsed.path)
        if allowed_path is None:
            raise ConfigurationError("connector base URL contains an unsafe path")
        self._allowed_origin = _origin(parsed)
        self._allowed_path = allowed_path

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        old_origin = _origin(urlparse(req.full_url))
        new_origin = _origin(urlparse(newurl))
        if old_origin != new_origin:
            raise ConnectorHttpError(
                "cross-origin redirect rejected by connector HTTP policy"
            )
        if (
            self._allowed_origin is not None
            and self._allowed_path is not None
            and not _url_within_scope(
                newurl,
                origin=self._allowed_origin,
                path=self._allowed_path,
            )
        ):
            raise ConnectorHttpError(
                "redirect outside the configured URL scope was rejected"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect TLS to an already-vetted address while preserving SNI."""

    _context: ssl.SSLContext
    _tunnel_host: str | None
    source_address: tuple[str, int] | None

    def connect(self) -> None:
        """Resolve once, vet every candidate, and connect only by sockaddr."""

        if self._tunnel_host is not None:
            raise ConnectorHttpError("HTTP proxy tunneling is disabled")
        raw_socket, approved_address = _connect_public_address(
            self.host,
            self.port,
            timeout=self.timeout,
            source_address=self.source_address,
        )
        try:
            wrapped = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except Exception:
            raw_socket.close()
            raise
        try:
            peer_address = ipaddress.ip_address(wrapped.getpeername()[0])
        except (OSError, ValueError) as error:
            wrapped.close()
            raise ConnectorHttpError(
                "TLS peer address could not be verified"
            ) from error
        if peer_address != approved_address:
            wrapped.close()
            raise ConnectorHttpError("TLS peer did not match the vetted destination")
        self.sock = wrapped


class _PinnedHTTPSHandler(HTTPSHandler):
    """urllib handler that uses a DNS-pinned HTTPS connection."""

    _context: ssl.SSLContext

    def https_open(self, req: Request) -> Any:
        """Open one request through the pinned connection implementation."""

        return self.do_open(
            _PinnedHTTPSConnection,
            req,
            context=self._context,
        )


def _create_ssl_context(ca_bundle_data: bytes | None) -> ssl.SSLContext:
    """Create TLS trust from immutable captured data, never from a live path."""

    return create_ssl_context(ca_bundle_data)


class UrllibTransport:
    """Standard-library HTTP transport with origin-and-path-bound redirects."""

    def __init__(
        self,
        *,
        ca_bundle: Path | None = None,
        ca_bundle_data: bytes | None = None,
        allowed_base_url: str | None = None,
    ) -> None:
        if ca_bundle is not None and ca_bundle_data is not None:
            raise ConfigurationError(
                "CA bundle path and captured data are mutually exclusive"
            )
        captured_data = (
            capture_ca_bundle(ca_bundle).data
            if ca_bundle is not None
            else ca_bundle_data
        )
        context = _create_ssl_context(captured_data)
        self._opener = build_opener(
            # Never inherit HTTP(S)_PROXY, macOS System Configuration proxies,
            # or credentials embedded in ambient proxy settings.
            ProxyHandler({}),
            _PinnedHTTPSHandler(context=context),
            _SameOriginRedirectHandler(allowed_base_url=allowed_base_url),
        )

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HttpResponse:
        """Perform one bounded HTTP request."""

        _require_public_https_destination(url)
        request = Request(
            url=url,
            data=body,
            headers=dict(headers),
            method=method,
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                payload = _read_bounded(response, max_response_bytes)
                return HttpResponse(
                    status=int(response.status),
                    headers=_normalize_headers(response.headers),
                    body=payload,
                    url=str(response.geturl()),
                )
        except HTTPError as error:
            payload = _read_bounded(error, max_response_bytes)
            return HttpResponse(
                status=int(error.code),
                headers=_normalize_headers(error.headers),
                body=payload,
                url=str(error.geturl()),
            )
        except ConnectorHttpError:
            raise
        except URLError as error:
            raise ConnectorHttpError(
                f"network request failed for {_safe_url(url)}"
            ) from error
        except TimeoutError as error:
            raise ConnectorHttpError(
                f"network request timed out for {_safe_url(url)}"
            ) from error


class SafeHttpClient:
    """Origin-and-base-path-bound, size-limited client for connector APIs.

    Parameters
    ----------
    base_url
        Connector API base URL. All requests and followed pagination links must
        remain on this origin and under this path.
    default_headers
        Headers applied to every request. Authentication values are never
        included in exceptions.
    transport
        Injectable transport. Defaults to ``UrllibTransport``.
    timeout_seconds
        Per-request timeout.
    max_response_bytes
        Maximum response body size.
    retry_attempts
        Number of retries after the first attempt for transient failures.
    """

    _RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})

    def __init__(
        self,
        *,
        base_url: str,
        default_headers: Mapping[str, str] | None = None,
        header_provider: Callable[[], Mapping[str, str]] | None = None,
        transport: HttpTransport | None = None,
        timeout_seconds: float = 20.0,
        max_response_bytes: int = 10 * 1024 * 1024,
        retry_attempts: int = 2,
        ca_bundle: Path | None = None,
        ca_bundle_data: bytes | None = None,
        allowed_methods: frozenset[str] = frozenset({"GET", "HEAD"}),
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        parsed = urlparse(self._base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigurationError("connector HTTP clients require an HTTPS base URL")
        if parsed.username or parsed.password:
            raise ConfigurationError("connector base URL must not include credentials")
        if "?" in base_url or "#" in base_url:
            raise ConfigurationError(
                "connector base URL must not include a query or fragment"
            )
        self._origin = _origin(parsed)
        scope_path = _decoded_safe_path(parsed.path)
        if scope_path is None:
            raise ConfigurationError("connector base URL contains an unsafe path")
        self._scope_path = scope_path
        self._headers = {
            "Accept": "application/json",
            "User-Agent": "master-agent/1.0.0",
            **dict(default_headers or {}),
        }
        self._header_provider = header_provider
        if ca_bundle is not None and ca_bundle_data is not None:
            raise ConfigurationError(
                "CA bundle path and captured data are mutually exclusive"
            )
        self._transport = transport or UrllibTransport(
            ca_bundle=ca_bundle,
            ca_bundle_data=ca_bundle_data,
            allowed_base_url=self._base_url,
        )
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._retry_attempts = max(0, retry_attempts)
        self._allowed_methods = frozenset(method.upper() for method in allowed_methods)
        if not self._allowed_methods:
            raise ConfigurationError("allowed_methods must not be empty")

    @property
    def base_url(self) -> str:
        """Return the normalized base URL."""

        return self._base_url.rstrip("/")

    def request_json(
        self,
        method: str,
        path_or_url: str,
        *,
        query: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json_body: Any | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
        headers: Mapping[str, str] | None = None,
        safe_to_retry: bool = False,
        max_response_bytes: int | None = None,
        accepted_statuses: frozenset[int] = frozenset(),
    ) -> tuple[Any, HttpResponse]:
        """Perform a URL-scope-bound request and decode JSON.

        Parameters
        ----------
        method
            HTTP method.
        path_or_url
            Relative path or same-origin absolute URL.
        query
            Query parameters. Sequence values are encoded with repeated keys.
        json_body
            JSON request body.
        headers
            Additional non-secret headers.
        safe_to_retry
            Whether a non-GET request is semantically safe to retry.

        Returns
        -------
        tuple[Any, HttpResponse]
            Decoded JSON value and response metadata.
        """

        response = self.request_bytes(
            method,
            path_or_url,
            query=query,
            json_body=json_body,
            body=body,
            content_type=content_type,
            headers=headers,
            safe_to_retry=safe_to_retry,
            max_response_bytes=max_response_bytes,
            accepted_statuses=accepted_statuses,
        )
        return response.json(), response

    def request_form(
        self,
        method: str,
        path_or_url: str,
        *,
        form: Mapping[str, Any] | Sequence[tuple[str, Any]],
        headers: Mapping[str, str] | None = None,
        safe_to_retry: bool = False,
        max_response_bytes: int | None = None,
        accepted_statuses: frozenset[int] = frozenset(),
    ) -> tuple[Any, HttpResponse]:
        """Send an ``application/x-www-form-urlencoded`` request."""

        encoded = urlencode(_query_items(form), doseq=True).encode("utf-8")
        response = self.request_bytes(
            method,
            path_or_url,
            body=encoded,
            content_type="application/x-www-form-urlencoded",
            headers=headers,
            safe_to_retry=safe_to_retry,
            max_response_bytes=max_response_bytes,
            accepted_statuses=accepted_statuses,
        )
        return response.json(), response

    def request_bytes(
        self,
        method: str,
        path_or_url: str,
        *,
        query: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json_body: Any | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
        headers: Mapping[str, str] | None = None,
        safe_to_retry: bool = False,
        max_response_bytes: int | None = None,
        accepted_statuses: frozenset[int] = frozenset(),
    ) -> HttpResponse:
        """Perform a URL-scope-bound request and return bounded bytes."""

        normalized_method = method.upper()
        if normalized_method not in self._allowed_methods:
            raise ConnectorHttpError(
                f"HTTP method {normalized_method} is not permitted by this connector"
            )
        url = self.resolve_url(path_or_url, query=query)
        dynamic_headers = (
            dict(self._header_provider()) if self._header_provider is not None else {}
        )
        request_headers = {
            **self._headers,
            **dynamic_headers,
            **dict(headers or {}),
        }
        if json_body is not None and body is not None:
            raise ConnectorHttpError("json_body and body are mutually exclusive")
        request_body = body
        if json_body is not None:
            request_body = json.dumps(
                json_body,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif content_type is not None:
            request_headers["Content-Type"] = content_type

        effective_max_bytes = self._max_response_bytes
        if max_response_bytes is not None:
            if max_response_bytes <= 0:
                raise ConnectorHttpError("max_response_bytes must be positive")
            effective_max_bytes = min(max_response_bytes, self._max_response_bytes)

        attempts = self._retry_attempts + 1
        for attempt in range(attempts):
            budget = _ACTION_BUDGET.get()
            if budget is not None:
                budget.reserve_request()
                remaining = budget.remaining_response_bytes
                if remaining <= 0:
                    raise ConnectorHttpError(
                        "connector action exceeded its global response-byte budget"
                    )
                request_max_bytes = min(effective_max_bytes, remaining)
            else:
                request_max_bytes = effective_max_bytes
            response = self._transport.request(
                method=normalized_method,
                url=url,
                headers=request_headers,
                body=request_body,
                timeout_seconds=self._timeout_seconds,
                max_response_bytes=request_max_bytes,
            )
            try:
                response_origin = _origin(urlparse(response.url))
            except (ConfigurationError, ValueError):
                response_origin = None
            if response_origin != self._origin:
                raise ConnectorHttpError(
                    "connector transport returned a response outside its configured "
                    "origin"
                )
            if not _url_within_scope(
                response.url,
                origin=self._origin,
                path=self._scope_path,
            ):
                raise ConnectorHttpError(
                    "connector transport returned a response outside its configured "
                    "URL scope"
                )
            if budget is not None:
                budget.record_response(len(response.body))
            response = replace(response, url=_safe_url(response.url))
            if 200 <= response.status < 300 or response.status in accepted_statuses:
                return response
            can_retry = (
                response.status in self._RETRYABLE_STATUSES
                and attempt + 1 < attempts
                and (normalized_method in {"GET", "HEAD"} or safe_to_retry)
            )
            if can_retry:
                time.sleep(_retry_delay_seconds(response, attempt))
                continue
            raise _http_error(response)
        raise ConnectorHttpError("HTTP retry loop exited unexpectedly")

    def resolve_url(
        self,
        path_or_url: str,
        *,
        query: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
    ) -> str:
        """Resolve and validate a relative or absolute API URL."""

        candidate = path_or_url.strip()
        if not candidate:
            raise ConnectorHttpError("request path must not be empty")
        parsed_candidate = urlparse(candidate)
        if parsed_candidate.netloc and not parsed_candidate.scheme:
            raise ConnectorHttpError("unsafe URL rejected by connector HTTP policy")
        if _decoded_safe_path(parsed_candidate.path) is None:
            raise ConnectorHttpError(
                "unsafe URL path rejected by connector HTTP policy"
            )
        if parsed_candidate.scheme:
            url = candidate
        else:
            url = urljoin(self._base_url, candidate.lstrip("/"))
        parsed = urlparse(url)
        try:
            candidate_origin = _origin(parsed)
        except (ConfigurationError, ValueError):
            candidate_origin = None
        if candidate_origin != self._origin:
            raise ConnectorHttpError(
                "connector attempted to access a URL outside its configured origin"
            )
        if not _url_within_scope(
            url,
            origin=self._origin,
            path=self._scope_path,
        ):
            raise ConnectorHttpError(
                "connector attempted to access a URL outside its configured URL scope"
            )
        if parsed.username or parsed.password or parsed.fragment:
            raise ConnectorHttpError("unsafe URL rejected by connector HTTP policy")
        if query:
            encoded = urlencode(_query_items(query), doseq=True)
            separator = "&" if parsed.query else "?"
            url = f"{url}{separator}{encoded}"
        return url


def download_public_https(
    url: str,
    *,
    allowed_host_suffixes: tuple[str, ...],
    transport: HttpTransport | None = None,
    timeout_seconds: float = 20.0,
    max_response_bytes: int = 2 * 1024 * 1024,
) -> HttpResponse:
    """Download a bounded HTTPS resource without authentication headers.

    This helper is intended for short-lived SharePoint download URLs returned
    by Microsoft Graph. It blocks IP literals, localhost, userinfo, and hosts
    outside an explicit suffix allowlist.
    """

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or _looks_like_ip(hostname)
        or hostname in {"localhost", "localhost.localdomain"}
    ):
        raise ConnectorHttpError("unsafe download URL rejected")
    normalized_suffixes = tuple(item.lower() for item in allowed_host_suffixes)
    if not any(
        hostname == suffix.lstrip(".") or hostname.endswith(suffix)
        for suffix in normalized_suffixes
    ):
        raise ConnectorHttpError(f"download host is not allowlisted: {hostname}")
    client = SafeHttpClient(
        base_url=f"https://{parsed.netloc}",
        default_headers={"Accept": "*/*"},
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        retry_attempts=1,
    )
    return client.request_bytes("GET", url)


def _read_bounded(stream: Any, max_bytes: int) -> bytes:
    payload = stream.read(max_bytes + 1)
    if not isinstance(payload, bytes):
        raise ConnectorHttpError("HTTP transport returned a non-bytes response")
    if len(payload) > max_bytes:
        raise ConnectorHttpError(
            f"response exceeded configured limit of {max_bytes} bytes"
        )
    return payload


def _normalize_headers(headers: Message | Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _decoded_safe_path(path: str) -> str | None:
    """Return a fully decoded path, or ``None`` for traversal-shaped input."""

    candidate = path or "/"
    for _ in range(8):
        if "\\" in candidate or any(
            segment.partition(";")[0] in {".", ".."} for segment in candidate.split("/")
        ):
            return None
        decoded = unquote(candidate)
        if decoded == candidate:
            normalized = candidate.rstrip("/")
            return normalized or "/"
        candidate = decoded
    return None


def _url_within_scope(
    url: str,
    *,
    origin: tuple[str, str, int],
    path: str,
) -> bool:
    """Return whether a URL remains in one origin and decoded base-path tree."""

    parsed = urlparse(url)
    try:
        candidate_origin = _origin(parsed)
    except (ConfigurationError, ValueError):
        return False
    candidate_path = _decoded_safe_path(parsed.path)
    if (
        candidate_origin != origin
        or parsed.username
        or parsed.password
        or parsed.fragment
        or candidate_path is None
    ):
        return False
    return (
        path == "/" or candidate_path == path or candidate_path.startswith(f"{path}/")
    )


def _origin(parsed: ParseResult) -> tuple[str, str, int]:
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if not scheme or not hostname:
        raise ConfigurationError("URL must include a scheme and hostname")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, hostname, port


def _query_items(
    query: Mapping[str, Any] | Sequence[tuple[str, Any]],
) -> list[tuple[str, Any]]:
    items = list(query.items()) if isinstance(query, Mapping) else list(query)
    normalized: list[tuple[str, Any]] = []
    for key, value in items:
        if value is None:
            continue
        if isinstance(value, (tuple, list, set)):
            for item in value:
                normalized.append((str(key), item))
        else:
            normalized.append((str(key), value))
    return normalized


def _retry_delay_seconds(response: HttpResponse, attempt: int) -> float:
    retry_after = response.headers.get("retry-after")
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), 5.0)
        except ValueError:
            pass
    return min(0.25 * (2.0**attempt), 2.0)


def _http_error(response: HttpResponse) -> ConnectorError:
    raw_request_id = (
        response.headers.get("x-request-id")
        or response.headers.get("request-id")
        or response.headers.get("x-arequestid")
        or response.headers.get("x-b3-traceid")
    )
    request_id = _safe_diagnostic_identifier(raw_request_id)
    suffix = f" request_id={request_id}" if request_id else ""
    message = f"HTTP {response.status} from {_safe_url(response.url)}{suffix}"
    if response.status == 401:
        return AuthenticationError(message)
    if response.status == 403:
        return AuthorizationError(message)
    if response.status == 404:
        return ResourceNotFoundError(message)
    if response.status == 429:
        retry_after: int | None = None
        raw_retry = response.headers.get("retry-after")
        if raw_retry:
            try:
                retry_after = max(0, int(float(raw_retry)))
            except ValueError:
                retry_after = None
        return RateLimitError(message, retry_after_seconds=retry_after)
    return ConnectorHttpError(
        message,
        status_code=response.status,
        request_id=request_id,
    )


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(query="", fragment="").geturl()


_DIAGNOSTIC_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _safe_diagnostic_identifier(value: str | None) -> str | None:
    """Return a bounded opaque identifier, never arbitrary provider text."""

    if value is None:
        return None
    rendered = value.strip()
    return rendered if _DIAGNOSTIC_IDENTIFIER_RE.fullmatch(rendered) else None


def _require_public_https_destination(url: str) -> None:
    """Reject private/reserved destinations immediately before I/O."""

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not hostname:
        raise ConnectorHttpError("network destination must be public HTTPS")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(
        ".local"
    ):
        raise ConnectorHttpError("private or local network destination rejected")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise ConnectorHttpError("private or reserved network destination rejected")
        return
    _public_address_records(hostname, parsed.port or 443, diagnostic_url=url)


def _public_address_records(
    hostname: str,
    port: int,
    *,
    diagnostic_url: str | None = None,
) -> tuple[tuple[Any, ...], ...]:
    """Resolve and return only a wholly public set of socket addresses."""

    try:
        records = tuple(socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
    except OSError as error:
        target = _safe_url(diagnostic_url or f"https://{hostname}:{port}")
        raise ConnectorHttpError(
            f"network destination could not be resolved for {target}"
        ) from error
    if not records:
        target = _safe_url(diagnostic_url or f"https://{hostname}:{port}")
        raise ConnectorHttpError(
            f"network destination could not be resolved for {target}"
        )
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0])
        except (IndexError, ValueError) as error:
            raise ConnectorHttpError(
                "network resolver returned an invalid address"
            ) from error
        if not address.is_global:
            raise ConnectorHttpError("private or reserved network destination rejected")
    return records


def _connect_public_address(
    hostname: str,
    port: int,
    *,
    timeout: object,
    source_address: tuple[str, int] | None,
) -> tuple[socket.socket, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Connect directly to a vetted resolver result without resolving again."""

    records = _public_address_records(hostname.rstrip("."), port)
    last_error: OSError | None = None
    for family, socktype, protocol, _, sockaddr in records:
        candidate = socket.socket(family, socktype, protocol)
        try:
            if timeout is None:
                candidate.settimeout(None)
            elif isinstance(timeout, (int, float)):
                candidate.settimeout(float(timeout))
            if source_address is not None:
                candidate.bind(source_address)
            candidate.connect(sockaddr)
            approved_address = ipaddress.ip_address(sockaddr[0])
            return candidate, approved_address
        except OSError as error:
            last_error = error
            candidate.close()
    raise ConnectorHttpError(
        "network request could not connect to a vetted public destination"
    ) from last_error


def _looks_like_ip(hostname: str) -> bool:
    if ":" in hostname:
        return True
    parts = hostname.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)
