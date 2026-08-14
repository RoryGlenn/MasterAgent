"""Contract-test fakes for connector HTTP interactions."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Mapping

from master_agent.http import HttpResponse


@dataclass(slots=True)
class ExpectedRequest:
    """One expected HTTP request and its synthetic response."""

    method: str
    url_contains: str
    payload: Any
    status: int = 200
    headers: Mapping[str, str] = field(default_factory=dict)
    response_url: str | None = None
    body_contains: str | None = None


class QueueTransport:
    """FIFO transport that validates connector request contracts."""

    def __init__(self, *expected: ExpectedRequest) -> None:
        self.expected = list(expected)
        self.requests: list[dict[str, Any]] = []

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
        """Validate and satisfy one expected request."""

        if not self.expected:
            raise AssertionError(f"unexpected request: {method} {url}")
        expected = self.expected.pop(0)
        if method != expected.method:
            raise AssertionError(f"expected {expected.method}, received {method}")
        if expected.url_contains not in url:
            raise AssertionError(
                f"expected URL containing {expected.url_contains!r}, received {url!r}"
            )
        rendered_body = body.decode("utf-8") if body is not None else None
        if expected.body_contains and (
            rendered_body is None or expected.body_contains not in rendered_body
        ):
            raise AssertionError(
                f"request body did not contain {expected.body_contains!r}: "
                f"{rendered_body!r}"
            )
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": rendered_body,
                "timeout_seconds": timeout_seconds,
                "max_response_bytes": max_response_bytes,
            }
        )
        response_body = (
            expected.payload
            if isinstance(expected.payload, bytes)
            else json.dumps(expected.payload).encode("utf-8")
        )
        return HttpResponse(
            status=expected.status,
            headers={str(k).lower(): str(v) for k, v in expected.headers.items()},
            body=response_body,
            url=expected.response_url or url,
        )

    def assert_drained(self) -> None:
        """Fail when the connector did not issue all expected requests."""

        if self.expected:
            raise AssertionError(f"{len(self.expected)} expected requests were not made")

@dataclass(slots=True)
class RecordedRequest:
    """HTTP request captured by ``ScriptedTransport``."""

    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    timeout_seconds: float
    max_response_bytes: int

    def json_body(self) -> Any:
        """Decode the request body as JSON."""

        if self.body is None:
            return None
        return json.loads(self.body.decode("utf-8"))


@dataclass(slots=True)
class _ScriptedResponse:
    """One reusable response registered for a route."""

    method: str
    path: str
    body: bytes
    status: int
    headers: Mapping[str, str]
    host: str | None = None


class ScriptedTransport:
    """Reusable route-based HTTP transport for connector contract tests.

    Routes remain available after a request so connector verification can
    re-read the same resource. When several responses are registered for the
    same route, they are served in registration order and the final response
    remains reusable.
    """

    def __init__(self) -> None:
        self._responses: list[_ScriptedResponse] = []
        self._route_offsets: dict[tuple[str, str, str | None], int] = {}
        self.requests: list[RecordedRequest] = []

    def add_json(
        self,
        method: str,
        path: str,
        payload: Any,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
    ) -> None:
        """Register a reusable JSON response for a method and URL path."""

        self._responses.append(
            _ScriptedResponse(
                method=method.upper(),
                path=path,
                body=json.dumps(payload).encode("utf-8"),
                status=status,
                headers=dict(headers or {}),
                host=host,
            )
        )

    def add_bytes(
        self,
        method: str,
        path: str,
        payload: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
    ) -> None:
        """Register a reusable byte response for a method and URL path."""

        self._responses.append(
            _ScriptedResponse(
                method=method.upper(),
                path=path,
                body=payload,
                status=status,
                headers=dict(headers or {}),
                host=host,
            )
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
        """Capture one request and return its scripted response."""

        from urllib.parse import urlparse

        parsed = urlparse(url)
        recorded = RecordedRequest(
            method=method.upper(),
            url=url,
            headers=dict(headers),
            body=body,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        self.requests.append(recorded)

        matches = [
            response
            for response in self._responses
            if response.method == recorded.method
            and response.path == parsed.path
            and (response.host is None or response.host == parsed.hostname)
        ]
        if not matches:
            raise AssertionError(f"no scripted response for {recorded.method} {url}")

        key = (recorded.method, parsed.path, parsed.hostname)
        offset = self._route_offsets.get(key, 0)
        selected = matches[min(offset, len(matches) - 1)]
        if offset < len(matches) - 1:
            self._route_offsets[key] = offset + 1

        if len(selected.body) > max_response_bytes:
            raise AssertionError(
                f"scripted response exceeded limit of {max_response_bytes} bytes"
            )
        return HttpResponse(
            status=selected.status,
            headers={str(k).lower(): str(v) for k, v in selected.headers.items()},
            body=selected.body,
            url=url,
        )

