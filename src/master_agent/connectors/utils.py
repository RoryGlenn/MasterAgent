"""Validation helpers shared by connector implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urljoin, urlparse

from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import AgentAction


def string_parameter(
    parameters: Mapping[str, Any],
    key: str,
    *,
    default: str | None = None,
    required: bool = False,
) -> str:
    """Read and validate a string action parameter."""

    value = parameters.get(key, default)
    if value is None:
        if required:
            raise ConnectorError(f"missing required parameter: {key}")
        return ""
    rendered = str(value).strip()
    if required and not rendered:
        raise ConnectorError(f"parameter must not be empty: {key}")
    return rendered


def integer_parameter(
    parameters: Mapping[str, Any],
    key: str,
    *,
    default: int,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    """Read and validate an integer action parameter."""

    try:
        value = int(parameters.get(key, default))
    except (TypeError, ValueError) as error:
        raise ConnectorError(f"parameter must be an integer: {key}") from error
    if value < minimum:
        raise ConnectorError(f"parameter {key} must be at least {minimum}")
    if maximum is not None:
        value = min(value, maximum)
    return value


def boolean_parameter(
    parameters: Mapping[str, Any],
    key: str,
    *,
    default: bool = False,
) -> bool:
    """Read a boolean parameter without accepting ambiguous strings."""

    value = parameters.get(key, default)
    if isinstance(value, bool):
        return value
    raise ConnectorError(f"parameter must be a boolean: {key}")


def string_list_parameter(
    parameters: Mapping[str, Any],
    key: str,
    *,
    default: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Read a list of non-empty strings."""

    value = parameters.get(key, default)
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if not isinstance(value, (tuple, list)):
        raise ConnectorError(f"parameter must be a list of strings: {key}")
    rendered = tuple(str(item).strip() for item in value if str(item).strip())
    return rendered


def quote_segment(value: str) -> str:
    """Quote one URL path segment."""

    return quote(value, safe="")


def safe_graph_resource_id(value: str) -> str:
    """Encode exactly one Microsoft Graph resource identifier path segment."""

    rendered = value.strip()
    if (
        not rendered
        or rendered in {".", ".."}
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in rendered
        )
    ):
        raise ConnectorError("unsafe Microsoft Graph resource identifier")
    return quote_segment(rendered)


def absolute_web_url(base_url: str, candidate: str | None) -> str | None:
    """Resolve a web UI URL without copying credentials or fragments."""

    if not candidate:
        return None
    resolved = urljoin(base_url.rstrip("/") + "/", candidate)
    parsed = urlparse(resolved)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return parsed._replace(fragment="").geturl()


def enforce_expected_version(action: AgentAction, observed: object | None) -> None:
    """Fail closed when a planned resource version no longer matches."""

    expected = action.target.expected_version
    if expected is None:
        return
    rendered = None if observed is None else str(observed)
    if rendered != expected:
        raise VersionConflictError(
            f"version conflict for {action.target.uri}: expected {expected}, "
            f"observed {rendered}"
        )
