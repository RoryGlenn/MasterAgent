"""Evidence digests and audit-safe summaries."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from master_agent.models import ExecutionResult

_SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "refresh_token",
    "api_token",
    "token",
    "secret",
    "password",
    "client_secret",
}

_KNOWN_ERROR_CODES = {
    "ApprovalRequiredError": "approval_required",
    "AuthenticationError": "authentication_failed",
    "AuthorizationError": "authorization_failed",
    "ConfigurationError": "configuration_failed",
    "ConnectorError": "connector_failed",
    "ConnectorHttpError": "connector_http_failed",
    "HttpRequestError": "http_request_failed",
    "PolicyDeniedError": "policy_denied",
    "RateLimitError": "rate_limited",
    "ResourceNotFoundError": "resource_not_found",
    "ValidationError": "validation_failed",
    "VerificationError": "verification_failed",
    "VersionConflictError": "version_conflict",
}


def content_digest(value: Any) -> str:
    """Return a deterministic SHA-256 digest for JSON-compatible content.

    Parameters
    ----------
    value
        Value to hash.

    Returns
    -------
    str
        Hexadecimal SHA-256 digest.
    """

    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def result_audit_summary(result: ExecutionResult) -> dict[str, Any]:
    """Build a low-content audit summary for a connector result.

    The summary intentionally excludes retrieved document bodies, issue text,
    messages, and other potentially sensitive payload values.
    """

    return {
        "action_id": str(result.action_id),
        "state": str(result.state),
        "connector_reference": _reference_summary(result.connector_reference),
        **audit_message_metadata(result.message, default_code="connector_result"),
        "before": _mapping_summary(result.before),
        "after": _mapping_summary(result.after),
    }


def audit_message_metadata(
    message: str,
    *,
    default_code: str,
) -> dict[str, Any]:
    """Return a stable reason code and digest without persisting free-form text."""

    prefix = message.split(":", 1)[0].strip()
    reason_code = _KNOWN_ERROR_CODES.get(prefix, default_code)
    if message.casefold().startswith("verification failed"):
        reason_code = "verification_failed"
    reason_code = re.sub(r"[^a-z0-9_]+", "_", reason_code.casefold()).strip("_")
    return {
        "reason_code": reason_code or "unspecified",
        "message_digest": hashlib.sha256(message.encode("utf-8")).hexdigest(),
        "message_length": len(message),
    }


def _reference_summary(value: str | None) -> dict[str, str] | None:
    """Return a query-free reference plus a digest of the original value."""

    if value is None:
        return None
    parsed = urlparse(value)
    safe_value = (
        parsed._replace(query="", fragment="").geturl()
        if parsed.scheme in {"http", "https"}
        else value
    )
    return {
        "value": safe_value,
        "digest": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def redact_secrets(value: Any) -> Any:
    """Recursively redact values whose keys commonly contain secrets."""

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in _SENSITIVE_KEYS:
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = redact_secrets(item)
        return redacted
    if isinstance(value, (tuple, list, set)):
        return [redact_secrets(item) for item in value]
    return value


def _mapping_summary(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    keys = sorted(str(key) for key in value.keys())
    summary: dict[str, Any] = {
        "digest": content_digest(redact_secrets(value)),
        "keys": keys[:50],
        "key_count": len(keys),
    }
    for count_key in ("count", "total", "returned"):
        count_value = value.get(count_key)
        if isinstance(count_value, int):
            summary[count_key] = count_value
    schema = value.get("schema")
    if isinstance(schema, str):
        summary["schema"] = schema
    return summary
