"""Domain exceptions for the master-agent runtime."""

from __future__ import annotations


class MasterAgentError(Exception):
    """Base exception for governed runtime failures."""


class StructuredDataTypeError(TypeError, ValueError):
    """Malformed structured data with backward-compatible value semantics."""


class ValidationError(MasterAgentError):
    """Raised when a model or configuration is invalid."""


class ConfigurationError(MasterAgentError):
    """Raised when runtime or integration configuration is invalid."""


class PolicyDeniedError(MasterAgentError):
    """Raised when policy prohibits an action."""


class ApprovalRequiredError(MasterAgentError):
    """Raised when an action lacks a valid approval."""


class ConnectorError(MasterAgentError):
    """Raised when a connector cannot execute an action."""


class PreEffectError(ConnectorError):
    """Certify that a connector stopped before any observable side effect."""


class UnsupportedCapabilityError(ConnectorError):
    """Raised when a connector receives an unregistered capability."""


class AuthenticationError(ConnectorError):
    """Raised when an external system rejects authentication."""


class AuthorizationError(ConnectorError):
    """Raised when credentials lack permission for a resource."""


class ResourceNotFoundError(ConnectorError):
    """Raised when an external resource does not exist or is not visible."""


class RateLimitError(ConnectorError):
    """Raised when an external service rate-limits a request."""

    def __init__(self, message: str, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class HttpRequestError(ConnectorError):
    """Raised for transport or unexpected HTTP failures."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.request_id = request_id


class ConnectorHttpError(HttpRequestError):
    """Raised for bounded connector HTTP failures.

    This compatibility name is used by the origin-restricted HTTP client.
    """


class NetworkDnsError(ConnectorHttpError):
    """Raised when a governed network destination cannot be safely resolved."""


class NetworkTlsError(ConnectorHttpError):
    """Raised when provider TLS identity or configured CA validation fails."""


class NetworkTimeoutError(ConnectorHttpError):
    """Raised when a governed provider or proxy operation times out."""


class ProxyAuthenticationError(AuthenticationError):
    """Raised when an explicitly selected proxy rejects brokered credentials."""


class VersionConflictError(ConnectorError):
    """Raised when a resource changed after planning."""


class VerificationError(MasterAgentError):
    """Raised when resulting state cannot be verified."""
