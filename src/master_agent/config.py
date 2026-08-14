"""Integration and workflow configuration models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import os
from pathlib import Path
from types import MappingProxyType
import tomllib
from typing import Any, Mapping
from urllib.parse import urlparse

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.http import HttpTransport
from master_agent.oauth import (
    EntraClientCredentialsProvider,
    EnvironmentTokenProvider,
    InMemoryTokenCache,
    RestrictedTokenFileProvider,
)


class DeploymentType(StrEnum):
    """Supported deployment families."""

    CLOUD = "cloud"
    DATA_CENTER = "data_center"


@dataclass(frozen=True, slots=True)
class ConnectorConfig:
    """Unresolved configuration for one connector.

    Secret values are referenced by environment-variable name and are never
    stored in TOML.
    """

    system: str
    enabled: bool
    deployment: DeploymentType
    base_url: str | None
    base_url_env: str | None
    auth_mode: AuthMode
    username_env: str | None
    secret_env: str | None
    ca_bundle_env: str | None = None
    timeout_seconds: float = 20.0
    max_pages: int = 10
    max_items: int = 200
    max_response_bytes: int = 10 * 1024 * 1024
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.system.strip():
            raise ConfigurationError("connector system must not be empty")
        if self.timeout_seconds <= 0:
            raise ConfigurationError("timeout_seconds must be positive")
        if self.max_pages <= 0:
            raise ConfigurationError("max_pages must be positive")
        if self.max_items <= 0:
            raise ConfigurationError("max_items must be positive")
        if self.max_response_bytes <= 0:
            raise ConfigurationError("max_response_bytes must be positive")
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))

    def required_environment_variables(self) -> tuple[str, ...]:
        """Return environment variables required by the connector.

        Returns
        -------
        tuple[str, ...]
            Required variable names in deterministic order.
        """

        names: list[str] = []
        if not self.base_url and self.base_url_env:
            names.append(self.base_url_env)
        if self.auth_mode is AuthMode.BASIC and self.username_env:
            names.append(self.username_env)
        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        if self.auth_mode is AuthMode.OAUTH_APPLICATION and oauth_flow == "client_credentials":
            for key in ("tenant_id_env", "client_id_env", "client_secret_env"):
                value = self.extra.get(key)
                if isinstance(value, str) and value.strip():
                    names.append(value.strip())
        elif self.auth_mode is AuthMode.OAUTH_DELEGATED and oauth_flow == "token_file":
            value = self.extra.get("token_file_env")
            if isinstance(value, str) and value.strip():
                names.append(value.strip())
        elif self.auth_mode is not AuthMode.NONE and self.secret_env:
            names.append(self.secret_env)
        return tuple(dict.fromkeys(names))

    def configuration_errors(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> tuple[str, ...]:
        """Return secret-safe configuration errors without making requests.

        Parameters
        ----------
        environ
            Environment mapping. Defaults to ``os.environ``.

        Returns
        -------
        tuple[str, ...]
            Deterministically ordered validation errors.
        """

        source = environ if environ is not None else os.environ
        errors: list[str] = []
        if not self.base_url and not self.base_url_env:
            errors.append("base_url or base_url_env is required")
        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        if self.auth_mode is AuthMode.BASIC and not self.username_env:
            errors.append("username_env is required for Basic authentication")
        if self.auth_mode is AuthMode.OAUTH_APPLICATION and oauth_flow == "client_credentials":
            for key in ("tenant_id_env", "client_id_env", "client_secret_env"):
                value = self.extra.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{key} is required for client_credentials authentication")
            scopes = self.extra.get("scopes", [])
            if not isinstance(scopes, list) or not all(isinstance(item, str) and item.strip() for item in scopes):
                errors.append("scopes must be a non-empty string list for OAuth")
            elif not scopes:
                errors.append("scopes must be a non-empty string list for OAuth")
        elif self.auth_mode is AuthMode.OAUTH_DELEGATED and oauth_flow == "token_file":
            value = self.extra.get("token_file_env")
            if not isinstance(value, str) or not value.strip():
                errors.append("token_file_env is required for token_file authentication")
        elif self.auth_mode is not AuthMode.NONE and not self.secret_env:
            errors.append("secret_env is required for authenticated connectors")
        errors.extend(
            f"environment variable {name} is missing"
            for name in self.missing_environment_variables(source)
        )
        base_url = (
            source.get(self.base_url_env, "") if self.base_url_env else ""
        ).strip() or (self.base_url or "").strip()
        if base_url:
            try:
                _validate_base_url(base_url, system=self.system)
            except ConfigurationError as error:
                errors.append(str(error))
        return tuple(dict.fromkeys(errors))

    def missing_environment_variables(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> tuple[str, ...]:
        """Return required variables that are currently absent."""

        source = environ if environ is not None else os.environ
        return tuple(
            name for name in self.required_environment_variables() if not source.get(name)
        )

    def resolve(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        auth_transport: HttpTransport | None = None,
    ) -> ResolvedConnectorConfig:
        """Resolve environment references into an in-memory connector config.

        Parameters
        ----------
        environ
            Environment mapping. Defaults to ``os.environ``.

        Returns
        -------
        ResolvedConnectorConfig
            Runtime configuration with authentication material.

        Raises
        ------
        ConfigurationError
            If the connector is disabled or required configuration is missing.
        """

        if not self.enabled:
            raise ConfigurationError(f"connector is disabled: {self.system}")
        source = environ if environ is not None else os.environ
        errors = self.configuration_errors(source)
        if errors:
            raise ConfigurationError(
                f"connector {self.system} configuration is invalid: "
                + "; ".join(errors)
            )

        base_url = (source.get(self.base_url_env, "") if self.base_url_env else "")
        base_url = base_url.strip() or (self.base_url or "").strip()
        if not base_url:
            raise ConfigurationError(
                f"connector {self.system} requires a base URL"
            )
        _validate_base_url(base_url, system=self.system)

        username = source.get(self.username_env) if self.username_env else None
        secret = source.get(self.secret_env) if self.secret_env else None
        if self.auth_mode is AuthMode.BASIC and not username:
            raise ConfigurationError(
                f"connector {self.system} requires a Basic-auth username"
            )

        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        token_provider = None
        if self.auth_mode is AuthMode.OAUTH_APPLICATION and oauth_flow == "client_credentials":
            tenant_id = _environment_value(source, self.extra, "tenant_id_env")
            client_id = _environment_value(source, self.extra, "client_id_env")
            client_secret = _environment_value(source, self.extra, "client_secret_env")
            scopes = tuple(str(item) for item in self.extra.get("scopes", []))
            token_provider = InMemoryTokenCache(
                EntraClientCredentialsProvider(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    scopes=scopes,
                    transport=auth_transport,
                    timeout_seconds=self.timeout_seconds,
                )
            )
            secret = None
        elif self.auth_mode is AuthMode.OAUTH_DELEGATED and oauth_flow == "token_file":
            token_path = Path(_environment_value(source, self.extra, "token_file_env"))
            token_provider = RestrictedTokenFileProvider(token_path)
            secret = None
        elif self.auth_mode in {AuthMode.BEARER, AuthMode.OAUTH_DELEGATED, AuthMode.OAUTH_APPLICATION}:
            if not self.secret_env:
                raise ConfigurationError(
                    f"connector {self.system} requires a token environment reference"
                )
            expires_at_env = self.extra.get("token_expires_at_env")
            token_provider = EnvironmentTokenProvider(
                token_env=self.secret_env,
                expires_at_env=(str(expires_at_env) if expires_at_env else None),
                scopes=tuple(str(item) for item in self.extra.get("scopes", [])),
                environ=source,
            )
            secret = None
        elif self.auth_mode is not AuthMode.NONE and not secret:
            raise ConfigurationError(
                f"connector {self.system} requires an authentication secret"
            )

        ca_bundle = (
            Path(source[self.ca_bundle_env]).expanduser()
            if self.ca_bundle_env and source.get(self.ca_bundle_env)
            else None
        )
        if ca_bundle is not None and not ca_bundle.is_file():
            raise ConfigurationError(
                f"connector {self.system} CA bundle does not exist: {ca_bundle}"
            )

        return ResolvedConnectorConfig(
            system=self.system,
            deployment=self.deployment,
            base_url=base_url.rstrip("/"),
            auth=ResolvedAuth(
                mode=self.auth_mode,
                username=username,
                secret=secret,
                token_provider=token_provider,
            ),
            timeout_seconds=self.timeout_seconds,
            max_pages=self.max_pages,
            max_items=self.max_items,
            max_response_bytes=self.max_response_bytes,
            ca_bundle=ca_bundle,
            extra=self.extra,
        )


@dataclass(frozen=True, slots=True)
class ResolvedConnectorConfig:
    """Runtime connector configuration with in-memory credentials."""

    system: str
    deployment: DeploymentType
    base_url: str
    auth: ResolvedAuth = field(repr=False)
    timeout_seconds: float = 20.0
    max_pages: int = 10
    max_items: int = 200
    max_response_bytes: int = 10 * 1024 * 1024
    ca_bundle: Path | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))


@dataclass(frozen=True, slots=True)
class IntegrationConfig:
    """Collection of connector configurations."""

    connectors: Mapping[str, ConnectorConfig]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "connectors",
            MappingProxyType(dict(self.connectors)),
        )

    @classmethod
    def from_toml(cls, path: ConfigSource) -> IntegrationConfig:
        """Load connector configuration from TOML.

        Parameters
        ----------
        path
            TOML configuration path.

        Returns
        -------
        IntegrationConfig
            Parsed integration configuration.
        """

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"integration configuration not found: {path}"
            ) from error
        raw_connectors = raw.get("connectors", {})
        if not isinstance(raw_connectors, Mapping):
            raise ConfigurationError("[connectors] must be a TOML table")

        parsed: dict[str, ConnectorConfig] = {}
        for system, value in raw_connectors.items():
            if not isinstance(value, Mapping):
                raise ConfigurationError(
                    f"connector config must be a table: {system}"
                )
            parsed[str(system)] = _parse_connector(str(system), value)
        return cls(connectors=parsed)

    def connector(self, system: str) -> ConnectorConfig:
        """Return one configured connector.

        Raises
        ------
        ConfigurationError
            If no connector exists for the system.
        """

        try:
            return self.connectors[system]
        except KeyError as error:
            raise ConfigurationError(
                f"connector is not configured: {system}"
            ) from error


_KNOWN_CONNECTOR_KEYS = {
    "enabled",
    "deployment",
    "base_url",
    "base_url_env",
    "auth_mode",
    "username_env",
    "secret_env",
    "ca_bundle_env",
    "timeout_seconds",
    "max_pages",
    "max_items",
    "max_response_bytes",
}


def _parse_connector(
    system: str,
    raw: Mapping[str, Any],
) -> ConnectorConfig:
    extra = {key: value for key, value in raw.items() if key not in _KNOWN_CONNECTOR_KEYS}
    try:
        deployment = DeploymentType(str(raw.get("deployment", "cloud")))
        auth_mode = AuthMode(str(raw.get("auth_mode", "none")))
    except ValueError as error:
        raise ConfigurationError(
            f"invalid deployment or auth mode for connector {system}"
        ) from error

    return ConnectorConfig(
        system=system,
        enabled=_strict_bool(raw.get("enabled", False), f"connector {system} enabled"),
        deployment=deployment,
        base_url=_optional_string(raw.get("base_url")),
        base_url_env=_optional_string(raw.get("base_url_env")),
        auth_mode=auth_mode,
        username_env=_optional_string(raw.get("username_env")),
        secret_env=_optional_string(raw.get("secret_env")),
        ca_bundle_env=_optional_string(raw.get("ca_bundle_env")),
        timeout_seconds=float(raw.get("timeout_seconds", 20.0)),
        max_pages=int(raw.get("max_pages", 10)),
        max_items=int(raw.get("max_items", 200)),
        max_response_bytes=int(raw.get("max_response_bytes", 10 * 1024 * 1024)),
        extra=extra,
    )


def _environment_value(
    source: Mapping[str, str],
    extra: Mapping[str, Any],
    key: str,
) -> str:
    variable = extra.get(key)
    if not isinstance(variable, str) or not variable.strip():
        raise ConfigurationError(f"missing environment reference: {key}")
    value = source.get(variable.strip(), "").strip()
    if not value:
        raise ConfigurationError(
            f"environment variable {variable.strip()} is missing"
        )
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered or None


def _validate_base_url(base_url: str, *, system: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ConfigurationError(
            f"connector {system} has an invalid base URL"
        )
    if parsed.username or parsed.password:
        raise ConfigurationError(
            f"connector {system} base URL must not contain credentials"
        )
    if parsed.scheme != "https":
        raise ConfigurationError(
            f"connector {system} must use HTTPS; terminate TLS before this client"
        )


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value
