"""Integration and workflow configuration models."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import ParseResult, urlparse

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.http import HttpTransport
from master_agent.oauth import (
    EntraClientCredentialsProvider,
    EnvironmentTokenProvider,
    InMemoryTokenCache,
    RestrictedTokenFileProvider,
    TokenProvider,
)
from master_agent.trust_store import CaBundleSnapshot, capture_ca_bundle

_PLACEHOLDER_PROVIDER_HOSTS = frozenset({"example.atlassian.net"})
_ATLASSIAN_CLOUD_ID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def is_placeholder_provider_url(value: str | None) -> bool:
    """Return whether an endpoint resolves to a packaged example hostname."""

    if value is None:
        return False
    try:
        hostname = (urlparse(value).hostname or "").casefold().rstrip(".")
    except ValueError:
        return False
    return hostname in _PLACEHOLDER_PROVIDER_HOSTS


class DeploymentType(StrEnum):
    """Supported deployment families."""

    CLOUD = "cloud"
    DATA_CENTER = "data_center"


class PrincipalAttestationAdapter(StrEnum):
    """Implemented provider-backed credential identity adapters."""

    GITHUB_AUTHENTICATED_USER = "github_authenticated_user"
    MICROSOFT_DELEGATED_USER = "microsoft_delegated_user"


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
    web_base_url: str | None = None
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

    @property
    def identity(self) -> str:
        """Return a stable, secret-free identity for approval/audit binding."""

        payload = {
            "system": self.system,
            "enabled": self.enabled,
            "deployment": str(self.deployment),
            "base_url": self.base_url,
            "base_url_env": self.base_url_env,
            "auth_mode": str(self.auth_mode),
            "username_env": self.username_env,
            "secret_env": self.secret_env,
            "web_base_url": self.web_base_url,
            "ca_bundle_env": self.ca_bundle_env,
            "timeout_seconds": self.timeout_seconds,
            "max_pages": self.max_pages,
            "max_items": self.max_items,
            "max_response_bytes": self.max_response_bytes,
            "extra": dict(self.extra),
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

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
        if (
            self.auth_mode is AuthMode.OAUTH_APPLICATION
            and oauth_flow == "client_credentials"
        ):
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

    def effective_base_url(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> str:
        """Return the environment-over-file provider URL selection."""

        source = environ if environ is not None else os.environ
        selected = source.get(self.base_url_env, "") if self.base_url_env else ""
        return selected.strip() or (self.base_url or "").strip()

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
        if (
            self.auth_mode is AuthMode.OAUTH_APPLICATION
            and oauth_flow == "client_credentials"
        ):
            for key in ("tenant_id_env", "client_id_env", "client_secret_env"):
                value = self.extra.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"{key} is required for client_credentials authentication"
                    )
            scopes = self.extra.get("scopes", [])
            if (
                not isinstance(scopes, list)
                or not all(isinstance(item, str) and item.strip() for item in scopes)
                or not scopes
            ):
                errors.append("scopes must be a non-empty string list for OAuth")
        elif self.auth_mode is AuthMode.OAUTH_DELEGATED and oauth_flow == "token_file":
            value = self.extra.get("token_file_env")
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    "token_file_env is required for token_file authentication"
                )
        elif self.auth_mode is not AuthMode.NONE and not self.secret_env:
            errors.append("secret_env is required for authenticated connectors")
        errors.extend(
            f"environment variable {name} is missing"
            for name in self.missing_environment_variables(source)
        )
        base_url = self.effective_base_url(source)
        if base_url:
            try:
                _validate_connector_urls(
                    base_url,
                    web_base_url=self.web_base_url,
                    system=self.system,
                    deployment=self.deployment,
                )
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
            name
            for name in self.required_environment_variables()
            if not source.get(name, "").strip()
        )

    def resolve_execution_target(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> tuple[str, Path | None]:
        """Resolve and validate the secret-free destination used by a connector.

        Unlike :meth:`resolve`, this method deliberately does not require or
        access authentication values. It is used while an operator binds the
        exact live destination and trust store to a plan before approval.
        """

        if not self.enabled:
            raise ConfigurationError(f"connector is disabled: {self.system}")
        source = environ if environ is not None else os.environ
        base_url = self.effective_base_url(source)
        if not base_url:
            raise ConfigurationError(f"connector {self.system} requires a base URL")
        _validate_connector_urls(
            base_url,
            web_base_url=self.web_base_url,
            system=self.system,
            deployment=self.deployment,
        )

        ca_bundle: Path | None = None
        if self.ca_bundle_env and source.get(self.ca_bundle_env):
            selected = Path(source[self.ca_bundle_env]).expanduser()
            try:
                ca_bundle = selected.resolve(strict=True)
            except OSError as error:
                raise ConfigurationError(
                    f"connector {self.system} CA bundle does not exist: {selected}"
                ) from error
            if not ca_bundle.is_file():
                raise ConfigurationError(
                    f"connector {self.system} CA bundle does not exist: {selected}"
                )
        return base_url.rstrip("/"), ca_bundle

    def capture_execution_target(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> ResolvedExecutionTarget:
        """Capture the destination and immutable CA bytes used by live TLS."""

        base_url, ca_bundle = self.resolve_execution_target(environ)
        return ResolvedExecutionTarget(
            system=self.system,
            config_identity=self.identity,
            base_url=base_url,
            ca_bundle=(capture_ca_bundle(ca_bundle) if ca_bundle is not None else None),
        )

    def credential_identity(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> str | None:
        """Return a flow-enforced credential principal for plan approval.

        Basic authentication binds the username the provider authenticates, and
        Entra client credentials bind the tenant/client pair used to acquire the
        token. Provider-backed adapters are resolved separately because they
        require a live attestation request. Other opaque bearer, delegated,
        token-file, and application-environment tokens do not expose an
        independently trustworthy principal. A declared label is not
        attestation, so live applied execution rejects those modes.
        """

        if self.auth_mode is AuthMode.NONE:
            return None
        if self.principal_attestation_adapter is not None:
            raise ConfigurationError(
                f"connector {self.system} credential identity requires "
                "provider attestation"
            )
        source = environ if environ is not None else os.environ
        if self.auth_mode is AuthMode.BASIC:
            if not self.username_env:
                raise ConfigurationError(
                    f"connector {self.system} requires a Basic-auth username"
                )
            username = source.get(self.username_env, "").strip()
            if not username:
                raise ConfigurationError(
                    f"connector {self.system} credential identity requires "
                    f"environment variable {self.username_env}"
                )
            return f"basic:{username}"

        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        if (
            self.auth_mode is AuthMode.OAUTH_APPLICATION
            and oauth_flow == "client_credentials"
        ):
            tenant_id = _environment_value(source, self.extra, "tenant_id_env")
            client_id = _environment_value(source, self.extra, "client_id_env")
            return f"entra-application:tenant={tenant_id};client={client_id}"

        raise ConfigurationError(self.principal_attestation_error() or "")

    @property
    def principal_attestation_adapter(self) -> PrincipalAttestationAdapter | None:
        """Return the implemented provider-backed principal adapter, if any."""

        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        if (
            self.system == "github"
            and self.deployment is DeploymentType.CLOUD
            and self.auth_mode is AuthMode.BEARER
            and oauth_flow == "environment"
        ):
            return PrincipalAttestationAdapter.GITHUB_AUTHENTICATED_USER
        if (
            self.system == "microsoft"
            and self.auth_mode is AuthMode.OAUTH_DELEGATED
            and oauth_flow in {"environment", "token_file"}
            and str(self.extra.get("identity_mode", "delegated")).casefold()
            == "delegated"
        ):
            return PrincipalAttestationAdapter.MICROSOFT_DELEGATED_USER
        return None

    def principal_attestation_error(self) -> str | None:
        """Return why this flow cannot bind a trusted applied-run principal."""

        if self.principal_attestation_adapter is not None:
            return None
        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        if self.auth_mode in {AuthMode.NONE, AuthMode.BASIC} or (
            self.auth_mode is AuthMode.OAUTH_APPLICATION
            and oauth_flow == "client_credentials"
        ):
            return None
        return (
            f"connector {self.system} uses opaque {self.auth_mode.value}/"
            f"{oauth_flow} credentials; live applied execution requires a "
            "provider-verified principal or trusted credential-broker "
            "attestation, and no such adapter is implemented"
        )

    def resolve(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        auth_transport: HttpTransport | None = None,
        execution_target: ResolvedExecutionTarget | None = None,
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

        target = execution_target or self.capture_execution_target(source)
        if target.system != self.system or target.config_identity != self.identity:
            raise ConfigurationError(
                f"connector {self.system} execution target does not match its config"
            )
        base_url = target.base_url
        ca_bundle = target.ca_bundle

        username = source.get(self.username_env) if self.username_env else None
        secret = source.get(self.secret_env) if self.secret_env else None
        if self.auth_mode is AuthMode.BASIC and not username:
            raise ConfigurationError(
                f"connector {self.system} requires a Basic-auth username"
            )

        oauth_flow = str(self.extra.get("oauth_flow", "environment")).strip()
        token_provider: TokenProvider | None = None
        if (
            self.auth_mode is AuthMode.OAUTH_APPLICATION
            and oauth_flow == "client_credentials"
        ):
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
                    ca_bundle_data=(ca_bundle.data if ca_bundle is not None else None),
                )
            )
            secret = None
        elif self.auth_mode is AuthMode.OAUTH_DELEGATED and oauth_flow == "token_file":
            token_path = Path(_environment_value(source, self.extra, "token_file_env"))
            token_provider = RestrictedTokenFileProvider(token_path)
            secret = None
        elif self.auth_mode in {
            AuthMode.BEARER,
            AuthMode.OAUTH_DELEGATED,
            AuthMode.OAUTH_APPLICATION,
        }:
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

        return ResolvedConnectorConfig(
            system=self.system,
            deployment=self.deployment,
            base_url=base_url,
            web_base_url=(self.web_base_url or base_url).rstrip("/"),
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
            ca_bundle=(ca_bundle.path if ca_bundle is not None else None),
            ca_bundle_data=(ca_bundle.data if ca_bundle is not None else None),
            ca_bundle_sha256=(ca_bundle.sha256 if ca_bundle is not None else None),
            extra=self.extra,
            config_identity=self.identity,
        )


@dataclass(frozen=True, slots=True)
class ResolvedExecutionTarget:
    """One captured connector destination before credentials are resolved."""

    system: str
    config_identity: str
    base_url: str
    ca_bundle: CaBundleSnapshot | None = None


@dataclass(frozen=True, slots=True)
class ResolvedConnectorConfig:
    """Runtime connector configuration with in-memory credentials."""

    system: str
    deployment: DeploymentType
    base_url: str
    auth: ResolvedAuth = field(repr=False)
    web_base_url: str | None = None
    timeout_seconds: float = 20.0
    max_pages: int = 10
    max_items: int = 200
    max_response_bytes: int = 10 * 1024 * 1024
    ca_bundle: Path | None = None
    ca_bundle_data: bytes | None = field(default=None, repr=False)
    ca_bundle_sha256: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)
    config_identity: str | None = None

    def __post_init__(self) -> None:
        if self.ca_bundle is not None and self.ca_bundle_data is None:
            snapshot = capture_ca_bundle(self.ca_bundle)
            object.__setattr__(self, "ca_bundle", snapshot.path)
            object.__setattr__(self, "ca_bundle_data", snapshot.data)
            object.__setattr__(self, "ca_bundle_sha256", snapshot.sha256)
        elif self.ca_bundle_data is not None:
            digest = hashlib.sha256(self.ca_bundle_data).hexdigest()
            if self.ca_bundle_sha256 is not None and self.ca_bundle_sha256 != digest:
                raise ConfigurationError(
                    "resolved connector CA data does not match its digest"
                )
            object.__setattr__(self, "ca_bundle_sha256", digest)
        elif self.ca_bundle_sha256 is not None:
            raise ConfigurationError(
                "resolved connector CA digest requires captured data"
            )
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))


@dataclass(frozen=True, slots=True)
class IntegrationConfig:
    """Collection of connector configurations."""

    connectors: Mapping[str, ConnectorConfig]
    source_sha256: str | None = None

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
                payload = handle.read()
            raw = tomllib.loads(payload.decode("utf-8"))
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
                raise ConfigurationError(f"connector config must be a table: {system}")
            parsed[str(system)] = _parse_connector(str(system), value)
        return cls(
            connectors=parsed,
            source_sha256=hashlib.sha256(payload).hexdigest(),
        )

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

    def credential_environment_variables(self) -> tuple[str, ...]:
        """Return the exact connector credential references a store may supply."""

        names: set[str] = set()
        for connector in self.connectors.values():
            for value in (connector.username_env, connector.secret_env):
                if value:
                    names.add(value)
            for key in (
                "token_file_env",
                "token_expires_at_env",
                "tenant_id_env",
                "client_id_env",
                "client_secret_env",
            ):
                value = connector.extra.get(key)
                if isinstance(value, str) and value.strip():
                    names.add(value.strip())
        return tuple(sorted(names))


_KNOWN_CONNECTOR_KEYS = {
    "enabled",
    "deployment",
    "base_url",
    "base_url_env",
    "web_base_url",
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
    extra = {
        key: value for key, value in raw.items() if key not in _KNOWN_CONNECTOR_KEYS
    }
    try:
        deployment = DeploymentType(str(raw.get("deployment", "cloud")))
        auth_mode = AuthMode(str(raw.get("auth_mode", "none")))
    except ValueError as error:
        raise ConfigurationError(
            f"invalid deployment or auth mode for connector {system}"
        ) from error

    connector = ConnectorConfig(
        system=system,
        enabled=_strict_bool(raw.get("enabled", False), f"connector {system} enabled"),
        deployment=deployment,
        base_url=_optional_string(raw.get("base_url")),
        base_url_env=_optional_string(raw.get("base_url_env")),
        auth_mode=auth_mode,
        username_env=_optional_string(raw.get("username_env")),
        secret_env=_optional_string(raw.get("secret_env")),
        web_base_url=_optional_string(raw.get("web_base_url")),
        ca_bundle_env=_optional_string(raw.get("ca_bundle_env")),
        timeout_seconds=float(raw.get("timeout_seconds", 20.0)),
        max_pages=int(raw.get("max_pages", 10)),
        max_items=int(raw.get("max_items", 200)),
        max_response_bytes=int(raw.get("max_response_bytes", 10 * 1024 * 1024)),
        extra=extra,
    )
    _validate_environment_references(connector)
    return connector


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
        raise ConfigurationError(f"environment variable {variable.strip()} is missing")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered or None


def _validate_base_url(base_url: str, *, system: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ConfigurationError(f"connector {system} has an invalid base URL")
    if parsed.username or parsed.password:
        raise ConfigurationError(
            f"connector {system} base URL must not contain credentials"
        )
    if "?" in base_url or "#" in base_url:
        raise ConfigurationError(
            f"connector {system} base URL must not contain a query or fragment"
        )
    if parsed.scheme != "https":
        raise ConfigurationError(
            f"connector {system} must use HTTPS; terminate TLS before this client"
        )
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ConfigurationError(
            f"connector {system} base URL must not use a private or reserved address"
        )
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(
        ".local"
    ):
        raise ConfigurationError(
            f"connector {system} base URL must not use a local hostname"
        )


def _validate_connector_urls(
    base_url: str,
    *,
    web_base_url: str | None,
    system: str,
    deployment: DeploymentType,
) -> None:
    """Validate the API destination and any separately approved UI origin."""

    _validate_base_url(base_url, system=system)
    _validate_provider_origin(
        base_url,
        system=system,
        deployment=deployment,
    )
    if web_base_url is not None:
        _validate_web_base_url(
            web_base_url,
            system=system,
            deployment=deployment,
        )
    if (
        deployment is DeploymentType.CLOUD
        and system in {"jira", "confluence"}
        and _is_atlassian_gateway_url(base_url, system=system)
        and web_base_url is None
    ):
        raise ConfigurationError(
            f"connector {system} Atlassian gateway base URL requires web_base_url"
        )


def _validate_provider_origin(
    base_url: str,
    *,
    system: str,
    deployment: DeploymentType,
) -> None:
    """Constrain cloud credentials to the provider's owned API domains."""

    if system == "microsoft" and deployment is not DeploymentType.CLOUD:
        raise ConfigurationError("connector microsoft requires Microsoft Graph Cloud")
    if deployment is not DeploymentType.CLOUD:
        return
    parsed = urlparse(base_url)
    hostname = (parsed.hostname or "").casefold()
    valid = True
    if system in {"jira", "confluence"}:
        valid = _is_atlassian_tenant_root(parsed) or _is_atlassian_gateway_url(
            base_url,
            system=system,
        )
    elif system == "bitbucket":
        valid = (
            hostname == "api.bitbucket.org"
            and _explicit_port(parsed) is None
            and parsed.path in {"/2.0", "/2.0/"}
            and not parsed.params
        )
    elif system == "github":
        valid = hostname.rstrip(".") == "api.github.com"
    elif system == "microsoft":
        valid = hostname.rstrip(".") in {
            "graph.microsoft.com",
            "graph.microsoft.us",
            "dod-graph.microsoft.us",
            "microsoftgraph.chinacloudapi.cn",
        }
    if not valid:
        raise ConfigurationError(
            f"connector {system} cloud base URL is outside approved provider origins"
        )


def _validate_web_base_url(
    web_base_url: str,
    *,
    system: str,
    deployment: DeploymentType,
) -> None:
    """Validate an approval-bound browser URL separately from the API root."""

    _validate_base_url(web_base_url, system=system)
    if (
        deployment is DeploymentType.CLOUD
        and system in {"jira", "confluence"}
        and not _is_atlassian_tenant_root(urlparse(web_base_url))
    ):
        raise ConfigurationError(
            f"connector {system} web_base_url must be an Atlassian tenant root"
        )


def _is_atlassian_gateway_url(base_url: str, *, system: str) -> bool:
    parsed = urlparse(base_url)
    if (
        (parsed.hostname or "").casefold() != "api.atlassian.com"
        or _explicit_port(parsed) is not None
        or parsed.params
    ):
        return False
    match = re.fullmatch(
        rf"/ex/{re.escape(system)}/({_ATLASSIAN_CLOUD_ID_PATTERN.pattern})/?",
        parsed.path,
    )
    return match is not None


def _is_atlassian_tenant_root(parsed: ParseResult) -> bool:
    hostname = (parsed.hostname or "").casefold()
    suffix = ".atlassian.net"
    if (
        not hostname.endswith(suffix)
        or hostname == suffix.removeprefix(".")
        or hostname.endswith(".")
        or _explicit_port(parsed) is not None
        or parsed.path not in {"", "/"}
        or parsed.params
    ):
        return False
    tenant = hostname[: -len(suffix)]
    return "." not in tenant and _DNS_LABEL_PATTERN.fullmatch(tenant) is not None


def _explicit_port(parsed: ParseResult) -> int | None:
    try:
        return parsed.port
    except ValueError as error:
        raise ConfigurationError("connector base URL has an invalid port") from error


_ALLOWED_ENVIRONMENT_REFERENCES: Mapping[str, Mapping[str, frozenset[str]]] = {
    "jira": {
        "base_url_env": frozenset({"MASTER_AGENT_JIRA_BASE_URL"}),
        "username_env": frozenset({"MASTER_AGENT_JIRA_USERNAME"}),
        "secret_env": frozenset({"MASTER_AGENT_JIRA_TOKEN"}),
        "ca_bundle_env": frozenset({"MASTER_AGENT_ENTERPRISE_CA_BUNDLE"}),
    },
    "confluence": {
        "base_url_env": frozenset({"MASTER_AGENT_CONFLUENCE_BASE_URL"}),
        "username_env": frozenset({"MASTER_AGENT_CONFLUENCE_USERNAME"}),
        "secret_env": frozenset({"MASTER_AGENT_CONFLUENCE_TOKEN"}),
        "ca_bundle_env": frozenset({"MASTER_AGENT_ENTERPRISE_CA_BUNDLE"}),
    },
    "bitbucket": {
        "base_url_env": frozenset({"MASTER_AGENT_BITBUCKET_BASE_URL"}),
        "username_env": frozenset(
            {
                "MASTER_AGENT_BITBUCKET_EMAIL",
                "MASTER_AGENT_BITBUCKET_USERNAME",
            }
        ),
        "secret_env": frozenset({"MASTER_AGENT_BITBUCKET_TOKEN"}),
        "ca_bundle_env": frozenset({"MASTER_AGENT_ENTERPRISE_CA_BUNDLE"}),
        "repository_root_env": frozenset({"MASTER_AGENT_REPOSITORY_ROOT"}),
    },
    "github": {
        "base_url_env": frozenset({"MASTER_AGENT_GITHUB_BASE_URL"}),
        "secret_env": frozenset({"MASTER_AGENT_GITHUB_TOKEN"}),
        "ca_bundle_env": frozenset({"MASTER_AGENT_ENTERPRISE_CA_BUNDLE"}),
    },
    "microsoft": {
        "base_url_env": frozenset({"MASTER_AGENT_GRAPH_BASE_URL"}),
        "secret_env": frozenset({"MASTER_AGENT_GRAPH_ACCESS_TOKEN"}),
        "ca_bundle_env": frozenset({"MASTER_AGENT_ENTERPRISE_CA_BUNDLE"}),
        "token_file_env": frozenset({"MASTER_AGENT_GRAPH_TOKEN_FILE"}),
        "token_expires_at_env": frozenset(
            {"MASTER_AGENT_GRAPH_ACCESS_TOKEN_EXPIRES_AT"}
        ),
        "tenant_id_env": frozenset({"MASTER_AGENT_ENTRA_TENANT_ID"}),
        "client_id_env": frozenset(
            {"MASTER_AGENT_ENTRA_APP_CLIENT_ID", "MASTER_AGENT_ENTRA_PUBLIC_CLIENT_ID"}
        ),
        "client_secret_env": frozenset({"MASTER_AGENT_ENTRA_APP_CLIENT_SECRET"}),
    },
}


def _validate_environment_references(config: ConnectorConfig) -> None:
    """Reject configuration that can select unrelated process secrets."""

    allowed = _ALLOWED_ENVIRONMENT_REFERENCES.get(config.system)
    references: dict[str, str | None] = {
        "base_url_env": config.base_url_env,
        "username_env": config.username_env,
        "secret_env": config.secret_env,
        "ca_bundle_env": config.ca_bundle_env,
    }
    for key in (
        "repository_root_env",
        "token_file_env",
        "token_expires_at_env",
        "tenant_id_env",
        "client_id_env",
        "client_secret_env",
    ):
        value = config.extra.get(key)
        references[key] = str(value).strip() if isinstance(value, str) else None
    configured = {key: value for key, value in references.items() if value}
    if not configured:
        return
    if allowed is None:
        raise ConfigurationError(
            f"connector {config.system} cannot reference process environment credentials"
        )
    for key, value in configured.items():
        if value not in allowed.get(key, frozenset()):
            raise ConfigurationError(
                f"connector {config.system} has an unapproved {key} reference"
            )


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value
