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
from pathlib import Path, PureWindowsPath
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
    RedditRefreshTokenProvider,
    RestrictedTokenFileProvider,
    TokenProvider,
)
from master_agent.platform_runtime import PlatformContract, require_platform_contract
from master_agent.trust_store import CaBundleSnapshot, capture_ca_bundle

_PLACEHOLDER_PROVIDER_HOSTS = frozenset({"example.atlassian.net"})
_ATLASSIAN_CLOUD_ID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_JIRA_CUSTOM_FIELD_PATTERN = re.compile(r"customfield_[1-9][0-9]{0,11}")
_JIRA_REVIEW_RELATION_KINDS = frozenset(
    {"bitbucket_pull_request_url", "confluence_page_url"}
)
_MAX_JIRA_REVIEW_CUSTOM_FIELDS = 16


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


class ConnectorImplementation(StrEnum):
    """Reviewed connector implementations selectable by trusted config."""

    NATIVE = "native"


class PrincipalAttestationAdapter(StrEnum):
    """Implemented provider-backed credential identity adapters."""

    GITHUB_AUTHENTICATED_USER = "github_authenticated_user"
    MICROSOFT_DELEGATED_USER = "microsoft_delegated_user"
    REDDIT_AUTHENTICATED_USER = "reddit_authenticated_user"


class ConnectorCredentialProvider(StrEnum):
    """Reviewed connector credential-source adapters."""

    ENVIRONMENT = "environment"
    WINDOWS_CREDENTIAL_MANAGER = "windows-credential-manager"
    WINDOWS_DPAPI = "windows-dpapi"


class NetworkMode(StrEnum):
    """Governed provider-network selection modes."""

    DIRECT = "direct"
    PROXY = "proxy"
    AMBIENT_PROXY = "ambient_proxy"


@dataclass(frozen=True, slots=True)
class JiraReviewFieldConfiguration:
    """Exact Jira custom fields admitted to the review-context contract."""

    acceptance_field_ids: tuple[str, ...] = ()
    relation_field_kinds: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        acceptance = tuple(self.acceptance_field_ids)
        relations = dict(self.relation_field_kinds)
        all_fields = (*acceptance, *relations)
        if len(all_fields) > _MAX_JIRA_REVIEW_CUSTOM_FIELDS:
            raise ConfigurationError(
                "Jira review custom fields exceed the 16-field limit"
            )
        if len(set(all_fields)) != len(all_fields):
            raise ConfigurationError(
                "Jira review custom fields must be unique and non-overlapping"
            )
        if any(
            not isinstance(field_id, str)
            or _JIRA_CUSTOM_FIELD_PATTERN.fullmatch(field_id) is None
            for field_id in all_fields
        ):
            raise ConfigurationError(
                "Jira review custom fields must use exact customfield_<digits> IDs"
            )
        if any(
            not isinstance(kind, str) or kind not in _JIRA_REVIEW_RELATION_KINDS
            for kind in relations.values()
        ):
            raise ConfigurationError(
                "Jira review relation fields use an unsupported relation kind"
            )
        object.__setattr__(self, "acceptance_field_ids", tuple(sorted(acceptance)))
        object.__setattr__(
            self,
            "relation_field_kinds",
            MappingProxyType(dict(sorted(relations.items()))),
        )

    @classmethod
    def from_extra(
        cls,
        extra: Mapping[str, Any],
    ) -> JiraReviewFieldConfiguration:
        """Parse the closed Jira review-field subset from connector extras."""

        raw_acceptance = extra.get("review_acceptance_field_ids", ())
        if not isinstance(raw_acceptance, (tuple, list)) or not all(
            isinstance(item, str) for item in raw_acceptance
        ):
            raise ConfigurationError(
                "Jira review_acceptance_field_ids must be a string list"
            )
        raw_relations = extra.get("review_relation_field_kinds", {})
        if not isinstance(raw_relations, Mapping) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_relations.items()
        ):
            raise ConfigurationError(
                "Jira review_relation_field_kinds must be a string table"
            )
        return cls(
            acceptance_field_ids=tuple(raw_acceptance),
            relation_field_kinds={
                str(key): str(value) for key, value in raw_relations.items()
            },
        )


@dataclass(frozen=True, slots=True)
class NetworkProfile:
    """Secret-free organization network policy selected by a connector."""

    name: str
    mode: NetworkMode = NetworkMode.DIRECT
    proxy_url: str | None = None
    proxy_username_env: str | None = None
    proxy_password_env: str | None = None
    ca_bundle_env: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, NetworkMode):
            raise ConfigurationError(
                f"network profile {self.name or '<invalid>'} mode is unsupported"
            )
        if (
            not self.name
            or self.name != self.name.strip()
            or not self.name.isprintable()
            or len(self.name) > 128
        ):
            raise ConfigurationError("network profile name is invalid")
        if self.mode is NetworkMode.DIRECT:
            if any(
                value is not None
                for value in (
                    self.proxy_url,
                    self.proxy_username_env,
                    self.proxy_password_env,
                )
            ):
                raise ConfigurationError(
                    f"network profile {self.name} direct mode forbids proxy settings"
                )
        elif self.mode is NetworkMode.PROXY:
            if self.proxy_url is None:
                raise ConfigurationError(
                    f"network profile {self.name} proxy mode requires proxy_url"
                )
            _validate_proxy_url(self.proxy_url, profile=self.name)
        elif self.proxy_url is not None:
            raise ConfigurationError(
                f"network profile {self.name} ambient_proxy mode forbids proxy_url"
            )
        if (self.proxy_username_env is None) != (self.proxy_password_env is None):
            raise ConfigurationError(
                f"network profile {self.name} proxy credentials require both "
                "username and password references"
            )
        for label, value in (
            ("proxy_username_env", self.proxy_username_env),
            ("proxy_password_env", self.proxy_password_env),
            ("ca_bundle_env", self.ca_bundle_env),
        ):
            if value is not None and (
                value != value.strip()
                or not value
                or not value.isprintable()
                or len(value) > 256
            ):
                raise ConfigurationError(
                    f"network profile {self.name} {label} is invalid"
                )
        allowed_references = {
            "proxy_username_env": "MASTER_AGENT_PROXY_USERNAME",
            "proxy_password_env": "MASTER_AGENT_PROXY_PASSWORD",
            "ca_bundle_env": "MASTER_AGENT_ENTERPRISE_CA_BUNDLE",
        }
        for label, expected in allowed_references.items():
            value = getattr(self, label)
            if value is not None and value != expected:
                raise ConfigurationError(
                    f"network profile {self.name} has an unapproved {label} reference"
                )

    @property
    def identity(self) -> str:
        """Return the stable secret-free profile identity."""

        payload = {
            "name": self.name,
            "mode": str(self.mode),
            "proxy_url": self.proxy_url,
            "proxy_username_env": self.proxy_username_env,
            "proxy_password_env": self.proxy_password_env,
            "ca_bundle_env": self.ca_bundle_env,
        }
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()

    def required_environment_variables(self) -> tuple[str, ...]:
        """Return credential-broker names required by this profile."""

        names: list[str] = []
        if self.mode is NetworkMode.AMBIENT_PROXY:
            names.append("HTTPS_PROXY")
        if self.proxy_username_env is not None:
            names.extend((self.proxy_username_env, self.proxy_password_env or ""))
        if self.ca_bundle_env is not None:
            names.append(self.ca_bundle_env)
        return tuple(name for name in names if name)

    def resolved_proxy_url(self, environ: Mapping[str, str]) -> str | None:
        """Resolve the secret-free proxy endpoint selected by this profile."""

        if self.mode is NetworkMode.DIRECT:
            return None
        value = (
            self.proxy_url
            if self.mode is NetworkMode.PROXY
            else environ.get("HTTPS_PROXY", "").strip()
        )
        if not value:
            raise ConfigurationError(
                f"network profile {self.name} requires an HTTPS proxy endpoint"
            )
        _validate_proxy_url(value, profile=self.name)
        return value.rstrip("/")


_DIRECT_NETWORK_PROFILE = NetworkProfile(name="direct")


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
    implementation: ConnectorImplementation = ConnectorImplementation.NATIVE
    web_base_url: str | None = None
    ca_bundle_env: str | None = None
    network_profile: NetworkProfile = field(
        default_factory=lambda: _DIRECT_NETWORK_PROFILE
    )
    timeout_seconds: float = 20.0
    max_pages: int = 10
    max_items: int = 200
    max_response_bytes: int = 10 * 1024 * 1024
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.system.strip():
            raise ConfigurationError("connector system must not be empty")
        if not isinstance(self.implementation, ConnectorImplementation):
            raise ConfigurationError(
                f"connector {self.system} implementation is unsupported"
            )
        if self.timeout_seconds <= 0:
            raise ConfigurationError("timeout_seconds must be positive")
        if self.max_pages <= 0:
            raise ConfigurationError("max_pages must be positive")
        if self.max_items <= 0:
            raise ConfigurationError("max_items must be positive")
        if self.max_response_bytes <= 0:
            raise ConfigurationError("max_response_bytes must be positive")
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))
        if self.system == "jira":
            JiraReviewFieldConfiguration.from_extra(self.extra)
        _validate_connector_credential_source(self)

    @property
    def credential_provider(self) -> ConnectorCredentialProvider:
        """Return the explicitly reviewed credential source adapter."""

        value = self.extra.get("credential_provider", "environment")
        if not isinstance(value, str) or value != value.strip():
            raise ConfigurationError(
                f"connector {self.system} credential_provider is invalid"
            )
        try:
            return ConnectorCredentialProvider(value)
        except ValueError as error:
            raise ConfigurationError(
                f"connector {self.system} credential_provider is unsupported"
            ) from error

    @property
    def credential_target(self) -> str | None:
        """Return reviewed non-secret provider metadata, if configured."""

        value = self.extra.get("credential_target")
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or not value.isprintable()
            or "\x00" in value
            or len(value) > 2048
        ):
            raise ConfigurationError(
                f"connector {self.system} credential_target is invalid"
            )
        return value

    def credential_environment_variables(self) -> tuple[str, ...]:
        """Return exact credential names this connector may resolve."""

        names: set[str] = set()
        for value in (self.username_env, self.secret_env):
            if value:
                names.add(value)
        for key in (
            "token_file_env",
            "token_expires_at_env",
            "tenant_id_env",
            "client_id_env",
            "client_secret_env",
            "refresh_token_env",
        ):
            value = self.extra.get(key)
            if isinstance(value, str) and value.strip():
                names.add(value.strip())
        names.update(self.network_profile.required_environment_variables())
        return tuple(sorted(names))

    @property
    def identity(self) -> str:
        """Return a stable, secret-free identity for approval/audit binding."""

        payload = {
            "system": self.system,
            "enabled": self.enabled,
            "deployment": str(self.deployment),
            "implementation": str(self.implementation),
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
        if self.network_profile != _DIRECT_NETWORK_PROFILE:
            payload["network_profile"] = self.network_profile.identity
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
        elif (
            self.auth_mode is AuthMode.OAUTH_DELEGATED
            and oauth_flow == "reddit_refresh_token"
        ):
            for key in ("client_id_env", "client_secret_env", "refresh_token_env"):
                value = self.extra.get(key)
                if isinstance(value, str) and value.strip():
                    names.append(value.strip())
        elif self.auth_mode is AuthMode.OAUTH_DELEGATED and oauth_flow == "token_file":
            value = self.extra.get("token_file_env")
            if isinstance(value, str) and value.strip():
                names.append(value.strip())
        elif self.auth_mode is not AuthMode.NONE and self.secret_env:
            names.append(self.secret_env)
        names.extend(self.network_profile.required_environment_variables())
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
        elif (
            self.auth_mode is AuthMode.OAUTH_DELEGATED
            and oauth_flow == "reddit_refresh_token"
        ):
            for key in ("client_id_env", "client_secret_env", "refresh_token_env"):
                value = self.extra.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"{key} is required for reddit_refresh_token authentication"
                    )
            user_agent = self.extra.get("user_agent")
            if not isinstance(user_agent, str) or not user_agent.strip():
                errors.append(
                    "user_agent is required for reddit_refresh_token authentication"
                )
            errors.extend(_reddit_credential_profile_errors(self))
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

        if self.ca_bundle_env and self.network_profile.ca_bundle_env:
            raise ConfigurationError(
                f"connector {self.system} cannot combine connector and network-profile "
                "CA bundle references"
            )
        ca_environment = self.network_profile.ca_bundle_env or self.ca_bundle_env
        ca_bundle = _resolve_ca_bundle_path(
            source.get(ca_environment, "") if ca_environment else "",
            label=f"connector {self.system}",
        )
        return base_url.rstrip("/"), ca_bundle

    def capture_execution_target(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> ResolvedExecutionTarget:
        """Capture the destination and immutable CA bytes used by live TLS."""

        source = environ if environ is not None else os.environ
        base_url, ca_bundle = self.resolve_execution_target(source)
        return ResolvedExecutionTarget(
            system=self.system,
            implementation=self.implementation,
            config_identity=self.identity,
            base_url=base_url,
            ca_bundle=(capture_ca_bundle(ca_bundle) if ca_bundle is not None else None),
            network_profile_name=self.network_profile.name,
            network_profile_sha256=self.network_profile.identity,
            proxy_url=self.network_profile.resolved_proxy_url(source),
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
        if (
            self.system == "reddit"
            and self.deployment is DeploymentType.CLOUD
            and self.auth_mode is AuthMode.OAUTH_DELEGATED
            and oauth_flow == "reddit_refresh_token"
        ):
            return PrincipalAttestationAdapter.REDDIT_AUTHENTICATED_USER
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
        if (
            target.network_profile_name != self.network_profile.name
            or target.network_profile_sha256 != self.network_profile.identity
            or target.proxy_url != self.network_profile.resolved_proxy_url(source)
        ):
            raise ConfigurationError(
                f"connector {self.system} network target does not match its profile"
            )
        base_url = target.base_url
        ca_bundle = target.ca_bundle
        proxy_username = (
            source.get(self.network_profile.proxy_username_env)
            if self.network_profile.proxy_username_env
            else None
        )
        proxy_password = (
            source.get(self.network_profile.proxy_password_env)
            if self.network_profile.proxy_password_env
            else None
        )

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
                    proxy_url=target.proxy_url,
                    proxy_username=proxy_username,
                    proxy_password=proxy_password,
                )
            )
            secret = None
        elif (
            self.auth_mode is AuthMode.OAUTH_DELEGATED
            and oauth_flow == "reddit_refresh_token"
        ):
            client_id = _environment_value(source, self.extra, "client_id_env")
            client_secret = _environment_value(source, self.extra, "client_secret_env")
            refresh_token = _environment_value(source, self.extra, "refresh_token_env")
            scopes = tuple(str(item) for item in self.extra.get("scopes", []))
            token_provider = InMemoryTokenCache(
                RedditRefreshTokenProvider(
                    client_id=client_id,
                    client_secret=client_secret,
                    refresh_token=refresh_token,
                    scopes=scopes,
                    user_agent=str(self.extra.get("user_agent", "")),
                    transport=auth_transport,
                    timeout_seconds=self.timeout_seconds,
                    ca_bundle_data=(ca_bundle.data if ca_bundle is not None else None),
                    proxy_url=target.proxy_url,
                    proxy_username=proxy_username,
                    proxy_password=proxy_password,
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
            implementation=self.implementation,
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
            network_profile_name=target.network_profile_name,
            network_profile_sha256=target.network_profile_sha256,
            proxy_url=target.proxy_url,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            extra=self.extra,
            config_identity=self.identity,
        )


@dataclass(frozen=True, slots=True)
class ResolvedExecutionTarget:
    """One captured connector destination before credentials are resolved."""

    system: str
    implementation: ConnectorImplementation
    config_identity: str
    base_url: str
    ca_bundle: CaBundleSnapshot | None = None
    network_profile_name: str = "direct"
    network_profile_sha256: str | None = None
    proxy_url: str | None = None


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
    network_profile_name: str = "direct"
    network_profile_sha256: str | None = None
    proxy_url: str | None = None
    proxy_username: str | None = field(default=None, repr=False)
    proxy_password: str | None = field(default=None, repr=False)
    extra: Mapping[str, Any] = field(default_factory=dict)
    config_identity: str | None = None
    implementation: ConnectorImplementation = ConnectorImplementation.NATIVE

    def __post_init__(self) -> None:
        if not isinstance(self.implementation, ConnectorImplementation):
            raise ConfigurationError(
                f"resolved connector {self.system} implementation is unsupported"
            )
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
        if (self.proxy_username is None) != (self.proxy_password is None):
            raise ConfigurationError(
                "resolved proxy credentials require both username and password"
            )
        if self.proxy_url is not None:
            _validate_proxy_url(self.proxy_url, profile=self.network_profile_name)
        if self.network_profile_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.network_profile_sha256
        ):
            raise ConfigurationError("resolved network profile digest is invalid")
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))
        if self.system == "jira":
            JiraReviewFieldConfiguration.from_extra(self.extra)


@dataclass(frozen=True, slots=True)
class IntegrationConfig:
    """Collection of connector configurations."""

    connectors: Mapping[str, ConnectorConfig]
    network_profiles: Mapping[str, NetworkProfile] = field(default_factory=dict)
    source_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "connectors",
            MappingProxyType(dict(self.connectors)),
        )
        object.__setattr__(
            self,
            "network_profiles",
            MappingProxyType(dict(self.network_profiles)),
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
        raw_profiles = raw.get("network_profiles", {})
        if not isinstance(raw_profiles, Mapping):
            raise ConfigurationError("[network_profiles] must be a TOML table")
        profiles: dict[str, NetworkProfile] = {
            "direct": _DIRECT_NETWORK_PROFILE,
        }
        for name, value in raw_profiles.items():
            if not isinstance(value, Mapping):
                raise ConfigurationError(
                    f"network profile config must be a table: {name}"
                )
            parsed_profile = _parse_network_profile(str(name), value)
            if str(name) == "direct" and parsed_profile != _DIRECT_NETWORK_PROFILE:
                raise ConfigurationError(
                    "the built-in direct network profile cannot be redefined"
                )
            profiles[str(name)] = parsed_profile

        raw_connectors = raw.get("connectors", {})
        if not isinstance(raw_connectors, Mapping):
            raise ConfigurationError("[connectors] must be a TOML table")

        parsed: dict[str, ConnectorConfig] = {}
        for system, value in raw_connectors.items():
            if not isinstance(value, Mapping):
                raise ConfigurationError(f"connector config must be a table: {system}")
            profile_name = str(value.get("network_profile", "direct")).strip()
            if profile_name not in profiles:
                raise ConfigurationError(
                    f"connector {system} selects unknown network profile: {profile_name}"
                )
            parsed[str(system)] = _parse_connector(
                str(system), value, network_profile=profiles[profile_name]
            )
        return cls(
            connectors=parsed,
            network_profiles=profiles,
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
            names.update(connector.credential_environment_variables())
        return tuple(sorted(names))


_KNOWN_CONNECTOR_KEYS = {
    "enabled",
    "deployment",
    "implementation",
    "base_url",
    "base_url_env",
    "web_base_url",
    "auth_mode",
    "username_env",
    "secret_env",
    "ca_bundle_env",
    "network_profile",
    "timeout_seconds",
    "max_pages",
    "max_items",
    "max_response_bytes",
}


def _parse_network_profile(
    name: str,
    raw: Mapping[str, Any],
) -> NetworkProfile:
    """Parse one closed, typed network profile."""

    allowed = {
        "mode",
        "proxy_url",
        "proxy_username_env",
        "proxy_password_env",
        "ca_bundle_env",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigurationError(
            f"network profile {name} contains unknown fields: "
            + ", ".join(sorted(str(item) for item in unknown))
        )
    try:
        mode = NetworkMode(str(raw.get("mode", "direct")))
    except ValueError as error:
        raise ConfigurationError(
            f"network profile {name} has an unsupported mode"
        ) from error
    return NetworkProfile(
        name=name,
        mode=mode,
        proxy_url=_optional_string(raw.get("proxy_url")),
        proxy_username_env=_optional_string(raw.get("proxy_username_env")),
        proxy_password_env=_optional_string(raw.get("proxy_password_env")),
        ca_bundle_env=_optional_string(raw.get("ca_bundle_env")),
    )


def _parse_connector(
    system: str,
    raw: Mapping[str, Any],
    *,
    network_profile: NetworkProfile = _DIRECT_NETWORK_PROFILE,
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
    try:
        implementation = ConnectorImplementation(
            str(raw.get("implementation", ConnectorImplementation.NATIVE))
        )
    except ValueError as error:
        raise ConfigurationError(
            f"connector {system} implementation is unsupported"
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
        implementation=implementation,
        web_base_url=_optional_string(raw.get("web_base_url")),
        ca_bundle_env=_optional_string(raw.get("ca_bundle_env")),
        network_profile=network_profile,
        timeout_seconds=float(raw.get("timeout_seconds", 20.0)),
        max_pages=int(raw.get("max_pages", 10)),
        max_items=int(raw.get("max_items", 200)),
        max_response_bytes=int(raw.get("max_response_bytes", 10 * 1024 * 1024)),
        extra=extra,
    )
    _validate_environment_references(connector)
    return connector


def _validate_connector_credential_source(config: ConnectorConfig) -> None:
    """Validate one exact provider/target pair without opening the source."""

    provider = config.credential_provider
    target = config.credential_target
    if provider is ConnectorCredentialProvider.ENVIRONMENT:
        if target is not None:
            raise ConfigurationError(
                f"connector {config.system} environment credentials forbid "
                "credential_target"
            )
        return
    if target is None:
        raise ConfigurationError(
            f"connector {config.system} native credential provider requires "
            "credential_target"
        )
    if not config.credential_environment_variables():
        raise ConfigurationError(
            f"connector {config.system} native credential provider has no declared "
            "credential names"
        )
    if provider is ConnectorCredentialProvider.WINDOWS_CREDENTIAL_MANAGER:
        if (
            not target.startswith("MasterAgent/")
            or target.endswith("/")
            or len(target.encode("utf-8")) > 512
        ):
            raise ConfigurationError(
                f"connector {config.system} Credential Manager target must be a "
                "bounded MasterAgent namespace"
            )
        return
    path = PureWindowsPath(target)
    if (
        not path.is_absolute()
        or re.fullmatch(r"[A-Za-z]:", path.drive) is None
        or len(path.parts) < 2
        or target.endswith(("/", "\\"))
        or any(part in {".", ".."} for part in path.parts[1:])
    ):
        raise ConfigurationError(
            f"connector {config.system} DPAPI target must be an absolute local "
            "Windows drive file"
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
        raise ConfigurationError(f"environment variable {variable.strip()} is missing")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered or None


def _validate_proxy_url(value: str, *, profile: str) -> None:
    """Require a credential-free HTTP CONNECT proxy authority."""

    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            f"network profile {profile} proxy endpoint is invalid"
        ) from error
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "http"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        raise ConfigurationError(
            f"network profile {profile} requires a credential-free HTTP proxy "
            "authority with an explicit port"
        )
    if hostname in {"localhost", "localhost.localdomain"}:
        raise ConfigurationError(
            f"network profile {profile} proxy endpoint must not use loopback"
        )
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    ):
        raise ConfigurationError(
            f"network profile {profile} proxy endpoint is not an allowed address"
        )


def _resolve_ca_bundle_path(value: str, *, label: str) -> Path | None:
    """Resolve one explicitly selected CA bundle through the platform contract."""

    if not value:
        return None
    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    selected = Path(value).expanduser()
    if os.name == "nt":
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsPathSecurityError,
            validate_windows_drive_path,
        )

        if not selected.is_absolute():
            selected = Path.cwd() / selected
        try:
            return Path(validate_windows_drive_path(selected).canonical)
        except WindowsPathSecurityError as error:
            raise ConfigurationError(f"{label} CA bundle path is unsafe") from error
    try:
        resolved = selected.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError(
            f"{label} CA bundle does not exist: {selected}"
        ) from error
    if not resolved.is_file():
        raise ConfigurationError(f"{label} CA bundle does not exist: {selected}")
    return resolved


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
    elif system == "reddit":
        valid = (
            hostname.rstrip(".") == "oauth.reddit.com"
            and _explicit_port(parsed) is None
            and parsed.path in {"", "/"}
        )
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
    if deployment is DeploymentType.CLOUD and system == "reddit":
        parsed = urlparse(web_base_url)
        if (
            (parsed.hostname or "").casefold().rstrip(".") != "www.reddit.com"
            or _explicit_port(parsed) is not None
            or parsed.path not in {"", "/"}
        ):
            raise ConfigurationError(
                "connector reddit web_base_url must be the fixed Reddit web root"
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
    "reddit": {
        "client_id_env": frozenset(
            {
                "MASTER_AGENT_REDDIT_READ_CLIENT_ID",
                "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_ID",
            }
        ),
        "client_secret_env": frozenset(
            {
                "MASTER_AGENT_REDDIT_READ_CLIENT_SECRET",
                "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_SECRET",
            }
        ),
        "refresh_token_env": frozenset(
            {
                "MASTER_AGENT_REDDIT_READ_REFRESH_TOKEN",
                "MASTER_AGENT_REDDIT_COMMUNICATION_REFRESH_TOKEN",
            }
        ),
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


_REDDIT_CREDENTIAL_PROFILES: Mapping[str, tuple[Mapping[str, str], frozenset[str]]] = {
    "read": (
        {
            "client_id_env": "MASTER_AGENT_REDDIT_READ_CLIENT_ID",
            "client_secret_env": "MASTER_AGENT_REDDIT_READ_CLIENT_SECRET",
            "refresh_token_env": "MASTER_AGENT_REDDIT_READ_REFRESH_TOKEN",
        },
        frozenset({"identity", "read", "history", "privatemessages"}),
    ),
    "communication": (
        {
            "client_id_env": "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_ID",
            "client_secret_env": "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_SECRET",
            "refresh_token_env": "MASTER_AGENT_REDDIT_COMMUNICATION_REFRESH_TOKEN",
        },
        frozenset({"identity", "read", "submit"}),
    ),
}


def _reddit_credential_profile_errors(config: ConnectorConfig) -> tuple[str, ...]:
    """Validate purpose-separated Reddit credential names, scopes, and gates."""

    profile = str(config.extra.get("credential_profile", "")).strip().casefold()
    contract = _REDDIT_CREDENTIAL_PROFILES.get(profile)
    if contract is None:
        return ("credential_profile must be read or communication for Reddit OAuth",)
    expected_names, expected_scopes = contract
    errors: list[str] = []
    for key, expected in expected_names.items():
        if config.extra.get(key) != expected:
            errors.append(f"Reddit {profile} profile requires {key}={expected}")
    raw_scopes = config.extra.get("scopes")
    if (
        not isinstance(raw_scopes, list)
        or not raw_scopes
        or not all(
            isinstance(item, str) and item and item == item.strip()
            for item in raw_scopes
        )
        or len(set(raw_scopes)) != len(raw_scopes)
    ):
        errors.append("Reddit scopes must be a non-empty unique string list")
    elif frozenset(raw_scopes) != expected_scopes:
        errors.append(
            f"Reddit {profile} profile scopes must be exactly: "
            + ", ".join(sorted(expected_scopes))
        )
    effect_flags = {
        key: config.extra.get(key, False)
        for key in (
            "posts_enabled",
            "comments_enabled",
            "edits_enabled",
            "deletes_enabled",
        )
    }
    if profile == "read" and any(value is True for value in effect_flags.values()):
        errors.append("Reddit read profile cannot enable provider mutations")
    if profile == "communication":
        if not any(
            effect_flags[key] is True for key in ("posts_enabled", "comments_enabled")
        ):
            errors.append("Reddit communication profile must enable posts or comments")
        if any(
            effect_flags[key] is True for key in ("edits_enabled", "deletes_enabled")
        ):
            errors.append(
                "Reddit communication profile cannot enable quarantined edit/delete"
            )
    return tuple(errors)


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
        "refresh_token_env",
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
