"""Declarative OAuth profiles and least-privilege readiness checks."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.oauth import (
    EntraClientCredentialsProvider,
    EntraDeviceCodeProvider,
    EnvironmentTokenProvider,
    RestrictedTokenFileProvider,
    TokenProvider,
)
from master_agent.platform_runtime import (
    PlatformContract,
    PlatformRuntimeStatus,
    get_secure_filesystem_backend,
    platform_runtime_status,
    require_platform_contract,
)


class OAuthFlow(StrEnum):
    """Supported credential acquisition flows."""

    ENVIRONMENT = "environment"
    RESTRICTED_FILE = "restricted_file"
    ENTRA_DEVICE_CODE = "entra_device_code"
    ENTRA_CLIENT_CREDENTIALS = "entra_client_credentials"


@dataclass(frozen=True, slots=True)
class OAuthProfile:
    """Secret-free OAuth profile definition."""

    name: str
    provider: str
    flow: OAuthFlow
    scopes: tuple[str, ...]
    tenant_id_env: str | None = None
    client_id_env: str | None = None
    client_secret_env: str | None = None
    access_token_env: str | None = None
    expires_at_env: str | None = None
    token_file: Path | None = None
    enabled: bool = False
    metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.provider.strip():
            raise ConfigurationError("OAuth profile name/provider must not be empty")
        if not self.scopes:
            raise ConfigurationError(
                f"OAuth profile requires at least one scope: {self.name}"
            )
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata or {})),
        )
        _validate_environment_references(self)

    def required_environment_variables(self) -> tuple[str, ...]:
        """Return required variable names without reading secret values."""

        names: list[str] = []
        if self.flow is OAuthFlow.ENVIRONMENT:
            if self.access_token_env:
                names.append(self.access_token_env)
        elif self.flow is OAuthFlow.ENTRA_DEVICE_CODE:
            if self.tenant_id_env:
                names.append(self.tenant_id_env)
            if self.client_id_env:
                names.append(self.client_id_env)
        elif self.flow is OAuthFlow.ENTRA_CLIENT_CREDENTIALS:
            for item in (
                self.tenant_id_env,
                self.client_id_env,
                self.client_secret_env,
            ):
                if item:
                    names.append(item)
        return tuple(dict.fromkeys(names))

    def readiness_errors(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        platform_status: PlatformRuntimeStatus | None = None,
    ) -> tuple[str, ...]:
        """Return configuration errors without exposing credential values."""

        source = environ if environ is not None else os.environ
        errors: list[str] = []
        if not self.enabled:
            return ("profile is disabled",)
        if self.flow is OAuthFlow.ENVIRONMENT and not self.access_token_env:
            errors.append("access_token_env is required")
        if self.flow is OAuthFlow.RESTRICTED_FILE and self.token_file is None:
            errors.append("token_file is required")
        if self.flow in {
            OAuthFlow.ENTRA_DEVICE_CODE,
            OAuthFlow.ENTRA_CLIENT_CREDENTIALS,
        }:
            if not self.tenant_id_env:
                errors.append("tenant_id_env is required")
            if not self.client_id_env:
                errors.append("client_id_env is required")
        if (
            self.flow is OAuthFlow.ENTRA_CLIENT_CREDENTIALS
            and not self.client_secret_env
        ):
            errors.append("client_secret_env is required")
        for name in self.required_environment_variables():
            if not source.get(name):
                errors.append(f"environment variable {name} is missing")
        if self.flow is OAuthFlow.RESTRICTED_FILE and self.token_file is not None:
            selected_platform = platform_status or platform_runtime_status()
            filesystem = selected_platform.contract_status(
                PlatformContract.SECURE_FILESYSTEM,
            )
            if not filesystem.available:
                errors.append(f"token file cannot be inspected: {filesystem.reason}")
            elif selected_platform.platform == "windows":
                from master_agent.platform_runtime.windows.filesystem import (
                    WindowsSecureFilesystemBackend,
                )

                try:
                    backend = get_secure_filesystem_backend()
                    if not isinstance(backend, WindowsSecureFilesystemBackend):
                        raise ConfigurationError(
                            "native Windows secure filesystem is unavailable"
                        )
                    selected = self.token_file.expanduser()
                    if not selected.is_absolute():
                        selected = Path.cwd() / selected
                    with backend.pin_file(selected, require_private=True):
                        pass
                except (ConfigurationError, OSError):
                    errors.append("token file cannot be inspected safely")
            elif not self.token_file.expanduser().is_file():
                errors.append(f"token file does not exist: {self.token_file}")
        return tuple(dict.fromkeys(errors))

    def build_provider(
        self,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> TokenProvider:
        """Construct the configured token provider in memory.

        Device-code providers still require the caller to register a challenge
        callback before :meth:`get_token` is invoked.
        """

        source = environ if environ is not None else os.environ
        if self.enabled and self.flow is OAuthFlow.RESTRICTED_FILE:
            require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
        errors = self.readiness_errors(source)
        if errors:
            raise ConfigurationError(
                f"OAuth profile {self.name} is not ready: " + "; ".join(errors)
            )
        if self.flow is OAuthFlow.ENVIRONMENT:
            assert self.access_token_env is not None
            return EnvironmentTokenProvider(
                token_env=self.access_token_env,
                expires_at_env=self.expires_at_env,
                scopes=self.scopes,
                environ=source,
            )
        if self.flow is OAuthFlow.RESTRICTED_FILE:
            assert self.token_file is not None
            return RestrictedTokenFileProvider(self.token_file)
        tenant = source[self.tenant_id_env or ""]
        client = source[self.client_id_env or ""]
        if self.flow is OAuthFlow.ENTRA_DEVICE_CODE:
            return EntraDeviceCodeProvider(
                tenant_id=tenant,
                client_id=client,
                scopes=self.scopes,
            )
        if self.flow is OAuthFlow.ENTRA_CLIENT_CREDENTIALS:
            secret = source[self.client_secret_env or ""]
            return EntraClientCredentialsProvider(
                tenant_id=tenant,
                client_id=client,
                client_secret=secret,
                scopes=self.scopes,
            )
        raise ConfigurationError(f"unsupported OAuth flow: {self.flow}")

    def to_dict(self) -> dict[str, Any]:
        """Return a secret-free profile summary."""

        return {
            "name": self.name,
            "provider": self.provider,
            "flow": str(self.flow),
            "enabled": self.enabled,
            "scopes": list(self.scopes),
            "required_environment_variables": list(
                self.required_environment_variables()
            ),
            "token_file": str(self.token_file) if self.token_file else None,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OAuthProfiles:
    """Immutable named OAuth profile collection."""

    profiles: Mapping[str, OAuthProfile]

    def __post_init__(self) -> None:
        object.__setattr__(self, "profiles", MappingProxyType(dict(self.profiles)))

    @classmethod
    def from_toml(cls, path: ConfigSource) -> OAuthProfiles:
        """Load OAuth profiles from TOML."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"OAuth configuration not found: {path}"
            ) from error
        table = raw.get("profiles", {})
        if not isinstance(table, Mapping):
            raise ConfigurationError("[profiles] must be a TOML table")
        profiles: dict[str, OAuthProfile] = {}
        for name, value in table.items():
            if not isinstance(value, Mapping):
                raise ConfigurationError(f"OAuth profile must be a table: {name}")
            try:
                flow = OAuthFlow(str(value["flow"]))
            except (KeyError, ValueError) as error:
                raise ConfigurationError(
                    f"OAuth profile {name} has an invalid flow"
                ) from error
            raw_scopes = value.get("scopes", [])
            if not isinstance(raw_scopes, list) or not all(
                isinstance(item, str) and item.strip() for item in raw_scopes
            ):
                raise ConfigurationError(
                    f"OAuth profile {name} scopes must be a string list"
                )
            known = {
                "provider",
                "flow",
                "scopes",
                "tenant_id_env",
                "client_id_env",
                "client_secret_env",
                "access_token_env",
                "expires_at_env",
                "token_file",
                "enabled",
            }
            token_file_value = str(value.get("token_file", "")).strip()
            profiles[str(name)] = OAuthProfile(
                name=str(name),
                provider=str(value.get("provider", "")),
                flow=flow,
                scopes=tuple(str(item) for item in raw_scopes),
                tenant_id_env=_optional(value, "tenant_id_env"),
                client_id_env=_optional(value, "client_id_env"),
                client_secret_env=_optional(value, "client_secret_env"),
                access_token_env=_optional(value, "access_token_env"),
                expires_at_env=_optional(value, "expires_at_env"),
                token_file=Path(token_file_value) if token_file_value else None,
                enabled=_strict_bool(
                    value.get("enabled", False), f"OAuth profile {name} enabled"
                ),
                metadata={key: item for key, item in value.items() if key not in known},
            )
        return cls(profiles)

    def profile(self, name: str) -> OAuthProfile:
        """Return a named profile or fail closed."""

        try:
            return self.profiles[name]
        except KeyError as error:
            raise ConfigurationError(f"unknown OAuth profile: {name}") from error


def _optional(value: Mapping[str, Any], key: str) -> str | None:
    rendered = str(value.get(key, "")).strip()
    return rendered or None


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value


_MICROSOFT_ENVIRONMENT_REFERENCES = frozenset(
    {
        "MASTER_AGENT_ENTRA_TENANT_ID",
        "MASTER_AGENT_ENTRA_PUBLIC_CLIENT_ID",
        "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
        "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
        "MASTER_AGENT_GRAPH_ACCESS_TOKEN",
        "MASTER_AGENT_GRAPH_ACCESS_TOKEN_EXPIRES_AT",
    }
)


def _validate_environment_references(profile: OAuthProfile) -> None:
    """Keep OAuth profiles from becoming arbitrary environment readers."""

    if profile.provider not in {"microsoft_entra", "microsoft_graph"}:
        if profile.required_environment_variables():
            raise ConfigurationError(
                f"OAuth provider {profile.provider} has no credential broker"
            )
        return
    for name in (
        profile.tenant_id_env,
        profile.client_id_env,
        profile.client_secret_env,
        profile.access_token_env,
        profile.expires_at_env,
    ):
        if name and name not in _MICROSOFT_ENVIRONMENT_REFERENCES:
            raise ConfigurationError(
                f"OAuth profile {profile.name} has an unapproved environment reference"
            )
