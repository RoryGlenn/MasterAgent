"""Typed, least-privilege credential handles for promoted capabilities.

Generated code never receives credential values.  A trusted provider adapter
may redeem one short-lived, single-use handle after the broker rechecks the
exact capsule, principal, account, scope, and destination binding.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from master_agent.credentials import CredentialStoreSnapshot
from master_agent.errors import AuthenticationError, ConfigurationError
from master_agent.models import CapabilityCapsuleExecutionBinding
from master_agent.resource_limits import measure_json_resources

CONNECTION_REQUEST_SCHEMA = "master-agent/capsule-connection-request@1"
_MAX_ACTIVE_HANDLES = 128


@dataclass(frozen=True, slots=True)
class RuntimePrincipal:
    """Authenticated execution identity bound to a provider account."""

    user_id: str
    agent_id: str
    tenant_id: str
    provider: str
    account_id: str
    scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("user_id", self.user_id),
            ("agent_id", self.agent_id),
            ("tenant_id", self.tenant_id),
            ("provider", self.provider),
            ("account_id", self.account_id),
        ):
            if not value or value != value.strip():
                raise ConfigurationError(f"runtime principal {name} is malformed")
        scopes = tuple(sorted(set(self.scopes)))
        if not scopes or any(not scope or scope != scope.strip() for scope in scopes):
            raise ConfigurationError("runtime principal scopes are malformed")
        object.__setattr__(self, "scopes", scopes)

    def binding_sha256(self) -> str:
        """Return a secret-free stable principal/account identity."""

        return _sha256_fields(
            self.user_id,
            self.agent_id,
            self.tenant_id,
            self.provider,
            self.account_id,
            *self.scopes,
        )


@dataclass(frozen=True, slots=True)
class CredentialMaterial:
    """Secret material visible only to a trusted provider adapter."""

    provider_id: str
    credential_name: str
    principal: RuntimePrincipal
    _value: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.provider_id or not self.credential_name or not self._value:
            raise AuthenticationError("credential material is incomplete")

    def reveal_to_provider(self) -> str:
        """Return the value to the broker-selected trusted provider adapter."""

        return self._value


class CredentialProvider(Protocol):
    """Credential source selected by trusted runtime configuration."""

    @property
    def provider_id(self) -> str:
        """Return a stable adapter identity."""

    @property
    def production_ready(self) -> bool:
        """Return whether the adapter is approved for production use."""

    def healthy(self) -> bool:
        """Perform a bounded, secret-free readiness probe."""

    def resolve(
        self,
        *,
        principal: RuntimePrincipal,
        credential_name: str,
    ) -> CredentialMaterial:
        """Resolve one exact credential without logging or serializing it."""


class TrustedProviderAdapter(Protocol):
    """Trusted typed adapter that may consume credential material."""

    @property
    def provider(self) -> str:
        """Return the provider system identifier."""

    def invoke(
        self,
        *,
        material: CredentialMaterial,
        origin: str,
        method: str,
        path: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Perform one typed, destination-bound provider operation."""


class LocalJsonCredentialProvider:
    """Development adapter over existing restricted JSON snapshots."""

    def __init__(
        self,
        accounts: Mapping[tuple[str, str], CredentialStoreSnapshot],
        *,
        provider_id: str = "local-json-development",
    ) -> None:
        if not accounts:
            raise ConfigurationError("local credential provider accounts are empty")
        self._accounts = dict(accounts)
        self._provider_id = provider_id

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def production_ready(self) -> bool:
        return False

    def healthy(self) -> bool:
        """Return whether the development snapshot remains available in memory."""

        return bool(self._accounts)

    def resolve(
        self,
        *,
        principal: RuntimePrincipal,
        credential_name: str,
    ) -> CredentialMaterial:
        try:
            snapshot = self._accounts[(principal.provider, principal.account_id)]
        except KeyError as error:
            raise AuthenticationError(
                "the selected provider account is not connected"
            ) from error
        if credential_name not in snapshot.names:
            raise AuthenticationError(
                "the selected account lacks the requested credential name"
            )
        # Snapshot owns the only file read; this in-memory copy never leaves the broker.
        value = snapshot.overlay({})[credential_name]
        return CredentialMaterial(
            provider_id=self.provider_id,
            credential_name=credential_name,
            principal=principal,
            _value=value,
        )


@dataclass(frozen=True, slots=True)
class OpaqueCredentialHandle:
    """Short-lived capability token safe for transport to a promoted worker."""

    token: str = field(repr=False)
    binding_sha256: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if len(self.token) < 32 or len(self.binding_sha256) != 64:
            raise AuthenticationError("opaque credential handle is malformed")
        if self.expires_at.tzinfo is None:
            raise AuthenticationError("credential handle expiry must be timezone-aware")

    def redacted_dict(self) -> dict[str, str]:
        """Serialize only non-redeemable metadata for plans/evidence/logs."""

        return {
            "handle_sha256": hashlib.sha256(self.token.encode()).hexdigest(),
            "binding_sha256": self.binding_sha256,
            "expires_at": self.expires_at.astimezone(UTC).isoformat(),
        }


@dataclass(slots=True)
class _Lease:
    material: CredentialMaterial
    capsule_binding_sha256: str
    binding_sha256: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ConnectionRequest:
    """Content-free connect-then-resume request bound to one exact run."""

    run_fingerprint: str
    capsule_manifest_sha256: str
    provider: str
    account_id: str
    credential_names: tuple[str, ...]
    scopes: tuple[str, ...]
    nonce: str
    schema: str = CONNECTION_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        for digest in (self.run_fingerprint, self.capsule_manifest_sha256):
            if len(digest) != 64:
                raise ConfigurationError("connection request digest is malformed")
        if self.schema != CONNECTION_REQUEST_SCHEMA or len(self.nonce) < 32:
            raise ConfigurationError("connection request schema or nonce is malformed")
        if not self.provider or not self.account_id:
            raise ConfigurationError("connection request account is incomplete")

    @property
    def fingerprint(self) -> str:
        return _sha256_fields(
            self.schema,
            self.run_fingerprint,
            self.capsule_manifest_sha256,
            self.provider,
            self.account_id,
            *self.credential_names,
            *self.scopes,
            self.nonce,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "run_fingerprint": self.run_fingerprint,
            "capsule_manifest_sha256": self.capsule_manifest_sha256,
            "provider": self.provider,
            "account_id": self.account_id,
            "credential_names": list(self.credential_names),
            "scopes": list(self.scopes),
            "nonce": self.nonce,
            "fingerprint": self.fingerprint,
        }


class CredentialBroker:
    """Issue and redeem exact single-use handles without exposing secrets."""

    def __init__(
        self,
        provider: CredentialProvider,
        *,
        maximum_ttl_seconds: int = 120,
    ) -> None:
        if not 1 <= maximum_ttl_seconds <= 300:
            raise ConfigurationError("credential handle TTL must be 1..300 seconds")
        self.provider = provider
        self.maximum_ttl_seconds = maximum_ttl_seconds
        self._leases: dict[str, _Lease] = {}

    def issue(
        self,
        *,
        capsule: CapabilityCapsuleExecutionBinding,
        principal: RuntimePrincipal,
        credential_name: str,
        now: datetime | None = None,
        ttl_seconds: int = 60,
    ) -> OpaqueCredentialHandle:
        """Issue one handle only for the exact plan-bound principal and scope."""

        current = (now or datetime.now(UTC)).astimezone(UTC)
        self._purge(current)
        if len(self._leases) >= _MAX_ACTIVE_HANDLES:
            raise AuthenticationError("credential broker active-handle limit reached")
        if not 1 <= ttl_seconds <= self.maximum_ttl_seconds:
            raise AuthenticationError("credential handle TTL is outside policy")
        _validate_principal_binding(capsule, principal, self.provider.provider_id)
        if credential_name not in capsule.credential_names:
            raise AuthenticationError("credential name is not allowed by the capsule")
        if not set(capsule.credential_scopes).issubset(principal.scopes):
            raise AuthenticationError(
                "runtime principal lacks capsule credential scopes"
            )
        material = self.provider.resolve(
            principal=principal,
            credential_name=credential_name,
        )
        if (
            material.provider_id != self.provider.provider_id
            or material.credential_name != credential_name
            or material.principal != principal
        ):
            raise AuthenticationError(
                "credential provider returned material for another binding"
            )
        token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(token.encode()).hexdigest()
        expires = current + timedelta(seconds=ttl_seconds)
        capsule_binding_sha256 = _sha256_mapping(capsule.to_dict())
        binding_sha256 = _sha256_fields(
            capsule_binding_sha256,
            principal.binding_sha256(),
            credential_name,
            self.provider.provider_id,
        )
        self._leases[token_sha256] = _Lease(
            material=material,
            capsule_binding_sha256=capsule_binding_sha256,
            binding_sha256=binding_sha256,
            expires_at=expires,
        )
        return OpaqueCredentialHandle(
            token=token,
            binding_sha256=binding_sha256,
            expires_at=expires,
        )

    def invoke(
        self,
        *,
        handle: OpaqueCredentialHandle,
        capsule: CapabilityCapsuleExecutionBinding,
        adapter: TrustedProviderAdapter,
        origin: str,
        method: str,
        path: str,
        payload: Mapping[str, Any],
        now: datetime | None = None,
    ) -> Mapping[str, Any]:
        """Redeem once through a trusted adapter after destination revalidation."""

        current = (now or datetime.now(UTC)).astimezone(UTC)
        self._purge(current)
        token_sha256 = hashlib.sha256(handle.token.encode()).hexdigest()
        lease = self._leases.pop(token_sha256, None)
        if lease is None:
            raise AuthenticationError(
                "credential handle is expired, unknown, or reused"
            )
        if current >= lease.expires_at or current >= handle.expires_at:
            raise AuthenticationError("credential handle expired")
        if not hmac.compare_digest(lease.binding_sha256, handle.binding_sha256):
            raise AuthenticationError("credential handle binding is invalid")
        observed_capsule_sha256 = _sha256_mapping(capsule.to_dict())
        if not hmac.compare_digest(
            lease.capsule_binding_sha256,
            observed_capsule_sha256,
        ):
            raise AuthenticationError(
                "credential handle belongs to another capsule binding"
            )
        expected_binding = _sha256_fields(
            observed_capsule_sha256,
            lease.material.principal.binding_sha256(),
            lease.material.credential_name,
            lease.material.provider_id,
        )
        if not hmac.compare_digest(expected_binding, handle.binding_sha256):
            raise AuthenticationError("credential handle authority drifted")
        canonical_origin = _canonical_origin(origin)
        normalized_method = method.upper()
        if adapter.provider != capsule.capability_id.split(".", 1)[0]:
            raise AuthenticationError(
                "provider adapter differs from the capsule system"
            )
        if canonical_origin not in capsule.allowed_origins:
            raise AuthenticationError(
                "provider origin is outside the capsule allowlist"
            )
        if normalized_method not in capsule.allowed_methods:
            raise AuthenticationError(
                "provider method is outside the capsule allowlist"
            )
        if not any(
            _path_is_within(path, prefix) for prefix in capsule.allowed_path_prefixes
        ):
            raise AuthenticationError("provider path is outside the capsule allowlist")
        measure_json_resources(
            payload,
            context="credential broker provider payload",
            max_bytes=capsule.max_input_bytes,
        )
        result = adapter.invoke(
            material=lease.material,
            origin=canonical_origin,
            method=normalized_method,
            path=path,
            payload=payload,
        )
        if not isinstance(result, Mapping):
            raise AuthenticationError("trusted provider adapter returned invalid data")
        measure_json_resources(
            result,
            context="credential broker provider result",
            max_bytes=capsule.max_output_bytes,
        )
        return dict(result)

    def connection_request(
        self,
        *,
        run_fingerprint: str,
        capsule: CapabilityCapsuleExecutionBinding,
        provider: str,
        account_id: str,
    ) -> ConnectionRequest:
        """Prepare the exact account connection required to resume a run."""

        if (
            provider != capsule.capability_id.split(".", 1)[0]
            or account_id != capsule.provider_account_id
            or not capsule.credential_names
        ):
            raise AuthenticationError(
                "connection request differs from the capsule provider account"
            )
        return ConnectionRequest(
            run_fingerprint=run_fingerprint,
            capsule_manifest_sha256=capsule.manifest_sha256,
            provider=provider,
            account_id=account_id,
            credential_names=capsule.credential_names,
            scopes=capsule.credential_scopes,
            nonce=secrets.token_urlsafe(24),
        )

    def _purge(self, now: datetime) -> None:
        expired = [
            key for key, lease in self._leases.items() if now >= lease.expires_at
        ]
        for key in expired:
            self._leases.pop(key, None)


def _validate_principal_binding(
    capsule: CapabilityCapsuleExecutionBinding,
    principal: RuntimePrincipal,
    provider_id: str,
) -> None:
    expected = (
        capsule.authenticated_principal,
        capsule.agent_identity,
        capsule.tenant_id,
        capsule.capability_id.split(".", 1)[0],
        capsule.provider_account_id,
        capsule.credential_provider_id,
    )
    observed = (
        principal.user_id,
        principal.agent_id,
        principal.tenant_id,
        principal.provider,
        principal.account_id,
        provider_id,
    )
    if observed != expected:
        raise AuthenticationError(
            "runtime principal, tenant, account, or credential provider drifted"
        )


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise AuthenticationError("provider origin port is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AuthenticationError("provider origin must be an exact HTTPS origin")
    host = parsed.hostname.casefold().rstrip(".")
    rendered = f"[{host}]" if ":" in host else host
    if port is not None and port != 443:
        rendered = f"{rendered}:{port}"
    return urlunsplit(("https", rendered, "", "", ""))


def _path_is_within(path: str, prefix: str) -> bool:
    if (
        not path.startswith("/")
        or "?" in path
        or "#" in path
        or "\\" in path
        or "%" in path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
    ):
        return False
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _sha256_fields(*fields: str) -> str:
    digest = hashlib.sha256()
    for value in fields:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _sha256_mapping(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
