"""Authenticated approval issuance and verification.

Approval JSON is untrusted input.  An approval only becomes an authorization
fact after its signature has been verified against an operator-supplied key
ring that binds a key ID to one normalized human identity.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import tomllib
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import Approval, ChangePlan


@dataclass(frozen=True, slots=True)
class ApprovalAuthority:
    """Trusted identity and HMAC key used for approval authentication."""

    key_id: str
    subject: str
    issuer: str
    tenant: str
    roles: tuple[str, ...]
    secret: bytes
    revoked_before: datetime | None = None
    revoked_approval_ids: frozenset[UUID] = frozenset()

    def __post_init__(self) -> None:
        if not self.key_id.strip() or self.key_id != self.key_id.strip():
            raise ConfigurationError("approval authority key_id must be normalized")
        _validate_claim(self.key_id, "key_id")
        if not self.subject.strip() or self.subject != self.subject.strip():
            raise ConfigurationError("approval authority subject must be normalized")
        _validate_claim(self.subject, "subject")
        _validate_claim(self.issuer, "issuer")
        _validate_claim(self.tenant, "tenant")
        if not self.roles:
            raise ConfigurationError("approval authority roles must not be empty")
        role_keys: set[str] = set()
        for role in self.roles:
            _validate_claim(role, "role")
            key = _claim_key(role)
            if key in role_keys:
                raise ConfigurationError("approval authority roles must be unique")
            role_keys.add(key)
        object.__setattr__(
            self,
            "roles",
            tuple(sorted(self.roles, key=lambda item: item.casefold())),
        )
        if len(self.secret) < 32:
            raise ConfigurationError(
                f"approval authority {self.key_id} requires at least 32 secret bytes"
            )
        if self.revoked_before is not None:
            _require_aware_datetime(self.revoked_before, "revoked_before")
        object.__setattr__(
            self,
            "revoked_approval_ids",
            frozenset(self.revoked_approval_ids),
        )


class ApprovalAuthenticator(Protocol):
    """Authenticate an approval and return its trusted human subject."""

    def authenticated_subject(self, approval: Approval) -> str | None:
        """Return the trusted subject, or ``None`` for an invalid artifact."""


class HmacApprovalAuthenticator:
    """Issue and verify SHA-256 HMAC approvals from an explicit key ring."""

    def __init__(self, authorities: Mapping[str, ApprovalAuthority]) -> None:
        normalized = dict(authorities)
        if not normalized:
            raise ConfigurationError("at least one approval authority is required")
        for key_id, authority in normalized.items():
            if key_id != authority.key_id:
                raise ConfigurationError(
                    "approval authority mapping key must match authority key_id"
                )
        self._authorities = MappingProxyType(normalized)

    @classmethod
    def from_toml(
        cls,
        path: ConfigSource,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> HmacApprovalAuthenticator:
        """Load identity bindings while resolving secrets from the environment."""

        return cls._from_toml(path, environ=environ, selected_key_ids=None)

    @classmethod
    def from_toml_for_key(
        cls,
        path: ConfigSource,
        *,
        key_id: str,
        environ: Mapping[str, str] | None = None,
    ) -> HmacApprovalAuthenticator:
        """Load only the selected signer's key from a shared authority ring."""

        if not key_id.strip() or key_id != key_id.strip():
            raise ConfigurationError("approval authority key_id must be normalized")
        return cls._from_toml(
            path,
            environ=environ,
            selected_key_ids=frozenset({key_id}),
        )

    @classmethod
    def _from_toml(
        cls,
        path: ConfigSource,
        *,
        environ: Mapping[str, str] | None,
        selected_key_ids: frozenset[str] | None,
    ) -> HmacApprovalAuthenticator:
        """Load a complete verifier ring or a signer-specific subset."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"approval authority configuration not found: {path}"
            ) from error
        table = raw.get("authorities")
        if not isinstance(table, Mapping) or not table:
            raise ConfigurationError("[authorities] must contain at least one entry")
        source = environ if environ is not None else os.environ
        authorities: dict[str, ApprovalAuthority] = {}
        for key_id, item in table.items():
            if not isinstance(item, Mapping):
                raise ConfigurationError(
                    f"approval authority {key_id} must be a TOML table"
                )
            enabled = item.get("enabled", True)
            if not isinstance(enabled, bool):
                raise ConfigurationError(
                    f"approval authority {key_id} enabled must be a boolean"
                )
            if not enabled:
                continue
            if selected_key_ids is not None and key_id not in selected_key_ids:
                continue
            subject = _required_string(item, "subject", key_id=str(key_id))
            issuer = _required_string(item, "issuer", key_id=str(key_id))
            tenant = _required_string(item, "tenant", key_id=str(key_id))
            roles_raw = item.get("roles")
            if (
                not isinstance(roles_raw, list)
                or not roles_raw
                or not all(isinstance(role, str) for role in roles_raw)
            ):
                raise ConfigurationError(
                    f"approval authority {key_id} roles must be a non-empty string list"
                )
            revoked_before = _optional_datetime(
                item.get("revoked_before"),
                key_id=str(key_id),
            )
            revoked_ids_raw = item.get("revoked_approval_ids", [])
            if not isinstance(revoked_ids_raw, list) or not all(
                isinstance(value, str) for value in revoked_ids_raw
            ):
                raise ConfigurationError(
                    f"approval authority {key_id} revoked_approval_ids must be a string list"
                )
            try:
                revoked_ids = frozenset(UUID(value) for value in revoked_ids_raw)
            except ValueError as error:
                raise ConfigurationError(
                    f"approval authority {key_id} has an invalid revoked approval ID"
                ) from error
            secret_env = str(item.get("secret_env", "")).strip()
            if not secret_env:
                raise ConfigurationError(
                    f"approval authority {key_id} requires secret_env"
                )
            secret = source.get(secret_env, "").encode("utf-8")
            if not secret:
                raise ConfigurationError(
                    f"approval authority secret is unavailable: {secret_env}"
                )
            authority = ApprovalAuthority(
                key_id=str(key_id),
                subject=subject,
                secret=secret,
                issuer=issuer,
                tenant=tenant,
                roles=tuple(roles_raw),
                revoked_before=revoked_before,
                revoked_approval_ids=revoked_ids,
            )
            authorities[authority.key_id] = authority
        if selected_key_ids is not None and set(authorities) != set(selected_key_ids):
            missing = ", ".join(sorted(selected_key_ids - set(authorities)))
            raise ConfigurationError(f"unknown approval authority key_id: {missing}")
        return cls(authorities)

    def issue(
        self,
        *,
        plan: ChangePlan,
        approved_action_ids: tuple[UUID, ...],
        key_id: str,
        issued_at: datetime,
        expires_at: datetime,
        approval_id: UUID | None = None,
    ) -> Approval:
        """Create a signed approval for an exact immutable plan manifest."""

        unknown = set(approved_action_ids) - {
            action.action_id for action in plan.actions
        }
        if unknown:
            raise ValidationError(
                f"approval references unknown action IDs: {sorted(map(str, unknown))}"
            )
        try:
            authority = self._authorities[key_id]
        except KeyError as error:
            raise ConfigurationError(
                f"unknown approval authority key_id: {key_id}"
            ) from error
        unsigned = Approval(
            approval_id=approval_id or uuid4(),
            plan_fingerprint=plan.fingerprint,
            approved_action_ids=approved_action_ids,
            approved_by=authority.subject,
            issuer=authority.issuer,
            tenant=authority.tenant,
            roles=authority.roles,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=authority.key_id,
            signature="pending",
        )
        signature = hmac.new(
            authority.secret,
            unsigned.signing_payload(),
            hashlib.sha256,
        ).hexdigest()
        return replace(unsigned, signature=signature)

    def authenticated_subject(self, approval: Approval) -> str | None:
        """Verify identity binding and signature without trusting JSON fields."""

        if approval.signature_scheme != "hmac-sha256":
            return None
        authority = self._authorities.get(approval.key_id)
        if authority is None or (
            approval.approved_by != authority.subject
            or approval.issuer != authority.issuer
            or approval.tenant != authority.tenant
            or approval.roles != authority.roles
        ):
            return None
        if approval.approval_id in authority.revoked_approval_ids:
            return None
        if (
            authority.revoked_before is not None
            and approval.issued_at <= authority.revoked_before
        ):
            return None
        expected = hmac.new(
            authority.secret,
            approval.signing_payload(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, approval.signature):
            return None
        return _principal_id(authority)


def _principal_id(authority: ApprovalAuthority) -> str:
    """Return a canonical issuer/tenant/subject identity for distinctness."""

    return "|".join(
        (
            _claim_key(authority.issuer),
            _claim_key(authority.tenant),
            _claim_key(authority.subject),
        )
    )


def _claim_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _validate_claim(value: str, name: str) -> None:
    if not value or value != value.strip():
        raise ConfigurationError(
            f"approval authority {name} must be a non-empty normalized value"
        )
    if unicodedata.normalize("NFC", value) != value:
        raise ConfigurationError(
            f"approval authority {name} must use Unicode NFC normalization"
        )
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        raise ConfigurationError(
            f"approval authority {name} must not contain control characters"
        )


def _required_string(
    item: Mapping[str, object],
    name: str,
    *,
    key_id: str,
) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value:
        raise ConfigurationError(
            f"approval authority {key_id} requires string field {name}"
        )
    return value


def _optional_datetime(value: object, *, key_id: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError(
            f"approval authority {key_id} revoked_before must be an ISO datetime"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ConfigurationError(
            f"approval authority {key_id} revoked_before must be an ISO datetime"
        ) from error
    _require_aware_datetime(parsed, "revoked_before")
    return parsed.astimezone(UTC)


def _require_aware_datetime(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConfigurationError(
            f"approval authority {name} must include a timezone offset"
        )
