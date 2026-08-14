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
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
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
    secret: bytes

    def __post_init__(self) -> None:
        if not self.key_id.strip() or self.key_id != self.key_id.strip():
            raise ConfigurationError("approval authority key_id must be normalized")
        if not self.subject.strip() or self.subject != self.subject.strip():
            raise ConfigurationError("approval authority subject must be normalized")
        if len(self.secret) < 32:
            raise ConfigurationError(
                f"approval authority {self.key_id} requires at least 32 secret bytes"
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
            subject = str(item.get("subject", ""))
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
            )
            authorities[authority.key_id] = authority
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
        if authority is None or approval.approved_by != authority.subject:
            return None
        expected = hmac.new(
            authority.secret,
            approval.signing_payload(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, approval.signature):
            return None
        return authority.subject
