"""Deterministic quarantine-to-enable promotion service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from master_agent.capsule_readiness import (
    AuthenticatedApprovalControl,
    assess_capsule_readiness,
)
from master_agent.capsule_runtime import (
    CapsuleValidation,
    CapsuleValidator,
    CapsuleWorker,
)
from master_agent.capsules import (
    CapsuleAuthority,
    CapsuleBundle,
    CapsuleManifest,
    CapsuleRole,
    CapsuleState,
    CapsuleStore,
    CapsuleTrustStore,
    advance_manifest,
    create_quarantined_manifest,
)
from master_agent.credential_broker import CredentialProvider
from master_agent.errors import ConfigurationError
from master_agent.governance import EnvironmentKind
from master_agent.receipts import ExternalReceiptSink


@dataclass(frozen=True, slots=True)
class PromotionResult:
    """Complete signed lifecycle and its deterministic evidence."""

    manifests: tuple[CapsuleManifest, ...]
    validation: CapsuleValidation

    @property
    def enabled(self) -> CapsuleManifest:
        manifest = self.manifests[-1]
        if manifest.state is not CapsuleState.ENABLED:  # pragma: no cover - invariant.
            raise RuntimeError("promotion result is not enabled")
        return manifest


class CapabilityPromotionService:
    """Own every authorized transition without letting code self-promote."""

    def __init__(
        self,
        *,
        store: CapsuleStore,
        trust: CapsuleTrustStore,
        worker: CapsuleWorker,
        validator: CapsuleValidator,
        authorities: dict[CapsuleRole, CapsuleAuthority],
        environment: str,
        credential_provider: CredentialProvider | None = None,
        approval_control: AuthenticatedApprovalControl | None = None,
        external_audit_sink: ExternalReceiptSink | None = None,
    ) -> None:
        required = frozenset(
            {
                CapsuleRole.GENERATOR,
                CapsuleRole.VALIDATOR,
                CapsuleRole.SANDBOX_VALIDATOR,
                CapsuleRole.REVIEWER,
                CapsuleRole.PUBLISHER,
                CapsuleRole.REVOKER,
            }
        )
        if set(authorities) != set(required):
            raise ConfigurationError("capsule promotion authorities are incomplete")
        for role, authority in authorities.items():
            if role not in authority.roles:
                raise ConfigurationError("capsule promotion authority role drifted")
        if environment == str(EnvironmentKind.PRODUCTION):
            readiness = assess_capsule_readiness(
                environment=EnvironmentKind.PRODUCTION,
                worker=worker,
                credential_provider=credential_provider,
                approval_control=approval_control,
                external_audit_sink=external_audit_sink,
            )
            if not readiness.ready:
                raise ConfigurationError(
                    "production capsule promotion requires live green controls: "
                    + "; ".join(readiness.errors)
                )
        self._store = store
        self._trust = trust
        self._worker = worker
        self._validator = validator
        self._authorities = dict(authorities)
        self._environment = environment

    def promote(
        self,
        bundle: CapsuleBundle,
        *,
        now: datetime | None = None,
    ) -> PromotionResult:
        """Validate, review, publish, and enable one immutable bundle."""

        if self._authorities[CapsuleRole.PUBLISHER].subject != bundle.spec.publisher:
            raise ConfigurationError(
                "capsule publisher identity differs from its authority"
            )

        quarantined = create_quarantined_manifest(
            bundle,
            authority=self._authorities[CapsuleRole.GENERATOR],
            environment=self._environment,
            worker_sha256=self._worker.identity_sha256,
            now=now,
        )
        self._store.install(bundle, quarantined, trust=self._trust)
        evidence = self._validator.validate(bundle)
        tested = advance_manifest(
            quarantined,
            CapsuleState.TESTED,
            authority=self._authorities[CapsuleRole.VALIDATOR],
            trust=self._trust,
            validation_result_sha256=evidence.validation_sha256,
            now=now,
        )
        self._store.append_manifest(tested, trust=self._trust)
        sandboxed = advance_manifest(
            tested,
            CapsuleState.SANDBOX_VALIDATED,
            authority=self._authorities[CapsuleRole.SANDBOX_VALIDATOR],
            trust=self._trust,
            sandbox_validation_sha256=evidence.sandbox_sha256,
            now=now,
        )
        self._store.append_manifest(sandboxed, trust=self._trust)
        reviewer = self._authorities[CapsuleRole.REVIEWER]
        reviewed = advance_manifest(
            sandboxed,
            CapsuleState.REVIEWED,
            authority=reviewer,
            trust=self._trust,
            reviewer=reviewer.subject,
            now=now,
        )
        self._store.append_manifest(reviewed, trust=self._trust)
        published = advance_manifest(
            reviewed,
            CapsuleState.PUBLISHED,
            authority=self._authorities[CapsuleRole.PUBLISHER],
            trust=self._trust,
            now=now,
        )
        self._store.append_manifest(published, trust=self._trust)
        enabled = advance_manifest(
            published,
            CapsuleState.ENABLED,
            authority=self._authorities[CapsuleRole.PUBLISHER],
            trust=self._trust,
            now=now,
        )
        self._store.append_manifest(enabled, trust=self._trust)
        return PromotionResult(
            manifests=(
                quarantined,
                tested,
                sandboxed,
                reviewed,
                published,
                enabled,
            ),
            validation=evidence,
        )

    def revoke(
        self,
        manifest: CapsuleManifest,
        *,
        now: datetime | None = None,
    ) -> CapsuleManifest:
        """Immediately append an independently signed revocation."""

        revoked = advance_manifest(
            manifest,
            CapsuleState.REVOKED,
            authority=self._authorities[CapsuleRole.REVOKER],
            trust=self._trust,
            now=now,
        )
        self._store.append_manifest(revoked, trust=self._trust)
        return revoked
