"""Deterministic quarantine-to-enable promotion service."""

from __future__ import annotations

from collections.abc import Mapping
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
        selected_environment = _environment_kind(
            environment,
            context="capsule promotion environment",
        )
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
        worker_sha256 = worker.identity_sha256
        if validator.worker_sha256 != worker_sha256:
            raise ConfigurationError(
                "capsule validator worker differs from the promotion worker"
            )
        if selected_environment is EnvironmentKind.PRODUCTION:
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
        for role, authority in authorities.items():
            if str(selected_environment) not in authority.environments:
                raise ConfigurationError(
                    "capsule promotion authority "
                    f"{role} is not valid in {selected_environment}"
                )
            if trust.authorities.get(authority.key_id) != authority:
                raise ConfigurationError(
                    f"capsule promotion authority {role} is not bound to the trust store"
                )
        self._store = store
        self._trust = trust
        self._worker = worker
        self._worker_sha256 = worker_sha256
        self._validator = validator
        self._authorities = dict(authorities)
        self._environment = selected_environment

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
            environment=str(self._environment),
            worker_sha256=self._worker_sha256,
            now=now,
        )
        self._store.install(bundle, quarantined, trust=self._trust)
        return self.promote_installed(bundle, quarantined, now=now)

    def promote_quarantined(
        self,
        bundle: CapsuleBundle,
        current: CapsuleManifest,
        *,
        now: datetime | None = None,
    ) -> PromotionResult:
        """Promote or resume an installed capsule; retained for API compatibility."""

        return self.promote_installed(bundle, current, now=now)

    def promote_installed(
        self,
        bundle: CapsuleBundle,
        current: CapsuleManifest,
        *,
        now: datetime | None = None,
    ) -> PromotionResult:
        """Promote or safely resume an authenticated installed capsule chain."""

        promotable_states = {
            CapsuleState.QUARANTINED,
            CapsuleState.TESTED,
            CapsuleState.SANDBOX_VALIDATED,
            CapsuleState.REVIEWED,
            CapsuleState.PUBLISHED,
            CapsuleState.ENABLED,
        }
        if current.state not in promotable_states:
            raise ConfigurationError(
                "existing capsule promotion cannot resume from its current state"
            )
        quarantine_environment = _environment_kind(
            current.environment,
            context="capsule installed environment",
        )
        if quarantine_environment is not self._environment:
            raise ConfigurationError(
                "capsule installed environment differs from the promotion service"
            )
        if current.worker_sha256 != self._worker_sha256:
            raise ConfigurationError(
                "capsule installed worker differs from the promotion worker"
            )
        if self._authorities[CapsuleRole.PUBLISHER].subject != bundle.spec.publisher:
            raise ConfigurationError(
                "capsule publisher identity differs from its authority"
            )
        installed = self._store.load_bundle(
            current.spec.capability_id,
            current.spec.version,
        )
        if installed != bundle:
            raise ConfigurationError(
                "installed quarantined capsule differs from the selected bundle"
            )
        chain = self._store.manifests(
            current.spec.capability_id,
            current.spec.version,
            trust=self._trust,
        )
        if not chain or chain[-1] != current:
            raise ConfigurationError(
                "selected manifest is not the latest installed capsule state"
            )
        evidence = self._validator.validate(bundle)
        _require_worker_evidence(
            evidence.validation,
            expected_sha256=self._worker_sha256,
            context="capsule validation evidence",
        )
        _require_worker_evidence(
            evidence.sandbox,
            expected_sha256=self._worker_sha256,
            context="capsule sandbox evidence",
        )
        states = tuple(item.state for item in chain)
        if CapsuleState.TESTED in states and (
            current.validation_result_sha256 != evidence.validation_sha256
        ):
            raise ConfigurationError(
                "capsule validation evidence differs from the installed chain"
            )
        if CapsuleState.SANDBOX_VALIDATED in states and (
            current.sandbox_validation_sha256 != evidence.sandbox_sha256
        ):
            raise ConfigurationError(
                "capsule sandbox evidence differs from the installed chain"
            )

        promoted = list(chain)
        while current.state is not CapsuleState.ENABLED:
            if current.state is CapsuleState.QUARANTINED:
                next_manifest = advance_manifest(
                    current,
                    CapsuleState.TESTED,
                    authority=self._authorities[CapsuleRole.VALIDATOR],
                    trust=self._trust,
                    validation_result_sha256=evidence.validation_sha256,
                    now=now,
                )
            elif current.state is CapsuleState.TESTED:
                next_manifest = advance_manifest(
                    current,
                    CapsuleState.SANDBOX_VALIDATED,
                    authority=self._authorities[CapsuleRole.SANDBOX_VALIDATOR],
                    trust=self._trust,
                    sandbox_validation_sha256=evidence.sandbox_sha256,
                    now=now,
                )
            elif current.state is CapsuleState.SANDBOX_VALIDATED:
                reviewer = self._authorities[CapsuleRole.REVIEWER]
                next_manifest = advance_manifest(
                    current,
                    CapsuleState.REVIEWED,
                    authority=reviewer,
                    trust=self._trust,
                    reviewer=reviewer.subject,
                    now=now,
                )
            elif current.state is CapsuleState.REVIEWED:
                next_manifest = advance_manifest(
                    current,
                    CapsuleState.PUBLISHED,
                    authority=self._authorities[CapsuleRole.PUBLISHER],
                    trust=self._trust,
                    now=now,
                )
            elif current.state is CapsuleState.PUBLISHED:
                next_manifest = advance_manifest(
                    current,
                    CapsuleState.ENABLED,
                    authority=self._authorities[CapsuleRole.PUBLISHER],
                    trust=self._trust,
                    now=now,
                )
            else:  # pragma: no cover - guarded by promotable_states.
                raise RuntimeError("unhandled capsule promotion state")
            self._store.append_manifest(next_manifest, trust=self._trust)
            promoted.append(next_manifest)
            current = next_manifest
        return PromotionResult(
            manifests=tuple(promoted),
            validation=evidence,
        )

    def disable(
        self,
        manifest: CapsuleManifest,
        *,
        now: datetime | None = None,
    ) -> CapsuleManifest:
        """Disable an enabled capsule by appending signed deprecation."""

        disabled = advance_manifest(
            manifest,
            CapsuleState.DEPRECATED,
            authority=self._authorities[CapsuleRole.PUBLISHER],
            trust=self._trust,
            now=now,
        )
        self._store.append_manifest(disabled, trust=self._trust)
        return disabled

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

    def remove(
        self,
        manifest: CapsuleManifest,
        *,
        now: datetime | None = None,
    ) -> CapsuleManifest:
        """Remove future routing by revocation while retaining immutable history."""

        return self.revoke(manifest, now=now)


def _environment_kind(value: str, *, context: str) -> EnvironmentKind:
    """Parse one exact deployment environment or fail closed."""

    try:
        return EnvironmentKind(value)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"{context} is unsupported") from error


def _require_worker_evidence(
    evidence: Mapping[str, object],
    *,
    expected_sha256: str,
    context: str,
) -> None:
    """Bind signed promotion evidence to the authorized execution worker."""

    if evidence.get("worker_sha256") != expected_sha256:
        raise ConfigurationError(f"{context} worker identity differs from promotion")
