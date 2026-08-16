"""Fail-closed production readiness for promoted capability execution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from master_agent.capsule_runtime import CapsuleWorker
from master_agent.credential_broker import CredentialProvider
from master_agent.governance import EnvironmentKind
from master_agent.models import freeze_json_mapping
from master_agent.receipts import ExternalReceiptSink


class _HealthControl(Protocol):
    def healthy(self) -> bool:
        """Perform a bounded readiness probe."""


class AuthenticatedApprovalControl(_HealthControl, Protocol):
    """Production approval service selected by trusted runtime configuration."""

    @property
    def control_id(self) -> str:
        """Return an operator-reviewed approval-control identity."""

    @property
    def production_ready(self) -> bool:
        """Return whether exact-plan authentication is production-approved."""

    def healthy(self) -> bool:
        """Perform a bounded readiness probe."""


@dataclass(frozen=True, slots=True)
class CapsuleReadinessReport:
    """Secret-free status of all production capsule dependencies."""

    ready: bool
    environment: EnvironmentKind
    checks: tuple[Mapping[str, object], ...]
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject structurally inconsistent readiness attestations."""

        expected = {
            "isolated_worker",
            "production_credential_provider",
            "authenticated_approvals",
            "external_tamper_resistant_audit",
        }
        immutable_checks = tuple(freeze_json_mapping(item) for item in self.checks)
        object.__setattr__(self, "checks", immutable_checks)
        names = [item.get("name") for item in immutable_checks]
        if len(names) != len(expected) or set(names) != expected:
            raise ValueError("capsule readiness checks are incomplete or duplicated")
        required_failures = any(
            item.get("required") is True and item.get("passed") is not True
            for item in immutable_checks
        )
        if self.ready != (not self.errors and not required_failures):
            raise ValueError("capsule readiness result is inconsistent")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "master-agent/capsule-readiness@1",
            "ready": self.ready,
            "environment": str(self.environment),
            "checks": [dict(item) for item in self.checks],
            "errors": list(self.errors),
        }


def assess_capsule_readiness(
    *,
    environment: EnvironmentKind,
    worker: CapsuleWorker | None,
    credential_provider: CredentialProvider | None,
    approval_control: AuthenticatedApprovalControl | None,
    external_audit_sink: ExternalReceiptSink | None,
) -> CapsuleReadinessReport:
    """Require every external authority control before production promotion."""

    worker_ready = worker is not None and worker.production_isolated
    credentials_ready = (
        credential_provider is not None
        and credential_provider.production_ready is True
        and _healthy(credential_provider)
    )
    approvals_ready = (
        approval_control is not None
        and approval_control.production_ready is True
        and _healthy(approval_control)
    )
    audit_ready = (
        external_audit_sink is not None
        and external_audit_sink.external is True
        and external_audit_sink.tamper_resistant is True
        and _healthy(external_audit_sink)
    )
    checks = (
        {
            "name": "isolated_worker",
            "required": True,
            "passed": worker_ready,
            "backend": worker.backend if worker is not None else None,
        },
        {
            "name": "production_credential_provider",
            "required": environment is EnvironmentKind.PRODUCTION,
            "passed": credentials_ready,
            "provider_id": (
                credential_provider.provider_id
                if credential_provider is not None
                else None
            ),
        },
        {
            "name": "authenticated_approvals",
            "required": environment is EnvironmentKind.PRODUCTION,
            "passed": approvals_ready,
            "control_id": (
                approval_control.control_id if approval_control is not None else None
            ),
        },
        {
            "name": "external_tamper_resistant_audit",
            "required": environment is EnvironmentKind.PRODUCTION,
            "passed": audit_ready,
            "sink_id": (
                external_audit_sink.sink_id if external_audit_sink is not None else None
            ),
        },
    )
    errors: list[str] = []
    if not worker_ready:
        errors.append("capsule OS isolation backend is unavailable")
    if environment is EnvironmentKind.PRODUCTION:
        if not credentials_ready:
            errors.append("production capsule credential provider is unavailable")
        if not approvals_ready:
            errors.append("production authenticated approvals are unavailable")
        if not audit_ready:
            errors.append(
                "production external tamper-resistant audit sink is unavailable"
            )
    return CapsuleReadinessReport(
        ready=not errors,
        environment=environment,
        checks=checks,
        errors=tuple(errors),
    )


def _healthy(control: _HealthControl) -> bool:
    """Convert a bounded adapter probe failure into a fail-closed result."""

    try:
        return control.healthy() is True
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
