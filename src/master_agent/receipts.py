"""Signed, content-free execution receipts and external audit export."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from master_agent.errors import ConfigurationError
from master_agent.models import Approval, ChangePlan, freeze_json_mapping
from master_agent.orchestrator import RunReport

EXECUTION_RECEIPT_SCHEMA = "master-agent/execution-receipt@1"


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    """Signed content-free evidence for one exact governed run."""

    receipt_id: UUID
    run_id: UUID
    plan_id: UUID
    plan_fingerprint: str
    dry_run: bool
    successful: bool
    approval_claims: tuple[Mapping[str, Any], ...]
    capsule_bindings: tuple[Mapping[str, Any], ...]
    action_outcomes: tuple[Mapping[str, Any], ...]
    audit_anchor_sha256: str
    created_at: datetime
    signer_key_id: str
    signature: str = ""
    schema: str = EXECUTION_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != EXECUTION_RECEIPT_SCHEMA:
            raise ConfigurationError("execution receipt schema is unsupported")
        for name, digest in (
            ("plan_fingerprint", self.plan_fingerprint),
            ("audit_anchor_sha256", self.audit_anchor_sha256),
        ):
            _validate_sha256(digest, f"execution receipt {name}")
        if self.created_at.tzinfo is None:
            raise ConfigurationError("execution receipt timestamp requires a timezone")
        if not self.signer_key_id:
            raise ConfigurationError("execution receipt signer is empty")
        if self.signature:
            _validate_sha256(self.signature, "execution receipt signature")
        object.__setattr__(
            self,
            "approval_claims",
            tuple(freeze_json_mapping(item) for item in self.approval_claims),
        )
        object.__setattr__(
            self,
            "capsule_bindings",
            tuple(freeze_json_mapping(item) for item in self.capsule_bindings),
        )
        object.__setattr__(
            self,
            "action_outcomes",
            tuple(freeze_json_mapping(item) for item in self.action_outcomes),
        )

    @property
    def receipt_sha256(self) -> str:
        if not self.signature:
            raise ConfigurationError("unsigned execution receipt has no identity")
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": str(self.receipt_id),
            "run_id": str(self.run_id),
            "plan_id": str(self.plan_id),
            "plan_fingerprint": self.plan_fingerprint,
            "dry_run": self.dry_run,
            "successful": self.successful,
            "approval_claims": [_jsonable(item) for item in self.approval_claims],
            "capsule_bindings": [_jsonable(item) for item in self.capsule_bindings],
            "action_outcomes": [_jsonable(item) for item in self.action_outcomes],
            "audit_anchor_sha256": self.audit_anchor_sha256,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
            "signer_key_id": self.signer_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}


@dataclass(frozen=True, slots=True)
class ReceiptSigner:
    """Authenticated receipt authority; key material never serializes."""

    key_id: str
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not self.key_id or len(self.secret) < 32:
            raise ConfigurationError(
                "receipt signer requires an identity and 32-byte key"
            )

    def sign(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        if receipt.signer_key_id != self.key_id:
            raise ConfigurationError("execution receipt signer identity drifted")
        signature = hmac.new(
            self.secret,
            _canonical_json(receipt.unsigned_dict()),
            hashlib.sha256,
        ).hexdigest()
        from dataclasses import replace

        return replace(receipt, signature=signature)

    def verify(self, receipt: ExecutionReceipt) -> bool:
        if receipt.signer_key_id != self.key_id or not receipt.signature:
            return False
        expected = self.sign(
            ExecutionReceipt(
                receipt_id=receipt.receipt_id,
                run_id=receipt.run_id,
                plan_id=receipt.plan_id,
                plan_fingerprint=receipt.plan_fingerprint,
                dry_run=receipt.dry_run,
                successful=receipt.successful,
                approval_claims=receipt.approval_claims,
                capsule_bindings=receipt.capsule_bindings,
                action_outcomes=receipt.action_outcomes,
                audit_anchor_sha256=receipt.audit_anchor_sha256,
                created_at=receipt.created_at,
                signer_key_id=receipt.signer_key_id,
            )
        ).signature
        return hmac.compare_digest(expected, receipt.signature)


class ExternalReceiptSink(Protocol):
    """Externally administered append-only/WORM receipt destination."""

    @property
    def sink_id(self) -> str:
        """Return an operator-reviewed sink identity."""

    @property
    def external(self) -> bool:
        """Return whether the sink is outside the MasterAgent host."""

    @property
    def tamper_resistant(self) -> bool:
        """Return whether writers cannot rewrite accepted records."""

    def healthy(self) -> bool:
        """Perform a bounded readiness probe."""

    def append(self, receipt: Mapping[str, Any]) -> str:
        """Append a signed receipt and return a non-secret locator."""


class TelemetrySink(Protocol):
    """OpenTelemetry/SIEM-compatible metadata event destination."""

    def emit(self, event: Mapping[str, Any]) -> None:
        """Emit one content-free event."""


def build_execution_receipt(
    *,
    plan: ChangePlan,
    report: RunReport,
    authenticated_approvals: Sequence[tuple[Approval, str]],
    audit_anchor_sha256: str,
    signer: ReceiptSigner,
    now: datetime | None = None,
) -> ExecutionReceipt:
    """Create and sign exact-plan evidence without provider/user content."""

    if report.plan_id != plan.plan_id or report.plan_fingerprint != plan.fingerprint:
        raise ConfigurationError("execution report differs from the receipt plan")
    context = plan.execution_context
    capsule_bindings = (
        tuple(item.to_dict() for item in context.capsules)
        if context is not None
        else ()
    )
    approval_claims = tuple(
        {
            "approval_id": str(item.approval_id),
            "approved_by": item.approved_by,
            "authenticated_principal": authenticated_subject,
            "issuer": item.issuer,
            "tenant": item.tenant,
            "roles": list(item.roles),
            "key_id": item.key_id,
            "approved_action_ids": [str(value) for value in item.approved_action_ids],
            "signature_sha256": hashlib.sha256(item.signature.encode()).hexdigest(),
        }
        for item, authenticated_subject in authenticated_approvals
        if item.plan_fingerprint == plan.fingerprint
    )
    outcomes: list[dict[str, Any]] = []
    for item in report.actions:
        result = item.result
        compensation = item.compensation
        outcomes.append(
            {
                "action_id": str(item.action_id),
                "capability": item.capability,
                "state": str(item.state),
                "policy_permitted": str(item.state)
                not in {"prohibited", "approval_required"},
                "connector_reference_sha256": (
                    hashlib.sha256(result.connector_reference.encode()).hexdigest()
                    if result is not None and result.connector_reference
                    else None
                ),
                "readback_verified": str(item.state) in {"verified", "reused"},
                "result_before_sha256": _mapping_digest(
                    result.before if result is not None else None
                ),
                "result_after_sha256": _mapping_digest(
                    result.after if result is not None else None
                ),
                "compensation_state": (
                    str(compensation.state) if compensation is not None else None
                ),
                "compensation_after_sha256": _mapping_digest(
                    compensation.after if compensation is not None else None
                ),
            }
        )
    unsigned = ExecutionReceipt(
        receipt_id=uuid4(),
        run_id=report.run_id,
        plan_id=plan.plan_id,
        plan_fingerprint=plan.fingerprint,
        dry_run=report.dry_run,
        successful=report.successful,
        approval_claims=approval_claims,
        capsule_bindings=capsule_bindings,
        action_outcomes=tuple(outcomes),
        audit_anchor_sha256=audit_anchor_sha256,
        created_at=(now or datetime.now(UTC)).astimezone(UTC),
        signer_key_id=signer.key_id,
    )
    return signer.sign(unsigned)


def export_execution_receipt(
    receipt: ExecutionReceipt,
    *,
    sink: ExternalReceiptSink,
) -> str:
    """Fail closed unless an external tamper-resistant sink is healthy."""

    if not sink.external or not sink.tamper_resistant or not sink.healthy():
        raise ConfigurationError("external tamper-resistant audit sink is not healthy")
    locator = sink.append(receipt.to_dict())
    if not locator or locator != locator.strip():
        raise ConfigurationError("external audit sink returned an invalid locator")
    return locator


def emit_receipt_telemetry(
    receipt: ExecutionReceipt,
    *,
    sink: TelemetrySink,
) -> None:
    """Export only cardinality-bounded identities, states, and digests."""

    sink.emit(
        {
            "event": "master_agent.execution_receipt",
            "receipt_id": str(receipt.receipt_id),
            "receipt_sha256": receipt.receipt_sha256,
            "plan_fingerprint": receipt.plan_fingerprint,
            "successful": receipt.successful,
            "dry_run": receipt.dry_run,
            "action_states": [
                {
                    "capability": item["capability"],
                    "state": item["state"],
                }
                for item in receipt.action_outcomes
            ],
            "capsule_manifest_sha256": [
                item["manifest_sha256"] for item in receipt.capsule_bindings
            ],
            "audit_anchor_sha256": receipt.audit_anchor_sha256,
        }
    )


def _mapping_digest(value: Mapping[str, Any] | None) -> str | None:
    return (
        hashlib.sha256(_canonical_json(value)).hexdigest()
        if value is not None
        else None
    )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ConfigurationError(f"{label} must be a lowercase SHA-256 digest")
