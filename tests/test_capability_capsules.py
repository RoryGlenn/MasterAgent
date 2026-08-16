"""End-to-end and adversarial tests for capability promotion."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import unittest
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.capsule_operations import CapsuleRunCoordinator, CapsuleRunState
from master_agent.capsule_promotion import CapabilityPromotionService, PromotionResult
from master_agent.capsule_runtime import (
    CapsuleValidator,
    CapsuleWorker,
    _validate_worker_artifact,
    activate_capsule,
    context_with_capsules,
)
from master_agent.capsules import (
    COMPENSATION_SCHEMA,
    DEPENDENCY_LOCK_SCHEMA,
    SBOM_FORMAT,
    SBOM_SPEC_VERSION,
    TEST_SUITE_SCHEMA,
    VERIFICATION_SCHEMA,
    CapsuleAuthority,
    CapsuleBundle,
    CapsuleRole,
    CapsuleSpec,
    CapsuleState,
    CapsuleStore,
    CapsuleTrustStore,
    LicensePolicy,
    advance_manifest,
    create_quarantined_manifest,
)
from master_agent.errors import ConfigurationError, ConnectorError, ValidationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ExecutionContext,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.receipts import ReceiptSigner
from master_agent.registry import ConnectorRegistry
from tests.helpers import private_temporary_directory


class CapabilityCapsuleTests(unittest.TestCase):
    """Exercise the complete quarantine-to-governed-execution lifecycle."""

    worker: CapsuleWorker

    @classmethod
    def setUpClass(cls) -> None:
        cls.worker = CapsuleWorker()

    def test_synthetic_capability_promotes_and_runs_through_orchestrator(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            result, store, trust = _promote(root, worker=self.worker)
            binding = result.enabled.binding(
                authenticated_principal="operator:alice",
                agent_identity="master-agent:test",
                tenant_id="tenant:test",
            )
            activated = activate_capsule(
                store=store,
                trust=trust,
                binding=binding,
                worker=self.worker,
                base_catalog=CapabilityCatalog({}),
            )
            registry = ConnectorRegistry()
            registry.register(activated.connector)
            audit = AuditLog(root / "audit.sqlite3")
            authenticator = HmacApprovalAuthenticator(
                {
                    "operator": ApprovalAuthority(
                        key_id="operator",
                        subject="alice@example.test",
                        issuer="master-agent.test",
                        tenant="tenant:test",
                        roles=("change-approver",),
                        secret=b"capsule-receipt-approval-secret-1",
                    )
                }
            )
            orchestrator = WorkflowOrchestrator(
                policy=_policy(authenticator),
                sources=SourceOfTruthRegistry(()),
                connectors=registry,
                audit=audit,
                capabilities=activated.catalog,
            )
            context = context_with_capsules(
                ExecutionContext(integrations_sha256="a" * 64),
                (result.enabled,),
                authenticated_principal="operator:alice",
                agent_identity="master-agent:test",
                tenant_id="tenant:test",
            )
            plan = _plan(context)
            approval_now = datetime.now(UTC)
            approval = authenticator.issue(
                plan=plan,
                approved_action_ids=(plan.actions[0].action_id,),
                key_id="operator",
                issued_at=approval_now - timedelta(seconds=1),
                expires_at=approval_now + timedelta(minutes=5),
            )
            invalid_approval = replace(approval, signature="0" * 64)
            signer = ReceiptSigner("test-receipts", b"r" * 32)
            external_sink = _ReceiptSink()
            telemetry_sink = _TelemetrySink()
            coordinated = CapsuleRunCoordinator(
                orchestrator=orchestrator,
                audit=audit,
                receipt_signer=signer,
                external_sink=external_sink,
                telemetry_sink=telemetry_sink,
            ).run(plan, approvals=(invalid_approval, approval))

            self.assertEqual(coordinated.state, CapsuleRunState.TERMINAL)
            self.assertIsNotNone(coordinated.report)
            self.assertIsNotNone(coordinated.receipt)
            assert coordinated.report is not None
            assert coordinated.receipt is not None
            self.assertTrue(coordinated.report.successful)
            self.assertIsNotNone(coordinated.report.actions[0].result)
            assert coordinated.report.actions[0].result is not None
            self.assertEqual(
                coordinated.report.actions[0].result.after,
                {"message": "Hello, Rahul"},
            )
            self.assertTrue(signer.verify(coordinated.receipt))
            self.assertEqual(len(coordinated.receipt.approval_claims), 1)
            self.assertEqual(
                coordinated.receipt.approval_claims[0]["approved_by"],
                "alice@example.test",
            )
            self.assertEqual(
                coordinated.receipt.approval_claims[0]["authenticated_principal"],
                "master-agent.test|tenant:test|alice@example.test",
            )
            self.assertEqual(
                coordinated.external_receipt_locator,
                f"worm:{coordinated.receipt.receipt_id}",
            )
            self.assertEqual(external_sink.receipts, [coordinated.receipt.to_dict()])
            self.assertEqual(len(telemetry_sink.events), 1)
            telemetry = telemetry_sink.events[0]
            self.assertEqual(
                telemetry["receipt_sha256"], coordinated.receipt.receipt_sha256
            )
            self.assertNotIn("message", json.dumps(telemetry).casefold())
            receipt_binding = coordinated.receipt.capsule_bindings[0]
            self.assertEqual(receipt_binding["version"], "1.0.0")
            self.assertEqual(receipt_binding["cpu_seconds"], 2)
            self.assertEqual(receipt_binding["max_processes"], 1)
            for name in (
                "manifest_sha256",
                "source_sha256",
                "artifact_sha256",
                "dependency_lock_sha256",
                "sbom_sha256",
                "test_suite_sha256",
                "validation_result_sha256",
                "sandbox_validation_sha256",
                "policy_contract_sha256",
                "worker_sha256",
            ):
                self.assertEqual(receipt_binding[name], getattr(binding, name))
            valid, detail = audit.verify_chain()
            self.assertTrue(valid, detail)
            audit.close()
            with sqlite3.connect(root / "audit.sqlite3") as connection:
                row = connection.execute(
                    "SELECT payload_json FROM audit_events "
                    "WHERE event_type = 'plan_started' ORDER BY id DESC LIMIT 1"
                ).fetchone()
            self.assertIsNotNone(row)
            assert row is not None
            audited = json.loads(str(row[0]))["capsule_bindings"][0]
            self.assertEqual(audited, binding.to_dict())

    def test_unpromoted_tampered_deprecated_and_revoked_capsules_fail_closed(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            bundle = _bundle()
            authorities, trust = _authorities()
            store = CapsuleStore(root / "quarantine")
            quarantined = create_quarantined_manifest(
                bundle,
                authority=authorities[CapsuleRole.GENERATOR],
                environment="test",
                worker_sha256=self.worker.identity_sha256,
            )
            store.install(bundle, quarantined, trust=trust)
            with self.assertRaisesRegex(ConfigurationError, "not promoted"):
                store.resolve_enabled(
                    bundle.spec.capability_id,
                    bundle.spec.version,
                    quarantined.manifest_sha256,
                    trust=trust,
                )

            result, promoted_store, promoted_trust = _promote(
                root / "promoted", worker=self.worker
            )
            capsule_directory = next(promoted_store.root.iterdir())
            program = capsule_directory / "program.py"
            program.write_bytes(
                b'def run(request):\n    return {"message": "tampered"}\n'
            )
            os.chmod(program, 0o600)
            with self.assertRaisesRegex(ConfigurationError, "digest drifted"):
                promoted_store.resolve_enabled(
                    result.enabled.spec.capability_id,
                    result.enabled.spec.version,
                    result.enabled.manifest_sha256,
                    trust=promoted_trust,
                )

            deprecated_result, deprecated_store, deprecated_trust = _promote(
                root / "deprecated", worker=self.worker
            )
            publisher = _authorities()[0][CapsuleRole.PUBLISHER]
            # Use the authority from the actual trust store, not an equal-looking key.
            publisher = deprecated_trust.authorities[publisher.key_id]
            deprecated = advance_manifest(
                deprecated_result.enabled,
                CapsuleState.DEPRECATED,
                authority=publisher,
                trust=deprecated_trust,
            )
            deprecated_store.append_manifest(deprecated, trust=deprecated_trust)
            with self.assertRaisesRegex(ConfigurationError, "deprecated"):
                deprecated_store.resolve_enabled(
                    deprecated.spec.capability_id,
                    deprecated.spec.version,
                    deprecated_result.enabled.manifest_sha256,
                    trust=deprecated_trust,
                )

            revoked_result, revoked_store, revoked_trust = _promote(
                root / "revoked", worker=self.worker
            )
            revoker = next(
                authority
                for authority in revoked_trust.authorities.values()
                if CapsuleRole.REVOKER in authority.roles
            )
            revoked = advance_manifest(
                revoked_result.enabled,
                CapsuleState.REVOKED,
                authority=revoker,
                trust=revoked_trust,
            )
            revoked_store.append_manifest(revoked, trust=revoked_trust)
            with self.assertRaisesRegex(ConfigurationError, "revoked"):
                revoked_store.resolve_enabled(
                    revoked.spec.capability_id,
                    revoked.spec.version,
                    revoked_result.enabled.manifest_sha256,
                    trust=revoked_trust,
                )

    def test_signature_substitution_and_dependency_confusion_are_rejected(self) -> None:
        immutable = _bundle()
        immutable_cases = immutable.test_suite["cases"]
        self.assertIsInstance(immutable_cases, tuple)
        with self.assertRaises(TypeError):
            immutable_cases[0]["expected"]["message"] = "tampered"

        with private_temporary_directory() as directory:
            result, _store, trust = _promote(Path(directory), worker=self.worker)
            substituted = replace(
                result.enabled,
                signature=hashlib.sha256(b"attacker").hexdigest(),
            )
            with self.assertRaisesRegex(ConfigurationError, "signature is invalid"):
                trust.verify(substituted)
            publisher = trust.authorities[result.enabled.signer_key_id]
            with self.assertRaisesRegex(ConfigurationError, "moved backwards"):
                advance_manifest(
                    result.enabled,
                    CapsuleState.DEPRECATED,
                    authority=publisher,
                    trust=trust,
                    now=datetime.fromisoformat(result.enabled.transitioned_at)
                    - timedelta(seconds=1),
                )

        bundle = _bundle(
            dependencies=[
                {
                    "name": "lookalike",
                    "version": "1.0.0",
                    "artifact_sha256": "1" * 64,
                    "license": "MIT",
                }
            ],
            components=[],
        )
        validator = CapsuleValidator(
            worker=self.worker, license_policy=_license_policy()
        )
        with self.assertRaisesRegex(ValidationError, "SBOM does not match"):
            validator.validate(bundle)

    def test_worker_denies_host_files_secrets_network_processes_and_exhaustion(
        self,
    ) -> None:
        probes = (
            b'def run(request):\n    return {"x": open("/etc/passwd").read()}\n',
            b'def run(request):\n    return {"x": __import__("os").environ}\n',
            b'def run(request):\n    return {"x": __import__("socket").socket()}\n',
            b'def run(request):\n    return {"x": __import__("subprocess").run(["id"])}\n',
            b'def run(request):\n    return {"x": request.__class__.__mro__}\n',
        )
        for source in probes:
            with self.subTest(source=source[:30]), self.assertRaises(ConnectorError):
                _run_source(self.worker, source)
        with self.assertRaisesRegex(ConnectorError, "timed out|malformed"):
            _run_source(
                self.worker,
                b"def run(request):\n    while True:\n        pass\n",
                timeout_seconds=1,
            )

    def test_bundle_reader_rejects_symlink_escape(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            bundle = _bundle()
            _write_bundle(root, bundle)
            outside = root / "outside.py"
            outside.write_text('def run(request):\n    return {"message": "no"}\n')
            (root / "program.py").unlink()
            (root / "program.py").symlink_to(outside)
            with self.assertRaises(ConfigurationError):
                CapsuleBundle.from_directory(root)

    def test_worker_artifact_accepts_private_group_but_rejects_world_write(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            artifact = Path(directory) / "worker.py"
            artifact.write_text("pass\n", encoding="utf-8")
            artifact.chmod(0o664)
            _validate_worker_artifact(artifact, executable=False)
            artifact.chmod(0o666)
            with self.assertRaisesRegex(ConfigurationError, "not a trusted"):
                _validate_worker_artifact(artifact, executable=False)

    def test_exact_resume_rejects_changed_plan_and_terminal_replay(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            result, store, trust = _promote(root, worker=self.worker)
            binding = result.enabled.binding()
            activated = activate_capsule(
                store=store,
                trust=trust,
                binding=binding,
                worker=self.worker,
                base_catalog=CapabilityCatalog({}),
            )
            registry = ConnectorRegistry()
            registry.register(activated.connector)
            audit = AuditLog(root / "resume.sqlite3")
            coordinator = CapsuleRunCoordinator(
                orchestrator=WorkflowOrchestrator(
                    policy=_policy(),
                    sources=SourceOfTruthRegistry(()),
                    connectors=registry,
                    audit=audit,
                    capabilities=activated.catalog,
                ),
                audit=audit,
                receipt_signer=ReceiptSigner("resume", b"z" * 32),
            )
            plan = _plan(
                context_with_capsules(ExecutionContext("a" * 64), (result.enabled,))
            )
            completed = coordinator.run(plan)
            with self.assertRaisesRegex(ConfigurationError, "already terminal"):
                coordinator.run(
                    plan,
                    coordinator_run_id=completed.coordinator_run_id,
                )
            changed = replace(plan, goal="a changed goal")
            with self.assertRaisesRegex(ConfigurationError, "exact captured plan"):
                coordinator.run(
                    changed,
                    coordinator_run_id=completed.coordinator_run_id,
                )
            audit.close()

    def test_production_promotion_probes_live_controls_and_license_policy_is_exact(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            authorities, trust = _authorities()
            with self.assertRaisesRegex(
                ConfigurationError, "live green controls.*credential provider"
            ):
                CapabilityPromotionService(
                    store=CapsuleStore(root / "production"),
                    trust=trust,
                    worker=self.worker,
                    validator=CapsuleValidator(
                        worker=self.worker,
                        license_policy=_license_policy(),
                    ),
                    authorities=authorities,
                    environment="production",
                )

        with self.assertRaisesRegex(ConfigurationError, "both allows and denies"):
            LicensePolicy(
                allowed_spdx=frozenset({"MIT"}),
                denied_spdx=frozenset({"MIT"}),
            )


class _ReceiptSink:
    sink_id = "external-worm-test"
    external = True
    tamper_resistant = True

    def __init__(self) -> None:
        self.receipts: list[dict[str, object]] = []

    def healthy(self) -> bool:
        return True

    def append(self, receipt: Mapping[str, object]) -> str:
        self.receipts.append(dict(receipt))
        return f"worm:{receipt['receipt_id']}"


class _TelemetrySink:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event: Mapping[str, object]) -> None:
        self.events.append(dict(event))


def _promote(
    root: Path,
    *,
    worker: CapsuleWorker,
) -> tuple[PromotionResult, CapsuleStore, CapsuleTrustStore]:
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    os.chmod(root, 0o700)
    authorities, trust = _authorities()
    store = CapsuleStore(root / "capsules")
    validator = CapsuleValidator(worker=worker, license_policy=_license_policy())
    service = CapabilityPromotionService(
        store=store,
        trust=trust,
        worker=worker,
        validator=validator,
        authorities=authorities,
        environment="test",
    )
    return service.promote(_bundle()), store, trust


def _authorities() -> tuple[dict[CapsuleRole, CapsuleAuthority], CapsuleTrustStore]:
    subjects = {
        CapsuleRole.GENERATOR: "generator",
        CapsuleRole.VALIDATOR: "validator",
        CapsuleRole.SANDBOX_VALIDATOR: "sandbox-validator",
        CapsuleRole.REVIEWER: "reviewer",
        CapsuleRole.PUBLISHER: "publisher",
        CapsuleRole.REVOKER: "security",
    }
    authorities = {
        role: CapsuleAuthority(
            key_id=f"test-{role}",
            subject=subject,
            roles=frozenset({role}),
            environments=frozenset({"test"}),
            secret=hashlib.sha256(f"secret:{role}".encode()).digest(),
        )
        for role, subject in subjects.items()
    }
    return authorities, CapsuleTrustStore(
        {authority.key_id: authority for authority in authorities.values()}
    )


def _bundle(
    *,
    dependencies: list[dict[str, str]] | None = None,
    components: list[dict[str, str]] | None = None,
) -> CapsuleBundle:
    selected_dependencies = dependencies or []
    selected_components = (
        components
        if components is not None
        else [
            {
                "name": item["name"],
                "version": item["version"],
                "license": item["license"],
            }
            for item in selected_dependencies
        ]
    )
    return CapsuleBundle(
        spec=CapsuleSpec(
            capability_id="synthetic.greeting.generate",
            version="1.0.0",
            system="synthetic",
            risk=RiskLevel.LOCAL_GENERATION,
            input_schema={"name": "string"},
            output_schema={"message": "string"},
            source_provenance="generated:test-fixture",
            source_license="LicenseRef-MasterAgent-Proprietary",
            publisher="publisher",
            intents=("generate greeting", "say hello"),
            negative_intents=("delete greeting",),
        ),
        source=(
            b"def run(request):\n"
            b'    name = request.get("name", "").strip()\n'
            b'    return {"message": "Hello, " + name}\n'
        ),
        dependency_lock={
            "schema": DEPENDENCY_LOCK_SCHEMA,
            "dependencies": selected_dependencies,
        },
        sbom={
            "bomFormat": SBOM_FORMAT,
            "specVersion": SBOM_SPEC_VERSION,
            "components": selected_components,
        },
        test_suite={
            "schema": TEST_SUITE_SCHEMA,
            "cases": [
                {"input": {"name": " Rahul "}, "expected": {"message": "Hello, Rahul"}}
            ],
        },
        verification_contract={
            "schema": VERIFICATION_SCHEMA,
            "mode": "deterministic_replay",
        },
        compensation_contract={
            "schema": COMPENSATION_SCHEMA,
            "mode": "not_applicable",
        },
        third_party_notices=(
            "\n".join(
                f"{item['name']} {item['version']} - {item['license']}"
                for item in selected_dependencies
            )
        ),
    )


def _license_policy() -> LicensePolicy:
    return LicensePolicy(
        allowed_spdx=frozenset({"LicenseRef-MasterAgent-Proprietary", "MIT"}),
        denied_spdx=frozenset({"AGPL-3.0-only"}),
    )


def _policy(
    approval_authenticator: HmacApprovalAuthenticator | None = None,
) -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig(
            auto_permit_risks=frozenset(
                {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
            ),
            require_approval_risks=frozenset(
                {
                    RiskLevel.REVERSIBLE_WRITE,
                    RiskLevel.EXTERNAL_COMMUNICATION,
                    RiskLevel.HIGH_IMPACT,
                }
            ),
            prohibit_risks=frozenset({RiskLevel.DESTRUCTIVE}),
            prohibited_capabilities=("*.delete",),
            write_capability_patterns=("*.create", "*.update", "*.delete"),
        ),
        approval_authenticator=approval_authenticator,
    )


def _plan(context: ExecutionContext) -> ChangePlan:
    return ChangePlan(
        goal="Generate a deterministic greeting.",
        actions=(
            AgentAction(
                capability="synthetic.greeting.generate",
                target=ResourceRef(
                    system="synthetic",
                    resource_type="capsule_request",
                    resource_id="greeting-1",
                ),
                parameters={"name": "Rahul"},
                risk=RiskLevel.LOCAL_GENERATION,
                authority_source=AuthoritySource.DIRECT_USER,
                requires_approval=False,
                idempotency_key="capsule:greeting:1",
                justification="The operator requested a greeting.",
            ),
        ),
        created_by="test",
        execution_context=context,
    )


def _run_source(
    worker: CapsuleWorker,
    source: bytes,
    *,
    timeout_seconds: int = 2,
) -> dict[str, object]:
    return worker.execute_program(
        source=source,
        request={},
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout_seconds=timeout_seconds,
        cpu_seconds=1,
        memory_bytes=64 * 1024 * 1024,
        max_processes=1,
    )


def _write_bundle(root: Path, bundle: CapsuleBundle) -> None:
    files = {
        "capsule.json": bundle.spec.to_dict(),
        "dependencies.lock.json": dict(bundle.dependency_lock),
        "sbom.cdx.json": dict(bundle.sbom),
        "tests.json": dict(bundle.test_suite),
        "verification.json": dict(bundle.verification_contract),
        "compensation.json": dict(bundle.compensation_contract),
    }
    for name, value in files.items():
        (root / name).write_text(
            json.dumps(
                value,
                default=_mapping_json_default,
            )
        )
        os.chmod(root / name, 0o600)
    (root / "program.py").write_bytes(bundle.source)
    (root / "THIRD_PARTY_NOTICES.md").write_text(bundle.third_party_notices)
    os.chmod(root / "program.py", 0o600)
    os.chmod(root / "THIRD_PARTY_NOTICES.md", 0o600)


def _mapping_json_default(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError(f"unsupported test JSON value: {type(value).__name__}")
