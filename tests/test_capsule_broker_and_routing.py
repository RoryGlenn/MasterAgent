"""Credential, routing, contextual-policy, and readiness capsule tests."""

from __future__ import annotations

import unittest
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from uuid import UUID

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.capability_routing import (
    CapabilityCard,
    CapabilityRouter,
    CapabilitySession,
)
from master_agent.capsule_readiness import assess_capsule_readiness
from master_agent.capsule_runtime import CapsuleWorker
from master_agent.credential_broker import (
    CredentialBroker,
    CredentialMaterial,
    LocalJsonCredentialProvider,
    ProviderOperationBinding,
    RuntimePrincipal,
    WindowsCredentialAccount,
    WindowsCredentialManagerProvider,
    WindowsDpapiCredentialProvider,
)
from master_agent.credentials import CredentialStoreSnapshot
from master_agent.errors import AuthenticationError, ConfigurationError, ValidationError
from master_agent.governance import EnvironmentKind
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    CapabilityCapsuleExecutionBinding,
    ChangePlan,
    DataClassification,
    ExecutionContext,
    ResourceRef,
    RiskLevel,
)
from master_agent.policy import ContextualPolicyConstraints, PolicyConfig, PolicyEngine

_ACTION_ID = UUID("00000000-0000-4000-8000-000000000001")


class CapsuleBrokerAndRoutingTests(unittest.TestCase):
    """Prove exact authority, advisory routing, and production gates."""

    worker: CapsuleWorker

    @classmethod
    def setUpClass(cls) -> None:
        cls.worker = CapsuleWorker()

    def test_opaque_credential_is_account_bound_single_use_and_redacted(self) -> None:
        binding = _provider_binding()
        snapshot = CredentialStoreSnapshot(
            Path("/private/test.json"),
            {"MASTER_AGENT_JIRA_TOKEN": "super-secret-value"},
        )
        provider = LocalJsonCredentialProvider({("jira", "account-7"): snapshot})
        broker = CredentialBroker(provider)
        principal = _principal()
        operation = _operation()
        handle = broker.issue(
            capsule=binding,
            principal=principal,
            credential_name="MASTER_AGENT_JIRA_TOKEN",
            operation=operation,
        )
        self.assertNotIn("super-secret-value", repr(handle))
        self.assertNotIn(handle.token, repr(handle))
        self.assertNotIn(handle.token, str(handle.redacted_dict()))
        adapter = _ProviderAdapter()
        result = broker.invoke(
            handle=handle,
            capsule=binding,
            adapter=adapter,
            operation=operation,
            payload={"summary_sha256": "a" * 64},
        )
        self.assertEqual(result, {"status": "accepted"})
        self.assertEqual(adapter.observed_secret, "super-secret-value")
        with self.assertRaisesRegex(AuthenticationError, "reused"):
            broker.invoke(
                handle=handle,
                capsule=binding,
                adapter=adapter,
                operation=operation,
                payload={},
            )
        with self.assertRaisesRegex(AuthenticationError, "drifted"):
            broker.issue(
                capsule=binding,
                principal=replace(principal, tenant_id="attacker"),
                credential_name="MASTER_AGENT_JIRA_TOKEN",
                operation=operation,
            )

    def test_windows_native_providers_are_production_and_exact_account_bound(
        self,
    ) -> None:
        secret = "native-provider-secret-canary"
        account = WindowsCredentialAccount(
            target="MasterAgent/tests/account",
            credential_names=("MASTER_AGENT_JIRA_TOKEN",),
        )
        cases = (
            (
                WindowsCredentialManagerProvider,
                "windows-credential-manager",
                account,
            ),
            (
                WindowsDpapiCredentialProvider,
                "windows-dpapi",
                replace(account, target=r"C:\MasterAgent\credentials.bin"),
            ),
        )
        for provider_type, storage_provider, selected_account in cases:
            with self.subTest(provider=storage_provider):
                backend = Mock()
                backend.backend_id = "windows-native-test"
                backend.load_credentials.return_value = {
                    "MASTER_AGENT_JIRA_TOKEN": secret
                }
                provider = provider_type(
                    {("jira", "account-7"): selected_account},
                    backend=backend,
                )
                binding = replace(
                    _provider_binding(),
                    credential_provider_id=provider.provider_id,
                )
                broker = CredentialBroker(provider)
                handle = broker.issue(
                    capsule=binding,
                    principal=_principal(),
                    credential_name="MASTER_AGENT_JIRA_TOKEN",
                    operation=_operation(),
                )
                adapter = _ProviderAdapter()
                broker.invoke(
                    handle=handle,
                    capsule=binding,
                    adapter=adapter,
                    operation=_operation(),
                    payload={},
                )

                self.assertTrue(provider.production_ready)
                self.assertTrue(provider.healthy())
                self.assertEqual(adapter.observed_secret, secret)
                self.assertNotIn(secret, repr(provider))
                backend.load_credentials.assert_called_once_with(
                    provider=storage_provider,
                    target=selected_account.target,
                    allowed_names=("MASTER_AGENT_JIRA_TOKEN",),
                )
                with self.assertRaisesRegex(AuthenticationError, "not connected"):
                    provider.resolve(
                        principal=replace(_principal(), account_id="other-account"),
                        credential_name="MASTER_AGENT_JIRA_TOKEN",
                    )

    def test_connection_request_and_destination_constraints_bind_exact_run(
        self,
    ) -> None:
        binding = _provider_binding()
        provider = LocalJsonCredentialProvider(
            {
                ("jira", "account-7"): CredentialStoreSnapshot(
                    Path("/private/test.json"),
                    {"MASTER_AGENT_JIRA_TOKEN": "secret"},
                )
            }
        )
        broker = CredentialBroker(provider)
        request = broker.connection_request(
            run_fingerprint="9" * 64,
            capsule=binding,
            provider="jira",
            account_id="account-7",
        )
        self.assertEqual(request.to_dict()["run_fingerprint"], "9" * 64)
        self.assertEqual(len(request.fingerprint), 64)
        with self.assertRaisesRegex(AuthenticationError, "path"):
            broker.issue(
                capsule=binding,
                principal=_principal(),
                credential_name="MASTER_AGENT_JIRA_TOKEN",
                operation=_operation(path="/rest/api/3/admin"),
            )
        for unsafe_path in (
            "/rest/api/3/issue/../admin",
            "/rest/api/3/issue/%2e%2e/admin",
        ):
            with (
                self.subTest(path=unsafe_path),
                self.assertRaisesRegex(AuthenticationError, "path"),
            ):
                _operation(path=unsafe_path)

    def test_credential_handle_binds_exact_plan_action_and_destination(self) -> None:
        binding = _provider_binding()
        provider = LocalJsonCredentialProvider(
            {
                ("jira", "account-7"): CredentialStoreSnapshot(
                    Path("/private/test.json"),
                    {"MASTER_AGENT_JIRA_TOKEN": "secret"},
                )
            }
        )
        approved = _operation()
        variants = (
            replace(approved, plan_fingerprint="e" * 64),
            replace(
                approved,
                action_id=UUID("00000000-0000-4000-8000-000000000002"),
            ),
            replace(approved, origin="https://other.atlassian.net"),
            replace(approved, method="GET"),
            replace(approved, path="/rest/api/3/issue/OTHER-1"),
        )
        for attempted in variants:
            with self.subTest(attempted=attempted.to_dict()):
                broker = CredentialBroker(provider)
                handle = broker.issue(
                    capsule=binding,
                    principal=_principal(),
                    credential_name="MASTER_AGENT_JIRA_TOKEN",
                    operation=approved,
                )
                with self.assertRaisesRegex(
                    AuthenticationError,
                    "another provider operation",
                ):
                    broker.invoke(
                        handle=handle,
                        capsule=binding,
                        adapter=_ProviderAdapter(),
                        operation=attempted,
                        payload={},
                    )

    def test_credential_handle_rejects_widened_binding_and_provider_drift(self) -> None:
        binding = _provider_binding()
        provider = LocalJsonCredentialProvider(
            {
                ("jira", "account-7"): CredentialStoreSnapshot(
                    Path("/private/test.json"),
                    {"MASTER_AGENT_JIRA_TOKEN": "secret"},
                )
            }
        )
        broker = CredentialBroker(provider)
        operation = _operation()
        handle = broker.issue(
            capsule=binding,
            principal=_principal(),
            credential_name="MASTER_AGENT_JIRA_TOKEN",
            operation=operation,
        )
        widened = replace(
            binding,
            allowed_path_prefixes=("/rest/api/3",),
        )
        with self.assertRaisesRegex(AuthenticationError, "another capsule binding"):
            broker.invoke(
                handle=handle,
                capsule=widened,
                adapter=_ProviderAdapter(),
                operation=operation,
                payload={},
            )

        drifted = CredentialBroker(_DriftedProvider())
        with self.assertRaisesRegex(AuthenticationError, "another binding"):
            drifted.issue(
                capsule=replace(
                    binding,
                    credential_provider_id="drifted-provider",
                ),
                principal=_principal(),
                credential_name="MASTER_AGENT_JIRA_TOKEN",
                operation=operation,
            )

    def test_router_handles_read_write_negation_policy_and_confusable_names(
        self,
    ) -> None:
        router = CapabilityRouter()
        read = _card(
            "jira.issue.read", RiskLevel.READ_ONLY, ("read issue", "show issue")
        )
        delete = _card(
            "jira.issue.delete",
            RiskLevel.DESTRUCTIVE,
            ("delete issue", "remove issue"),
        )
        decision = router.resolve(
            "Show the issue; do not delete it",
            (read, delete),
            policy_allows=lambda _card: True,
        )
        self.assertEqual(
            [card.capability_id for card in decision.cards],
            ["jira.issue.read"],
        )
        contracted = router.resolve(
            "Show the issue; don't delete it",
            (read, delete),
            policy_allows=lambda _card: True,
        )
        self.assertEqual(
            [card.capability_id for card in contracted.cards],
            ["jira.issue.read"],
        )
        modified = router.resolve(
            "Show the issue; do not ever delete it",
            (read, delete),
            policy_allows=lambda _card: True,
        )
        self.assertEqual(
            [card.capability_id for card in modified.cards],
            ["jira.issue.read"],
        )
        emphatic = router.resolve(
            "Show the issue; do not under any circumstances ever delete it",
            (read, delete),
            policy_allows=lambda _card: True,
        )
        self.assertEqual(
            [card.capability_id for card in emphatic.cards],
            ["jira.issue.read"],
        )
        with self.assertRaisesRegex(ValidationError, "no policy-permitted"):
            router.resolve(
                "show the issue",
                (read, delete),
                policy_allows=lambda card: card.risk is RiskLevel.DESTRUCTIVE,
            )
        confusable = _card(
            "jirai.ssue.read",
            RiskLevel.READ_ONLY,
            ("read issue",),
        )
        first = _card("jira.issue.read", RiskLevel.READ_ONLY, ("read issue",))
        # Punctuation moves but the normalized alphanumeric skeleton is identical.
        second = replace(confusable, capability_id="jirai.ssue.read")
        self.assertEqual(
            _skeleton(first.capability_id), _skeleton(second.capability_id)
        )
        with self.assertRaisesRegex(ConfigurationError, "confusable"):
            router.resolve(
                "read issue",
                (first, second),
                policy_allows=lambda _card: True,
            )

    def test_active_session_blocks_unselected_versions_and_exhausted_budgets(
        self,
    ) -> None:
        now = datetime.now(UTC)
        selected = _card("jira.issue.read", RiskLevel.READ_ONLY, ("read issue",))
        session = CapabilitySession(
            plan_fingerprint="a" * 64,
            cards=(selected,),
            expires_at=now + timedelta(minutes=1),
            maximum_calls=1,
            maximum_total_bytes=1_024,
        )
        session.authorize(
            plan_fingerprint="a" * 64,
            capability_id=selected.capability_id,
            version=selected.version,
            manifest_sha256=selected.manifest_sha256,
            payload={"key": "value"},
            now=now,
        )
        with self.assertRaisesRegex(ConfigurationError, "call budget"):
            session.authorize(
                plan_fingerprint="a" * 64,
                capability_id=selected.capability_id,
                version=selected.version,
                manifest_sha256=selected.manifest_sha256,
                payload={},
                now=now,
            )
        with self.assertRaisesRegex(ConfigurationError, "outside"):
            CapabilitySession(
                plan_fingerprint="a" * 64,
                cards=(selected,),
                expires_at=now + timedelta(minutes=1),
                maximum_calls=2,
                maximum_total_bytes=1_024,
            ).authorize(
                plan_fingerprint="a" * 64,
                capability_id=selected.capability_id,
                version="2.0.0",
                manifest_sha256=selected.manifest_sha256,
                payload={},
                now=now,
            )

    def test_contextual_policy_binds_principal_account_target_budget_and_time(
        self,
    ) -> None:
        binding = _provider_binding(risk=RiskLevel.LOCAL_GENERATION)
        plan = _local_plan(binding)
        constraints = ContextualPolicyConstraints(
            authenticated_principals=frozenset({"operator:alice"}),
            agent_identities=frozenset({"master-agent:test"}),
            tenant_ids=frozenset({"tenant-4"}),
            provider_account_ids=frozenset({"account-7"}),
            resource_allowlists={"jira.synthetic.generate": ("jira:allowed-",)},
            maximum_items_per_action=8,
            maximum_bytes_per_action=1_024,
            allowed_classifications=frozenset({DataClassification.INTERNAL}),
        )
        engine = PolicyEngine(_policy_config(), contextual_constraints=constraints)
        action = plan.actions[0]
        permitted = engine.evaluate(plan, action)
        self.assertTrue(permitted.permitted, permitted.reason)
        drifted_binding = replace(binding, tenant_id="attacker")
        assert plan.execution_context is not None
        drifted = replace(
            plan,
            execution_context=replace(
                plan.execution_context,
                capsules=(drifted_binding,),
            ),
        )
        rejected = engine.evaluate(drifted, drifted.actions[0])
        self.assertFalse(rejected.permitted)
        self.assertIn("principal, tenant, or account", rejected.reason)
        relabeled_action = replace(
            action,
            data_classification=DataClassification.CONFIDENTIAL,
        )
        relabeled = replace(plan, actions=(relabeled_action,))
        classification = engine.evaluate(relabeled, relabeled_action)
        self.assertFalse(classification.permitted)
        self.assertIn("classification", classification.reason)

    def test_production_readiness_requires_all_external_controls(self) -> None:
        local_provider = LocalJsonCredentialProvider(
            {
                ("jira", "account-7"): CredentialStoreSnapshot(
                    Path("/private/test.json"),
                    {"MASTER_AGENT_JIRA_TOKEN": "secret"},
                )
            }
        )
        blocked = assess_capsule_readiness(
            environment=EnvironmentKind.PRODUCTION,
            worker=self.worker,
            credential_provider=local_provider,
            approval_control=_ProductionApprovalControl(),
            external_audit_sink=_ExternalSink(),
        )
        self.assertFalse(blocked.ready)
        self.assertTrue(any("credential provider" in error for error in blocked.errors))
        ready = assess_capsule_readiness(
            environment=EnvironmentKind.PRODUCTION,
            worker=self.worker,
            credential_provider=_ProductionProvider(),
            approval_control=_ProductionApprovalControl(),
            external_audit_sink=_ExternalSink(),
        )
        self.assertTrue(ready.ready, ready.errors)
        unhealthy = assess_capsule_readiness(
            environment=EnvironmentKind.PRODUCTION,
            worker=self.worker,
            credential_provider=_ProductionProvider(),
            approval_control=_UnhealthyApprovalControl(),
            external_audit_sink=_ExternalSink(),
        )
        self.assertFalse(unhealthy.ready)
        self.assertIn(
            "production authenticated approvals are unavailable",
            unhealthy.errors,
        )

    def test_approval_cannot_replay_after_capsule_identity_changes(self) -> None:
        binding = _provider_binding()
        plan = _write_plan(binding)
        authenticator = HmacApprovalAuthenticator(
            {
                "operator": ApprovalAuthority(
                    key_id="operator",
                    subject="alice@example.test",
                    issuer="master-agent.test",
                    tenant="tenant-4",
                    roles=("change-approver",),
                    secret=b"capsule-approval-regression-secret",
                )
            }
        )
        now = datetime.now(UTC)
        approval = authenticator.issue(
            plan=plan,
            approved_action_ids=(plan.actions[0].action_id,),
            key_id="operator",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )
        engine = PolicyEngine(_policy_config(), approval_authenticator=authenticator)
        self.assertTrue(
            engine.evaluate(
                plan, plan.actions[0], approvals=(approval,), now=now
            ).permitted
        )

        changed_binding = replace(binding, manifest_sha256="f" * 64)
        assert plan.execution_context is not None
        changed = replace(
            plan,
            execution_context=replace(
                plan.execution_context,
                capsules=(changed_binding,),
            ),
        )
        replay = engine.evaluate(
            changed,
            changed.actions[0],
            approvals=(approval,),
            now=now,
        )
        self.assertNotEqual(plan.fingerprint, changed.fingerprint)
        self.assertFalse(replay.permitted)
        self.assertTrue(replay.approval_required)


class _ProviderAdapter:
    provider = "jira"

    def __init__(self) -> None:
        self.observed_secret: str | None = None

    def invoke(
        self,
        *,
        material: CredentialMaterial,
        origin: str,
        method: str,
        path: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.observed_secret = material.reveal_to_provider()
        return {"status": "accepted"}


class _ProductionProvider:
    provider_id = "production-secret-manager"
    production_ready = True

    def healthy(self) -> bool:
        return True

    def resolve(
        self,
        *,
        principal: RuntimePrincipal,
        credential_name: str,
    ) -> CredentialMaterial:
        return CredentialMaterial(
            provider_id=self.provider_id,
            credential_name=credential_name,
            principal=principal,
            _value="production-secret",
        )


class _DriftedProvider:
    provider_id = "drifted-provider"
    production_ready = False

    def healthy(self) -> bool:
        return True

    def resolve(
        self,
        *,
        principal: RuntimePrincipal,
        credential_name: str,
    ) -> CredentialMaterial:
        return CredentialMaterial(
            provider_id=self.provider_id,
            credential_name="ANOTHER_CREDENTIAL",
            principal=principal,
            _value="wrong-secret",
        )


class _ExternalSink:
    sink_id = "external-worm-test"
    external = True
    tamper_resistant = True

    def healthy(self) -> bool:
        return True

    def append(self, receipt: Mapping[str, Any]) -> str:
        return f"worm:{receipt['receipt_id']}"


class _ProductionApprovalControl:
    control_id = "production-exact-plan-approval"
    production_ready = True

    def healthy(self) -> bool:
        return True


class _UnhealthyApprovalControl(_ProductionApprovalControl):
    def healthy(self) -> bool:
        raise RuntimeError("probe unavailable")


def _provider_binding(
    *, risk: RiskLevel = RiskLevel.REVERSIBLE_WRITE
) -> CapabilityCapsuleExecutionBinding:
    return CapabilityCapsuleExecutionBinding(
        capability_id="jira.synthetic.generate",
        version="1.0.0",
        risk=risk,
        manifest_sha256="1" * 64,
        source_sha256="2" * 64,
        artifact_sha256="3" * 64,
        dependency_lock_sha256="4" * 64,
        sbom_sha256="5" * 64,
        test_suite_sha256="6" * 64,
        validation_result_sha256="7" * 64,
        sandbox_validation_sha256="8" * 64,
        verification_contract_sha256="9" * 64,
        compensation_contract_sha256="a" * 64,
        policy_contract_sha256="b" * 64,
        worker_sha256="c" * 64,
        publisher="publisher",
        reviewer="reviewer",
        signer_key_id="publisher-key",
        authenticated_principal="operator:alice",
        agent_identity="master-agent:test",
        tenant_id="tenant-4",
        provider_account_id="account-7",
        credential_provider_id="local-json-development",
        allowed_origins=("https://example.atlassian.net",),
        allowed_methods=("POST",),
        allowed_path_prefixes=("/rest/api/3/issue",),
        credential_names=("MASTER_AGENT_JIRA_TOKEN",),
        credential_scopes=("write:jira-work",),
    )


def _principal() -> RuntimePrincipal:
    return RuntimePrincipal(
        user_id="operator:alice",
        agent_id="master-agent:test",
        tenant_id="tenant-4",
        provider="jira",
        account_id="account-7",
        scopes=("write:jira-work",),
    )


def _operation(
    *,
    plan_fingerprint: str = "f" * 64,
    action_id: UUID = _ACTION_ID,
    origin: str = "https://example.atlassian.net",
    method: str = "POST",
    path: str = "/rest/api/3/issue",
) -> ProviderOperationBinding:
    return ProviderOperationBinding(
        plan_fingerprint=plan_fingerprint,
        action_id=action_id,
        origin=origin,
        method=method,
        path=path,
    )


def _card(
    capability_id: str,
    risk: RiskLevel,
    intents: tuple[str, ...],
) -> CapabilityCard:
    return CapabilityCard(
        capability_id=capability_id,
        version="1.0.0",
        manifest_sha256="d" * 64,
        risk=risk,
        intents=intents,
        negative_intents=(),
        data_classification=DataClassification.INTERNAL,
    )


def _skeleton(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _local_plan(binding: CapabilityCapsuleExecutionBinding) -> ChangePlan:
    action = AgentAction(
        capability=binding.capability_id,
        target=ResourceRef(
            system="jira",
            resource_type="capsule_request",
            resource_id="allowed-1",
        ),
        parameters={"value": "safe"},
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="contextual:1",
        justification="Test contextual policy.",
    )
    return ChangePlan(
        goal="Test contextual constraints.",
        actions=(action,),
        created_by="test",
        execution_context=ExecutionContext(
            integrations_sha256="e" * 64,
            capsules=(binding,),
        ),
    )


def _write_plan(binding: CapabilityCapsuleExecutionBinding) -> ChangePlan:
    action = AgentAction(
        capability=binding.capability_id,
        target=ResourceRef(
            system="jira",
            resource_type="capsule_request",
            resource_id="allowed-1",
            expected_version="1",
        ),
        parameters={"value": "safe"},
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="capsule-approval:1",
        justification="Test capsule approval binding.",
    )
    return ChangePlan(
        goal="Test exact capsule approval binding.",
        actions=(action,),
        created_by="test",
        execution_context=ExecutionContext(
            integrations_sha256="e" * 64,
            capsules=(binding,),
        ),
    )


def _policy_config() -> PolicyConfig:
    return PolicyConfig(
        auto_permit_risks=frozenset({RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}),
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
    )
