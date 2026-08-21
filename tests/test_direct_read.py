"""Focused tests for the stateless typed-provider direct read route."""

from __future__ import annotations

import unittest
from dataclasses import replace
from types import SimpleNamespace

from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.connectors.mock import MockConnector
from master_agent.connectors.read_only import ReadOnlyConnector, RetrievedPayload
from master_agent.direct_read import DirectReadSession, preflight_direct_read_plan
from master_agent.errors import (
    ConfigurationError,
    ConnectorHttpError,
    VerificationError,
)
from master_agent.governance import (
    ApprovalTier,
    EnvironmentKind,
    GovernanceProfile,
    GovernanceRule,
)
from master_agent.http import SafeHttpClient
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    CapabilityCapsuleExecutionBinding,
    ChangePlan,
    ConnectorExecutionBinding,
    DataClassification,
    ExecutionContext,
    PluginExecutionBinding,
    ResourceRef,
    RiskLevel,
)
from master_agent.policy import PolicyConfig, PolicyEngine
from tests.fakes import ExpectedRequest, QueueTransport

_CAPABILITY = "provider.item.read"
_CONFIG_IDENTITY = "a" * 64
_INTEGRATIONS_IDENTITY = "b" * 64
_BASE_URL = "https://provider.example.test/v1"


class _ReadConnector(ReadOnlyConnector):
    """Small typed connector whose reads exercise the HTTP lifecycle budget."""

    def __init__(self, transport: QueueTransport, *, max_pages: int = 4) -> None:
        super().__init__(system="provider", capabilities=frozenset({_CAPABILITY}))
        self._config = SimpleNamespace(
            auth=SimpleNamespace(mode="bearer"),
            config_identity=_CONFIG_IDENTITY,
            base_url=_BASE_URL,
            max_pages=max_pages,
            max_response_bytes=4096,
            ca_bundle=None,
            ca_bundle_sha256=None,
        )
        self._client = SafeHttpClient(
            base_url=_BASE_URL,
            transport=transport,
            retry_attempts=0,
        )

    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        payload, response = self._client.request_json(
            "GET",
            f"items/{action.target.resource_id}",
        )
        if not isinstance(payload, dict):
            raise TypeError("test provider payload must be an object")
        return RetrievedPayload(
            data={"item": payload},
            connector_reference=response.url,
        )


class _RejectingSources(SourceOfTruthRegistry):
    """Test source registry which proves validation occurs before dispatch."""

    def validate(
        self,
        plan: ChangePlan,
        action: AgentAction,
    ) -> tuple[bool, str]:
        del plan, action
        return False, "source-of-truth test rejection"


class DirectReadSessionTests(unittest.TestCase):
    """Prove direct reads retain controls while avoiding persistent runtime state."""

    def test_no_io_preflight_validates_before_connector_construction(self) -> None:
        self.assertEqual(
            preflight_direct_read_plan(
                plan=_plan(_action("one")),
                catalog=_catalog(),
                governance=_governance(),
                policy=_policy(),
                sources=SourceOfTruthRegistry(()),
            ),
            "provider",
        )

        with self.assertRaisesRegex(ConfigurationError, "direct-user"):
            preflight_direct_read_plan(
                plan=_plan(
                    replace(
                        _action("one"),
                        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
                    )
                ),
                catalog=_catalog(),
                governance=_governance(),
                policy=_policy(),
                sources=SourceOfTruthRegistry(()),
            )

    def test_executes_each_one_provider_read_and_returns_typed_payloads(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/items/one", {"name": "one"}),
            ExpectedRequest("GET", "/items/one", {"name": "one"}),
            ExpectedRequest("GET", "/items/two", {"name": "two"}),
            ExpectedRequest("GET", "/items/two", {"name": "two"}),
        )
        report = self._session(transport).execute(_plan(_action("one"), _action("two")))

        self.assertTrue(report.successful)
        self.assertEqual(report.provider, "provider")
        self.assertEqual(len(report.actions), 2)
        self.assertEqual(report.payloads[0].data["item"]["name"], "one")
        self.assertEqual(report.payloads[1].data["item"]["name"], "two")
        self.assertTrue(report.actions[0].verification.verified)
        self.assertIn("security", report.payloads[0].data)
        self.assertEqual(
            report.to_dict()["schema"], "master-agent/direct-read-report@1"
        )
        transport.assert_drained()

    def test_preflight_rejects_non_read_before_any_provider_request(self) -> None:
        transport = QueueTransport()
        invalid = replace(_action("two"), risk=RiskLevel.REVERSIBLE_WRITE)

        with self.assertRaisesRegex(ConfigurationError, "read-only"):
            self._session(transport).execute(_plan(_action("one"), invalid))

        self.assertEqual(transport.requests, [])

    def test_preflight_rejects_non_direct_authority_before_any_provider_request(
        self,
    ) -> None:
        transport = QueueTransport()
        invalid = replace(
            _action("one"),
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        )

        with self.assertRaisesRegex(ConfigurationError, "direct-user"):
            self._session(transport).execute(_plan(invalid))

        self.assertEqual(transport.requests, [])

    def test_preflight_rejects_cross_provider_before_any_provider_request(self) -> None:
        transport = QueueTransport()
        other = replace(
            _action("two"),
            target=ResourceRef("other", "item", "two"),
            capability="other.item.read",
        )

        with self.assertRaisesRegex(ConfigurationError, "exactly one provider"):
            self._session(transport).execute(_plan(_action("one"), other))

        self.assertEqual(transport.requests, [])

    def test_rejects_persisted_execution_context_plugins_and_capsules(self) -> None:
        transport = QueueTransport()
        plugin_context = ExecutionContext(
            integrations_sha256=_INTEGRATIONS_IDENTITY,
            plugins=(
                PluginExecutionBinding(
                    name="untrusted-provider",
                    group="master_agent.connectors",
                    entry_point="untrusted:connector",
                    distribution="untrusted-provider",
                    distribution_version="1.0.0",
                    artifact_sha256="c" * 64,
                    identity_sha256="d" * 64,
                ),
            ),
        )
        plugin_plan = replace(_plan(_action("one")), execution_context=plugin_context)

        with self.assertRaisesRegex(ConfigurationError, "plugins"):
            self._session(transport).execute(plugin_plan)

        capsule_context = ExecutionContext(
            integrations_sha256=_INTEGRATIONS_IDENTITY,
            capsules=(_capsule_binding(),),
        )
        capsule_plan = replace(
            _plan(_action("two")),
            execution_context=capsule_context,
        )
        with self.assertRaisesRegex(ConfigurationError, "capsules"):
            self._session(transport).execute(capsule_plan)

        self.assertEqual(transport.requests, [])

    def test_requires_a_typed_read_only_connector(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "ReadOnlyConnector"):
            DirectReadSession(
                catalog=_catalog(),
                governance=_governance(),
                policy=_policy(),
                sources=SourceOfTruthRegistry(()),
                connector=MockConnector("provider", capabilities={_CAPABILITY}),  # type: ignore[arg-type]
                execution_binding=_binding(),
            )

    def test_validates_catalog_policy_source_and_execution_binding_preflight(
        self,
    ) -> None:
        transport = QueueTransport()
        action = _action("one")
        disabled_catalog = CapabilityCatalog(
            {
                _CAPABILITY: replace(
                    _catalog().definition(_CAPABILITY),
                    enabled=False,
                )
            }
        )
        with self.assertRaisesRegex(ConfigurationError, "disabled"):
            self._session(transport, catalog=disabled_catalog).execute(_plan(action))

        approval_policy = PolicyEngine(
            PolicyConfig(
                auto_permit_risks=frozenset(),
                require_approval_risks=frozenset({RiskLevel.READ_ONLY}),
                prohibit_risks=frozenset(),
                prohibited_capabilities=(),
                write_capability_patterns=("*.update",),
            )
        )
        with self.assertRaisesRegex(ConfigurationError, "approval"):
            self._session(transport, policy=approval_policy).execute(_plan(action))

        with self.assertRaisesRegex(ConfigurationError, "source-of-truth"):
            self._session(transport, sources=_RejectingSources(())).execute(
                _plan(action)
            )

        with self.assertRaisesRegex(ConfigurationError, "credential scopes"):
            self._session(
                transport,
                execution_binding=replace(_binding(), credential_scopes=()),
            ).execute(_plan(action))

        self.assertEqual(transport.requests, [])

    def test_execute_and_verify_share_one_http_budget(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/items/one", {"name": "one"}),
            ExpectedRequest("GET", "/items/one", {"name": "one"}),
        )

        with self.assertRaisesRegex(ConnectorHttpError, "request/page budget"):
            self._session(transport, max_pages=1).execute(_plan(_action("one")))

        self.assertEqual(len(transport.requests), 1)

    def test_does_not_return_payload_when_independent_verification_fails(self) -> None:
        transport = QueueTransport(
            ExpectedRequest("GET", "/items/one", {"name": "one"}),
            ExpectedRequest("GET", "/items/one", {"name": "changed"}),
        )

        with self.assertRaisesRegex(VerificationError, "did not independently verify"):
            self._session(transport).execute(_plan(_action("one")))

        transport.assert_drained()

    def _session(
        self,
        transport: QueueTransport,
        *,
        catalog: CapabilityCatalog | None = None,
        governance: GovernanceProfile | None = None,
        policy: PolicyEngine | None = None,
        sources: SourceOfTruthRegistry | None = None,
        execution_binding: ConnectorExecutionBinding | None = None,
        max_pages: int = 4,
    ) -> DirectReadSession:
        return DirectReadSession(
            catalog=catalog or _catalog(),
            governance=governance or _governance(),
            policy=policy or _policy(),
            sources=sources or SourceOfTruthRegistry(()),
            connector=_ReadConnector(transport, max_pages=max_pages),
            execution_binding=execution_binding or _binding(),
        )


def _catalog() -> CapabilityCatalog:
    return CapabilityCatalog(
        {
            _CAPABILITY: CapabilityDefinition(
                name=_CAPABILITY,
                enabled=True,
                authentication="configured_connector",
                risk=RiskLevel.READ_ONLY,
                required_scopes=("items:read",),
                target_system="provider",
                target_resource_types=("item",),
            )
        }
    )


def _governance() -> GovernanceProfile:
    return GovernanceProfile(
        organization="test-organization",
        environment=EnvironmentKind.DEVELOPMENT,
        secret_manager="test-secret-manager",
        audit_sink="not-used-by-direct-read",
        external_model_policy="test-policy",
        rules=(
            GovernanceRule(
                pattern=_CAPABILITY,
                owner="provider-owner",
                authentication="configured_connector",
                data_classifications=frozenset({DataClassification.INTERNAL}),
                approval_tier=ApprovalTier.AUTOMATIC,
                environments=frozenset({EnvironmentKind.DEVELOPMENT}),
            ),
        ),
        metadata={"allow_ephemeral_direct_reads": True},
    )


def _policy() -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig(
            auto_permit_risks=frozenset({RiskLevel.READ_ONLY}),
            require_approval_risks=frozenset(),
            prohibit_risks=frozenset(),
            prohibited_capabilities=(),
            write_capability_patterns=("*.update",),
        )
    )


def _binding() -> ConnectorExecutionBinding:
    return ConnectorExecutionBinding(
        system="provider",
        deployment="cloud",
        config_identity_sha256=_CONFIG_IDENTITY,
        resolved_base_url=_BASE_URL,
        resolved_origin="https://provider.example.test",
        authentication_mode="bearer",
        credential_identity="provider:user:1",
        credential_scopes=("items:read",),
    )


def _capsule_binding() -> CapabilityCapsuleExecutionBinding:
    digest = "e" * 64
    return CapabilityCapsuleExecutionBinding(
        capability_id=_CAPABILITY,
        version="1.0.0",
        risk=RiskLevel.READ_ONLY,
        manifest_sha256=digest,
        source_sha256=digest,
        artifact_sha256=digest,
        dependency_lock_sha256=digest,
        sbom_sha256=digest,
        test_suite_sha256=digest,
        validation_result_sha256=digest,
        sandbox_validation_sha256=digest,
        verification_contract_sha256=digest,
        compensation_contract_sha256=digest,
        policy_contract_sha256=digest,
        worker_sha256=digest,
        publisher="test-publisher",
        reviewer="test-reviewer",
        signer_key_id="test-signer",
    )


def _action(resource_id: str) -> AgentAction:
    return AgentAction(
        capability=_CAPABILITY,
        target=ResourceRef("provider", "item", resource_id),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"provider:read:{resource_id}",
        justification="Read the directly requested provider resource.",
        data_classification=DataClassification.INTERNAL,
    )


def _plan(*actions: AgentAction) -> ChangePlan:
    return ChangePlan(
        goal="Read directly requested provider resources.",
        actions=actions,
        created_by="direct-user",
    )


if __name__ == "__main__":
    unittest.main()
