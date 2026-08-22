"""Capability catalog, governance, and multi-approval tests."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConfigurationError
from master_agent.governance import ApprovalTier, GovernanceProfile
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.policy import PolicyConfig, PolicyEngine

ROOT = Path(__file__).resolve().parents[1]


class CapabilityGovernanceTests(unittest.TestCase):
    """Validate fail-closed capability and governance behavior."""

    def test_repository_catalog_has_governance_coverage(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        report = governance.coverage_report(catalog)
        self.assertTrue(report["ready"], report["errors"])
        self.assertGreater(len(report["covered"]), 20)

    def test_direct_read_session_requires_explicit_governance_opt_in(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        action = AgentAction(
            capability="github.repository.list",
            target=ResourceRef("github", "repository_collection", "me"),
            parameters={"limit": 10, "visibility": "all"},
            risk=RiskLevel.READ_ONLY,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="direct-read-governance",
            justification="List repositories visible to the requesting user.",
        )
        plan = ChangePlan(
            goal="List the repositories visible to me.",
            actions=(action,),
            created_by="direct-user",
        )

        allowed, reason = governance.allows_direct_read_session(plan)
        self.assertTrue(allowed, reason)

        disabled = replace(
            governance,
            metadata={
                **dict(governance.metadata),
                "allow_ephemeral_direct_reads": False,
            },
        )
        allowed, reason = disabled.allows_direct_read_session(plan)
        self.assertFalse(allowed)
        self.assertIn("disables", reason)

        malformed = replace(
            governance,
            metadata={
                **dict(governance.metadata),
                "allow_ephemeral_direct_reads": "true",
            },
        )
        allowed, reason = malformed.allows_direct_read_session(plan)
        self.assertFalse(allowed)
        self.assertIn("boolean", reason)

    def test_disabled_capability_is_rejected(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        action = AgentAction(
            capability="bitbucket.pull_request.merge",
            target=ResourceRef("bitbucket", "pull_request", "9"),
            parameters={"destination": "main"},
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="merge-disabled",
            justification="test",
        )
        allowed, reason = catalog.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("disabled", reason)

    def test_enabled_modifier_requires_declared_provider_precondition(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "provider_precondition"):
            CapabilityDefinition(
                name="example.item.update",
                enabled=True,
                authentication="configured_connector",
                risk=RiskLevel.REVERSIBLE_WRITE,
                reversible=True,
                requires_expected_version=True,
                target_resource_types=("item",),
                parameter_schema={"value": "string"},
            )

    def test_target_and_parameter_schema_are_enforced_before_policy(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        action = AgentAction(
            capability="github.issue.create",
            target=ResourceRef("github", "issue", "new"),
            parameters={
                "owner": "RoryGlenn",
                "repository": "MasterAgent",
                "title": "Safety regression",
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="schema-contract",
            justification="test executable capability schema",
        )

        allowed, reason = catalog.validate_action(action)
        self.assertTrue(allowed, reason)

        wrong_type = replace(
            action,
            target=ResourceRef("github", "repository", "new"),
        )
        allowed, reason = catalog.validate_action(wrong_type)
        self.assertFalse(allowed)
        self.assertIn("resource type", reason)

        unknown_parameter = replace(
            action,
            parameters={**dict(action.parameters), "assumed_permission": "admin"},
        )
        allowed, reason = catalog.validate_action(unknown_parameter)
        self.assertFalse(allowed)
        self.assertIn("unexpected parameters", reason)

    def test_effective_identity_authentication_and_scopes_are_enforced(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        action = AgentAction(
            capability="outlook.email.send",
            target=ResourceRef("outlook", "message", "new"),
            parameters={
                "to": ["operator@example.test"],
                "subject": "Reviewed",
                "body": "Exact approved content",
            },
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="effective-scope-contract",
            justification="test effective OAuth authority",
        )
        connector = MockConnector("outlook", capabilities={action.capability})
        connector._config = SimpleNamespace(  # type: ignore[attr-defined]
            auth=SimpleNamespace(mode="oauth_delegated"),
            config_identity="a" * 64,
            base_url="https://graph.microsoft.com/v1.0",
            ca_bundle=None,
            ca_bundle_sha256=None,
        )
        binding = ConnectorExecutionBinding(
            system="microsoft",
            deployment="cloud",
            config_identity_sha256="a" * 64,
            resolved_base_url="https://graph.microsoft.com/v1.0",
            resolved_origin="https://graph.microsoft.com",
            authentication_mode="oauth_delegated",
            credential_identity="microsoft:user:42",
            credential_scopes=("Mail.ReadWrite", "Mail.Send"),
        )

        allowed, reason = catalog.validate_execution(
            action,
            connector,
            binding,
            connector_mode="live",
        )
        self.assertTrue(allowed, reason)

        allowed, reason = catalog.validate_execution(
            action,
            connector,
            replace(binding, credential_scopes=("Mail.ReadWrite",)),
            connector_mode="live",
        )
        self.assertFalse(allowed)
        self.assertIn("Mail.Send", reason)

        allowed, reason = catalog.validate_execution(
            action,
            connector,
            replace(binding, authentication_mode="bearer"),
            connector_mode="live",
        )
        self.assertFalse(allowed)
        self.assertIn("authentication", reason)

        allowed, reason = catalog.validate_execution(
            action,
            connector,
            replace(binding, credential_identity=None),
            connector_mode="live",
        )
        self.assertFalse(allowed)
        self.assertIn("identity", reason)

        connector._config.base_url = "https://evil.example/exfil"
        allowed, reason = catalog.validate_execution(
            action,
            connector,
            binding,
            connector_mode="live",
        )
        self.assertFalse(allowed)
        self.assertIn("endpoint drifted", reason)
        connector._config.base_url = binding.resolved_base_url

        connector._config.ca_bundle = Path("/tmp/unapproved-ca.pem")
        connector._config.ca_bundle_sha256 = "b" * 64
        allowed, reason = catalog.validate_execution(
            action,
            connector,
            binding,
            connector_mode="live",
        )
        self.assertFalse(allowed)
        self.assertIn("CA identity drifted", reason)

    def test_reversible_metadata_requires_a_compensating_connector(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        action = AgentAction(
            capability="github.issue.create",
            target=ResourceRef("github", "issue", "new"),
            parameters={
                "owner": "RoryGlenn",
                "repository": "MasterAgent",
                "title": "Reviewed",
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="reversibility-contract",
            justification="test reversible connector enforcement",
        )
        binding = ConnectorExecutionBinding(
            system="github",
            deployment="cloud",
            config_identity_sha256="a" * 64,
            resolved_base_url="https://api.github.com",
            resolved_origin="https://api.github.com",
            authentication_mode="bearer",
            credential_identity="github:user:42",
        )

        connector = MockConnector("github", capabilities={action.capability})
        connector._config = SimpleNamespace(  # type: ignore[attr-defined]
            auth=SimpleNamespace(mode="bearer"),
            config_identity="a" * 64,
            base_url="https://api.github.com",
            ca_bundle=None,
            ca_bundle_sha256=None,
        )
        allowed, reason = catalog.validate_execution(
            action,
            connector,
            binding,
            connector_mode="live",
        )

        self.assertFalse(allowed)
        self.assertIn("compensation", reason)

    def test_external_model_policy_requires_an_explicit_classification(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        definition = CapabilityDefinition(
            name="example.summary.generate",
            enabled=True,
            authentication="local",
            risk=RiskLevel.LOCAL_GENERATION,
            target_resource_types=("summary",),
            parameter_schema={"body": "string"},
            max_input_bytes=1024,
            max_output_bytes=1024,
            uses_external_model=True,
        )
        action = AgentAction(
            capability=definition.name,
            target=ResourceRef("example", "summary", "1"),
            parameters={"body": "internal material"},
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="external-model-boundary",
            justification="test external model policy",
        )

        allowed, reason = governance.validate_external_model(action, definition)
        self.assertFalse(allowed)
        self.assertIn("does not approve", reason)

        approved = replace(
            governance,
            metadata={
                **dict(governance.metadata),
                "external_model_approved_classifications": ["internal"],
            },
        )
        allowed, reason = approved.validate_external_model(action, definition)
        self.assertTrue(allowed, reason)

    def test_onenote_writes_are_disabled_by_catalog_and_governance(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        for capability in ("onenote.page.create", "onenote.page.update"):
            with self.subTest(capability=capability):
                definition = catalog.definitions[capability]
                rule = governance.rule_for(capability)
                self.assertFalse(definition.enabled)
                self.assertIsNotNone(rule)
                assert rule is not None
                self.assertFalse(rule.enabled)
                self.assertEqual(rule.pattern, capability)

    def test_local_git_mutations_are_disabled_by_catalog_and_governance(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        for capability in (
            "bitbucket.branch.push",
            "repository.branch.create",
            "repository.branch.push",
            "repository.commit.create",
            "repository.patch.apply",
        ):
            with self.subTest(capability=capability):
                definition = catalog.definitions[capability]
                rule = governance.rule_for(capability)
                self.assertFalse(definition.enabled)
                self.assertIsNotNone(rule)
                assert rule is not None
                self.assertFalse(rule.enabled)
                self.assertEqual(rule.approval_tier, ApprovalTier.PROHIBITED)
                self.assertEqual(rule.pattern, capability)

    def test_standalone_git_restore_has_no_execution_or_governance_route(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")

        self.assertNotIn("repository.worktree.restore", catalog.definitions)
        rule = governance.rule_for("repository.worktree.restore")
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertFalse(rule.enabled)
        self.assertEqual(rule.pattern, "*")

    def test_version_and_classification_contracts_fail_closed(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        action = AgentAction(
            capability="confluence.page.update",
            target=ResourceRef("confluence", "page", "42"),
            parameters={"title": "Status", "body": "changed"},
            risk=RiskLevel.REVERSIBLE_WRITE,
            data_classification=DataClassification.RESTRICTED,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="version-classification",
            justification="test",
        )

        allowed, reason = catalog.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("expected_version", reason)
        allowed, reason = governance.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("classification", reason)

    def test_dual_governance_requires_two_distinct_approvers(self) -> None:
        authenticator = HmacApprovalAuthenticator(
            {
                name: ApprovalAuthority(
                    key_id=name,
                    subject=name,
                    issuer="master-agent.test",
                    tenant="test-tenant",
                    roles=("change-approver",),
                    secret=(f"{name}-approval-secret-" + "x" * 32).encode(),
                )
                for name in ("alice", "bob")
            }
        )
        policy = PolicyEngine(
            PolicyConfig.from_toml(ROOT / "config/policy.toml"),
            approval_authenticator=authenticator,
        )
        action = AgentAction(
            capability="example.high_impact",
            target=ResourceRef("example", "resource", "1"),
            parameters={},
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="dual-test",
            justification="test",
        )
        plan = ChangePlan(
            goal="dual approval test", actions=(action,), created_by="test"
        )
        now = datetime.now(UTC)

        def approval(name: str):
            return authenticator.issue(
                plan=plan,
                approved_action_ids=(action.action_id,),
                key_id=name,
                issued_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(minutes=10),
            )

        one = policy.evaluate(
            plan,
            action,
            approvals=(approval("alice"),),
            now=now,
            minimum_distinct_approvers=2,
        )
        self.assertFalse(one.permitted)
        two = policy.evaluate(
            plan,
            action,
            approvals=(approval("alice"), approval("bob")),
            now=now,
            minimum_distinct_approvers=2,
        )
        self.assertTrue(two.permitted)

    def test_governance_specific_rule_beats_catch_all(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        self.assertEqual(
            governance.approval_tier_for("outlook.email.send"),
            ApprovalTier.SINGLE,
        )
        self.assertEqual(
            governance.approval_tier_for("repository.permission.change"),
            ApprovalTier.PROHIBITED,
        )
        for capability in (
            "github.repository.settings.update",
            "github.collaborator.access.update",
        ):
            with self.subTest(capability=capability):
                self.assertEqual(
                    governance.approval_tier_for(capability),
                    ApprovalTier.PROHIBITED,
                )

    def test_github_admin_mutations_without_provider_cas_are_disabled(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        action = AgentAction(
            capability="github.collaborator.access.update",
            target=ResourceRef("github", "collaborator", "RoryGlenn/alice"),
            parameters={
                "owner": "RoryGlenn",
                "repository": "MasterAgent",
                "username": "alice",
                "role": "push",
            },
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="github-existing-collaborator-role",
            justification="test typed access administration",
        )

        allowed, reason = catalog.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("disabled", reason)
        allowed, reason = governance.validate_action(action)
        self.assertFalse(allowed)
        self.assertIn("disables", reason)

    def test_read_check_write_mutations_are_disabled_without_provider_cas(
        self,
    ) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        for capability in (
            "github.repository.settings.update",
            "github.collaborator.access.update",
            "jira.issue.update",
            "jira.issue.transition",
            "jira.issue.compensate",
            "sharepoint.file.upload",
        ):
            with self.subTest(capability=capability):
                self.assertFalse(catalog.definitions[capability].enabled)
                rule = governance.rule_for(capability)
                self.assertIsNotNone(rule)
                assert rule is not None
                self.assertFalse(rule.enabled)
                self.assertEqual(rule.approval_tier, ApprovalTier.PROHIBITED)

    def test_governance_minimum_forces_approval_even_if_risk_is_auto_permitted(
        self,
    ) -> None:
        action = AgentAction(
            capability="example.high_impact",
            target=ResourceRef("example", "resource", "1"),
            parameters={},
            risk=RiskLevel.HIGH_IMPACT,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="governance-forces-approval",
            justification="test",
        )
        plan = ChangePlan(
            goal="governance approval", actions=(action,), created_by="test"
        )
        policy = PolicyEngine(
            PolicyConfig(
                auto_permit_risks=frozenset({RiskLevel.HIGH_IMPACT}),
                require_approval_risks=frozenset(),
                prohibit_risks=frozenset(),
                prohibited_capabilities=(),
                write_capability_patterns=(),
            )
        )

        decision = policy.evaluate(
            plan,
            action,
            minimum_distinct_approvers=2,
        )

        self.assertFalse(decision.permitted)
        self.assertTrue(decision.approval_required)
        self.assertIn("2 distinct", decision.reason)


if __name__ == "__main__":
    unittest.main()
