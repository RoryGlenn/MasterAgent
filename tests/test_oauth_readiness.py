"""OAuth lifecycle and deployment-readiness tests."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.governance import EnvironmentKind, GovernanceProfile
from master_agent.identity import IdentityRegistry
from master_agent.models import DataClassification
from master_agent.oauth import AccessToken, InMemoryTokenCache, StaticTokenProvider
from master_agent.oauth_config import OAuthFlow, OAuthProfiles
from master_agent.provider_egress import (
    ModelContextRule,
    ProviderDataEgressPolicy,
    ProviderDataHandling,
    ProviderDataRoute,
)
from master_agent.readiness import assess_readiness

ROOT = Path(__file__).resolve().parents[1]


class OAuthReadinessTests(unittest.TestCase):
    """Exercise safe token lifecycle and readiness reporting."""

    def test_profiles_load_disabled_without_credentials(self) -> None:
        profiles = OAuthProfiles.from_toml(ROOT / "config/oauth.toml")
        self.assertEqual(
            profiles.profile("microsoft_delegated").flow,
            OAuthFlow.ENTRA_DEVICE_CODE,
        )
        self.assertFalse(profiles.profile("microsoft_delegated").enabled)
        self.assertIn("Notes.Read", profiles.profile("microsoft_delegated").scopes)
        self.assertNotIn(
            "Notes.ReadWrite",
            profiles.profile("microsoft_reversible_writes").scopes,
        )
        rendered = repr(profiles)
        self.assertNotIn("client-secret", rendered)

    def test_live_microsoft_profiles_are_disabled_exact_delegated_grants(
        self,
    ) -> None:
        profiles = OAuthProfiles.from_toml(ROOT / "config/oauth.toml")
        expected_scopes = {
            "microsoft_integration_read": (
                "User.Read",
                "Mail.Read",
                "Chat.Read",
                "Sites.Read.All",
                "Notes.Read",
            ),
            "microsoft_integration_effects": (
                "User.Read",
                "Sites.ReadWrite.All",
                "Mail.ReadWrite",
                "Mail.Send",
                "Chat.Read",
                "ChatMessage.Send",
            ),
        }

        for name, scopes in expected_scopes.items():
            with self.subTest(profile=name):
                profile = profiles.profile(name)
                self.assertFalse(profile.enabled)
                self.assertEqual(profile.flow, OAuthFlow.ENTRA_DEVICE_CODE)
                self.assertEqual(profile.metadata["identity_mode"], "delegated")
                self.assertEqual(profile.scopes, scopes)

    def test_in_memory_cache_reuses_valid_token(self) -> None:
        token = AccessToken(
            value="secret-token",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scopes=("User.Read",),
            source="test",
        )
        cache = InMemoryTokenCache(StaticTokenProvider(token))
        self.assertIs(cache.get_token(), cache.get_token())
        self.assertNotIn("secret-token", repr(token))

    def test_safe_defaults_are_available_but_not_connected(self) -> None:
        report = assess_readiness(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            integrations=IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
            oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
            environ={},
        )
        self.assertTrue(report.ready, report.errors)
        self.assertTrue(
            any("available but inactive" in item for item in report.warnings)
        )
        self.assertFalse(any("principal" in item for item in report.errors))

    def test_ordinary_readiness_does_not_require_provider_egress_policy(self) -> None:
        governance = replace(
            GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            model_context=None,
        )
        report = assess_readiness(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=governance,
            integrations=IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
            oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
            environ={},
        )

        self.assertTrue(report.ready, report.errors)
        self.assertFalse(
            any(check["name"] == "model_context_policy" for check in report.checks)
        )

    def test_microsoft_delegated_principal_adapter_is_ready_without_network(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "oauth_delegated"
oauth_flow = "environment"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
credential_identity = "tenant-a:claimed-user"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
                governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
                integrations=IntegrationConfig.from_toml(path),
                oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
                environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "opaque-token"},
            )

        connector_check = next(
            check for check in report.checks if check["name"] == "connector:microsoft"
        )
        self.assertTrue(report.ready, report.errors)
        self.assertEqual(
            connector_check["principal_attestation"],
            "microsoft_delegated_user",
        )
        self.assertNotIn("opaque-token", str(report.to_dict()))

    def test_github_provider_attestation_adapter_is_ready_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GITHUB_TOKEN"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
                governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
                integrations=IntegrationConfig.from_toml(path),
                oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
                environ={"MASTER_AGENT_GITHUB_TOKEN": "opaque-token"},
            )

        connector_check = next(
            check for check in report.checks if check["name"] == "connector:github"
        )
        self.assertTrue(report.ready, report.errors)
        self.assertTrue(connector_check["passed"])
        self.assertEqual(
            connector_check["principal_attestation"],
            "github_authenticated_user",
        )
        self.assertNotIn("opaque-token", str(report.to_dict()))

    def test_selected_internal_provider_egress_is_ready_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "none"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
                governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
                integrations=IntegrationConfig.from_toml(path),
                oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
                environ={},
                egress_checks=(("jira", DataClassification.INTERNAL),),
            )

        check = next(
            item
            for item in report.checks
            if item["name"] == "provider_data_egress:jira:internal"
        )
        self.assertTrue(report.ready, report.errors)
        self.assertTrue(check["passed"])
        self.assertTrue(check["ephemeral_allowed"])
        self.assertEqual(check["destination"], "local-operator-or-approved-agent")

    def test_selected_confidential_provider_egress_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "none"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
                governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
                integrations=IntegrationConfig.from_toml(path),
                oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
                environ={},
                egress_checks=(("jira", DataClassification.CONFIDENTIAL),),
            )

        check = next(
            item
            for item in report.checks
            if item["name"] == "provider_data_egress:jira:confidential"
        )
        self.assertFalse(report.ready)
        self.assertFalse(check["passed"])
        self.assertIn("denies provider data", check["reason"])

    def test_denied_egress_does_not_inspect_environment_or_tokens(self) -> None:
        class TrackingEnvironment(dict[str, str]):
            def __init__(self) -> None:
                super().__init__({"MASTER_AGENT_GITHUB_TOKEN": "secret-canary"})
                self.reads: list[str] = []

            def get(self, key: str, default: str | None = None) -> str | None:
                self.reads.append(key)
                return super().get(key, default)

        class ForbiddenTokens(dict[str, AccessToken]):
            def items(self) -> object:
                raise AssertionError("denied readiness must not inspect tokens")

        environ = TrackingEnvironment()
        report = assess_readiness(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            integrations=IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
            oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
            environ=environ,
            tokens=ForbiddenTokens(),
            egress_checks=(("github", DataClassification.CONFIDENTIAL),),
        )

        self.assertFalse(report.ready)
        self.assertEqual(environ.reads, [])

    def test_selected_egress_requires_ready_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GITHUB_TOKEN"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
                governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
                integrations=IntegrationConfig.from_toml(path),
                oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
                environ={},
                egress_checks=(("github", DataClassification.INTERNAL),),
            )

        check = next(
            item
            for item in report.checks
            if item["name"] == "provider_data_egress:github:internal"
        )
        self.assertFalse(report.ready)
        self.assertFalse(check["credential_ready"])
        self.assertIn("MASTER_AGENT_GITHUB_TOKEN", check["reason"])

    def test_selected_egress_recognizes_narrow_probe_contract(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        governance = replace(
            governance,
            model_context=ProviderDataEgressPolicy(
                destination="approved-agent",
                model_tenancy="approved-tenant",
                source_data_environment="nonproduction",
                dlp_adapter="none",
                development_default_classification=DataClassification.INTERNAL,
                rules=(
                    ModelContextRule(
                        name="jira-probe-only",
                        providers=("jira",),
                        capabilities=("jira.connection.probe",),
                        data_classifications=frozenset({DataClassification.INTERNAL}),
                        destinations=frozenset({"approved-agent"}),
                        model_tenancies=frozenset({"approved-tenant"}),
                        routes=frozenset({ProviderDataRoute.EPHEMERAL}),
                        handling=ProviderDataHandling.ALLOW,
                        audit_required=False,
                        dlp_required=False,
                        redacted_fields=frozenset(),
                        allowed_fields=frozenset({"*"}),
                        max_items=1,
                        max_output_bytes=4096,
                    ),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "none"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            report = assess_readiness(
                catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
                governance=governance,
                integrations=IntegrationConfig.from_toml(path),
                oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
                environ={},
                egress_checks=(("jira", DataClassification.INTERNAL),),
            )

        check = next(
            item
            for item in report.checks
            if item["name"] == "provider_data_egress:jira:internal"
        )
        self.assertTrue(check["passed"], report.errors)
        self.assertEqual(check["approved_capabilities"], ["jira.connection.probe"])

    def test_enabled_profile_reports_only_variable_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oauth.toml"
            path.write_text(
                """
[profiles.graph]
enabled = true
provider = "microsoft_graph"
flow = "environment"
access_token_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
scopes = ["User.Read"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            profile = OAuthProfiles.from_toml(path).profile("graph")
            errors = profile.readiness_errors({})
            self.assertIn(
                "environment variable MASTER_AGENT_GRAPH_ACCESS_TOKEN is missing",
                errors,
            )
            self.assertNotIn("Bearer", " ".join(errors))

    def test_production_rejects_named_but_unimplemented_audit_sink(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        governance = replace(
            governance,
            environment=EnvironmentKind.PRODUCTION,
            audit_sink="fictional-external-sink",
            metadata={**dict(governance.metadata), "production_approved": True},
        )

        report = assess_readiness(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=governance,
            integrations=IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
            oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
            environ={},
        )

        self.assertFalse(report.ready)
        self.assertTrue(
            any("no implemented typed adapter" in error for error in report.errors)
        )
        self.assertTrue(
            any("requires an implemented external" in error for error in report.errors)
        )

    def test_non_development_rejects_packaged_placeholder_facts(self) -> None:
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")
        governance = replace(
            governance,
            environment=EnvironmentKind.NON_PRODUCTION,
        )

        report = assess_readiness(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=governance,
            integrations=IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
            oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
            identities=IdentityRegistry.from_toml(ROOT / "config/identities.toml"),
            environ={},
        )

        rendered = "\n".join(report.errors)
        self.assertFalse(report.ready)
        self.assertIn("organization must not be a placeholder", rendered)
        self.assertNotIn("requires an enabled connector", rendered)
        self.assertIn("identity is a placeholder", rendered)


if __name__ == "__main__":
    unittest.main()
