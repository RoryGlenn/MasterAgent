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
from master_agent.oauth import AccessToken, InMemoryTokenCache, StaticTokenProvider
from master_agent.oauth_config import OAuthFlow, OAuthProfiles
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

    def test_safe_defaults_are_governed_but_not_connected(self) -> None:
        report = assess_readiness(
            catalog=CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml"),
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            integrations=IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
            oauth_profiles=OAuthProfiles.from_toml(ROOT / "config/oauth.toml"),
            environ={},
        )
        self.assertTrue(report.ready, report.errors)
        self.assertTrue(any("not connected" in item for item in report.warnings))
        self.assertFalse(any("principal" in item for item in report.errors))

    def test_enabled_opaque_connector_reports_missing_principal_adapter(self) -> None:
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

        rendered = "\n".join(report.errors)
        self.assertFalse(report.ready)
        self.assertIn("trusted credential-broker attestation", rendered)
        self.assertIn("no such adapter is implemented", rendered)
        self.assertNotIn("opaque-token", rendered)

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
        self.assertIn("requires an enabled connector", rendered)
        self.assertIn("identity is a placeholder", rendered)


if __name__ == "__main__":
    unittest.main()
