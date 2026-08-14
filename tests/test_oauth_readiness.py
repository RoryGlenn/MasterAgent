"""OAuth lifecycle and deployment-readiness tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.governance import GovernanceProfile
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

    def test_enabled_profile_reports_only_variable_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oauth.toml"
            path.write_text(
                """
[profiles.graph]
enabled = true
provider = "microsoft_graph"
flow = "environment"
access_token_env = "GRAPH_TOKEN"
scopes = ["User.Read"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            profile = OAuthProfiles.from_toml(path).profile("graph")
            errors = profile.readiness_errors({})
            self.assertIn("environment variable GRAPH_TOKEN is missing", errors)
            self.assertNotIn("Bearer", " ".join(errors))


if __name__ == "__main__":
    unittest.main()
