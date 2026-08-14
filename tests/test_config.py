"""Integration configuration and authentication tests."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import IntegrationConfig
from master_agent.errors import ConfigurationError


class IntegrationConfigTests(unittest.TestCase):
    """Verify secret references, validation, and resolution."""

    def test_repository_config_parses_without_resolving_secrets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = IntegrationConfig.from_toml(root / "config/integrations.toml")
        self.assertEqual(
            set(config.connectors),
            {"jira", "confluence", "bitbucket", "microsoft"},
        )
        self.assertFalse(config.connector("jira").enabled)
        self.assertEqual(config.connector("jira").auth_mode, AuthMode.BASIC)

    def test_enabled_connector_reports_missing_environment(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url_env = "JIRA_URL"
auth_mode = "basic"
username_env = "JIRA_USER"
secret_env = "JIRA_TOKEN"
""".strip(),
                encoding="utf-8",
            )
            connector = IntegrationConfig.from_toml(path).connector("jira")
            errors = connector.configuration_errors({})
            self.assertIn("environment variable JIRA_URL is missing", errors)
            self.assertIn("environment variable JIRA_USER is missing", errors)
            self.assertIn("environment variable JIRA_TOKEN is missing", errors)
            with self.assertRaises(ConfigurationError):
                connector.resolve({})

    def test_secret_is_not_exposed_in_repr(self) -> None:
        auth = ResolvedAuth(
            mode=AuthMode.BEARER,
            secret="never-print-this-secret",
        )
        self.assertNotIn("never-print-this-secret", repr(auth))
        self.assertEqual(
            auth.headers(),
            {"Authorization": "Bearer never-print-this-secret"},
        )

    def test_http_base_url_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "data_center"
base_url = "http://jira.internal"
auth_mode = "none"
""".strip(),
                encoding="utf-8",
            )
            connector = IntegrationConfig.from_toml(path).connector("jira")
            with self.assertRaisesRegex(ConfigurationError, "must use HTTPS"):
                connector.resolve({})

    def test_missing_config_file_raises_domain_error(self) -> None:
        with self.assertRaises(ConfigurationError):
            IntegrationConfig.from_toml(Path("/definitely/missing.toml"))


if __name__ == "__main__":
    unittest.main()
