"""Configuration and environment-discovery tests."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from master_agent.auth import AuthMode
from master_agent.config import ConnectorConfig, DeploymentType, IntegrationConfig
from master_agent.discovery import DiscoveryStatus, discover_integrations


class ConfigurationTests(unittest.TestCase):
    """Verify secret-reference configuration behavior."""

    def test_missing_environment_is_reported_without_secret_values(self) -> None:
        config = ConnectorConfig(
            system="jira",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
            base_url_env=None,
            auth_mode=AuthMode.BASIC,
            username_env="JIRA_USER",
            secret_env="JIRA_TOKEN",
        )
        self.assertEqual(
            config.missing_environment_variables({}),
            ("JIRA_USER", "JIRA_TOKEN"),
        )
        errors = config.configuration_errors({})
        self.assertIn("environment variable JIRA_TOKEN is missing", errors)
        self.assertNotIn("secret-value", " ".join(errors))

    def test_resolved_auth_secret_is_excluded_from_repr(self) -> None:
        config = ConnectorConfig(
            system="jira",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
            base_url_env=None,
            auth_mode=AuthMode.BASIC,
            username_env="JIRA_USER",
            secret_env="JIRA_TOKEN",
        )
        resolved = config.resolve(
            {"JIRA_USER": "rory@example.com", "JIRA_TOKEN": "secret-value"}
        )
        self.assertNotIn("secret-value", repr(resolved))
        self.assertNotIn("secret-value", repr(resolved.auth))

    def test_invalid_ca_bundle_fails_closed(self) -> None:
        config = ConnectorConfig(
            system="jira",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
            base_url_env=None,
            auth_mode=AuthMode.NONE,
            username_env=None,
            secret_env=None,
            ca_bundle_env="CA_BUNDLE",
        )
        with self.assertRaisesRegex(Exception, "CA bundle does not exist"):
            config.resolve({"CA_BUNDLE": "/does/not/exist.pem"})

    def test_toml_uses_nested_connector_tables(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = false
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "none"
""".strip(),
                encoding="utf-8",
            )
            parsed = IntegrationConfig.from_toml(path)
            self.assertEqual(parsed.connector("jira").system, "jira")


class DiscoveryTests(unittest.TestCase):
    """Verify discovery remains useful before credentials are configured."""

    def test_disabled_connector_is_reported(self) -> None:
        config = IntegrationConfig(
            connectors={
                "jira": ConnectorConfig(
                    system="jira",
                    enabled=False,
                    deployment=DeploymentType.CLOUD,
                    base_url="https://example.atlassian.net",
                    base_url_env=None,
                    auth_mode=AuthMode.NONE,
                    username_env=None,
                    secret_env=None,
                )
            }
        )
        records = discover_integrations(config, environ={})
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].status, DiscoveryStatus.DISABLED)

    def test_microsoft_configuration_expands_to_phase_2b_runtime_systems(self) -> None:
        config = IntegrationConfig(
            connectors={
                "microsoft": ConnectorConfig(
                    system="microsoft",
                    enabled=True,
                    deployment=DeploymentType.CLOUD,
                    base_url="https://graph.microsoft.com/v1.0",
                    base_url_env=None,
                    auth_mode=AuthMode.BEARER,
                    username_env=None,
                    secret_env="GRAPH_TOKEN",
                )
            }
        )
        records = discover_integrations(config, environ={})
        self.assertEqual(
            {record.system for record in records},
            {"microsoft", "sharepoint", "outlook", "teams"},
        )
        self.assertTrue(
            all(record.status is DiscoveryStatus.MISSING_ENVIRONMENT for record in records)
        )
        self.assertTrue(all(record.missing_environment == ("GRAPH_TOKEN",) for record in records))


if __name__ == "__main__":
    unittest.main()
