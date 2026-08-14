"""Environment and connectivity discovery tests."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from master_agent.config import IntegrationConfig
from master_agent.discovery import (
    DiscoveryStatus,
    EnvironmentDiscovery,
    discover_integrations,
)
from tests.fakes import ScriptedTransport


class DiscoveryTests(unittest.TestCase):
    """Verify readiness reporting without credential disclosure."""

    def test_missing_environment_is_reported_without_secret_value(self) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url_env = "JIRA_URL"
auth_mode = "bearer"
secret_env = "JIRA_TOKEN"
"""
        )
        records = discover_integrations(
            config,
            environ={"JIRA_TOKEN": "do-not-print-this"},
            systems={"jira"},
        )
        self.assertEqual(records[0].status, DiscoveryStatus.MISSING_ENVIRONMENT)
        rendered = str(records[0].to_dict())
        self.assertNotIn("do-not-print-this", rendered)
        self.assertIn("JIRA_URL", rendered)

    def test_ready_connector_exposes_capabilities_without_network_probe(self) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://jira.example.test"
auth_mode = "none"
"""
        )
        report = EnvironmentDiscovery(
            config,
            environ={},
            systems={"jira"},
        ).inspect(probe=False)
        self.assertTrue(report.ready)
        self.assertEqual(report.connectors[0].status, DiscoveryStatus.READY)
        self.assertIn("jira.issue.search", report.connectors[0].capabilities)

    def test_probe_uses_read_only_server_info(self) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://jira.example.test"
auth_mode = "none"
"""
        )
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/rest/api/3/serverInfo",
            {
                "baseUrl": "https://jira.example.test",
                "version": "1001.0.0",
                "deploymentType": "Cloud",
            },
        )
        report = EnvironmentDiscovery(
            config,
            environ={},
            transport=transport,
            systems={"jira"},
        ).inspect(probe=True)
        self.assertTrue(report.ready)
        self.assertEqual(report.connectors[0].status, DiscoveryStatus.REACHABLE)
        self.assertEqual(report.connectors[0].probe["deployment_type"], "Cloud")
        self.assertEqual(len(transport.requests), 1)

    def test_all_disabled_is_not_live_ready(self) -> None:
        root = Path(__file__).resolve().parents[1]
        report = EnvironmentDiscovery(
            IntegrationConfig.from_toml(root / "config/integrations.toml"),
            environ={},
        ).inspect()
        self.assertFalse(report.ready)
        self.assertTrue(
            all(item.status is DiscoveryStatus.DISABLED for item in report.connectors)
        )


def _config(content: str) -> IntegrationConfig:
    directory = TemporaryDirectory()
    path = Path(directory.name) / "integrations.toml"
    path.write_text(content.strip(), encoding="utf-8")
    config = IntegrationConfig.from_toml(path)
    # Keep the temporary directory alive for the duration of the returned object.
    setattr(config, "_test_directory", directory) if hasattr(config, "__dict__") else None
    directory.cleanup()
    return config


if __name__ == "__main__":
    unittest.main()
