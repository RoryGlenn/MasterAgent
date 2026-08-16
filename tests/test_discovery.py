"""Environment and connectivity discovery tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

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
base_url_env = "MASTER_AGENT_JIRA_BASE_URL"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
"""
        )
        records = discover_integrations(
            config,
            environ={"MASTER_AGENT_JIRA_TOKEN": "do-not-print-this"},
            systems={"jira"},
        )
        self.assertEqual(records[0].status, DiscoveryStatus.MISSING_ENVIRONMENT)
        rendered = str(records[0].to_dict())
        self.assertNotIn("do-not-print-this", rendered)
        self.assertIn("MASTER_AGENT_JIRA_BASE_URL", rendered)

    def test_ready_connector_exposes_capabilities_without_network_probe(self) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
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
base_url = "https://example.atlassian.net"
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

    def test_defaults_are_available_but_need_credentials(self) -> None:
        root = Path(__file__).resolve().parents[1]
        report = EnvironmentDiscovery(
            IntegrationConfig.from_toml(root / "config/integrations.toml"),
            environ={},
        ).inspect()
        self.assertFalse(report.ready)
        self.assertTrue(
            all(
                item.status is DiscoveryStatus.MISSING_ENVIRONMENT
                for item in report.connectors
            )
        )

    def test_explicit_onenote_discovery_builds_the_opted_in_runtime(self) -> None:
        config = _config(
            """
[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
identity_mode = "delegated"
onenote_read_enabled = true
"""
        )
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/me/onenote/notebooks",
            {"value": []},
        )

        records = discover_integrations(
            config,
            environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "opaque-token"},
            probe=True,
            transport=transport,
            systems={"onenote"},
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].system, "onenote")
        self.assertEqual(records[0].status, DiscoveryStatus.REACHABLE)
        self.assertEqual(len(transport.requests), 1)


def _config(content: str) -> IntegrationConfig:
    directory = TemporaryDirectory()
    path = Path(directory.name) / "integrations.toml"
    path.write_text(content.strip(), encoding="utf-8")
    config = IntegrationConfig.from_toml(path)
    # Keep the temporary directory alive for the duration of the returned object.
    setattr(config, "_test_directory", directory) if hasattr(
        config, "__dict__"
    ) else None
    directory.cleanup()
    return config


if __name__ == "__main__":
    unittest.main()
