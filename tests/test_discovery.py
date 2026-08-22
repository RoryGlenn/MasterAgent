"""Environment and connectivity discovery tests."""

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent.config import IntegrationConfig
from master_agent.discovery import (
    DiscoveryStatus,
    EnvironmentDiscovery,
    discover_integrations,
)
from master_agent.errors import ConfigurationError
from master_agent.governance import EnvironmentKind, GovernanceProfile
from master_agent.models import DataClassification
from master_agent.oauth import AccessToken, write_token_file
from tests.fakes import ScriptedTransport

ROOT = Path(__file__).resolve().parents[1]


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

    def test_invalid_endpoint_is_not_echoed_in_discovery_records(self) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url_env = "MASTER_AGENT_JIRA_BASE_URL"
auth_mode = "none"
"""
        )
        endpoint = (
            "https://user:password-canary@example.atlassian.net/private-path"
            "?token=query-canary"
        )

        for probe in (False, True):
            with self.subTest(probe=probe):
                transport = ScriptedTransport()
                records = discover_integrations(
                    config,
                    environ={"MASTER_AGENT_JIRA_BASE_URL": endpoint},
                    probe=probe,
                    transport=transport,
                    systems={"jira"},
                    governance=(
                        GovernanceProfile.from_toml(ROOT / "config/governance.toml")
                        if probe
                        else None
                    ),
                )
                rendered = str(records[0].to_dict())
                self.assertEqual(records[0].status, DiscoveryStatus.FAILED)
                self.assertIsNone(records[0].base_url)
                self.assertNotIn("password-canary", rendered)
                self.assertNotIn("query-canary", rendered)
                self.assertEqual(transport.requests, [])

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
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
        ).inspect(probe=True)
        self.assertTrue(report.ready)
        self.assertEqual(report.connectors[0].status, DiscoveryStatus.REACHABLE)
        self.assertEqual(
            report.connectors[0].probe["schema"],
            "master-agent/provider-probe@1",
        )
        self.assertTrue(report.connectors[0].probe["reachable"])
        self.assertIsNotNone(report.connectors[0].egress)
        self.assertNotIn("1001.0.0", str(report.connectors[0].to_dict()))
        self.assertNotIn("jira.example.test", str(report.connectors[0].to_dict()))
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
auth_mode = "oauth_delegated"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
identity_mode = "delegated"
oauth_flow = "environment"
onenote_read_enabled = true
"""
        )
        transport = ScriptedTransport()
        transport.add_json(
            "GET",
            "/v1.0/me",
            {"id": "user-42"},
        )
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
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].system, "onenote")
        self.assertEqual(records[0].status, DiscoveryStatus.REACHABLE)
        self.assertEqual(len(transport.requests), 2)

    def test_probe_requires_policy_and_denies_confidential_before_network(self) -> None:
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

        with self.assertRaisesRegex(ConfigurationError, "model-context policy"):
            discover_integrations(
                config,
                environ={},
                probe=True,
                transport=transport,
                systems={"jira"},
            )
        denied = discover_integrations(
            config,
            environ={},
            probe=True,
            transport=transport,
            systems={"jira"},
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            data_classification=DataClassification.CONFIDENTIAL,
        )

        self.assertEqual(denied[0].status, DiscoveryStatus.FAILED)
        self.assertIn("denies", denied[0].error_message)
        self.assertEqual(transport.requests, [])

    def test_nondevelopment_probe_requires_explicit_classification_before_network(
        self,
    ) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "none"
"""
        )
        governance = replace(
            GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            environment=EnvironmentKind.NON_PRODUCTION,
        )
        transport = ScriptedTransport()

        with self.assertRaisesRegex(ConfigurationError, "required outside development"):
            discover_integrations(
                config,
                environ={},
                probe=True,
                transport=transport,
                systems={"jira"},
                governance=governance,
            )

        self.assertEqual(transport.requests, [])

    def test_authenticated_probe_policy_denial_precedes_principal_request(self) -> None:
        config = _config(
            """
[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GITHUB_TOKEN"
"""
        )
        transport = ScriptedTransport()

        records = discover_integrations(
            config,
            environ={"MASTER_AGENT_GITHUB_TOKEN": "opaque-token"},
            probe=True,
            transport=transport,
            systems={"github"},
            governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            data_classification=DataClassification.CONFIDENTIAL,
        )

        self.assertEqual(records[0].status, DiscoveryStatus.FAILED)
        self.assertEqual(records[0].missing_environment, ())
        self.assertEqual(transport.requests, [])

    def test_empty_or_unconfigured_probe_selection_fails_closed(self) -> None:
        config = _config(
            """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "none"
"""
        )
        governance = GovernanceProfile.from_toml(ROOT / "config/governance.toml")

        for systems in (set(), {"unknown-provider"}):
            with (
                self.subTest(systems=systems),
                self.assertRaisesRegex(
                    ConfigurationError,
                    "selected system|unconfigured systems",
                ),
            ):
                discover_integrations(
                    config,
                    environ={},
                    probe=True,
                    systems=systems,
                    governance=governance,
                )

    def test_probe_reuses_attested_token_when_token_file_changes(self) -> None:
        with TemporaryDirectory() as directory:
            token_path = Path(directory) / "graph-token.json"
            token_a = AccessToken(
                value="token-A",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                scopes=("Notes.Read", "User.Read"),
                source="test",
            )
            token_b = replace(token_a, value="token-B")
            write_token_file(token_path, token_a)
            transport = ScriptedTransport()
            transport.add_json("GET", "/v1.0/me", {"id": "account-A"})
            transport.add_json(
                "GET",
                "/v1.0/me/onenote/notebooks",
                {"value": []},
            )
            original_request = transport.request

            def swap_after_attestation(**kwargs: object) -> object:
                response = original_request(**kwargs)  # type: ignore[arg-type]
                if len(transport.requests) == 1:
                    write_token_file(token_path, token_b)
                return response

            with patch.object(
                transport,
                "request",
                side_effect=swap_after_attestation,
            ):
                records = discover_integrations(
                    IntegrationConfig.from_toml(ROOT / "config/integrations.toml"),
                    environ={"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_path)},
                    probe=True,
                    transport=transport,
                    systems={"onenote"},
                    governance=GovernanceProfile.from_toml(
                        ROOT / "config/governance.toml"
                    ),
                )

        self.assertEqual(records[0].status, DiscoveryStatus.REACHABLE)
        self.assertEqual(
            [request.headers.get("Authorization") for request in transport.requests],
            ["Bearer token-A", "Bearer token-A"],
        )


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
