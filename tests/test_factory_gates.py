"""Connector-factory tests for independent read, write, and send gates."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from master_agent.config import IntegrationConfig
from master_agent.connectors.factory import build_live_connectors


class ConnectorFactoryGateTests(unittest.TestCase):
    """Verify that broad runtime flags cannot bypass provider-specific gates."""

    def test_jira_write_requires_runtime_and_both_config_gates(self) -> None:
        """Jira writes remain unavailable until both reviewed flags are true."""

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                _jira_config(write_enabled=True, writes_enabled=False),
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(path)
            connectors = build_live_connectors(
                config,
                environ={
                    "MASTER_AGENT_JIRA_USERNAME": "user@example.test",
                    "MASTER_AGENT_JIRA_TOKEN": "token",
                },
                systems={"jira"},
                include_writes=True,
            )
            self.assertEqual(len(connectors), 1)
            self.assertNotIn(
                "jira.issue.update",
                {capability for item in connectors for capability in item.capabilities},
            )

            path.write_text(
                _jira_config(write_enabled=True, writes_enabled=True),
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(path)
            connectors = build_live_connectors(
                config,
                environ={
                    "MASTER_AGENT_JIRA_USERNAME": "user@example.test",
                    "MASTER_AGENT_JIRA_TOKEN": "token",
                },
                systems={"jira"},
                include_writes=True,
            )
            capabilities = {
                capability for item in connectors for capability in item.capabilities
            }
            self.assertIn("jira.issue.update", capabilities)

    def test_microsoft_mutations_require_granular_provider_gates(self) -> None:
        """Generic runtime permission alone must not enable Microsoft mutations."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "integrations.toml"
            path.write_text(
                _microsoft_config(
                    write_enabled=True,
                    send_enabled=True,
                    granular=False,
                ),
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(path)
            connectors = build_live_connectors(
                config,
                environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "token"},
                systems={"sharepoint", "onenote", "outlook", "teams"},
                include_writes=True,
                include_communications=True,
                artifact_root=root / "artifacts",
            )
            capabilities = {
                capability for item in connectors for capability in item.capabilities
            }
            self.assertNotIn("sharepoint.file.upload", capabilities)
            self.assertNotIn("onenote.page.update", capabilities)
            self.assertNotIn("outlook.email.send", capabilities)
            self.assertNotIn("teams.chat.message.send", capabilities)
            self.assertNotIn("onenote.page.read", capabilities)

            path.write_text(
                _microsoft_config(
                    write_enabled=True,
                    send_enabled=True,
                    granular=True,
                ),
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(path)
            connectors = build_live_connectors(
                config,
                environ={"MASTER_AGENT_GRAPH_ACCESS_TOKEN": "token"},
                systems={"sharepoint", "onenote", "outlook", "teams"},
                include_writes=True,
                include_communications=True,
                artifact_root=root / "artifacts",
            )
            capabilities = {
                capability for item in connectors for capability in item.capabilities
            }
            self.assertIn("sharepoint.file.upload", capabilities)
            self.assertNotIn("onenote.page.update", capabilities)
            self.assertIn("outlook.email.send", capabilities)
            self.assertIn("teams.chat.message.send", capabilities)
            self.assertIn("onenote.page.read", capabilities)


def _jira_config(*, write_enabled: bool, writes_enabled: bool) -> str:
    return f"""[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
write_enabled = {str(write_enabled).lower()}
writes_enabled = {str(writes_enabled).lower()}
"""


def _microsoft_config(
    *,
    write_enabled: bool,
    send_enabled: bool,
    granular: bool,
) -> str:
    flag = str(granular).lower()
    return f"""[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
identity_mode = "delegated"
max_pages = 16
write_enabled = {str(write_enabled).lower()}
send_enabled = {str(send_enabled).lower()}
sharepoint_writes_enabled = {flag}
onenote_read_enabled = {flag}
onenote_writes_enabled = {flag}
outlook_send_enabled = {flag}
teams_send_enabled = {flag}
"""


if __name__ == "__main__":
    unittest.main()
