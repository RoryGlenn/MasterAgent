"""Connector-construction gates and capability-catalog consistency tests."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.communications import (
    OutlookSendConnector,
    TeamsSendConnector,
)
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.confluence_write import ConfluenceWriteConnector
from master_agent.connectors.drafts import (
    ConfluenceDraftConnector,
    JiraDraftConnector,
    OutlookDraftConnector,
    PowerPointDraftConnector,
    RepositoryDraftConnector,
    TeamsDraftConnector,
)
from master_agent.connectors.factory import build_live_connectors
from master_agent.connectors.git_remote import GitBranchPushConnector
from master_agent.connectors.git_workspace import GitWorkspaceConnector
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.connectors.jira import JiraConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.microsoft import (
    MicrosoftIdentityConnector,
    SharePointConnector,
)
from master_agent.connectors.onenote import OneNoteReadConnector, OneNoteWriteConnector
from master_agent.connectors.outlook import OutlookConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.connectors.teams import TeamsConnector
from master_agent.errors import ConfigurationError

ROOT = Path(__file__).resolve().parents[1]


class ConnectorFactoryTests(unittest.TestCase):
    """Verify the CLI flag, provider gate, and capability gate all apply."""

    def test_mutation_connectors_require_all_explicit_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "integrations.toml"
            config_path.write_text(
                _integration_text(enable_mutations=False), encoding="utf-8"
            )
            config = IntegrationConfig.from_toml(config_path)

            read_only = build_live_connectors(
                config,
                environ={},
                include_writes=True,
                include_communications=True,
                workspace_root=root,
                artifact_root=root,
            )
            capabilities = _capabilities(read_only)
            self.assertIn("jira.issue.search", capabilities)
            self.assertIn("onenote.page.read", capabilities)
            self.assertNotIn("jira.issue.update", capabilities)
            self.assertNotIn("sharepoint.file.upload", capabilities)
            self.assertNotIn("outlook.email.send", capabilities)
            self.assertNotIn("teams.chat.message.send", capabilities)
            self.assertNotIn("bitbucket.branch.push", capabilities)

            config_path.write_text(
                _integration_text(enable_mutations=True), encoding="utf-8"
            )
            config = IntegrationConfig.from_toml(config_path)
            caller_did_not_enable = build_live_connectors(
                config,
                environ={},
                include_writes=False,
                include_communications=False,
                workspace_root=root,
                artifact_root=root,
            )
            self.assertNotIn("jira.issue.update", _capabilities(caller_did_not_enable))

            fully_enabled = build_live_connectors(
                config,
                environ={},
                include_writes=True,
                include_communications=True,
                workspace_root=root,
                artifact_root=root,
            )
            capabilities = _capabilities(fully_enabled)
            for capability in (
                "jira.issue.update",
                "confluence.page.update",
                "bitbucket.pull_request.create",
                "bitbucket.branch.push",
                "sharepoint.file.upload",
                "onenote.page.update",
                "outlook.email.send",
                "teams.chat.message.send",
                "repository.patch.apply",
            ):
                self.assertIn(capability, capabilities)

    def test_sharepoint_write_requires_artifact_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "integrations.toml"
            path.write_text(_integration_text(enable_mutations=True), encoding="utf-8")
            config = IntegrationConfig.from_toml(path)
            with self.assertRaisesRegex(ConfigurationError, "artifact_root"):
                build_live_connectors(
                    config,
                    environ={},
                    systems={"sharepoint"},
                    include_writes=True,
                )


class CapabilityCatalogConsistencyTests(unittest.TestCase):
    """Ensure every deterministic connector capability is governed."""

    def test_connector_capabilities_exist_in_catalog(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        connector_classes = (
            BitbucketConnector,
            BitbucketWriteConnector,
            OutlookSendConnector,
            TeamsSendConnector,
            ConfluenceConnector,
            ConfluenceWriteConnector,
            JiraDraftConnector,
            ConfluenceDraftConnector,
            OutlookDraftConnector,
            TeamsDraftConnector,
            PowerPointDraftConnector,
            RepositoryDraftConnector,
            GitBranchPushConnector,
            GitWorkspaceConnector,
            IdentityMapConnector,
            JiraConnector,
            JiraWriteConnector,
            MicrosoftIdentityConnector,
            SharePointConnector,
            OneNoteReadConnector,
            OneNoteWriteConnector,
            OutlookConnector,
            SharePointWriteConnector,
            TeamsConnector,
        )
        connector_capabilities = {
            capability
            for connector_class in connector_classes
            for capability in getattr(connector_class, "_CAPABILITIES", frozenset())
        }
        missing = sorted(connector_capabilities - set(catalog.definitions))
        self.assertEqual(missing, [])


def _capabilities(connectors: tuple[object, ...]) -> set[str]:
    return {
        capability for connector in connectors for capability in connector.capabilities
    }


def _integration_text(*, enable_mutations: bool) -> str:
    value = "true" if enable_mutations else "false"
    return textwrap.dedent(
        f"""
        [connectors.jira]
        enabled = true
        deployment = "cloud"
        base_url = "https://example.atlassian.net"
        auth_mode = "none"
        write_enabled = {value}
        writes_enabled = {value}

        [connectors.confluence]
        enabled = true
        deployment = "cloud"
        base_url = "https://example.atlassian.net"
        auth_mode = "none"
        write_enabled = {value}
        writes_enabled = {value}

        [connectors.bitbucket]
        enabled = true
        deployment = "cloud"
        base_url = "https://api.bitbucket.org/2.0"
        auth_mode = "none"
        write_enabled = {value}
        pull_request_writes_enabled = {value}
        branch_push_enabled = {value}
        branch_prefix = "agent/"

        [connectors.microsoft]
        enabled = true
        deployment = "cloud"
        base_url = "https://graph.microsoft.com/v1.0"
        auth_mode = "none"
        identity_mode = "delegated"
        write_enabled = {value}
        send_enabled = {value}
        sharepoint_writes_enabled = {value}
        onenote_read_enabled = true
        onenote_writes_enabled = {value}
        outlook_send_enabled = {value}
        teams_send_enabled = {value}
        """
    ).strip()


if __name__ == "__main__":
    unittest.main()
