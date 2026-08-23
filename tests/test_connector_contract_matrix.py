"""Offline connector inventory, factory, routing, and local-artifact contracts."""

from __future__ import annotations

import importlib
import inspect
import textwrap
import unittest
from pathlib import Path

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.connectors.base import ClosableConnector
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
    RedditDraftConnector,
    RepositoryDraftConnector,
    TeamsDraftConnector,
)
from master_agent.connectors.factory import build_draft_registry, build_live_registry
from master_agent.connectors.git_remote import GitBranchPushConnector
from master_agent.connectors.git_workspace import GitWorkspaceConnector
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.github_write import (
    GitHubAdminConnector,
    GitHubWriteConnector,
)
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.connectors.jira import JiraConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.microsoft import (
    MicrosoftIdentityConnector,
    SharePointConnector,
)
from master_agent.connectors.mock import MockConnector
from master_agent.connectors.onenote import OneNoteReadConnector, OneNoteWriteConnector
from master_agent.connectors.outlook import OutlookConnector
from master_agent.connectors.reddit import RedditConnector
from master_agent.connectors.reddit_write import RedditWriteConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.connectors.teams import TeamsConnector
from master_agent.models import RiskLevel
from tests.helpers import action_for, private_temporary_directory

ROOT = Path(__file__).resolve().parents[1]

_LIVE_CONNECTOR_TYPES = frozenset(
    {
        BitbucketConnector,
        BitbucketWriteConnector,
        ConfluenceConnector,
        ConfluenceWriteConnector,
        GitHubConnector,
        GitHubWriteConnector,
        GitHubAdminConnector,
        JiraConnector,
        JiraWriteConnector,
        MicrosoftIdentityConnector,
        SharePointConnector,
        SharePointWriteConnector,
        OutlookConnector,
        OutlookSendConnector,
        TeamsConnector,
        TeamsSendConnector,
        OneNoteReadConnector,
        RedditConnector,
        RedditWriteConnector,
    }
)
_DRAFT_CONNECTOR_TYPES = frozenset(
    {
        JiraDraftConnector,
        ConfluenceDraftConnector,
        OutlookDraftConnector,
        TeamsDraftConnector,
        PowerPointDraftConnector,
        RepositoryDraftConnector,
        RedditDraftConnector,
    }
)
_DIRECT_OR_QUARANTINED_CONNECTOR_TYPES = frozenset(
    {
        GitBranchPushConnector,
        GitWorkspaceConnector,
        IdentityMapConnector,
        MockConnector,
        OneNoteWriteConnector,
    }
)
_CONNECTOR_MODULES = (
    "bitbucket",
    "bitbucket_write",
    "communications",
    "confluence",
    "confluence_write",
    "drafts",
    "git_remote",
    "git_workspace",
    "github",
    "github_write",
    "identity",
    "jira",
    "jira_write",
    "microsoft",
    "onenote",
    "outlook",
    "reddit",
    "reddit_write",
    "sharepoint_write",
    "teams",
)


class ConnectorFactoryContractTests(unittest.TestCase):
    """Verify the factory and registry expose every explicitly gated connector."""

    def test_every_live_connector_builds_and_resolves_its_capabilities(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            config_path = root / "integrations.toml"
            config_path.write_text(_integration_text(), encoding="utf-8")
            registry = build_live_registry(
                IntegrationConfig.from_toml(config_path),
                environ={},
                systems={
                    "jira",
                    "confluence",
                    "bitbucket",
                    "github",
                    "microsoft",
                    "sharepoint",
                    "outlook",
                    "teams",
                    "onenote",
                    "reddit",
                },
                include_writes=True,
                include_communications=True,
                workspace_root=root,
                artifact_root=root,
            )
            try:
                self.assertEqual(
                    {type(connector) for connector in registry.connectors()},
                    _LIVE_CONNECTOR_TYPES,
                )
                for connector in registry.connectors():
                    with self.subTest(connector=type(connector).__name__):
                        self.assertTrue(connector.capabilities)
                        for capability in connector.capabilities:
                            self.assertIs(
                                registry.resolve(connector.system, capability),
                                connector,
                            )
            finally:
                _close_connectors(registry)


class LocalConnectorContractTests(unittest.TestCase):
    """Verify local connector output and digest checks without provider access."""

    def test_every_draft_connector_creates_and_verifies_an_artifact(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            registry = build_draft_registry(root)
            try:
                self.assertEqual(
                    {type(connector) for connector in registry.connectors()},
                    _DRAFT_CONNECTOR_TYPES,
                )
                for case in _draft_cases():
                    with self.subTest(capability=case[1]):
                        system, capability, resource_type, resource_id, parameters = (
                            case
                        )
                        connector = registry.resolve(system, capability)
                        action = action_for(
                            capability,
                            system=system,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            risk=RiskLevel.LOCAL_GENERATION,
                            parameters=parameters,
                            requires_approval=False,
                        )
                        result = connector.execute(action)
                        self.assertIsNotNone(result.after)
                        assert result.after is not None
                        artifact = Path(str(result.after["path"]))
                        self.assertTrue(artifact.is_file())
                        self.assertTrue(
                            artifact.resolve().is_relative_to(root.resolve())
                        )
                        self.assertTrue(connector.verify(action, result).verified)
            finally:
                _close_connectors(registry)


class ConnectorInventoryContractTests(unittest.TestCase):
    """Require every connector class to have an explicit test classification."""

    def test_every_connector_class_is_accounted_for(self) -> None:
        discovered = _discover_connector_types()
        accounted = (
            _LIVE_CONNECTOR_TYPES
            | _DRAFT_CONNECTOR_TYPES
            | _DIRECT_OR_QUARANTINED_CONNECTOR_TYPES
        )
        self.assertEqual(
            {connector.__name__ for connector in discovered},
            {connector.__name__ for connector in accounted},
        )

    def test_quarantined_connector_capabilities_remain_disabled(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        for connector_type in (GitBranchPushConnector, GitWorkspaceConnector):
            for capability in connector_type._CAPABILITIES:
                with self.subTest(
                    connector=connector_type.__name__,
                    capability=capability,
                ):
                    self.assertFalse(catalog.definitions[capability].enabled)
        self.assertEqual(OneNoteWriteConnector._CAPABILITIES, frozenset())
        self.assertFalse(catalog.definitions["reddit.content.edit"].enabled)
        self.assertFalse(catalog.definitions["reddit.content.delete"].enabled)


def _integration_text() -> str:
    return textwrap.dedent(
        """
        [connectors.jira]
        enabled = true
        deployment = "cloud"
        base_url = "https://example.atlassian.net"
        auth_mode = "none"
        max_pages = 16
        write_enabled = true
        writes_enabled = true

        [connectors.confluence]
        enabled = true
        deployment = "cloud"
        base_url = "https://example.atlassian.net"
        auth_mode = "none"
        max_pages = 16
        write_enabled = true
        writes_enabled = true

        [connectors.bitbucket]
        enabled = true
        deployment = "cloud"
        base_url = "https://api.bitbucket.org/2.0"
        auth_mode = "none"
        max_pages = 16
        write_enabled = true
        pull_request_writes_enabled = true
        branch_push_enabled = false
        branch_prefix = "agent/"

        [connectors.github]
        enabled = true
        deployment = "cloud"
        base_url = "https://api.github.com"
        auth_mode = "none"
        max_pages = 16
        write_enabled = true
        writes_enabled = true
        admin_enabled = true

        [connectors.microsoft]
        enabled = true
        deployment = "cloud"
        base_url = "https://graph.microsoft.com/v1.0"
        auth_mode = "none"
        max_pages = 16
        write_enabled = true
        send_enabled = true
        sharepoint_writes_enabled = true
        onenote_read_enabled = true
        outlook_send_enabled = true
        teams_send_enabled = true
        identity_mode = "delegated"
        default_identity = "me"
        teams_probe = "chats"
        max_upload_bytes = 1000000

        [connectors.reddit]
        enabled = true
        deployment = "cloud"
        base_url = "https://oauth.reddit.com"
        web_base_url = "https://www.reddit.com"
        auth_mode = "none"
        user_agent = "MasterAgent/1.0 test"
        posts_enabled = true
        comments_enabled = true
        edits_enabled = false
        deletes_enabled = false
        """
    ).strip()


def _draft_cases() -> tuple[
    tuple[str, str, str, str, dict[str, object]],
    ...,
]:
    return (
        (
            "jira",
            "jira.issue.update.draft",
            "issue",
            "RISE-1",
            {"before": {"summary": "Old"}, "fields": {"summary": "New"}},
        ),
        (
            "confluence",
            "confluence.page.create.draft",
            "page",
            "status-page",
            {
                "title": "Status",
                "body": "<p>Ready</p>",
                "space_id": "SPACE",
            },
        ),
        (
            "outlook",
            "outlook.email.draft",
            "message",
            "status-email",
            {
                "to": ["rory@example.com"],
                "subject": "Status",
                "body": "Ready",
            },
        ),
        (
            "teams",
            "teams.message.draft",
            "message",
            "status-message",
            {
                "recipient_type": "chat",
                "recipient_id": "chat-1",
                "body": "Ready",
            },
        ),
        (
            "powerpoint",
            "powerpoint.presentation.generate",
            "presentation",
            "status-deck",
            {
                "title": "Status",
                "slides": [{"title": "Summary", "bullets": ["Ready"]}],
            },
        ),
        (
            "repository",
            "repository.patch.generate",
            "patch",
            "status-patch",
            {
                "relative_path": "README.md",
                "before_text": "old\n",
                "after_text": "new\n",
            },
        ),
        (
            "reddit",
            "reddit.post.draft",
            "post",
            "reddit-draft",
            {
                "subreddit": "python",
                "title": "Typed connectors",
                "body": "Ready for review.",
            },
        ),
    )


def _discover_connector_types() -> frozenset[type[object]]:
    discovered: set[type[object]] = set()
    for module_name in _CONNECTOR_MODULES:
        module = importlib.import_module(f"master_agent.connectors.{module_name}")
        for _name, candidate in inspect.getmembers(module, inspect.isclass):
            if candidate.__module__ != module.__name__:
                continue
            if hasattr(candidate, "_CAPABILITIES"):
                discovered.add(candidate)
    discovered.add(MockConnector)
    return frozenset(discovered)


def _close_connectors(registry: object) -> None:
    for connector in registry.connectors():
        if isinstance(connector, ClosableConnector):
            connector.close()


if __name__ == "__main__":
    unittest.main()
