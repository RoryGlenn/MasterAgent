"""Integration coverage for every MasterAgent connector surface."""

from __future__ import annotations

import importlib
import inspect
import textwrap
import unittest
from pathlib import Path
from urllib.parse import urlparse

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
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.connectors.teams import TeamsConnector
from master_agent.identity import IdentityRegistry, PersonIdentity
from master_agent.models import RiskLevel
from master_agent.registry import ConnectorRegistry
from tests.fakes import ScriptedTransport
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
    "sharepoint_write",
    "teams",
)
_READ_PROBE_TYPES = {
    "jira": JiraConnector,
    "confluence": ConfluenceConnector,
    "bitbucket": BitbucketConnector,
    "github": GitHubConnector,
    "microsoft": MicrosoftIdentityConnector,
    "sharepoint": SharePointConnector,
    "outlook": OutlookConnector,
    "teams": TeamsConnector,
    "onenote": OneNoteReadConnector,
}


class LiveConnectorIntegrationTests(unittest.TestCase):
    """Exercise live connector construction through the shared runtime boundary."""

    def test_all_live_connectors_build_and_resolve_every_capability(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            registry = _build_live_registry(root, enable_effects=True)
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

    def test_every_read_connector_completes_its_provider_probe(self) -> None:
        transport = ScriptedTransport()
        _register_probe_responses(transport)
        with private_temporary_directory() as directory:
            registry = _build_live_registry(
                Path(directory),
                enable_effects=False,
                transport=transport,
            )
            try:
                for system, connector_type in _READ_PROBE_TYPES.items():
                    with self.subTest(system=system):
                        connector = _only_connector_of_type(
                            registry,
                            system,
                            connector_type,
                        )
                        probe = connector.probe()
                        self.assertTrue(probe["reachable"])
            finally:
                _close_connectors(registry)

        self.assertEqual(
            {urlparse(request.url).path for request in transport.requests},
            {
                "/rest/api/3/serverInfo",
                "/wiki/rest/api/content/search",
                "/2.0/user",
                "/user",
                "/v1.0/me",
                "/v1.0/sites/root",
                "/v1.0/me/mailFolders/inbox",
                "/v1.0/me/chats",
                "/v1.0/me/onenote/notebooks",
            },
        )
        self.assertEqual(len(transport.requests), len(_READ_PROBE_TYPES))


class LocalConnectorIntegrationTests(unittest.TestCase):
    """Execute local connectors through registry selection and verification."""

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

    def test_identity_and_mock_connectors_execute_through_registry(self) -> None:
        identity_registry = IdentityRegistry(
            people={
                "rory": PersonIdentity(
                    key="rory",
                    display_name="Rory Glenn",
                    aliases=("Rory",),
                    identifiers={"github": "RoryGlenn"},
                )
            }
        )
        registry = ConnectorRegistry()
        identity = IdentityMapConnector(identity_registry)
        mock = MockConnector(
            "mock",
            initial_resources={"item-1": {"value": "ready", "version": "1"}},
            capabilities={"mock.item.read"},
        )
        registry.register(identity)
        registry.register(mock)

        identity_action = action_for(
            "identity.identifier.resolve",
            system="identity",
            resource_type="person",
            resource_id="rory",
            risk=RiskLevel.READ_ONLY,
            parameters={"target_system": "github"},
            requires_approval=False,
        )
        identity_result = registry.resolve(
            "identity",
            identity_action.capability,
        ).execute(identity_action)
        self.assertEqual(identity_result.after["identifier"], "RoryGlenn")
        self.assertTrue(identity.verify(identity_action, identity_result).verified)

        mock_action = action_for(
            "mock.item.read",
            system="mock",
            resource_type="item",
            resource_id="item-1",
            risk=RiskLevel.READ_ONLY,
            requires_approval=False,
        )
        mock_result = registry.resolve("mock", mock_action.capability).execute(
            mock_action
        )
        self.assertEqual(mock_result.after["value"], "ready")
        self.assertTrue(mock.verify(mock_action, mock_result).verified)


class ConnectorInventoryIntegrationTests(unittest.TestCase):
    """Prevent connector implementations from bypassing integration coverage."""

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


def _build_live_registry(
    root: Path,
    *,
    enable_effects: bool,
    transport: ScriptedTransport | None = None,
) -> ConnectorRegistry:
    config_path = root / "integrations.toml"
    config_path.write_text(
        _integration_text(enable_effects=enable_effects),
        encoding="utf-8",
    )
    config = IntegrationConfig.from_toml(config_path)
    return build_live_registry(
        config,
        environ={},
        transport=transport,
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
        },
        include_writes=enable_effects,
        include_communications=enable_effects,
        workspace_root=root,
        artifact_root=root,
    )


def _integration_text(*, enable_effects: bool) -> str:
    enabled = "true" if enable_effects else "false"
    return textwrap.dedent(
        f"""
        [connectors.jira]
        enabled = true
        deployment = "cloud"
        base_url = "https://example.atlassian.net"
        auth_mode = "none"
        max_pages = 16
        write_enabled = {enabled}
        writes_enabled = {enabled}

        [connectors.confluence]
        enabled = true
        deployment = "cloud"
        base_url = "https://example.atlassian.net"
        auth_mode = "none"
        max_pages = 16
        write_enabled = {enabled}
        writes_enabled = {enabled}

        [connectors.bitbucket]
        enabled = true
        deployment = "cloud"
        base_url = "https://api.bitbucket.org/2.0"
        auth_mode = "none"
        max_pages = 16
        write_enabled = {enabled}
        pull_request_writes_enabled = {enabled}
        branch_push_enabled = false
        branch_prefix = "agent/"

        [connectors.github]
        enabled = true
        deployment = "cloud"
        base_url = "https://api.github.com"
        auth_mode = "none"
        max_pages = 16
        write_enabled = {enabled}
        writes_enabled = {enabled}
        admin_enabled = {enabled}

        [connectors.microsoft]
        enabled = true
        deployment = "cloud"
        base_url = "https://graph.microsoft.com/v1.0"
        auth_mode = "none"
        max_pages = 16
        write_enabled = {enabled}
        send_enabled = {enabled}
        sharepoint_writes_enabled = {enabled}
        onenote_read_enabled = true
        outlook_send_enabled = {enabled}
        teams_send_enabled = {enabled}
        identity_mode = "delegated"
        default_identity = "me"
        teams_probe = "chats"
        max_upload_bytes = 1000000
        """
    ).strip()


def _register_probe_responses(transport: ScriptedTransport) -> None:
    transport.add_json(
        "GET",
        "/rest/api/3/serverInfo",
        {
            "baseUrl": "https://example.atlassian.net",
            "version": "1001.0.0",
            "deploymentType": "Cloud",
        },
        host="example.atlassian.net",
    )
    transport.add_json(
        "GET",
        "/wiki/rest/api/content/search",
        {"results": []},
        host="example.atlassian.net",
    )
    transport.add_json(
        "GET",
        "/2.0/user",
        {
            "uuid": "{user-1}",
            "display_name": "Rory Glenn",
            "nickname": "rory",
        },
        host="api.bitbucket.org",
    )
    transport.add_json(
        "GET",
        "/user",
        {"id": 1, "login": "RoryGlenn"},
        host="api.github.com",
    )
    transport.add_json(
        "GET",
        "/v1.0/me",
        {
            "id": "user-1",
            "displayName": "Rory Glenn",
            "mail": "rory@example.com",
            "userPrincipalName": "rory@example.com",
        },
        host="graph.microsoft.com",
    )
    transport.add_json(
        "GET",
        "/v1.0/sites/root",
        {
            "id": "tenant.sharepoint.com,site,web",
            "displayName": "Company",
            "webUrl": "https://tenant.sharepoint.com",
        },
        host="graph.microsoft.com",
    )
    transport.add_json(
        "GET",
        "/v1.0/me/mailFolders/inbox",
        {
            "id": "inbox",
            "displayName": "Inbox",
            "totalItemCount": 0,
            "unreadItemCount": 0,
            "childFolderCount": 0,
        },
        host="graph.microsoft.com",
    )
    transport.add_json(
        "GET",
        "/v1.0/me/chats",
        {"value": []},
        host="graph.microsoft.com",
    )
    transport.add_json(
        "GET",
        "/v1.0/me/onenote/notebooks",
        {"value": []},
        host="graph.microsoft.com",
    )


def _only_connector_of_type(
    registry: ConnectorRegistry,
    system: str,
    connector_type: type[object],
) -> object:
    matches = [
        connector
        for connector in registry.connectors(system)
        if isinstance(connector, connector_type)
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"expected one {connector_type.__name__} for {system}, found {len(matches)}"
        )
    return matches[0]


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


def _close_connectors(registry: ConnectorRegistry) -> None:
    for connector in registry.connectors():
        if isinstance(connector, ClosableConnector):
            connector.close()


if __name__ == "__main__":
    unittest.main()
