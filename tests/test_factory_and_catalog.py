"""Connector-construction gates and capability-catalog consistency tests."""

from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

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
from master_agent.connectors.github import GitHubConnector
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
from master_agent.execution_context import capture_connector_executions
from master_agent.models import ChangePlan, ExecutionContext
from master_agent.oauth import AccessToken, write_token_file
from tests.fakes import ScriptedTransport

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
                "sharepoint.file.upload",
                "outlook.email.send",
                "teams.chat.message.send",
            ):
                self.assertIn(capability, capabilities)
            self.assertNotIn("bitbucket.branch.push", capabilities)
            self.assertNotIn("repository.patch.apply", capabilities)
            self.assertNotIn("onenote.page.create", capabilities)
            self.assertNotIn("onenote.page.update", capabilities)

    def test_bitbucket_local_git_publication_is_explicitly_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "integrations.toml"
            config_path.write_text(
                _integration_text(
                    enable_mutations=True,
                    enable_git_mutations=True,
                ),
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(config_path)

            with self.assertRaisesRegex(
                ConfigurationError,
                "branch publication is disabled",
            ):
                build_live_connectors(
                    config,
                    environ={},
                    include_writes=True,
                    workspace_root=root,
                    artifact_root=root,
                )

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

    def test_approved_factory_reuses_attested_token_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "graph-token.json"
            token_a = AccessToken(
                value="token-A",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                scopes=("Notes.Read", "User.Read"),
                source="test",
            )
            token_b = replace(token_a, value="token-B")
            write_token_file(token_path, token_a)
            config = IntegrationConfig.from_toml(ROOT / "config/integrations.toml")
            environ = {"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_path)}
            initial_transport = ScriptedTransport()
            initial_transport.add_json("GET", "/v1.0/me", {"id": "account-A"})
            captured = capture_connector_executions(
                config,
                environ=environ,
                systems={"onenote"},
                principal_transport=initial_transport,
            )
            assert config.source_sha256 is not None
            approved = ExecutionContext(
                integrations_sha256=config.source_sha256,
                connectors=tuple(item.binding for item in captured),
            )

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
                connectors = build_live_connectors(
                    config,
                    environ=environ,
                    transport=transport,
                    systems={"onenote"},
                    approved_execution_context=approved,
                )
                connector = next(
                    item for item in connectors if item.system == "onenote"
                )
                connector.probe()  # type: ignore[attr-defined]

        self.assertEqual(
            [request.headers.get("Authorization") for request in transport.requests],
            ["Bearer token-A", "Bearer token-A"],
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
            GitHubConnector,
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

    def test_catalog_serialization_preserves_read_result_contracts(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        serialized = catalog.to_dict()["capabilities"]

        for name in catalog.enabled_names():
            definition = catalog.definition(name)
            with self.subTest(capability=name):
                self.assertEqual(
                    serialized[name]["read_result_schema"],
                    definition.read_result_schema,
                )
                self.assertEqual(
                    serialized[name]["read_result_resources"],
                    dict(definition.read_result_resources),
                )
                self.assertEqual(
                    serialized[name]["read_result_metadata"],
                    list(definition.read_result_metadata),
                )

    def test_onenote_writes_are_disabled_in_catalog_and_connector(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")

        self.assertFalse(catalog.definitions["onenote.page.create"].enabled)
        self.assertFalse(catalog.definitions["onenote.page.update"].enabled)
        self.assertEqual(OneNoteWriteConnector._CAPABILITIES, frozenset())

    def test_local_git_mutations_are_disabled_in_catalog(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")

        for capability in (
            "bitbucket.branch.push",
            "repository.branch.create",
            "repository.branch.push",
            "repository.commit.create",
            "repository.patch.apply",
        ):
            with self.subTest(capability=capability):
                self.assertFalse(catalog.definitions[capability].enabled)

    def test_checked_in_weekly_status_plan_satisfies_capability_contracts(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        plan = ChangePlan.from_dict(
            json.loads(
                (ROOT / "examples/weekly-status-plan.json").read_text(encoding="utf-8")
            )
        )

        errors = [
            reason
            for action in plan.actions
            for allowed, reason in (catalog.validate_action(action),)
            if not allowed
        ]

        self.assertEqual(errors, [])


def _capabilities(connectors: tuple[object, ...]) -> set[str]:
    return {
        capability for connector in connectors for capability in connector.capabilities
    }


def _integration_text(
    *,
    enable_mutations: bool,
    enable_git_mutations: bool = False,
) -> str:
    value = "true" if enable_mutations else "false"
    git_value = "true" if enable_git_mutations else "false"
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
        branch_push_enabled = {git_value}
        branch_prefix = "agent/"

        [connectors.microsoft]
        enabled = true
        deployment = "cloud"
        base_url = "https://graph.microsoft.com/v1.0"
        auth_mode = "none"
        identity_mode = "delegated"
        max_pages = 16
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
