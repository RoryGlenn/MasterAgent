"""Credentialed live integration tests for external connector implementations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from master_agent.auth import AuthMode
from master_agent.config import ConnectorConfig, IntegrationConfig
from master_agent.connectors.base import ClosableConnector
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.communications import (
    OutlookSendConnector,
    TeamsSendConnector,
)
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.confluence_write import ConfluenceWriteConnector
from master_agent.connectors.factory import build_live_registry
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.github_write import (
    GitHubAdminConnector,
    GitHubWriteConnector,
)
from master_agent.connectors.jira import JiraConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.microsoft import (
    MicrosoftIdentityConnector,
    SharePointConnector,
)
from master_agent.connectors.onenote import OneNoteReadConnector
from master_agent.connectors.outlook import OutlookConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.connectors.teams import TeamsConnector
from master_agent.models import AgentAction, ExecutionResult, RiskLevel
from master_agent.oauth import RestrictedTokenFileProvider
from master_agent.registry import ConnectorRegistry
from tests.helpers import action_for, read_action

_READ_SYSTEMS = frozenset(
    {
        "jira",
        "confluence",
        "bitbucket",
        "github",
        "microsoft",
        "sharepoint",
        "outlook",
        "teams",
        "onenote",
    }
)
_PROVIDER_CONFIG_NAMES = (
    "jira",
    "confluence",
    "bitbucket",
    "github",
    "microsoft",
)
_READ_CONNECTOR_TYPES = {
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
_EFFECT_CONNECTOR_TYPES = (
    JiraWriteConnector,
    ConfluenceWriteConnector,
    BitbucketWriteConnector,
    GitHubWriteConnector,
    SharePointWriteConnector,
)
_EFFECT_SYSTEMS = frozenset(
    {"jira", "confluence", "bitbucket", "github", "microsoft", "sharepoint"}
)
_COMMUNICATION_SYSTEMS = frozenset({"microsoft", "outlook", "teams"})
_MICROSOFT_READ_SCOPES = frozenset(
    {"User.Read", "Mail.Read", "Chat.Read", "Sites.Read.All", "Notes.Read"}
)
_MICROSOFT_EFFECT_SCOPES = frozenset(
    {
        "User.Read",
        "Sites.ReadWrite.All",
        "Mail.ReadWrite",
        "Mail.Send",
        "Chat.Read",
        "ChatMessage.Send",
    }
)
_READ_FIXTURE_ENV = (
    "MASTER_AGENT_LIVE_JIRA_ISSUE_ID",
    "MASTER_AGENT_LIVE_CONFLUENCE_PAGE_ID",
    "MASTER_AGENT_LIVE_BITBUCKET_WORKSPACE",
    "MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY",
    "MASTER_AGENT_LIVE_GITHUB_OWNER",
    "MASTER_AGENT_LIVE_GITHUB_REPOSITORY",
    "MASTER_AGENT_LIVE_MICROSOFT_IDENTITY",
    "MASTER_AGENT_LIVE_SHAREPOINT_SITE_ID",
    "MASTER_AGENT_LIVE_OUTLOOK_MESSAGE_ID",
    "MASTER_AGENT_LIVE_TEAMS_CHAT_ID",
    "MASTER_AGENT_LIVE_TEAMS_MESSAGE_ID",
    "MASTER_AGENT_LIVE_ONENOTE_PAGE_ID",
)
_EFFECT_FIXTURE_ENV = (
    "MASTER_AGENT_LIVE_RUN_ID",
    "MASTER_AGENT_LIVE_JIRA_ISSUE_ID",
    "MASTER_AGENT_LIVE_CONFLUENCE_SPACE_ID",
    "MASTER_AGENT_LIVE_BITBUCKET_WORKSPACE",
    "MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY",
    "MASTER_AGENT_LIVE_BITBUCKET_SOURCE_BRANCH",
    "MASTER_AGENT_LIVE_BITBUCKET_DESTINATION_BRANCH",
    "MASTER_AGENT_LIVE_GITHUB_OWNER",
    "MASTER_AGENT_LIVE_GITHUB_REPOSITORY",
    "MASTER_AGENT_LIVE_MICROSOFT_IDENTITY",
    "MASTER_AGENT_LIVE_SHAREPOINT_DRIVE_ID",
    "MASTER_AGENT_LIVE_SHAREPOINT_ITEM_ID",
    "MASTER_AGENT_LIVE_OUTLOOK_RECIPIENT",
    "MASTER_AGENT_LIVE_TEAMS_CHAT_ID",
)
_ADMIN_FIXTURE_ENV = (
    "MASTER_AGENT_LIVE_RUN_ID",
    "MASTER_AGENT_LIVE_GITHUB_ADMIN_OWNER",
    "MASTER_AGENT_LIVE_GITHUB_ADMIN_REPOSITORY",
)
_RECOVERY_SCHEMA = "master-agent/live-connector-recovery@1"
_RECOVERY_MAX_ENTRIES = 8
_RECOVERY_MAX_BYTES = 1024 * 1024
_RECOVERY_CAPABILITIES = frozenset(
    {
        "jira.issue.comment.create",
        "confluence.page.create",
        "bitbucket.pull_request.create",
        "github.issue.create",
        "sharepoint.file.upload",
        "github.repository.settings.update",
    }
)
_RECOVERY_MODES = frozenset({"effects", "admin"})
_SECRET_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
_GITHUB_ADMIN_SETTINGS = frozenset(
    {
        "has_issues",
        "has_projects",
        "has_wiki",
        "has_discussions",
        "allow_squash_merge",
        "allow_merge_commit",
        "allow_rebase_merge",
        "allow_auto_merge",
        "delete_branch_on_merge",
        "web_commit_signoff_required",
    }
)


@unittest.skipUnless(
    os.environ.get("MASTER_AGENT_RUN_LIVE_CONNECTOR_TESTS") == "1",
    "credentialed live connector tests are opt-in",
)
class CredentialedReadConnectorIntegrationTests(unittest.TestCase):
    """Use real credentials and provider requests for every read connector."""

    config: IntegrationConfig
    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = _load_live_config()
        _preflight_read_environment(cls.config)
        cls.temporary_directory = _private_temporary_directory()
        root = Path(cls.temporary_directory.name)
        cls.registry = build_live_registry(
            cls.config,
            environ=os.environ,
            systems=set(_READ_SYSTEMS),
            include_writes=False,
            include_communications=False,
            workspace_root=root,
            artifact_root=root,
        )
        for system, connector_type in _READ_CONNECTOR_TYPES.items():
            _connector(cls.registry, system, connector_type)

    @classmethod
    def tearDownClass(cls) -> None:
        _close_connectors(cls.registry)
        cls.temporary_directory.cleanup()

    def test_every_read_connector_reaches_its_real_provider(self) -> None:
        """Run each connector's fixed credentialed provider probe."""

        for system, connector_type in _READ_CONNECTOR_TYPES.items():
            with self.subTest(system=system):
                if system == "github" and _github_actions_token_selected():
                    continue
                connector = _connector(self.registry, system, connector_type)
                probe = connector.probe()
                self.assertTrue(probe.get("reachable"))
                reference = probe.get("reference")
                self.assertIsInstance(reference, str)
                self.assertTrue(str(reference).startswith("https://"))

    def test_every_read_connector_executes_and_independently_verifies(self) -> None:
        """Exercise one stable typed read and provider re-read per connector."""

        for action in _read_actions():
            with self.subTest(
                system=action.target.system, capability=action.capability
            ):
                connector = self.registry.resolve(
                    action.target.system,
                    action.capability,
                )
                result = connector.execute(action)
                self.assertIsNotNone(result.after)
                self.assertTrue(
                    connector.verify(action, result).verified,
                    msg=f"provider re-read failed for {action.capability}",
                )
                self.assertTrue(result.connector_reference.startswith("https://"))


@unittest.skipUnless(
    os.environ.get("MASTER_AGENT_RUN_LIVE_EFFECT_TESTS") == "1",
    "credentialed live connector effect tests are opt-in",
)
class CredentialedEffectConnectorIntegrationTests(unittest.TestCase):
    """Exercise reversible sandbox writes before any communication is sent."""

    config: IntegrationConfig
    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]
    artifact_root: Path
    recovery_root: Path
    run_label: str

    @classmethod
    def setUpClass(cls) -> None:
        _require_exact_env("MASTER_AGENT_LIVE_NON_PRODUCTION", "true")
        cls.config = _load_live_config()
        _preflight_effect_environment(cls.config)
        cls.recovery_root = _private_recovery_root()
        cls.temporary_directory = _private_temporary_directory()
        cls.artifact_root = Path(cls.temporary_directory.name)
        cls.run_label = _required_env("MASTER_AGENT_LIVE_RUN_ID")
        cls.registry = build_live_registry(
            cls.config,
            environ=os.environ,
            systems=set(_EFFECT_SYSTEMS),
            include_writes=True,
            include_communications=False,
            workspace_root=cls.artifact_root,
            artifact_root=cls.artifact_root,
        )
        for connector_type in _EFFECT_CONNECTOR_TYPES:
            _connector_by_type(cls.registry, connector_type)
        _probe_selected_connectors(cls.registry, _EFFECT_SYSTEMS)

    @classmethod
    def tearDownClass(cls) -> None:
        _close_connectors(cls.registry)
        cls.temporary_directory.cleanup()

    def test_jira_comment_create_verify_and_delete(self) -> None:
        connector = _connector_by_type(self.registry, JiraWriteConnector)
        action = action_for(
            "jira.issue.comment.create",
            system="jira",
            resource_type="issue",
            resource_id=_required_env("MASTER_AGENT_LIVE_JIRA_ISSUE_ID"),
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "body": (
                    "MasterAgent credentialed integration test "
                    f"{self.run_label}. This comment should be deleted automatically."
                )
            },
        )
        self._execute_verify_and_compensate(connector, action)

    def test_confluence_page_create_verify_and_delete(self) -> None:
        connector = _connector_by_type(self.registry, ConfluenceWriteConnector)
        parameters: dict[str, object] = {
            "title": f"MasterAgent integration {self.run_label}",
            "body": (
                "<p>Credentialed MasterAgent integration test. "
                "This page should be deleted automatically.</p>"
            ),
            "representation": "storage",
            "status": "current",
            "space_id": _required_env("MASTER_AGENT_LIVE_CONFLUENCE_SPACE_ID"),
        }
        parent_id = os.environ.get(
            "MASTER_AGENT_LIVE_CONFLUENCE_PARENT_ID",
            "",
        ).strip()
        if parent_id:
            parameters["parent_id"] = parent_id
        action = action_for(
            "confluence.page.create",
            system="confluence",
            resource_type="page",
            resource_id=f"integration-{self.run_label}",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters=parameters,
        )
        self._execute_verify_and_compensate(connector, action)

    def test_bitbucket_pull_request_create_verify_and_decline(self) -> None:
        connector = _connector_by_type(self.registry, BitbucketWriteConnector)
        action = action_for(
            "bitbucket.pull_request.create",
            system="bitbucket",
            resource_type="pull_request",
            resource_id=f"integration-{self.run_label}",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "workspace": _required_env("MASTER_AGENT_LIVE_BITBUCKET_WORKSPACE"),
                "repository": _required_env("MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY"),
                "title": f"MasterAgent integration {self.run_label}",
                "description": "Credentialed integration test; decline after verify.",
                "source_branch": _required_env(
                    "MASTER_AGENT_LIVE_BITBUCKET_SOURCE_BRANCH"
                ),
                "destination_branch": _required_env(
                    "MASTER_AGENT_LIVE_BITBUCKET_DESTINATION_BRANCH"
                ),
                "close_source_branch": False,
            },
        )
        self._execute_verify_and_compensate(connector, action)

    def test_github_issue_create_verify_and_close(self) -> None:
        connector = _connector_by_type(self.registry, GitHubWriteConnector)
        action = action_for(
            "github.issue.create",
            system="github",
            resource_type="issue",
            resource_id=f"integration-{self.run_label}",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "owner": _required_env("MASTER_AGENT_LIVE_GITHUB_OWNER"),
                "repository": _required_env("MASTER_AGENT_LIVE_GITHUB_REPOSITORY"),
                "title": f"MasterAgent integration {self.run_label}",
                "body": "Credentialed integration test; close after verification.",
            },
        )
        self._execute_verify_and_compensate(connector, action)

    def test_sharepoint_replace_verify_and_restore(self) -> None:
        connector = _connector_by_type(self.registry, SharePointWriteConnector)
        local_path = self.artifact_root / f"sharepoint-{self.run_label}.txt"
        payload = (
            f"MasterAgent credentialed SharePoint integration {self.run_label}\n"
        ).encode()
        local_path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        action = action_for(
            "sharepoint.file.upload",
            system="sharepoint",
            resource_type="file",
            resource_id=_required_env("MASTER_AGENT_LIVE_SHAREPOINT_ITEM_ID"),
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "drive_id": _required_env("MASTER_AGENT_LIVE_SHAREPOINT_DRIVE_ID"),
                "local_path": str(local_path),
                "local_sha256": digest,
                "content_type": "text/plain",
            },
        )
        self._execute_verify_and_compensate(connector, action)

    def _execute_verify_and_compensate(
        self,
        connector: object,
        action: AgentAction,
    ) -> None:
        _execute_verify_and_compensate(
            connector,
            action,
            recovery_root=self.recovery_root,
            run_label=self.run_label,
            mode="effects",
        )


@unittest.skipUnless(
    os.environ.get("MASTER_AGENT_RUN_LIVE_COMMUNICATION_TESTS") == "1",
    "credentialed live connector communication tests are opt-in",
)
class CredentialedCommunicationConnectorIntegrationTests(unittest.TestCase):
    """Send only after the workflow's reversible stage and recovery pass."""

    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]
    run_label: str

    @classmethod
    def setUpClass(cls) -> None:
        _require_exact_env("MASTER_AGENT_LIVE_NON_PRODUCTION", "true")
        config = _load_live_config()
        _preflight_communication_environment(config)
        cls.run_label = _required_env("MASTER_AGENT_LIVE_RUN_ID")
        cls.temporary_directory = _private_temporary_directory()
        root = Path(cls.temporary_directory.name)
        cls.registry = build_live_registry(
            config,
            environ=os.environ,
            systems=set(_COMMUNICATION_SYSTEMS),
            include_writes=False,
            include_communications=True,
            workspace_root=root,
            artifact_root=root,
        )
        _connector_by_type(cls.registry, OutlookSendConnector)
        _connector_by_type(cls.registry, TeamsSendConnector)
        _probe_selected_connectors(cls.registry, _COMMUNICATION_SYSTEMS)

    @classmethod
    def tearDownClass(cls) -> None:
        _close_connectors(cls.registry)
        cls.temporary_directory.cleanup()

    def test_outlook_sends_to_the_dedicated_test_recipient(self) -> None:
        connector = _connector_by_type(self.registry, OutlookSendConnector)
        identity = _required_env("MASTER_AGENT_LIVE_MICROSOFT_IDENTITY")
        action = action_for(
            "outlook.email.send",
            system="outlook",
            resource_type="message",
            resource_id=identity,
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={
                "identity": identity,
                "to": [_required_env("MASTER_AGENT_LIVE_OUTLOOK_RECIPIENT")],
                "subject": f"MasterAgent integration {self.run_label}",
                "body": (
                    "Credentialed MasterAgent Outlook integration test. "
                    f"Run: {self.run_label}"
                ),
                "content_type": "Text",
            },
        )
        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)

    def test_teams_posts_to_the_dedicated_test_chat(self) -> None:
        connector = _connector_by_type(self.registry, TeamsSendConnector)
        chat_id = _required_env("MASTER_AGENT_LIVE_TEAMS_CHAT_ID")
        action = action_for(
            "teams.chat.message.send",
            system="teams",
            resource_type="chat",
            resource_id=chat_id,
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={
                "chat_id": chat_id,
                "body": (
                    "Credentialed MasterAgent Teams integration test. "
                    f"Run: {self.run_label}"
                ),
                "content_type": "text",
            },
        )
        result = connector.execute(action)
        self.assertTrue(connector.verify(action, result).verified)


@unittest.skipUnless(
    os.environ.get("MASTER_AGENT_RUN_LIVE_GITHUB_ADMIN_TESTS") == "1",
    "credentialed GitHub administration integration test is opt-in",
)
class CredentialedGitHubAdminConnectorIntegrationTests(unittest.TestCase):
    """Toggle and restore one benign setting in a dedicated sandbox repository."""

    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]
    recovery_root: Path
    run_label: str

    @classmethod
    def setUpClass(cls) -> None:
        _require_exact_env(
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_NON_PRODUCTION",
            "true",
        )
        config = _load_live_config()
        _preflight_admin_environment(config)
        cls.recovery_root = _private_recovery_root()
        cls.run_label = _required_env("MASTER_AGENT_LIVE_RUN_ID")
        cls.temporary_directory = _private_temporary_directory()
        root = Path(cls.temporary_directory.name)
        cls.registry = build_live_registry(
            config,
            environ=os.environ,
            systems={"github"},
            include_writes=True,
            include_communications=False,
            workspace_root=root,
            artifact_root=root,
        )
        github_read = _connector(cls.registry, "github", GitHubConnector)
        probe = github_read.probe()
        if probe.get("reachable") is not True:
            raise AssertionError("GitHub admin credential identity preflight failed")
        _connector_by_type(cls.registry, GitHubAdminConnector)

    @classmethod
    def tearDownClass(cls) -> None:
        _close_connectors(cls.registry)
        cls.temporary_directory.cleanup()

    def test_repository_setting_update_verify_and_restore(self) -> None:
        connector = _connector_by_type(self.registry, GitHubAdminConnector)
        owner = _required_env("MASTER_AGENT_LIVE_GITHUB_ADMIN_OWNER")
        repository = _required_env("MASTER_AGENT_LIVE_GITHUB_ADMIN_REPOSITORY")
        setting = os.environ.get(
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_SETTING",
            "has_wiki",
        ).strip()
        if setting not in _GITHUB_ADMIN_SETTINGS:
            self.fail(f"unsupported GitHub administration test setting: {setting}")
        before = connector._read_settings(owner, repository)
        settings = before.get("settings")
        self.assertIsInstance(settings, dict)
        assert isinstance(settings, dict)
        current = settings.get(setting)
        self.assertIsInstance(current, bool)
        assert isinstance(current, bool)
        action = action_for(
            "github.repository.settings.update",
            system="github",
            resource_type="repository",
            resource_id=f"{owner}/{repository}",
            risk=RiskLevel.REVERSIBLE_WRITE,
            expected_version=str(before.get("version", "")),
            parameters={
                "owner": owner,
                "repository": repository,
                "settings": {setting: not current},
            },
        )
        _execute_verify_and_compensate(
            connector,
            action,
            recovery_root=self.recovery_root,
            run_label=self.run_label,
            mode="admin",
        )


def _read_actions() -> tuple[AgentAction, ...]:
    microsoft_identity = _required_env("MASTER_AGENT_LIVE_MICROSOFT_IDENTITY")
    return (
        read_action(
            "jira.issue.read",
            system="jira",
            resource_type="issue",
            resource_id=_required_env("MASTER_AGENT_LIVE_JIRA_ISSUE_ID"),
        ),
        read_action(
            "confluence.page.read",
            system="confluence",
            resource_type="page",
            resource_id=_required_env("MASTER_AGENT_LIVE_CONFLUENCE_PAGE_ID"),
        ),
        read_action(
            "bitbucket.repository.read",
            system="bitbucket",
            resource_type="repository",
            resource_id=_required_env("MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY"),
            parameters={
                "workspace": _required_env("MASTER_AGENT_LIVE_BITBUCKET_WORKSPACE"),
                "repository": _required_env("MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY"),
            },
        ),
        read_action(
            "github.repository.read",
            system="github",
            resource_type="repository",
            resource_id=_required_env("MASTER_AGENT_LIVE_GITHUB_REPOSITORY"),
            parameters={
                "owner": _required_env("MASTER_AGENT_LIVE_GITHUB_OWNER"),
                "repository": _required_env("MASTER_AGENT_LIVE_GITHUB_REPOSITORY"),
            },
        ),
        read_action(
            "microsoft.identity.read",
            system="microsoft",
            resource_type="user",
            resource_id=microsoft_identity,
        ),
        read_action(
            "sharepoint.site.read",
            system="sharepoint",
            resource_type="site",
            resource_id=_required_env("MASTER_AGENT_LIVE_SHAREPOINT_SITE_ID"),
        ),
        read_action(
            "outlook.message.read",
            system="outlook",
            resource_type="message",
            resource_id=_required_env("MASTER_AGENT_LIVE_OUTLOOK_MESSAGE_ID"),
            parameters={"identity": microsoft_identity},
        ),
        read_action(
            "teams.chat.message.read",
            system="teams",
            resource_type="message",
            resource_id=_required_env("MASTER_AGENT_LIVE_TEAMS_MESSAGE_ID"),
            parameters={"chat_id": _required_env("MASTER_AGENT_LIVE_TEAMS_CHAT_ID")},
        ),
        read_action(
            "onenote.page.read",
            system="onenote",
            resource_type="page",
            resource_id=_required_env("MASTER_AGENT_LIVE_ONENOTE_PAGE_ID"),
            parameters={"identity": microsoft_identity},
        ),
    )


def _load_live_config() -> IntegrationConfig:
    path = Path(_required_env("MASTER_AGENT_LIVE_INTEGRATIONS_FILE"))
    if not path.is_file():
        raise AssertionError(f"live integrations file does not exist: {path}")
    return IntegrationConfig.from_toml(path)


def _require_credentialed_provider_configs(
    config: IntegrationConfig,
    *,
    names: tuple[str, ...] = _PROVIDER_CONFIG_NAMES,
) -> None:
    problems: list[str] = []
    for name in names:
        connector = config.connectors.get(name)
        if connector is None:
            problems.append(f"missing connector configuration: {name}")
            continue
        if not connector.enabled:
            problems.append(f"connector is disabled: {name}")
        if connector.auth_mode is AuthMode.NONE:
            problems.append(f"connector uses auth_mode=none: {name}")
        problems.extend(
            f"{name}: {message}"
            for message in connector.configuration_errors(os.environ)
        )
    if problems:
        raise AssertionError("; ".join(problems))


def _preflight_read_environment(config: IntegrationConfig) -> None:
    """Validate every read-only gate and fixture before provider requests."""

    _require_credentialed_provider_configs(config)
    _require_fixture_environment(_READ_FIXTURE_ENV)
    _require_privilege_profile(config, mode="read")
    _require_microsoft_delegated_token(
        config,
        required_scopes=_MICROSOFT_READ_SCOPES,
        minimum_remaining_seconds=_required_job_lifetime_seconds(),
    )


def _preflight_effect_environment(config: IntegrationConfig) -> None:
    """Validate all reversible and communication gates before any mutation."""

    _require_credentialed_provider_configs(config)
    _require_fixture_environment(_EFFECT_FIXTURE_ENV)
    _require_privilege_profile(config, mode="effects")
    _require_microsoft_delegated_token(
        config,
        required_scopes=_MICROSOFT_EFFECT_SCOPES,
        minimum_remaining_seconds=_required_job_lifetime_seconds(),
    )


def _preflight_communication_environment(config: IntegrationConfig) -> None:
    """Re-check the delegated identity and dedicated targets before sends."""

    _require_credentialed_provider_configs(config, names=("microsoft",))
    _require_fixture_environment(
        (
            "MASTER_AGENT_LIVE_RUN_ID",
            "MASTER_AGENT_LIVE_MICROSOFT_IDENTITY",
            "MASTER_AGENT_LIVE_OUTLOOK_RECIPIENT",
            "MASTER_AGENT_LIVE_TEAMS_CHAT_ID",
        )
    )
    _require_privilege_profile(config, mode="effects")
    _require_microsoft_delegated_token(
        config,
        required_scopes=_MICROSOFT_EFFECT_SCOPES,
        minimum_remaining_seconds=_required_job_lifetime_seconds(),
    )


def _preflight_admin_environment(config: IntegrationConfig) -> None:
    """Validate the isolated GitHub admin profile and every target fixture."""

    _require_credentialed_provider_configs(config, names=("github",))
    _require_fixture_environment(_ADMIN_FIXTURE_ENV)
    _require_privilege_profile(config, mode="admin")


def _require_fixture_environment(names: Sequence[str]) -> None:
    missing = [name for name in names if not os.environ.get(name, "").strip()]
    if missing:
        raise AssertionError(
            "required live integration variables are missing: " + ", ".join(missing)
        )


def _required_job_lifetime_seconds() -> int:
    return _required_positive_int_env(
        "MASTER_AGENT_LIVE_JOB_TIMEOUT_SECONDS"
    ) + _required_positive_int_env("MASTER_AGENT_LIVE_CLEANUP_MARGIN_SECONDS")


def _required_positive_int_env(name: str) -> int:
    raw = _required_env(name)
    try:
        value = int(raw)
    except ValueError as error:
        raise AssertionError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise AssertionError(f"{name} must be a positive integer")
    return value


def _require_microsoft_delegated_token(
    config: IntegrationConfig,
    *,
    required_scopes: frozenset[str],
    minimum_remaining_seconds: int,
    now: datetime | None = None,
) -> None:
    connector = _configured_connector(config, "microsoft")
    if connector.auth_mode is not AuthMode.OAUTH_DELEGATED:
        raise AssertionError(
            "Microsoft integration tests require auth_mode=oauth_delegated"
        )
    oauth_flow = str(connector.extra.get("oauth_flow", "")).strip()
    identity_mode = str(connector.extra.get("identity_mode", "")).strip()
    token_file_env = str(connector.extra.get("token_file_env", "")).strip()
    if oauth_flow != "token_file" or identity_mode != "delegated":
        raise AssertionError(
            "Microsoft integration tests require delegated token_file authentication"
        )
    if token_file_env != "MASTER_AGENT_GRAPH_TOKEN_FILE":
        raise AssertionError(
            "Microsoft integration tests require the pinned token_file_env"
        )
    configured_scopes = _configured_scopes(connector)
    if configured_scopes != required_scopes:
        raise AssertionError(
            "Microsoft connector scopes must exactly match the integration profile: "
            f"expected {sorted(required_scopes)}, observed {sorted(configured_scopes)}"
        )
    token_path = Path(_required_env(token_file_env))
    token = RestrictedTokenFileProvider(token_path).get_token()
    token_scopes = frozenset(item.strip() for item in token.scopes if item.strip())
    if token_scopes != required_scopes:
        raise AssertionError(
            "Microsoft delegated token scopes must exactly match the integration "
            f"profile: expected {sorted(required_scopes)}, "
            f"observed {sorted(token_scopes)}"
        )
    current = now or datetime.now(UTC)
    remaining_seconds = (token.expires_at - current).total_seconds()
    if remaining_seconds < minimum_remaining_seconds:
        raise AssertionError(
            "Microsoft delegated token lifetime is shorter than the job timeout "
            f"plus cleanup reserve ({minimum_remaining_seconds} seconds required)"
        )


def _configured_scopes(connector: ConnectorConfig) -> frozenset[str]:
    raw = connector.extra.get("scopes", ())
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise TypeError("Microsoft connector scopes must be a string list")
    scopes = [str(item).strip() for item in raw]
    if not scopes or any(not item for item in scopes):
        raise AssertionError("Microsoft connector scopes must be a non-empty list")
    if len(scopes) != len(set(scopes)):
        raise AssertionError("Microsoft connector scopes must not contain duplicates")
    return frozenset(scopes)


def _require_privilege_profile(config: IntegrationConfig, *, mode: str) -> None:
    all_flags = {
        "jira": ("write_enabled", "writes_enabled"),
        "confluence": ("write_enabled", "writes_enabled"),
        "bitbucket": (
            "write_enabled",
            "pull_request_writes_enabled",
            "branch_push_enabled",
        ),
        "github": ("write_enabled", "writes_enabled", "admin_enabled"),
        "microsoft": (
            "write_enabled",
            "sharepoint_writes_enabled",
            "send_enabled",
            "outlook_send_enabled",
            "teams_send_enabled",
        ),
    }
    if mode == "read":
        for system, flags in all_flags.items():
            _require_feature_flags(
                _configured_connector(config, system),
                disabled=frozenset(flags),
            )
        return
    if mode == "effects":
        _require_feature_flags(
            _configured_connector(config, "jira"),
            enabled=frozenset({"write_enabled", "writes_enabled"}),
        )
        _require_feature_flags(
            _configured_connector(config, "confluence"),
            enabled=frozenset({"write_enabled", "writes_enabled"}),
        )
        _require_feature_flags(
            _configured_connector(config, "bitbucket"),
            enabled=frozenset({"write_enabled", "pull_request_writes_enabled"}),
            disabled=frozenset({"branch_push_enabled"}),
        )
        _require_feature_flags(
            _configured_connector(config, "github"),
            enabled=frozenset({"write_enabled", "writes_enabled"}),
            disabled=frozenset({"admin_enabled"}),
        )
        _require_feature_flags(
            _configured_connector(config, "microsoft"),
            enabled=frozenset(
                {
                    "write_enabled",
                    "sharepoint_writes_enabled",
                    "send_enabled",
                    "outlook_send_enabled",
                    "teams_send_enabled",
                }
            ),
        )
        return
    if mode == "admin":
        _require_feature_flags(
            _configured_connector(config, "github"),
            enabled=frozenset({"write_enabled", "admin_enabled"}),
            disabled=frozenset({"writes_enabled"}),
        )
        return
    raise AssertionError(f"unsupported live integration privilege mode: {mode}")


def _require_feature_flags(
    connector: ConnectorConfig,
    *,
    enabled: frozenset[str] = frozenset(),
    disabled: frozenset[str] = frozenset(),
) -> None:
    overlap = enabled & disabled
    if overlap:
        raise AssertionError(f"contradictory feature flags: {sorted(overlap)}")
    problems: list[str] = []
    for flag in sorted(enabled):
        if connector.extra.get(flag) is not True:
            problems.append(f"{connector.system}.{flag} must be true")
    for flag in sorted(disabled):
        if connector.extra.get(flag, False) is not False:
            problems.append(f"{connector.system}.{flag} must be false")
    if problems:
        raise AssertionError("; ".join(problems))


def _configured_connector(config: IntegrationConfig, system: str) -> ConnectorConfig:
    connector = config.connectors.get(system)
    if connector is None:
        raise AssertionError(f"missing connector configuration: {system}")
    return connector


def _github_actions_token_selected() -> bool:
    return (
        os.environ.get("MASTER_AGENT_LIVE_GITHUB_ACTIONS_TOKEN", "").strip().lower()
        == "true"
    )


def _probe_selected_connectors(
    registry: ConnectorRegistry,
    systems: Sequence[str] | frozenset[str],
) -> None:
    for system in sorted(systems):
        if system == "github" and _github_actions_token_selected():
            connector = _connector(registry, system, GitHubConnector)
            action = read_action(
                "github.repository.read",
                system="github",
                resource_type="repository",
                resource_id=_required_env("MASTER_AGENT_LIVE_GITHUB_REPOSITORY"),
                parameters={
                    "owner": _required_env("MASTER_AGENT_LIVE_GITHUB_OWNER"),
                    "repository": _required_env("MASTER_AGENT_LIVE_GITHUB_REPOSITORY"),
                },
            )
            result = connector.execute(action)
            if connector.verify(action, result).verified is not True:
                raise AssertionError("provider preflight failed for github")
            continue
        connector_type = _READ_CONNECTOR_TYPES[system]
        connector = _connector(registry, system, connector_type)
        probe = connector.probe()
        if probe.get("reachable") is not True:
            raise AssertionError(f"provider preflight failed for {system}")


def _execute_verify_and_compensate(
    connector: Any,
    action: AgentAction,
    *,
    recovery_root: Path,
    run_label: str,
    mode: str,
) -> None:
    """Run and compensate one effect with a durable returned-result boundary.

    A provider commit followed by a lost response cannot be located generically:
    no provider identifier exists until ``execute`` returns. Such failures remain
    visible operator cleanup work instead of being falsely marked recoverable.
    """

    result = connector.execute(action)
    entry_path: Path | None = None
    try:
        entry_path = _write_recovery_entry(
            recovery_root,
            action,
            result,
            run_label=run_label,
            mode=mode,
        )
        verification = connector.verify(action, result)
        if verification.verified is not True:
            raise AssertionError(f"provider re-read failed for {action.capability}")
    finally:
        compensation = connector.compensate(action, result)
        verified = connector.verify_compensation(action, result, compensation)
        if verified.verified is not True:
            raise AssertionError(
                f"provider compensation failed for {action.capability}"
            )
        if entry_path is not None:
            _remove_recovery_entry(recovery_root, entry_path)


def _write_recovery_entry(
    root: Path,
    action: AgentAction,
    result: ExecutionResult,
    *,
    run_label: str,
    mode: str,
) -> Path:
    _validate_recovery_mode(mode)
    _validate_private_recovery_root(root)
    if action.capability not in _recovery_capabilities(mode):
        raise AssertionError(
            f"capability is not recoverable in {mode} mode: {action.capability}"
        )
    if result.action_id != action.action_id:
        raise AssertionError("recovery result action ID does not match its action")
    if len(_recovery_entry_paths(root, mode=mode)) >= _RECOVERY_MAX_ENTRIES:
        raise AssertionError("live connector recovery journal is full")
    payload: dict[str, object] = {
        "schema": _RECOVERY_SCHEMA,
        "mode": mode,
        "run_label": run_label,
        "action": action.to_dict(),
        "result": result.to_dict(),
    }
    _reject_recovery_secret_keys(payload)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > _RECOVERY_MAX_BYTES:
        raise AssertionError("live connector recovery entry is too large")
    path = root / f"recovery-{mode}-{action.action_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("recovery journal write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        _validate_recovery_file_stat(os.fstat(descriptor), path)
    finally:
        os.close(descriptor)
    return path


def _replay_recovery_entries(
    registry: ConnectorRegistry,
    root: Path,
    *,
    run_label: str,
    mode: str,
) -> int:
    recovered = 0
    for path in _recovery_entry_paths(root, mode=mode):
        action, result = _read_recovery_entry(
            path,
            expected_run_label=run_label,
            expected_mode=mode,
        )
        connector = registry.resolve(action.target.system, action.capability)
        compensation = connector.compensate(action, result)
        verification = connector.verify_compensation(action, result, compensation)
        if verification.verified is not True:
            raise AssertionError(
                f"recovery compensation could not be verified: {action.capability}"
            )
        _remove_recovery_entry(root, path)
        recovered += 1
    return recovered


def _read_recovery_entry(
    path: Path,
    *,
    expected_run_label: str,
    expected_mode: str,
) -> tuple[AgentAction, ExecutionResult]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        _validate_recovery_file_stat(file_stat, path)
        if file_stat.st_size > _RECOVERY_MAX_BYTES:
            raise AssertionError(f"recovery entry is too large: {path.name}")
        raw_bytes = b""
        while len(raw_bytes) <= _RECOVERY_MAX_BYTES:
            chunk = os.read(descriptor, min(65536, _RECOVERY_MAX_BYTES + 1))
            if not chunk:
                break
            raw_bytes += chunk
    finally:
        os.close(descriptor)
    if len(raw_bytes) > _RECOVERY_MAX_BYTES:
        raise AssertionError(f"recovery entry is too large: {path.name}")
    try:
        payload = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(f"recovery entry is invalid JSON: {path.name}") from error
    if not isinstance(payload, Mapping):
        raise TypeError(f"recovery entry must be an object: {path.name}")
    expected_keys = {"schema", "mode", "run_label", "action", "result"}
    if set(payload) != expected_keys or payload.get("schema") != _RECOVERY_SCHEMA:
        raise AssertionError(f"recovery entry schema is invalid: {path.name}")
    if payload.get("mode") != expected_mode:
        raise AssertionError(f"recovery entry mode does not match: {path.name}")
    if payload.get("run_label") != expected_run_label:
        raise AssertionError(f"recovery entry run label does not match: {path.name}")
    action_raw = payload.get("action")
    result_raw = payload.get("result")
    if not isinstance(action_raw, Mapping) or not isinstance(result_raw, Mapping):
        raise TypeError(f"recovery entry payload is invalid: {path.name}")
    _reject_recovery_secret_keys(payload)
    action = AgentAction.from_dict(action_raw)
    result = ExecutionResult.from_dict(result_raw)
    if action.capability not in _recovery_capabilities(expected_mode):
        raise AssertionError(f"recovery capability is not allowed: {action.capability}")
    if action.action_id != result.action_id:
        raise AssertionError("recovery result action ID does not match its action")
    expected_name = f"recovery-{expected_mode}-{action.action_id}.json"
    if path.name != expected_name:
        raise AssertionError(f"recovery entry name does not match payload: {path.name}")
    return action, result


def _recovery_entry_paths(root: Path, *, mode: str) -> tuple[Path, ...]:
    _validate_recovery_mode(mode)
    _validate_private_recovery_root(root)
    entries = sorted(root.iterdir(), key=lambda item: item.name)
    if len(entries) > _RECOVERY_MAX_ENTRIES:
        raise AssertionError("live connector recovery journal exceeds its entry bound")
    prefix = f"recovery-{mode}-"
    for path in entries:
        if not path.name.startswith(prefix) or not path.name.endswith(".json"):
            raise AssertionError(
                f"unexpected file in live connector recovery journal: {path.name}"
            )
        _validate_recovery_file_stat(path.lstat(), path)
    return tuple(entries)


def _remove_recovery_entry(root: Path, path: Path) -> None:
    _validate_private_recovery_root(root)
    if path.parent != root or path.name not in {
        item.name for item in _recovery_entry_paths(root, mode=_mode_from_path(path))
    }:
        raise AssertionError("recovery entry is outside the private journal")
    path.unlink()


def _mode_from_path(path: Path) -> str:
    for mode in sorted(_RECOVERY_MODES):
        if path.name.startswith(f"recovery-{mode}-"):
            return mode
    raise AssertionError(f"recovery entry has an unsupported name: {path.name}")


def _validate_private_recovery_root(root: Path) -> None:
    if not root.is_absolute():
        raise AssertionError("live connector recovery root must be absolute")
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise AssertionError("live connector recovery root is unavailable") from error
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        raise AssertionError("live connector recovery root must be a real directory")
    mode = stat.S_IMODE(root_stat.st_mode)
    if mode != 0o700:
        raise AssertionError("live connector recovery root must have mode 0700")
    if hasattr(os, "getuid") and root_stat.st_uid != os.getuid():
        raise AssertionError("live connector recovery root must be owned by this user")


def _validate_recovery_file_stat(file_stat: os.stat_result, path: Path) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise AssertionError(f"recovery entry must be a regular file: {path.name}")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise AssertionError(f"recovery entry must have mode 0600: {path.name}")
    if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
        raise AssertionError(f"recovery entry must be owned by this user: {path.name}")


def _reject_recovery_secret_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).casefold().replace("_", "").replace("-", "")
            if any(fragment in key for fragment in _SECRET_KEY_FRAGMENTS):
                raise AssertionError(
                    "recovery entry contains a credential-like field name"
                )
            _reject_recovery_secret_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_recovery_secret_keys(item)


def _recovery_capabilities(mode: str) -> frozenset[str]:
    _validate_recovery_mode(mode)
    if mode == "admin":
        return frozenset({"github.repository.settings.update"})
    return _RECOVERY_CAPABILITIES - {"github.repository.settings.update"}


def _validate_recovery_mode(mode: str) -> None:
    if mode not in _RECOVERY_MODES:
        raise AssertionError(f"unsupported live connector recovery mode: {mode}")


def _private_recovery_root() -> Path:
    root = Path(_required_env("MASTER_AGENT_LIVE_RECOVERY_ROOT"))
    _validate_private_recovery_root(root)
    return root


def _recover_live_effects(mode: str) -> int:
    root = _private_recovery_root()
    run_label = _required_env("MASTER_AGENT_LIVE_RUN_ID")
    if not _recovery_entry_paths(root, mode=mode):
        return 0
    config = _load_live_config()
    if mode == "effects":
        _require_exact_env("MASTER_AGENT_LIVE_NON_PRODUCTION", "true")
        _require_credentialed_provider_configs(config)
        _require_privilege_profile(config, mode="effects")
        _require_microsoft_delegated_token(
            config,
            required_scopes=_MICROSOFT_EFFECT_SCOPES,
            minimum_remaining_seconds=0,
        )
        systems = set(_EFFECT_SYSTEMS)
    else:
        _require_exact_env(
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_NON_PRODUCTION",
            "true",
        )
        _require_credentialed_provider_configs(config, names=("github",))
        _require_privilege_profile(config, mode="admin")
        systems = {"github"}
    temporary_directory = _private_temporary_directory()
    root_path = Path(temporary_directory.name)
    registry = build_live_registry(
        config,
        environ=os.environ,
        systems=systems,
        include_writes=True,
        include_communications=False,
        workspace_root=root_path,
        artifact_root=root_path,
    )
    try:
        _replay_recovery_entries(
            registry,
            root,
            run_label=run_label,
            mode=mode,
        )
    finally:
        _close_connectors(registry)
        temporary_directory.cleanup()
    return 0


def _connector(
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


def _connector_by_type(
    registry: ConnectorRegistry,
    connector_type: type[object],
) -> object:
    matches = [
        connector
        for connector in registry.connectors()
        if isinstance(connector, connector_type)
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"expected one {connector_type.__name__}, found {len(matches)}"
        )
    return matches[0]


def _close_connectors(registry: ConnectorRegistry) -> None:
    for connector in registry.connectors():
        if isinstance(connector, ClosableConnector):
            connector.close()


def _private_temporary_directory() -> tempfile.TemporaryDirectory[str]:
    directory = tempfile.TemporaryDirectory(prefix="master-agent-live-")
    Path(directory.name).chmod(0o700)
    return directory


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise AssertionError(f"required live integration variable is missing: {name}")
    return value


def _require_exact_env(name: str, expected: str) -> None:
    observed = os.environ.get(name, "").strip().lower()
    if observed != expected.lower():
        raise AssertionError(f"{name} must equal {expected!r} for this live test")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "recover":
        parser = argparse.ArgumentParser(
            description="Recover returned live connector effects for this run."
        )
        parser.add_argument("command", choices=("recover",))
        parser.add_argument(
            "--mode", choices=tuple(sorted(_RECOVERY_MODES)), required=True
        )
        arguments = parser.parse_args()
        raise SystemExit(_recover_live_effects(arguments.mode))
    unittest.main()
