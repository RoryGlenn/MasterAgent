"""Credentialed live integration tests for external connector implementations."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from master_agent.auth import AuthMode
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
    OutlookSendConnector,
    TeamsSendConnector,
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
        _require_credentialed_provider_configs(cls.config)
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
    """Exercise real sandbox writes, compensation, and communications."""

    config: IntegrationConfig
    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]
    artifact_root: Path
    run_label: str

    @classmethod
    def setUpClass(cls) -> None:
        _require_exact_env("MASTER_AGENT_LIVE_NON_PRODUCTION", "true")
        cls.config = _load_live_config()
        _require_credentialed_provider_configs(cls.config)
        cls.temporary_directory = _private_temporary_directory()
        cls.artifact_root = Path(cls.temporary_directory.name)
        cls.run_label = os.environ.get("MASTER_AGENT_LIVE_RUN_ID", "").strip()
        if not cls.run_label:
            cls.run_label = f"local-{uuid4().hex[:12]}"
        cls.registry = build_live_registry(
            cls.config,
            environ=os.environ,
            systems=set(_READ_SYSTEMS),
            include_writes=True,
            include_communications=True,
            workspace_root=cls.artifact_root,
            artifact_root=cls.artifact_root,
        )
        for connector_type in _EFFECT_CONNECTOR_TYPES:
            _connector_by_type(cls.registry, connector_type)

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

    def test_outlook_sends_to_the_dedicated_test_recipient(self) -> None:
        connector = _connector_by_type(self.registry, OutlookSendConnector)
        identity = os.environ.get("MASTER_AGENT_LIVE_MICROSOFT_IDENTITY", "me").strip()
        action = action_for(
            "outlook.email.send",
            system="outlook",
            resource_type="message",
            resource_id=identity or "me",
            risk=RiskLevel.EXTERNAL_COMMUNICATION,
            parameters={
                "identity": identity or "me",
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

    def _execute_verify_and_compensate(
        self,
        connector: object,
        action: AgentAction,
    ) -> None:
        result: ExecutionResult | None = None
        try:
            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
        finally:
            if result is not None:
                compensation = connector.compensate(action, result)
                self.assertTrue(
                    connector.verify_compensation(
                        action,
                        result,
                        compensation,
                    ).verified
                )


@unittest.skipUnless(
    os.environ.get("MASTER_AGENT_RUN_LIVE_GITHUB_ADMIN_TESTS") == "1",
    "credentialed GitHub administration integration test is opt-in",
)
class CredentialedGitHubAdminConnectorIntegrationTests(unittest.TestCase):
    """Toggle and restore one benign setting in a dedicated sandbox repository."""

    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        _require_exact_env(
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_NON_PRODUCTION",
            "true",
        )
        config = _load_live_config()
        _require_credentialed_provider_configs(config, names=("github",))
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
        result: ExecutionResult | None = None
        try:
            result = connector.execute(action)
            self.assertTrue(connector.verify(action, result).verified)
        finally:
            if result is not None:
                compensation = connector.compensate(action, result)
                self.assertTrue(
                    connector.verify_compensation(
                        action,
                        result,
                        compensation,
                    ).verified
                )


def _read_actions() -> tuple[AgentAction, ...]:
    microsoft_identity = (
        os.environ.get(
            "MASTER_AGENT_LIVE_MICROSOFT_IDENTITY",
            "me",
        ).strip()
        or "me"
    )
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
    unittest.main()
