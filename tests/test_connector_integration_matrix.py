"""Credentialed live integration tests for external connector implementations."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from master_agent.auth import AuthMode
from master_agent.config import (
    ConnectorConfig,
    ConnectorCredentialProvider,
    ConnectorImplementation,
    DeploymentType,
    IntegrationConfig,
)
from master_agent.config_sources import ConfigSnapshot
from master_agent.connectors.base import ClosableConnector
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.communications import (
    OutlookSendConnector,
    TeamsSendConnector,
)
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.confluence_write import ConfluenceWriteConnector
from master_agent.connectors.drafts import write_artifact_bundle
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
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError
from master_agent.execution_context import (
    capture_connector_executions,
    preflight_connector_implementations,
)
from master_agent.models import (
    ActionState,
    AgentAction,
    ChangePlan,
    DataClassification,
    ExecutionResult,
    RiskLevel,
)
from master_agent.oauth import RestrictedTokenFileProvider
from master_agent.operating import OperatingMode, OrganizationProfile
from master_agent.orchestrator import RunReport
from master_agent.performance import (
    NATIVE_CONNECTOR_IMPLEMENTATION,
    MeasurementMode,
    PerformanceCase,
    PerformanceCounter,
    PerformanceOutcome,
    PerformanceSnapshot,
    ProviderActivity,
    bounded_capability,
)
from master_agent.registry import ConnectorRegistry
from master_agent.workflows.engineering_work_item_review import (
    MANIFEST_SCHEMA as T1_EWIR_MANIFEST_SCHEMA,
)
from master_agent.workflows.engineering_work_item_review import (
    WORKFLOW_ID as T1_EWIR_WORKFLOW_ID,
)
from master_agent.workflows.engineering_work_item_review import (
    WORKFLOW_SCHEMA as T1_EWIR_WORKFLOW_SCHEMA,
)
from master_agent.workflows.engineering_work_item_review import (
    EngineeringWorkItemReviewSettings,
    build_engineering_work_item_review_plan,
    validate_engineering_work_item_review_plan,
)
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
_T1_EWIR_CONFIG_FILES = (
    "engineering-work-item-review.toml",
    "integrations.toml",
    "organization-profile.toml",
)
_T1_EWIR_EXPECTED_CREDENTIAL_REFERENCES = {
    "jira": ("MASTER_AGENT_JIRA_USERNAME", "MASTER_AGENT_JIRA_TOKEN"),
    "confluence": (
        "MASTER_AGENT_CONFLUENCE_USERNAME",
        "MASTER_AGENT_CONFLUENCE_TOKEN",
    ),
    "bitbucket": (
        "MASTER_AGENT_BITBUCKET_EMAIL",
        "MASTER_AGENT_BITBUCKET_TOKEN",
    ),
}
_T1_EWIR_PROFILE_SCHEMA = "master-agent/organization-profile@1"
_T1_EWIR_ROOT_PATTERN = re.compile(
    r"master-agent-live-t1-ewir-[1-9][0-9]{0,19}-[1-9][0-9]{0,9}"
)
_T1_EWIR_RUN_PATTERN = re.compile(r"[0-9a-f]{32}")
_T1_EWIR_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_T1_EWIR_MAX_CONFIG_BYTES = 512 * 1024
_T1_EWIR_MAX_RESULT_BYTES = 32 * 1024 * 1024
_T1_EWIR_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_T1_EWIR_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024


class Tier1ProtectedLiveHarnessTests(unittest.TestCase):
    """Exercise fail-closed Tier-1 preparation and evidence readback offline."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.runner_temp = Path(self.temporary_directory.name).resolve()
        self.runner_temp.chmod(0o700)
        self.environ = _t1_ewir_test_environment(self.runner_temp)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @property
    def root(self) -> Path:
        return self.runner_temp / "master-agent-live-t1-ewir-123-1"

    def test_prepare_creates_only_the_three_fixed_private_configuration_files(
        self,
    ) -> None:
        _prepare_t1_ewir_live_case(self.root, environ=self.environ)

        self.assertEqual(
            {item.name for item in self.root.iterdir()},
            set(_T1_EWIR_CONFIG_FILES),
        )
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for path in self.root.iterdir():
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        profile = OrganizationProfile.from_toml(self.root / "organization-profile.toml")
        self.assertIs(profile.mode, OperatingMode.EMPLOYEE)
        settings = EngineeringWorkItemReviewSettings.from_toml(
            self.root / "engineering-work-item-review.toml"
        )
        plan = build_engineering_work_item_review_plan("ENG-1", settings)
        self.assertEqual(profile.capabilities, _t1_ewir_plan_dimensions(plan)[0])

    def test_prepare_rejects_extra_page_and_diffstat_before_provider_use(self) -> None:
        self.environ["T1_EWIR_WORKFLOW_TOML"] = self.environ[
            "T1_EWIR_WORKFLOW_TOML"
        ].replace('page_ids = ["11"]', 'page_ids = ["11", "12"]')
        with self.assertRaisesRegex(AssertionError, "exactly one Confluence"):
            _prepare_t1_ewir_live_case(self.root, environ=self.environ)

        second = self.runner_temp / "master-agent-live-t1-ewir-123-2"
        self.environ["GITHUB_RUN_ATTEMPT"] = "2"
        self.environ["T1_EWIR_WORKFLOW_TOML"] = self.environ[
            "T1_EWIR_WORKFLOW_TOML"
        ].replace('page_ids = ["11", "12"]', 'page_ids = ["11"]')
        self.environ["T1_EWIR_WORKFLOW_TOML"] = self.environ[
            "T1_EWIR_WORKFLOW_TOML"
        ].replace("include_diffstat = false", "include_diffstat = true")
        with self.assertRaisesRegex(AssertionError, "forbids diffstat"):
            _prepare_t1_ewir_live_case(second, environ=self.environ)

    def test_prepare_rejects_write_capability_and_unselected_credential(self) -> None:
        self.environ["LIVE_INTEGRATIONS_TOML"] = self.environ[
            "LIVE_INTEGRATIONS_TOML"
        ].replace("writes_enabled = false", "writes_enabled = true", 1)
        with self.assertRaisesRegex(AssertionError, "writes_enabled must be false"):
            _prepare_t1_ewir_live_case(self.root, environ=self.environ)

        second = self.runner_temp / "master-agent-live-t1-ewir-123-2"
        self.environ["GITHUB_RUN_ATTEMPT"] = "2"
        self.environ["LIVE_INTEGRATIONS_TOML"] = _t1_ewir_test_integrations().replace(
            'secret_env = "MASTER_AGENT_BITBUCKET_TOKEN"',
            'secret_env = "MASTER_AGENT_GITHUB_TOKEN"',
        )
        self.environ["MASTER_AGENT_GITHUB_TOKEN"] = "unselected-canary"
        with self.assertRaisesRegex(ConfigurationError, "unapproved secret_env"):
            _prepare_t1_ewir_live_case(second, environ=self.environ)

    def test_cli_failure_is_fixed_and_does_not_emit_exception_content(self) -> None:
        error_output = io.StringIO()
        canary = "https://private.example/fixture?token=secret-canary"
        with (
            patch(
                f"{__name__}._prepare_t1_ewir_live_case",
                side_effect=RuntimeError(canary),
            ),
            redirect_stderr(error_output),
        ):
            status = _run_t1_ewir_harness_command(
                ("prepare-t1-ewir", "--root", str(self.root))
            )

        self.assertEqual(status, 1)
        self.assertEqual(
            error_output.getvalue(),
            "T1-EWIR-001 protected preflight failed\n",
        )
        self.assertNotIn(canary, error_output.getvalue())


def _t1_ewir_test_environment(runner_temp: Path) -> dict[str, str]:
    return {
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": "a" * 40,
        "LIVE_INTEGRATIONS_TOML": _t1_ewir_test_integrations(),
        "T1_EWIR_WORKFLOW_TOML": _t1_ewir_test_workflow(),
        "ENTERPRISE_CA_BUNDLE_PEM": "",
        "MASTER_AGENT_LIVE_JIRA_ISSUE_ID": "ENG-1",
        "MASTER_AGENT_JIRA_USERNAME": "engineer@example.test",
        "MASTER_AGENT_JIRA_TOKEN": "jira-secret-canary",
        "MASTER_AGENT_CONFLUENCE_USERNAME": "engineer@example.test",
        "MASTER_AGENT_CONFLUENCE_TOKEN": "confluence-secret-canary",
        "MASTER_AGENT_BITBUCKET_EMAIL": "engineer@example.test",
        "MASTER_AGENT_BITBUCKET_TOKEN": "bitbucket-secret-canary",
        "MASTER_AGENT_PROXY_USERNAME": "",
        "MASTER_AGENT_PROXY_PASSWORD": "",
    }


def _t1_ewir_test_integrations() -> str:
    return """
[connectors.jira]
enabled = true
deployment = "cloud"
implementation = "native"
base_url = "https://acme.atlassian.net"
web_base_url = "https://acme.atlassian.net"
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
writes_enabled = false
write_enabled = false
review_acceptance_field_ids = ["customfield_10001"]

[connectors.confluence]
enabled = true
deployment = "cloud"
implementation = "native"
base_url = "https://acme.atlassian.net"
web_base_url = "https://acme.atlassian.net"
auth_mode = "basic"
username_env = "MASTER_AGENT_CONFLUENCE_USERNAME"
secret_env = "MASTER_AGENT_CONFLUENCE_TOKEN"
writes_enabled = false
write_enabled = false

[connectors.bitbucket]
enabled = true
deployment = "cloud"
implementation = "native"
base_url = "https://api.bitbucket.org/2.0"
web_base_url = "https://bitbucket.org"
auth_mode = "basic"
username_env = "MASTER_AGENT_BITBUCKET_EMAIL"
secret_env = "MASTER_AGENT_BITBUCKET_TOKEN"
max_items = 100
pull_request_writes_enabled = false
branch_push_enabled = false
write_enabled = false
""".lstrip()


def _t1_ewir_test_workflow() -> str:
    return """
[case]
id = "T1-EWIR-001"
data_classification = "internal"

[bitbucket]
deployment = "cloud"
origin = "https://bitbucket.org"
workspace = "acme"
repository = "widget"
pull_request_id = "7"
build_status_limit = 50
diffstat_limit = 50
include_diffstat = false

[confluence]
origin = "https://acme.atlassian.net"
space_id = "space-1"
space_key = "ENG"
page_ids = ["11"]
""".lstrip()


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


def _prepare_t1_ewir_live_case(
    root: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Create and preflight the narrow protected `T1-EWIR-001` case.

    This boundary performs no provider request. The command wrapper deliberately
    suppresses exception details so protected configuration values cannot enter
    a workflow log.
    """

    source = dict(environ if environ is not None else os.environ)
    _validate_t1_ewir_root_target(root, source)
    integrations_payload = _required_t1_payload(
        source,
        "LIVE_INTEGRATIONS_TOML",
        maximum=_T1_EWIR_MAX_CONFIG_BYTES,
    )
    workflow_payload = _required_t1_payload(
        source,
        "T1_EWIR_WORKFLOW_TOML",
        maximum=_T1_EWIR_MAX_CONFIG_BYTES,
    )
    issue_key = _required_t1_text(source, "MASTER_AGENT_LIVE_JIRA_ISSUE_ID")
    integrations_path = root / "integrations.toml"
    workflow_path = root / "engineering-work-item-review.toml"
    profile_path = root / "organization-profile.toml"
    _settings, integrations, profile_payload = _preflight_t1_ewir_payloads(
        root,
        issue_key=issue_key,
        environ=source,
        integrations_payload=integrations_payload,
        workflow_payload=workflow_payload,
        profile_payload=None,
        validate_environment=False,
    )

    ca_payload = source.get("ENTERPRISE_CA_BUNDLE_PEM", "")
    encoded_ca = ca_payload.encode("utf-8")
    if len(encoded_ca) > _T1_EWIR_MAX_CONFIG_BYTES:
        raise AssertionError("protected Tier-1 CA bundle is too large")
    if ca_payload:
        ca_path = _t1_ewir_sibling_path(root, "enterprise-ca.pem")
        source["MASTER_AGENT_ENTERPRISE_CA_BUNDLE"] = str(ca_path)
    else:
        source["MASTER_AGENT_ENTERPRISE_CA_BUNDLE"] = ""

    os.mkdir(root, mode=0o700)
    with PinnedDirectory.open(root) as pinned:
        published = write_artifact_bundle(
            pinned,
            (
                (integrations_path, integrations_payload, "application/toml"),
                (workflow_path, workflow_payload, "application/toml"),
                (profile_path, profile_payload, "application/toml"),
            ),
            max_output_bytes=_T1_EWIR_MAX_CONFIG_BYTES,
        )
        if len(published) != len(_T1_EWIR_CONFIG_FILES):
            raise AssertionError("protected Tier-1 configuration bundle is incomplete")
    command_output_path = _t1_ewir_sibling_path(root, "command-output.log")
    sibling_files = [(command_output_path, b"", "text/plain")]
    if encoded_ca:
        sibling_files.append((ca_path, encoded_ca, "application/x-pem-file"))
    with PinnedDirectory.open(root.parent, require_private=False) as runner_temp:
        write_artifact_bundle(
            runner_temp,
            sibling_files,
            max_output_bytes=_T1_EWIR_MAX_CONFIG_BYTES,
        )

    _validate_t1_ewir_connector_environment(integrations, source)
    _validate_t1_ewir_materialized_files(root, after_run=False)


def _verify_t1_ewir_live_case(
    root: Path,
    *,
    command_exit_code: int,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Validate one complete private live run and return content-free Markdown."""

    if isinstance(command_exit_code, bool) or command_exit_code != 0:
        raise AssertionError("protected Tier-1 production command did not succeed")
    source = dict(environ if environ is not None else os.environ)
    _validate_t1_ewir_root_target(root, source, must_exist=True)
    configurations = _validate_t1_ewir_materialized_files(root, after_run=True)
    issue_key = _required_t1_text(source, "MASTER_AGENT_LIVE_JIRA_ISSUE_ID")
    ca_path = _t1_ewir_sibling_path(root, "enterprise-ca.pem")
    if ca_path.exists():
        _read_t1_ewir_private_file(ca_path, maximum=_T1_EWIR_MAX_CONFIG_BYTES)
        source["MASTER_AGENT_ENTERPRISE_CA_BUNDLE"] = str(ca_path)
    else:
        source["MASTER_AGENT_ENTERPRISE_CA_BUNDLE"] = ""
    settings, integrations, _profile_payload = _preflight_t1_ewir_payloads(
        root,
        issue_key=issue_key,
        environ=source,
        integrations_payload=configurations["integrations.toml"],
        workflow_payload=configurations["engineering-work-item-review.toml"],
        profile_payload=configurations["organization-profile.toml"],
        validate_environment=True,
    )

    command_output = _t1_ewir_sibling_path(root, "command-output.log")
    _read_t1_ewir_private_file(
        command_output, maximum=_T1_EWIR_MAX_COMMAND_OUTPUT_BYTES
    )

    state_root = root / "state"
    runs_root = state_root / "runs"
    with PinnedDirectory.open(state_root) as state:
        if state.list_children() != ("runs",):
            raise AssertionError("protected Tier-1 state root has unexpected entries")
        with state.pin_child("runs") as runs:
            run_names = runs.list_children()
            if (
                len(run_names) != 1
                or _T1_EWIR_RUN_PATTERN.fullmatch(run_names[0]) is None
            ):
                raise AssertionError("protected Tier-1 evidence must contain one run")
            run_root = runs_root / run_names[0]
            with runs.pin_child(run_names[0]) as run:
                for name in ("artifacts", "results"):
                    with run.pin_child(name):
                        pass

    raw_bound_plan = _read_t1_ewir_private_json(
        run_root / "bound-plan.json",
        maximum=_T1_EWIR_MAX_CONFIG_BYTES,
    )
    bound_plan = ChangePlan.from_dict(raw_bound_plan)
    if raw_bound_plan != bound_plan.to_dict():
        raise AssertionError("protected Tier-1 persisted plan is non-canonical")
    validate_engineering_work_item_review_plan(bound_plan, settings)
    jira_targets = tuple(
        action.target.resource_id
        for action in bound_plan.actions
        if action.capability == "jira.issue.review_context.read"
    )
    if jira_targets != (issue_key,):
        raise AssertionError("protected Tier-1 Jira target is foreign")
    _validate_t1_ewir_execution_context(
        bound_plan,
        run_root=run_root,
        integrations=integrations,
        environ=source,
    )

    raw_report = _read_t1_ewir_private_json(
        run_root / "results" / "result.json",
        maximum=_T1_EWIR_MAX_RESULT_BYTES,
    )
    report = RunReport.from_dict(raw_report)
    if raw_report != report.to_dict():
        raise AssertionError("protected Tier-1 persisted result is non-canonical")
    report_action_ids = tuple(action.action_id for action in report.actions)
    bound_action_ids = tuple(action.action_id for action in bound_plan.actions)
    report_action_pairs = {
        (action.action_id, action.capability) for action in report.actions
    }
    bound_action_pairs = {
        (action.action_id, action.capability) for action in bound_plan.actions
    }
    if (
        report.dry_run
        or not report.successful
        or report.compensated
        or report.plan_id != bound_plan.plan_id
        or report.plan_fingerprint != bound_plan.fingerprint
        or len(report.actions) != len(bound_plan.actions)
        or len(set(report_action_ids)) != len(report_action_ids)
        or len(set(bound_action_ids)) != len(bound_action_ids)
        or report_action_pairs != bound_action_pairs
        or any(action.state is not ActionState.VERIFIED for action in report.actions)
    ):
        raise AssertionError("protected Tier-1 result is incomplete or foreign")

    _validate_t1_ewir_artifacts(
        run_root / "artifacts",
        report=report,
        settings=settings,
    )
    performance = _validate_t1_ewir_performance(report, plan=bound_plan)
    commit = _required_t1_text(source, "GITHUB_SHA")
    if _T1_EWIR_COMMIT_PATTERN.fullmatch(commit) is None:
        raise AssertionError("protected Tier-1 commit identity is malformed")
    counters = performance.counters
    implementations = ", ".join(
        f"{item.system}=native/bound" for item in performance.connector_implementations
    )
    return "\n".join(
        (
            "### Protected T1-EWIR-001 repository evidence",
            "",
            f"- checked-out commit: `{commit}`",
            "- complete: `true`",
            "- artifacts: `3` regular mode-`0600` files",
            "- measurement: `local_runtime` (`baseline_eligible=false`)",
            f"- connector implementations: `{implementations}`",
            (
                "- connector initializations: "
                f"`{counters[PerformanceCounter.CONNECTOR_INITIALIZATIONS]}`"
            ),
            (
                "- credential resolutions: "
                f"`{counters[PerformanceCounter.CREDENTIAL_RESOLUTIONS]}`"
            ),
            (
                "- principal attestations: "
                f"`{counters[PerformanceCounter.PRINCIPAL_ATTESTATIONS]}`"
            ),
            (
                "- provider content calls: "
                f"`{counters[PerformanceCounter.PROVIDER_TRANSPORT_CALLS]}` "
                "(initial case limit `14`; fixed outer bound `<20`)"
            ),
            "- governance interactions: `0`; approval interactions: `0`",
            "- unselected-provider activity: `0`",
            (
                "- certification: repository-side #94 evidence only; Windows 11 "
                "standard-user #172 baseline remains pending"
            ),
            "",
        )
    )


def _preflight_t1_ewir_payloads(
    root: Path,
    *,
    issue_key: str,
    environ: Mapping[str, str],
    integrations_payload: bytes,
    workflow_payload: bytes,
    profile_payload: bytes | None,
    validate_environment: bool,
) -> tuple[EngineeringWorkItemReviewSettings, IntegrationConfig, bytes]:
    integrations_path = root / "integrations.toml"
    workflow_path = root / "engineering-work-item-review.toml"
    profile_path = root / "organization-profile.toml"
    integrations = IntegrationConfig.from_toml(
        ConfigSnapshot(integrations_path, integrations_payload)
    )
    settings = EngineeringWorkItemReviewSettings.from_toml(
        ConfigSnapshot(workflow_path, workflow_payload)
    )
    expected_plan = build_engineering_work_item_review_plan(issue_key, settings)
    expected_capabilities, expected_systems = _t1_ewir_plan_dimensions(expected_plan)
    expected_profile = _t1_ewir_profile_payload(
        root,
        integrations_path=integrations_path,
        workflow_path=workflow_path,
        capabilities=expected_capabilities,
    )
    if profile_payload is not None and profile_payload != expected_profile:
        raise AssertionError("protected Tier-1 profile differs")
    profile_payload = expected_profile
    OrganizationProfile.from_toml(ConfigSnapshot(profile_path, profile_payload))

    if settings.bitbucket_deployment is not DeploymentType.CLOUD:
        raise AssertionError("protected Tier-1 Bitbucket deployment must be Cloud")
    if settings.include_diffstat:
        raise AssertionError("protected Tier-1 initial case forbids diffstat")
    if len(settings.confluence_page_ids) != 1:
        raise AssertionError(
            "protected Tier-1 initial case requires exactly one Confluence page"
        )
    if settings.data_classification not in {
        DataClassification.INTERNAL,
        DataClassification.CONFIDENTIAL,
        DataClassification.RESTRICTED,
    }:
        raise AssertionError(
            "protected Tier-1 classification must be internal or stricter"
        )
    expected_implementations = tuple(
        (system, NATIVE_CONNECTOR_IMPLEMENTATION) for system in expected_systems
    )
    if (
        preflight_connector_implementations(integrations, systems=set(expected_systems))
        != expected_implementations
    ):
        raise AssertionError("protected Tier-1 connector implementation set differs")
    for name in expected_systems:
        connector = _configured_connector(integrations, name)
        expected_username, expected_secret = _T1_EWIR_EXPECTED_CREDENTIAL_REFERENCES[
            name
        ]
        if (
            not connector.enabled
            or connector.deployment is not DeploymentType.CLOUD
            or connector.implementation is not ConnectorImplementation.NATIVE
            or connector.auth_mode is not AuthMode.BASIC
            or connector.credential_provider
            is not ConnectorCredentialProvider.ENVIRONMENT
            or connector.username_env != expected_username
            or connector.secret_env != expected_secret
            or connector.base_url is None
            or connector.base_url_env is not None
            or connector.ca_bundle_env
            not in {None, "MASTER_AGENT_ENTERPRISE_CA_BUNDLE"}
        ):
            raise AssertionError(
                "protected Tier-1 connector selection or credential binding differs"
            )

    _require_feature_flags(
        _configured_connector(integrations, "jira"),
        disabled=frozenset({"write_enabled", "writes_enabled"}),
    )
    _require_feature_flags(
        _configured_connector(integrations, "confluence"),
        disabled=frozenset({"write_enabled", "writes_enabled"}),
    )
    bitbucket = _configured_connector(integrations, "bitbucket")
    _require_feature_flags(
        bitbucket,
        disabled=frozenset(
            {"write_enabled", "pull_request_writes_enabled", "branch_push_enabled"}
        ),
    )
    if settings.build_status_limit > bitbucket.max_items:
        raise AssertionError("protected Tier-1 build-status limit exceeds connector")
    if settings.diffstat_limit > bitbucket.max_items:
        raise AssertionError("protected Tier-1 diffstat limit exceeds connector")
    if settings.bitbucket_origin not in _t1_ewir_connector_origins(bitbucket):
        raise AssertionError("protected Tier-1 Bitbucket origin differs")
    confluence = _configured_connector(integrations, "confluence")
    if settings.confluence_origin not in _t1_ewir_connector_origins(confluence):
        raise AssertionError("protected Tier-1 Confluence origin differs")

    if validate_environment:
        _validate_t1_ewir_connector_environment(integrations, environ)
    return settings, integrations, profile_payload


def _validate_t1_ewir_connector_environment(
    integrations: IntegrationConfig,
    environ: Mapping[str, str],
) -> None:
    for name in _T1_EWIR_EXPECTED_CREDENTIAL_REFERENCES:
        if _configured_connector(integrations, name).configuration_errors(environ):
            raise AssertionError(
                "protected Tier-1 connector configuration is incomplete"
            )


def _t1_ewir_plan_dimensions(
    plan: ChangePlan,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(sorted({action.capability for action in plan.actions})),
        tuple(sorted({action.target.system for action in plan.actions})),
    )


def _validate_t1_ewir_execution_context(
    plan: ChangePlan,
    *,
    run_root: Path,
    integrations: IntegrationConfig,
    environ: Mapping[str, str],
) -> None:
    context = plan.execution_context
    if context is None or context.runtime is None:
        raise AssertionError("protected Tier-1 bound plan lacks a runtime context")
    if context.plugins or context.capsules:
        raise AssertionError("protected Tier-1 bound plan includes an extension")
    _capabilities, systems = _t1_ewir_plan_dimensions(plan)
    captured = capture_connector_executions(
        integrations,
        environ=environ,
        systems=set(systems),
        require_trusted_principal=False,
        include_resolved_credentials=False,
        approved_execution_context=context,
    )
    if len(captured) != len(systems) or any(
        binding.authentication_mode != str(AuthMode.BASIC)
        for binding in context.connectors
    ):
        raise AssertionError("protected Tier-1 connector execution binding differs")
    runtime = context.runtime
    if (
        runtime.connector_mode != "live"
        or runtime.include_writes
        or runtime.include_communications
        or runtime.credential_file is not None
        or Path(runtime.audit_database) != run_root / "state" / "audit.sqlite3"
        or Path(runtime.artifact_root) != run_root / "artifacts"
        or Path(runtime.workspace_root or "") != run_root / "workspace"
        or Path(runtime.result_json or "") != run_root / "results" / "result.json"
    ):
        raise AssertionError("protected Tier-1 runtime binding differs")


def _validate_t1_ewir_artifacts(
    artifact_root: Path,
    *,
    report: RunReport,
    settings: EngineeringWorkItemReviewSettings,
) -> None:
    expected_names = {
        "engineering-work-item-review.json",
        "engineering-work-item-review.md",
        "manifest.json",
    }
    payloads: dict[str, bytes] = {}
    with PinnedDirectory.open(artifact_root) as artifacts:
        if set(artifacts.list_children()) != expected_names:
            raise AssertionError("protected Tier-1 artifact set differs")
        for name in expected_names:
            _path, payload, _identity = artifacts.read_child_bytes(
                name, max_bytes=_T1_EWIR_MAX_ARTIFACT_BYTES
            )
            payloads[name] = payload
    review = _decode_t1_ewir_json(payloads["engineering-work-item-review.json"])
    manifest = _decode_t1_ewir_json(payloads["manifest.json"])
    if (
        review.get("schema") != T1_EWIR_WORKFLOW_SCHEMA
        or review.get("workflow_id") != T1_EWIR_WORKFLOW_ID
        or review.get("workflow_configuration_sha256") != settings.configuration_sha256
        or review.get("outcome") != "complete"
        or review.get("complete") is not True
        or review.get("run_id") != str(report.run_id)
        or review.get("plan_id") != str(report.plan_id)
        or review.get("plan_fingerprint") != report.plan_fingerprint
        or review.get("failures") != []
        or review.get("stale_evidence") != []
        or review.get("ambiguities") != []
    ):
        raise AssertionError("protected Tier-1 review is incomplete or malformed")
    expected_manifest = {
        "schema": T1_EWIR_MANIFEST_SCHEMA,
        "workflow_id": T1_EWIR_WORKFLOW_ID,
        "outcome": "complete",
        "complete": True,
        "run_id": str(report.run_id),
        "plan_fingerprint": report.plan_fingerprint,
        "verification": "create-only readback SHA-256",
    }
    if any(manifest.get(key) != value for key, value in expected_manifest.items()):
        raise AssertionError("protected Tier-1 manifest is incomplete or malformed")
    raw_records = manifest.get("artifacts")
    if not isinstance(raw_records, list) or any(
        not isinstance(record, Mapping) for record in raw_records
    ):
        raise AssertionError("protected Tier-1 manifest artifact list differs")
    expected_records = {
        name: {
            "filename": name,
            "bytes": len(payloads[name]),
            "sha256": hashlib.sha256(payloads[name]).hexdigest(),
        }
        for name in (
            "engineering-work-item-review.json",
            "engineering-work-item-review.md",
        )
    }
    observed_records = {
        str(record.get("filename")): dict(record) for record in raw_records
    }
    if len(raw_records) != 2 or observed_records != expected_records:
        raise AssertionError("protected Tier-1 manifest readback digest differs")


def _validate_t1_ewir_performance(
    report: RunReport,
    *,
    plan: ChangePlan,
) -> PerformanceSnapshot:
    performance = report.performance
    if performance is None:
        raise AssertionError("protected Tier-1 result lacks performance evidence")
    capabilities, systems = _t1_ewir_plan_dimensions(plan)
    bounded_capabilities = tuple(
        sorted({bounded_capability(item) for item in capabilities})
    )
    if (
        performance.measurement_mode is not MeasurementMode.LOCAL_RUNTIME
        or performance.baseline_eligible
        or performance.case_id is not PerformanceCase.T1_EWIR_001
        or performance.capabilities != bounded_capabilities
        or performance.risk_tiers != (str(RiskLevel.READ_ONLY),)
        or performance.systems != systems
    ):
        raise AssertionError("protected Tier-1 performance dimensions differ")
    expected_implementations = tuple(
        (system, NATIVE_CONNECTOR_IMPLEMENTATION, True) for system in systems
    )
    observed_implementations = tuple(
        (item.system, item.implementation, item.bound)
        for item in performance.connector_implementations
    )
    if observed_implementations != expected_implementations:
        raise AssertionError("protected Tier-1 implementation dimensions differ")
    counters = performance.counters
    for counter in (
        PerformanceCounter.SELECTED_SYSTEMS,
        PerformanceCounter.SELECTED_CONNECTOR_IMPLEMENTATIONS,
        PerformanceCounter.CONNECTOR_INITIALIZATIONS,
        PerformanceCounter.CREDENTIAL_RESOLUTIONS,
    ):
        if counters[counter] != len(systems):
            raise AssertionError("protected Tier-1 selected-provider count differs")
    if counters[PerformanceCounter.PRINCIPAL_ATTESTATIONS] != 2 * len(systems):
        raise AssertionError("protected Tier-1 principal-attestation count differs")
    if (
        counters[PerformanceCounter.GOVERNANCE_INTERACTIONS] != 0
        or counters[PerformanceCounter.APPROVAL_INTERACTIONS] != 0
    ):
        raise AssertionError("protected Tier-1 run required an interaction")
    provider_calls = counters[PerformanceCounter.PROVIDER_TRANSPORT_CALLS]
    if not 0 < provider_calls <= 14:
        raise AssertionError("protected Tier-1 provider-call budget failed")
    if any(
        count != 0
        for outcome, count in performance.outcomes.items()
        if outcome is not PerformanceOutcome.VERIFIED
    ):
        raise AssertionError("protected Tier-1 performance outcome is incomplete")
    if performance.outcomes[PerformanceOutcome.VERIFIED] != len(report.actions):
        raise AssertionError("protected Tier-1 verified outcome count differs")
    selected = frozenset(systems)
    for system, activity in performance.provider_activity.items():
        values = tuple(activity[item] for item in ProviderActivity)
        if system not in selected and any(values):
            raise AssertionError("protected Tier-1 unselected-provider activity found")
        if system in selected and (
            activity[ProviderActivity.CREDENTIAL_RESOLUTIONS] != 1
            or activity[ProviderActivity.CONNECTOR_INITIALIZATIONS] != 1
            or activity[ProviderActivity.PRINCIPAL_ATTESTATIONS] != 2
            or activity[ProviderActivity.PROVIDER_TRANSPORT_CALLS] <= 0
            or activity[ProviderActivity.VERIFICATION_CALLS] <= 0
        ):
            raise AssertionError("protected Tier-1 selected-provider activity differs")
    return performance


def _t1_ewir_profile_payload(
    root: Path,
    *,
    integrations_path: Path,
    workflow_path: Path,
    capabilities: Sequence[str],
) -> bytes:
    rendered_capabilities = ", ".join(json.dumps(item) for item in capabilities)
    return (
        "\n".join(
            (
                f'schema = "{_T1_EWIR_PROFILE_SCHEMA}"',
                'organization = "protected-live-t1-ewir"',
                'mode = "employee"',
                f"state_root = {json.dumps(str(root / 'state'))}",
                'connector_mode = "live"',
                "writes_enabled = false",
                "communications_enabled = false",
                f"capabilities = [{rendered_capabilities}]",
                "",
                "[configuration]",
                f"engineering_work_item_review = {json.dumps(str(workflow_path))}",
                f"integrations = {json.dumps(str(integrations_path))}",
                "",
            )
        )
    ).encode("utf-8")


def _validate_t1_ewir_root_target(
    root: Path,
    environ: Mapping[str, str],
    *,
    must_exist: bool = False,
) -> None:
    runner_temp = Path(_required_t1_text(environ, "RUNNER_TEMP"))
    if not runner_temp.is_absolute():
        raise AssertionError("RUNNER_TEMP must be absolute for protected Tier-1")
    _validate_t1_ewir_directory(runner_temp, require_mode=False)
    run_id = _required_t1_text(environ, "GITHUB_RUN_ID")
    run_attempt = _required_t1_text(environ, "GITHUB_RUN_ATTEMPT")
    expected_name = f"master-agent-live-t1-ewir-{run_id}-{run_attempt}"
    if (
        _T1_EWIR_ROOT_PATTERN.fullmatch(expected_name) is None
        or root.parent != runner_temp
        or root.name != expected_name
        or not root.is_absolute()
    ):
        raise AssertionError("protected Tier-1 root does not match this workflow run")
    if must_exist:
        _validate_t1_ewir_directory(root)
    elif os.path.lexists(root):
        raise AssertionError("protected Tier-1 root already exists")


def _validate_t1_ewir_materialized_files(
    root: Path, *, after_run: bool
) -> dict[str, bytes]:
    expected = set(_T1_EWIR_CONFIG_FILES)
    if after_run:
        expected.add("state")
    payloads: dict[str, bytes] = {}
    with PinnedDirectory.open(root) as pinned:
        if set(pinned.list_children()) != expected:
            raise AssertionError("protected Tier-1 private root entries differ")
        for name in _T1_EWIR_CONFIG_FILES:
            _path, payload, _identity = pinned.read_child_bytes(
                name, max_bytes=_T1_EWIR_MAX_CONFIG_BYTES
            )
            if not payload:
                raise AssertionError("protected Tier-1 configuration is empty")
            payloads[name] = payload
    return payloads


def _t1_ewir_connector_origins(connector: ConnectorConfig) -> frozenset[str]:
    values = (connector.base_url or "", connector.web_base_url or "")
    origins: set[str] = set()
    for value in values:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if parsed.scheme != "https" or not hostname:
            continue
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname
        if parsed.port not in {None, 443}:
            rendered_host = f"{rendered_host}:{parsed.port}"
        origins.add(f"https://{rendered_host}")
    if connector.system == "bitbucket" and connector.deployment is DeploymentType.CLOUD:
        origins.add("https://bitbucket.org")
    return frozenset(origins)


def _read_t1_ewir_private_file(path: Path, *, maximum: int) -> bytes:
    with PinnedDirectory.open(path.parent, require_private=False) as parent:
        _selected, payload, _identity = parent.read_child_bytes(
            path.name,
            max_bytes=maximum,
            require_private=True,
        )
    return payload


def _read_t1_ewir_private_json(path: Path, *, maximum: int) -> Mapping[str, object]:
    return _decode_t1_ewir_json(_read_t1_ewir_private_file(path, maximum=maximum))


def _decode_t1_ewir_json(payload: bytes) -> Mapping[str, object]:
    try:
        decoded = json.loads(
            payload,
            object_pairs_hook=_t1_ewir_unique_json_object,
            parse_constant=_reject_t1_ewir_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AssertionError("protected Tier-1 evidence is invalid JSON") from error
    if not isinstance(decoded, Mapping):
        raise TypeError("protected Tier-1 JSON evidence must be an object")
    return decoded


def _t1_ewir_unique_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_t1_ewir_json_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _validate_t1_ewir_directory(path: Path, *, require_mode: bool = True) -> None:
    if path.is_symlink():
        raise AssertionError("protected Tier-1 private directory must be real")
    with PinnedDirectory.open(path, require_private=require_mode) as directory:
        if hasattr(os, "geteuid") and directory.identity.owner != os.geteuid():
            raise AssertionError("protected Tier-1 private directory owner differs")


def _required_t1_payload(
    environ: Mapping[str, str],
    name: str,
    *,
    maximum: int,
) -> bytes:
    raw = environ.get(name)
    if raw is None or not raw:
        raise AssertionError(f"required protected Tier-1 value is missing: {name}")
    payload = raw.encode("utf-8")
    if len(payload) > maximum:
        raise AssertionError(f"required protected Tier-1 value is too large: {name}")
    return payload


def _required_t1_text(environ: Mapping[str, str], name: str) -> str:
    raw = environ.get(name)
    if raw is None or not raw or raw != raw.strip() or not raw.isprintable():
        raise AssertionError(f"required protected Tier-1 value is invalid: {name}")
    return raw


def _t1_ewir_sibling_path(root: Path, suffix: str) -> Path:
    return root.parent / f"{root.name}-{suffix}"


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


def _run_t1_ewir_harness_command(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare or verify the protected T1-EWIR-001 live case."
    )
    parser.add_argument(
        "command",
        choices=("prepare-t1-ewir", "verify-t1-ewir"),
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--command-exit-code", type=int)
    parsed = parser.parse_args(arguments)
    if parsed.command == "prepare-t1-ewir":
        if parsed.command_exit_code is not None:
            parser.error("prepare-t1-ewir does not accept --command-exit-code")
        try:
            _prepare_t1_ewir_live_case(parsed.root)
        except Exception:  # noqa: BLE001 - all provider-free failures stay redacted
            print("T1-EWIR-001 protected preflight failed", file=sys.stderr)
            return 1
        return 0
    if parsed.command_exit_code is None:
        parser.error("verify-t1-ewir requires --command-exit-code")
    try:
        summary = _verify_t1_ewir_live_case(
            parsed.root,
            command_exit_code=parsed.command_exit_code,
        )
    except Exception:  # noqa: BLE001 - all evidence failures stay redacted
        print("T1-EWIR-001 protected evidence verification failed", file=sys.stderr)
        return 1
    print(summary, end="")
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
    if len(sys.argv) > 1 and sys.argv[1] in {
        "prepare-t1-ewir",
        "verify-t1-ewir",
    }:
        raise SystemExit(_run_t1_ewir_harness_command(sys.argv[1:]))
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
