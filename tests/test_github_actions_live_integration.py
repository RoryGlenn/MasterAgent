"""Live GitHub connector tests using the repository-scoped Actions credential."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import TypeVar
from uuid import uuid4

from master_agent.auth import AuthMode
from master_agent.config import IntegrationConfig
from master_agent.connectors.base import ClosableConnector
from master_agent.connectors.factory import build_live_registry
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.github_write import GitHubWriteConnector
from master_agent.models import ExecutionResult, RiskLevel
from master_agent.registry import ConnectorRegistry
from tests.helpers import action_for, read_action

_ConnectorType = TypeVar("_ConnectorType")


@unittest.skipUnless(
    os.environ.get("MASTER_AGENT_RUN_GITHUB_ACTIONS_LIVE_TESTS") == "1",
    "GitHub Actions live connector test is opt-in",
)
class GitHubActionsLiveIntegrationTests(unittest.TestCase):
    """Read a real repository and exercise a real issue create/close lifecycle."""

    config: IntegrationConfig
    registry: ConnectorRegistry
    temporary_directory: tempfile.TemporaryDirectory[str]
    read_connector: GitHubConnector
    write_connector: GitHubWriteConnector
    owner: str
    repository: str
    run_label: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = _load_live_config()
        _require_credentialed_github_config(cls.config)
        cls.temporary_directory = _private_temporary_directory()
        root = Path(cls.temporary_directory.name)
        cls.registry = build_live_registry(
            cls.config,
            environ=os.environ,
            systems={"github"},
            include_writes=True,
            include_communications=False,
            workspace_root=root,
            artifact_root=root,
        )
        cls.read_connector = _connector_by_type(cls.registry, GitHubConnector)
        cls.write_connector = _connector_by_type(cls.registry, GitHubWriteConnector)
        cls.owner = _required_env("MASTER_AGENT_LIVE_GITHUB_OWNER")
        cls.repository = _required_env("MASTER_AGENT_LIVE_GITHUB_REPOSITORY")
        cls.run_label = os.environ.get("MASTER_AGENT_LIVE_RUN_ID", "").strip()
        if not cls.run_label:
            cls.run_label = f"local-{uuid4().hex[:12]}"

    @classmethod
    def tearDownClass(cls) -> None:
        _close_connectors(cls.registry)
        cls.temporary_directory.cleanup()

    def test_repository_read_and_independent_re_read(self) -> None:
        """Fetch the real repository twice through the production connector."""

        action = read_action(
            "github.repository.read",
            system="github",
            resource_type="repository",
            resource_id=self.repository,
            parameters={
                "owner": self.owner,
                "repository": self.repository,
            },
        )
        result = self.read_connector.execute(action)

        self.assertTrue(result.connector_reference.startswith("https://"))
        self.assertTrue(self.read_connector.verify(action, result).verified)

    def test_issue_create_verify_and_close(self) -> None:
        """Create a real issue, re-read it, close it, and verify closure."""

        action = action_for(
            "github.issue.create",
            system="github",
            resource_type="issue",
            resource_id=f"actions-integration-{self.run_label}",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "owner": self.owner,
                "repository": self.repository,
                "title": f"MasterAgent GitHub integration {self.run_label}",
                "body": (
                    "Automated credentialed integration test using the "
                    "repository-scoped GitHub Actions token. This issue should "
                    "be closed automatically after independent verification."
                ),
            },
        )
        result: ExecutionResult | None = None
        try:
            result = self.write_connector.execute(action)
            self.assertTrue(self.write_connector.verify(action, result).verified)
        finally:
            if result is not None:
                compensation = self.write_connector.compensate(action, result)
                self.assertTrue(
                    self.write_connector.verify_compensation(
                        action,
                        result,
                        compensation,
                    ).verified
                )


def _load_live_config() -> IntegrationConfig:
    path = Path(_required_env("MASTER_AGENT_LIVE_INTEGRATIONS_FILE"))
    if not path.is_file():
        raise AssertionError(f"live integrations file does not exist: {path}")
    return IntegrationConfig.from_toml(path)


def _require_credentialed_github_config(config: IntegrationConfig) -> None:
    connector = config.connectors.get("github")
    problems: list[str] = []
    if connector is None:
        problems.append("missing connector configuration: github")
    else:
        if not connector.enabled:
            problems.append("connector is disabled: github")
        if connector.auth_mode is AuthMode.NONE:
            problems.append("connector uses auth_mode=none: github")
        problems.extend(connector.configuration_errors(os.environ))
    if problems:
        raise AssertionError("; ".join(problems))


def _connector_by_type(
    registry: ConnectorRegistry,
    connector_type: type[_ConnectorType],
) -> _ConnectorType:
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
    directory = tempfile.TemporaryDirectory(prefix="master-agent-github-live-")
    Path(directory.name).chmod(0o700)
    return directory


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise AssertionError(f"required live integration variable is missing: {name}")
    return value


if __name__ == "__main__":
    unittest.main()
