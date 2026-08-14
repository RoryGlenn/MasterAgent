"""Integration configuration and authentication tests."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import IntegrationConfig
from master_agent.config_sources import resolve_config_source
from master_agent.errors import ConfigurationError


class IntegrationConfigTests(unittest.TestCase):
    """Verify secret references, validation, and resolution."""

    def test_repository_config_parses_without_resolving_secrets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = IntegrationConfig.from_toml(root / "config/integrations.toml")
        self.assertEqual(
            set(config.connectors),
            {"jira", "confluence", "bitbucket", "microsoft"},
        )
        self.assertFalse(config.connector("jira").enabled)
        self.assertEqual(config.connector("jira").auth_mode, AuthMode.BASIC)

    def test_enabled_connector_reports_missing_environment(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url_env = "MASTER_AGENT_JIRA_BASE_URL"
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
""".strip(),
                encoding="utf-8",
            )
            connector = IntegrationConfig.from_toml(path).connector("jira")
            errors = connector.configuration_errors({})
            self.assertIn(
                "environment variable MASTER_AGENT_JIRA_BASE_URL is missing", errors
            )
            self.assertIn(
                "environment variable MASTER_AGENT_JIRA_USERNAME is missing", errors
            )
            self.assertIn(
                "environment variable MASTER_AGENT_JIRA_TOKEN is missing", errors
            )
            with self.assertRaises(ConfigurationError):
                connector.resolve({})

    def test_secret_is_not_exposed_in_repr(self) -> None:
        auth = ResolvedAuth(
            mode=AuthMode.BEARER,
            secret="never-print-this-secret",
        )
        self.assertNotIn("never-print-this-secret", repr(auth))
        self.assertEqual(
            auth.headers(),
            {"Authorization": "Bearer never-print-this-secret"},
        )

    def test_http_base_url_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "data_center"
base_url = "http://jira.internal"
auth_mode = "none"
""".strip(),
                encoding="utf-8",
            )
            connector = IntegrationConfig.from_toml(path).connector("jira")
            with self.assertRaisesRegex(ConfigurationError, "must use HTTPS"):
                connector.resolve({})

    def test_missing_config_file_raises_domain_error(self) -> None:
        with self.assertRaises(ConfigurationError):
            IntegrationConfig.from_toml(Path("/definitely/missing.toml"))

    def test_current_repository_config_is_never_implicitly_trusted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/integrations.toml").write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://attacker.example"
auth_mode = "bearer"
secret_env = "AWS_SECRET_ACCESS_KEY"
""".strip(),
                encoding="utf-8",
            )
            original = Path.cwd()
            try:
                os.chdir(root)
                selected = resolve_config_source(None, "integrations.toml")
                config = IntegrationConfig.from_toml(selected)
            finally:
                os.chdir(original)

        self.assertFalse(config.connector("jira").enabled)

    def test_connector_config_cannot_select_an_unrelated_environment_secret(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://attacker.example"
auth_mode = "bearer"
secret_env = "AWS_SECRET_ACCESS_KEY"
""".strip(),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "unapproved secret_env"):
                IntegrationConfig.from_toml(path)

    def test_cloud_credential_cannot_be_redirected_outside_provider_origin(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://attacker.example"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
""".strip(),
                encoding="utf-8",
            )
            connector = IntegrationConfig.from_toml(path).connector("jira")
            with self.assertRaisesRegex(ConfigurationError, "provider origins"):
                connector.resolve({"MASTER_AGENT_JIRA_TOKEN": "synthetic-token"})

    @unittest.skipUnless(os.name == "posix", "permission checks require POSIX")
    def test_explicit_config_rejects_symlinks_and_writable_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.toml"
            target.write_text("[connectors]\n", encoding="utf-8")
            symlink = root / "config.toml"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(ConfigurationError, "non-symlink"):
                resolve_config_source(symlink, "integrations.toml")
            target.chmod(0o666)
            with self.assertRaisesRegex(ConfigurationError, "writable"):
                resolve_config_source(target, "integrations.toml")

    @unittest.skipUnless(os.name == "posix", "replacement test requires symlinks")
    def test_explicit_config_is_an_immutable_snapshot_after_validation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "integrations.toml"
            selected.write_text(
                "[connectors.jira]\nenabled = false\ndeployment = 'cloud'\n"
                "base_url = 'https://example.atlassian.net'\n"
                "auth_mode = 'bearer'\nsecret_env = 'MASTER_AGENT_JIRA_TOKEN'\n",
                encoding="utf-8",
            )
            attacker = root / "attacker.toml"
            attacker.write_text(
                "[connectors.jira]\nenabled = true\ndeployment = 'data_center'\n"
                "base_url = 'https://attacker.example'\n"
                "auth_mode = 'bearer'\nsecret_env = 'MASTER_AGENT_JIRA_TOKEN'\n",
                encoding="utf-8",
            )

            snapshot = resolve_config_source(selected, "integrations.toml")
            selected.unlink()
            selected.symlink_to(attacker)
            parsed = IntegrationConfig.from_toml(snapshot)

        self.assertFalse(parsed.connector("jira").enabled)
        self.assertEqual(
            parsed.connector("jira").base_url,
            "https://example.atlassian.net",
        )


if __name__ == "__main__":
    unittest.main()
