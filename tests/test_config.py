"""Integration configuration and authentication tests."""

import hashlib
import os
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import (
    ConnectorConfig,
    ConnectorCredentialProvider,
    DeploymentType,
    IntegrationConfig,
    NetworkMode,
    NetworkProfile,
)
from master_agent.config_sources import resolve_config_source
from master_agent.errors import ConfigurationError
from master_agent.trust_store import capture_ca_bundle
from tests.helpers import private_temporary_directory


class IntegrationConfigTests(unittest.TestCase):
    """Verify secret references, validation, and resolution."""

    def test_named_proxy_profile_is_identity_bound_and_resolves_brokered_secrets(
        self,
    ) -> None:
        profile = NetworkProfile(
            name="corporate",
            mode=NetworkMode.PROXY,
            proxy_url="http://proxy.corp.example:8080",
            proxy_username_env="MASTER_AGENT_PROXY_USERNAME",
            proxy_password_env="MASTER_AGENT_PROXY_PASSWORD",
        )
        connector = ConnectorConfig(
            system="github",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://api.github.com",
            base_url_env=None,
            auth_mode=AuthMode.NONE,
            username_env=None,
            secret_env=None,
            network_profile=profile,
        )
        environ = {
            "MASTER_AGENT_PROXY_USERNAME": "proxy-user",
            "MASTER_AGENT_PROXY_PASSWORD": "proxy-secret-marker",
        }

        target = connector.capture_execution_target(environ)
        resolved = connector.resolve(environ, execution_target=target)

        self.assertEqual(target.network_profile_name, "corporate")
        self.assertEqual(target.network_profile_sha256, profile.identity)
        self.assertEqual(target.proxy_url, "http://proxy.corp.example:8080")
        self.assertEqual(resolved.proxy_username, "proxy-user")
        self.assertEqual(resolved.proxy_password, "proxy-secret-marker")
        self.assertNotIn("proxy-secret-marker", repr(target))
        self.assertNotIn("proxy-secret-marker", repr(resolved))
        self.assertIn(
            "MASTER_AGENT_PROXY_PASSWORD",
            connector.credential_environment_variables(),
        )

    def test_network_profiles_reject_credentials_urls_and_unapproved_references(
        self,
    ) -> None:
        invalid = (
            {"mode": NetworkMode.PROXY, "proxy_url": "https://proxy.example:8443"},
            {
                "mode": NetworkMode.PROXY,
                "proxy_url": "http://user:secret@proxy.example:8080",
            },
            {"mode": NetworkMode.PROXY, "proxy_url": "http://127.0.0.1:8080"},
            {
                "mode": NetworkMode.PROXY,
                "proxy_url": "http://proxy.example:8080",
                "proxy_username_env": "UNREVIEWED_USERNAME",
                "proxy_password_env": "MASTER_AGENT_PROXY_PASSWORD",
            },
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ConfigurationError):
                NetworkProfile(name="invalid", **values)

    def test_network_profile_captures_enterprise_ca_identity(self) -> None:
        with private_temporary_directory() as directory:
            ca_bundle = Path(directory) / "enterprise-ca.pem"
            ca_bundle.write_bytes(b"-----BEGIN CERTIFICATE-----\nmanaged\n")
            expected_digest = hashlib.sha256(ca_bundle.read_bytes()).hexdigest()
            profile = NetworkProfile(
                name="corporate-ca",
                mode=NetworkMode.PROXY,
                proxy_url="http://proxy.corp.example:8080",
                ca_bundle_env="MASTER_AGENT_ENTERPRISE_CA_BUNDLE",
            )
            connector = ConnectorConfig(
                system="github",
                enabled=True,
                deployment=DeploymentType.CLOUD,
                base_url="https://api.github.com",
                base_url_env=None,
                auth_mode=AuthMode.NONE,
                username_env=None,
                secret_env=None,
                network_profile=profile,
            )

            target = connector.capture_execution_target(
                {"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(ca_bundle)}
            )

        self.assertIsNotNone(target.ca_bundle)
        assert target.ca_bundle is not None
        self.assertEqual(target.ca_bundle.path, ca_bundle.resolve())
        self.assertEqual(
            target.ca_bundle.sha256,
            expected_digest,
        )

    def test_ambient_proxy_is_consumed_only_by_an_opted_in_profile(self) -> None:
        direct = NetworkProfile(name="direct-test")
        ambient = NetworkProfile(
            name="managed-workstation", mode=NetworkMode.AMBIENT_PROXY
        )
        environ = {"HTTPS_PROXY": "http://proxy.corp.example:8080"}

        self.assertIsNone(direct.resolved_proxy_url(environ))
        self.assertEqual(
            ambient.resolved_proxy_url(environ),
            "http://proxy.corp.example:8080",
        )
        self.assertEqual(ambient.required_environment_variables(), ("HTTPS_PROXY",))

    def test_integration_config_selects_only_declared_network_profiles(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "network-profile.toml"
            path.write_text(
                """
[network_profiles.corporate]
mode = "proxy"
proxy_url = "http://proxy.corp.example:8080"

[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "none"
network_profile = "corporate"
""",
                encoding="utf-8",
            )
            parsed = IntegrationConfig.from_toml(path)

        self.assertEqual(parsed.connector("github").network_profile.name, "corporate")

    def test_builtin_direct_profile_cannot_be_redefined_as_a_proxy(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "network-profile.toml"
            path.write_text(
                """
[network_profiles.direct]
mode = "proxy"
proxy_url = "http://proxy.corp.example:8080"

[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "none"
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ConfigurationError,
                "built-in direct network profile cannot be redefined",
            ):
                IntegrationConfig.from_toml(path)

    def test_windows_ca_target_is_lexical_until_native_capture(self) -> None:
        connector = ConnectorConfig(
            system="jira",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
            base_url_env=None,
            auth_mode=AuthMode.NONE,
            username_env=None,
            secret_env=None,
            ca_bundle_env="CA_BUNDLE",
        )
        selected = Mock(spec=Path)
        selected.expanduser.return_value = selected
        selected.is_absolute.return_value = True
        canonical = Path("/synthetic/windows-ca.pem")
        validated = Mock(canonical=r"C:\Trust\enterprise-ca.pem")
        windows_os = Mock()
        windows_os.name = "nt"
        with (
            patch("master_agent.config.os", windows_os),
            patch(
                "master_agent.config.Path",
                side_effect=(selected, canonical),
            ),
            patch(
                "master_agent.platform_runtime.windows.filesystem."
                "validate_windows_drive_path",
                return_value=validated,
            ) as validate_path,
            patch("master_agent.config.require_platform_contract"),
        ):
            base_url, ca_bundle = connector.resolve_execution_target(
                {"CA_BUNDLE": r"C:\Trust\enterprise-ca.pem"}
            )

        self.assertEqual(base_url, "https://example.atlassian.net")
        self.assertEqual(ca_bundle, canonical)
        validate_path.assert_called_once_with(selected)
        selected.resolve.assert_not_called()
        selected.is_file.assert_not_called()

    def test_windows_ca_native_open_error_is_bounded(self) -> None:
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        backend = Mock(spec=WindowsSecureFilesystemBackend)
        backend.read_restricted_file.side_effect = OSError("native failure")
        windows_os = Mock()
        windows_os.name = "nt"
        selected = Path("/missing/enterprise-ca.pem")

        with (
            patch("master_agent.trust_store.os", windows_os),
            patch(
                "master_agent.trust_store.get_secure_filesystem_backend",
                return_value=backend,
            ),
            patch("master_agent.trust_store.require_platform_contract"),
            self.assertRaisesRegex(
                ConfigurationError,
                "connector CA bundle could not be captured safely",
            ),
        ):
            capture_ca_bundle(selected)

        backend.read_restricted_file.assert_called_once_with(
            selected,
            4 * 1024 * 1024,
            require_private=False,
        )

    def test_repository_config_parses_without_resolving_secrets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = IntegrationConfig.from_toml(root / "config/integrations.toml")
        self.assertEqual(
            set(config.connectors),
            {"jira", "confluence", "bitbucket", "github", "microsoft", "reddit"},
        )
        self.assertTrue(config.connector("jira").enabled)
        self.assertEqual(config.connector("jira").auth_mode, AuthMode.BASIC)
        self.assertTrue(
            {
                "MASTER_AGENT_GRAPH_TOKEN_FILE",
                "MASTER_AGENT_GRAPH_ACCESS_TOKEN",
                "MASTER_AGENT_GRAPH_ACCESS_TOKEN_EXPIRES_AT",
                "MASTER_AGENT_ENTRA_TENANT_ID",
                "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
                "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
            }.issubset(config.credential_environment_variables())
        )

    def test_native_credential_source_metadata_is_validated_and_identity_bound(
        self,
    ) -> None:
        connector = ConnectorConfig(
            system="jira",
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url="https://example.atlassian.net",
            base_url_env=None,
            auth_mode=AuthMode.BASIC,
            username_env="MASTER_AGENT_JIRA_USERNAME",
            secret_env="MASTER_AGENT_JIRA_TOKEN",
            extra={
                "credential_provider": "windows-credential-manager",
                "credential_target": "MasterAgent/production/jira",
            },
        )

        self.assertEqual(
            connector.credential_provider,
            ConnectorCredentialProvider.WINDOWS_CREDENTIAL_MANAGER,
        )
        self.assertEqual(connector.credential_target, "MasterAgent/production/jira")
        self.assertNotEqual(connector.identity, replace(connector, extra={}).identity)
        invalid = (
            {"credential_target": "MasterAgent/unselected"},
            {"credential_provider": "windows-dpapi"},
            {
                "credential_provider": "windows-credential-manager",
                "credential_target": "unscoped/jira",
            },
            {
                "credential_provider": "windows-dpapi",
                "credential_target": r"\\server\share\credentials.bin",
            },
            {
                "credential_provider": "windows-dpapi",
                "credential_target": r"C:\MasterAgent\..\credentials.bin",
            },
        )
        for extra in invalid:
            with self.subTest(extra=extra), self.assertRaises(ConfigurationError):
                replace(connector, extra=extra)

    def test_native_dpapi_declares_entra_and_token_file_credential_shapes(
        self,
    ) -> None:
        common = {
            "system": "microsoft",
            "enabled": True,
            "deployment": DeploymentType.CLOUD,
            "base_url": "https://graph.microsoft.com/v1.0",
            "base_url_env": None,
            "username_env": None,
            "ca_bundle_env": None,
        }
        client_credentials = ConnectorConfig(
            **common,
            auth_mode=AuthMode.OAUTH_APPLICATION,
            secret_env=None,
            extra={
                "credential_provider": "windows-dpapi",
                "credential_target": r"C:\MasterAgent\entra.dpapi",
                "oauth_flow": "client_credentials",
                "tenant_id_env": "MASTER_AGENT_ENTRA_TENANT_ID",
                "client_id_env": "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
                "client_secret_env": "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
                "scopes": ["https://graph.microsoft.com/.default"],
            },
        )
        token_file = ConnectorConfig(
            **common,
            auth_mode=AuthMode.OAUTH_DELEGATED,
            secret_env=None,
            extra={
                "credential_provider": "windows-dpapi",
                "credential_target": r"C:\MasterAgent\delegated.dpapi",
                "oauth_flow": "token_file",
                "token_file_env": "MASTER_AGENT_GRAPH_TOKEN_FILE",
            },
        )

        self.assertEqual(
            client_credentials.credential_environment_variables(),
            (
                "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
                "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
                "MASTER_AGENT_ENTRA_TENANT_ID",
            ),
        )
        self.assertEqual(
            token_file.credential_environment_variables(),
            ("MASTER_AGENT_GRAPH_TOKEN_FILE",),
        )

    def test_enabled_connector_reports_missing_environment(self) -> None:
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
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

    def test_base_url_query_and_fragment_are_rejected(self) -> None:
        for suffix in ("?", "#", "?access_token=secret", "#access_token=secret"):
            with (
                self.subTest(suffix=suffix),
                private_temporary_directory() as directory,
            ):
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    "[connectors.jira]\n"
                    "enabled = true\n"
                    'deployment = "data_center"\n'
                    f'base_url = "https://jira.example.test{suffix}"\n'
                    'auth_mode = "none"\n',
                    encoding="utf-8",
                )
                connector = IntegrationConfig.from_toml(path).connector("jira")
                with self.assertRaisesRegex(
                    ConfigurationError,
                    "query or fragment",
                ):
                    connector.resolve({})

    def test_missing_config_file_raises_domain_error(self) -> None:
        with self.assertRaises(ConfigurationError):
            IntegrationConfig.from_toml(Path("/definitely/missing.toml"))

    def test_current_repository_config_is_never_implicitly_trusted(self) -> None:
        with private_temporary_directory() as directory:
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

        self.assertTrue(config.connector("jira").enabled)
        self.assertEqual(
            config.connector("jira").base_url, "https://example.atlassian.net"
        )

    def test_connector_config_cannot_select_an_unrelated_environment_secret(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
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

    def test_scoped_atlassian_gateway_roots_resolve_with_separate_web_root(
        self,
    ) -> None:
        cloud_id = "12345678-1234-1234-1234-123456789abc"
        for system in ("jira", "confluence"):
            with (
                self.subTest(system=system),
                private_temporary_directory() as directory,
            ):
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    f"[connectors.{system}]\n"
                    "enabled = true\n"
                    'deployment = "cloud"\n'
                    f'base_url = "https://api.atlassian.com/ex/{system}/'
                    f'{cloud_id}/"\n'
                    'web_base_url = "https://acme.atlassian.net/"\n'
                    'auth_mode = "none"\n',
                    encoding="utf-8",
                )

                connector = IntegrationConfig.from_toml(path).connector(system)
                resolved = connector.resolve({})

                self.assertEqual(
                    resolved.base_url,
                    f"https://api.atlassian.com/ex/{system}/{cloud_id}",
                )
                self.assertEqual(
                    resolved.web_base_url,
                    "https://acme.atlassian.net",
                )

    def test_atlassian_gateway_root_requires_approved_web_root(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                "[connectors.jira]\n"
                "enabled = true\n"
                'deployment = "cloud"\n'
                'base_url = "https://api.atlassian.com/ex/jira/'
                '12345678-1234-1234-1234-123456789abc"\n'
                'auth_mode = "none"\n',
                encoding="utf-8",
            )
            connector = IntegrationConfig.from_toml(path).connector("jira")

            with self.assertRaisesRegex(ConfigurationError, "requires web_base_url"):
                connector.resolve({})

    def test_cloud_atlassian_api_roots_reject_ambiguous_shapes(self) -> None:
        cloud_id = "12345678-1234-1234-1234-123456789abc"
        invalid_urls = (
            f"https://api.atlassian.com/ex/confluence/{cloud_id}",
            "https://api.atlassian.com/ex/jira/not-a-cloud-id",
            f"https://api.atlassian.com/ex/jira/{cloud_id}/rest",
            f"https://api.atlassian.com:443/ex/jira/{cloud_id}",
            "https://acme.atlassian.net/wiki",
            "https://acme.atlassian.net:443",
            "https://nested.acme.atlassian.net",
        )
        for base_url in invalid_urls:
            with (
                self.subTest(base_url=base_url),
                private_temporary_directory() as directory,
            ):
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    "[connectors.jira]\n"
                    "enabled = true\n"
                    'deployment = "cloud"\n'
                    f'base_url = "{base_url}"\n'
                    'web_base_url = "https://acme.atlassian.net"\n'
                    'auth_mode = "none"\n',
                    encoding="utf-8",
                )
                connector = IntegrationConfig.from_toml(path).connector("jira")

                with self.assertRaisesRegex(ConfigurationError, "provider origins"):
                    connector.resolve({})

    def test_atlassian_web_root_is_tenant_only_and_approval_bound(self) -> None:
        cloud_id = "12345678-1234-1234-1234-123456789abc"
        identities: list[str] = []
        for web_base_url in (
            "https://acme.atlassian.net",
            "https://other.atlassian.net",
        ):
            with private_temporary_directory() as directory:
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    "[connectors.jira]\n"
                    "enabled = true\n"
                    'deployment = "cloud"\n'
                    f'base_url = "https://api.atlassian.com/ex/jira/{cloud_id}"\n'
                    f'web_base_url = "{web_base_url}"\n'
                    'auth_mode = "none"\n',
                    encoding="utf-8",
                )
                identities.append(
                    IntegrationConfig.from_toml(path).connector("jira").identity
                )
        self.assertNotEqual(identities[0], identities[1])

        for web_base_url in (
            "https://api.atlassian.com",
            "https://acme.atlassian.net/wiki",
            "https://acme.atlassian.net:443",
        ):
            with (
                self.subTest(web_base_url=web_base_url),
                private_temporary_directory() as directory,
            ):
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    "[connectors.jira]\n"
                    "enabled = true\n"
                    'deployment = "cloud"\n'
                    f'base_url = "https://api.atlassian.com/ex/jira/{cloud_id}"\n'
                    f'web_base_url = "{web_base_url}"\n'
                    'auth_mode = "none"\n',
                    encoding="utf-8",
                )
                connector = IntegrationConfig.from_toml(path).connector("jira")
                with self.assertRaisesRegex(ConfigurationError, "tenant root"):
                    connector.resolve({})

    def test_cloud_tenant_root_remains_compatible_without_web_override(self) -> None:
        with private_temporary_directory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                "[connectors.jira]\n"
                "enabled = true\n"
                'deployment = "cloud"\n'
                'base_url = "https://acme.atlassian.net/"\n'
                'auth_mode = "none"\n',
                encoding="utf-8",
            )

            resolved = IntegrationConfig.from_toml(path).connector("jira").resolve({})

            self.assertEqual(resolved.base_url, "https://acme.atlassian.net")
            self.assertEqual(resolved.web_base_url, "https://acme.atlassian.net")

    def test_bitbucket_cloud_root_and_email_environment_are_exact(self) -> None:
        for username_env in (
            "MASTER_AGENT_BITBUCKET_EMAIL",
            "MASTER_AGENT_BITBUCKET_USERNAME",
        ):
            with (
                self.subTest(username_env=username_env),
                private_temporary_directory() as directory,
            ):
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    "[connectors.bitbucket]\n"
                    "enabled = true\n"
                    'deployment = "cloud"\n'
                    'base_url = "https://api.bitbucket.org/2.0"\n'
                    'auth_mode = "basic"\n'
                    f'username_env = "{username_env}"\n'
                    'secret_env = "MASTER_AGENT_BITBUCKET_TOKEN"\n',
                    encoding="utf-8",
                )
                connector = IntegrationConfig.from_toml(path).connector("bitbucket")
                resolved = connector.resolve(
                    {
                        username_env: "operator@example.test",
                        "MASTER_AGENT_BITBUCKET_TOKEN": "synthetic-token",
                    }
                )
                self.assertEqual(resolved.base_url, "https://api.bitbucket.org/2.0")

        for base_url in (
            "https://api.bitbucket.org",
            "https://api.bitbucket.org/1.0",
            "https://api.bitbucket.org/2.0/repositories",
            "https://api.bitbucket.org:443/2.0",
        ):
            with (
                self.subTest(base_url=base_url),
                private_temporary_directory() as directory,
            ):
                path = Path(directory) / "integrations.toml"
                path.write_text(
                    "[connectors.bitbucket]\n"
                    "enabled = true\n"
                    'deployment = "cloud"\n'
                    f'base_url = "{base_url}"\n'
                    'auth_mode = "none"\n',
                    encoding="utf-8",
                )
                connector = IntegrationConfig.from_toml(path).connector("bitbucket")
                with self.assertRaisesRegex(ConfigurationError, "provider origins"):
                    connector.resolve({})

    @unittest.skipUnless(os.name == "posix", "permission checks require POSIX")
    def test_explicit_config_rejects_symlinks_and_writable_files(self) -> None:
        with private_temporary_directory() as directory:
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
        with private_temporary_directory() as directory:
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
