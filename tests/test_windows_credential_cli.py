"""Connector-level selection tests for configured Windows credential sources."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from master_agent import cli as cli_module
from master_agent.auth import AuthMode
from master_agent.cli import (
    _credential_environment,
    _load_credential_store,
    _readiness,
)
from master_agent.config import ConnectorConfig, DeploymentType, IntegrationConfig
from master_agent.errors import ConfigurationError
from master_agent.platform_runtime import platform_runtime_status
from master_agent.readiness import ReadinessReport
from tests.helpers import private_temporary_directory

_SECRET = "configured-native-secret-canary"


def _microsoft_connector(
    *,
    flow: str,
    target: str,
) -> ConnectorConfig:
    extra: dict[str, object] = {
        "credential_provider": "windows-dpapi",
        "credential_target": target,
        "oauth_flow": flow,
    }
    auth_mode = AuthMode.OAUTH_APPLICATION
    if flow == "client_credentials":
        extra.update(
            {
                "tenant_id_env": "MASTER_AGENT_ENTRA_TENANT_ID",
                "client_id_env": "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
                "client_secret_env": "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
                "scopes": ["https://graph.microsoft.com/.default"],
            }
        )
    else:
        auth_mode = AuthMode.OAUTH_DELEGATED
        extra["token_file_env"] = "MASTER_AGENT_GRAPH_TOKEN_FILE"
    return ConnectorConfig(
        system="microsoft",
        enabled=True,
        deployment=DeploymentType.CLOUD,
        base_url="https://graph.microsoft.com/v1.0",
        base_url_env=None,
        auth_mode=auth_mode,
        username_env=None,
        secret_env=None,
        extra=extra,
    )


class WindowsCredentialCliTests(unittest.TestCase):
    def test_entra_client_credentials_load_from_one_reviewed_native_source(
        self,
    ) -> None:
        connector = _microsoft_connector(
            flow="client_credentials",
            target=r"C:\MasterAgent\entra.dpapi",
        )
        integrations = IntegrationConfig(connectors={"microsoft": connector})
        values = {
            "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-id",
            "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-id",
            "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET": _SECRET,
        }
        backend = Mock()
        backend.backend_id = "windows-native-test"
        backend.load_credentials.return_value = values

        with patch(
            "master_agent.cli.get_credential_storage_backend",
            return_value=backend,
        ):
            store = _load_credential_store(
                None,
                integrations=integrations,
                governance=Mock(),
                connector_mode="live",
                systems={"microsoft"},
            )

        self.assertIsNotNone(store)
        assert store is not None
        ambient_secret = "ambient-secret-canary"
        environ = _credential_environment(
            store,
            {"master_agent_entra_app_client_secret": ambient_secret},
            declared_names=integrations.credential_environment_variables(),
        )
        resolved = connector.resolve(environ)

        self.assertEqual(environ["MASTER_AGENT_ENTRA_APP_CLIENT_SECRET"], _SECRET)
        self.assertNotIn("master_agent_entra_app_client_secret", environ)
        self.assertIsNotNone(resolved.auth.token_provider)
        self.assertNotIn(_SECRET, repr(resolved))
        self.assertEqual(
            store.shadowed_ambient_names(
                {"master_agent_entra_app_client_secret": ambient_secret}
            ),
            ("MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",),
        )
        backend.load_credentials.assert_called_once_with(
            provider="windows-dpapi",
            target=r"C:\MasterAgent\entra.dpapi",
            allowed_names=(
                "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
                "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
                "MASTER_AGENT_ENTRA_TENANT_ID",
            ),
        )

    def test_delegated_token_file_path_can_come_from_native_source(self) -> None:
        with private_temporary_directory() as directory:
            token_path = Path(directory) / "graph-token.json"
            connector = _microsoft_connector(
                flow="token_file",
                target=r"C:\MasterAgent\delegated.dpapi",
            )
            integrations = IntegrationConfig(connectors={"microsoft": connector})
            backend = Mock()
            backend.backend_id = "windows-native-test"
            backend.load_credentials.return_value = {
                "MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_path)
            }
            with patch(
                "master_agent.cli.get_credential_storage_backend",
                return_value=backend,
            ):
                store = _load_credential_store(
                    None,
                    integrations=integrations,
                    governance=Mock(),
                    connector_mode="live",
                    systems={"microsoft"},
                )
            assert store is not None
            environ = _credential_environment(
                store,
                {},
                declared_names=integrations.credential_environment_variables(),
            )
            resolved = connector.resolve(environ)

        self.assertIsNotNone(resolved.auth.token_provider)
        self.assertNotIn(str(token_path), repr(resolved))

    def test_native_loader_bounds_provider_exceptions(self) -> None:
        connector = _microsoft_connector(
            flow="client_credentials",
            target=r"C:\MasterAgent\entra.dpapi",
        )
        backend = Mock()
        backend.backend_id = "windows-native-test"
        backend.load_credentials.side_effect = ConfigurationError(
            "backend exposed " + _SECRET
        )
        with (
            patch(
                "master_agent.cli.get_credential_storage_backend",
                return_value=backend,
            ),
            self.assertRaisesRegex(
                ConfigurationError,
                "could not be loaded safely",
            ) as raised,
        ):
            _load_credential_store(
                None,
                integrations=IntegrationConfig(connectors={"microsoft": connector}),
                governance=Mock(),
                connector_mode="live",
                systems={"microsoft"},
            )
        self.assertNotIn(_SECRET, str(raised.exception))

    def test_readiness_serializes_source_names_without_secret_values(self) -> None:
        connector = _microsoft_connector(
            flow="client_credentials",
            target=r"C:\MasterAgent\entra.dpapi",
        )
        integrations = IntegrationConfig(connectors={"microsoft": connector})
        governance = Mock()
        catalog = Mock()
        backend = Mock()
        backend.backend_id = "windows-native-test"
        backend.load_credentials.return_value = {
            "MASTER_AGENT_ENTRA_TENANT_ID": "tenant-id",
            "MASTER_AGENT_ENTRA_APP_CLIENT_ID": "client-id",
            "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET": _SECRET,
        }
        report = ReadinessReport(
            ready=True,
            environment="production",
            checks=(),
            errors=(),
            warnings=(),
            platform_runtime=platform_runtime_status(),
        )
        write_json = Mock()
        ambient_secret = "ambient-readiness-secret-canary"
        output = Path("/bounded/readiness.json")
        terminal = StringIO()
        with (
            patch.object(
                cli_module.IntegrationConfig,
                "from_toml",
                return_value=integrations,
            ),
            patch.object(
                cli_module.GovernanceProfile,
                "from_toml",
                return_value=governance,
            ),
            patch.object(
                cli_module.CapabilityCatalog,
                "from_toml",
                return_value=catalog,
            ),
            patch.object(cli_module.OAuthProfiles, "from_toml", return_value=Mock()),
            patch.object(cli_module.IdentityRegistry, "from_toml", return_value=Mock()),
            patch.object(
                cli_module,
                "provider_data_egress_policy_denials",
                return_value=(),
            ),
            patch.object(cli_module, "assess_readiness", return_value=report),
            patch.object(
                cli_module,
                "get_credential_storage_backend",
                return_value=backend,
            ),
            patch.object(cli_module, "resolve_config_source", return_value=Mock()),
            patch.object(cli_module, "require_persistent_state_platform"),
            patch.object(cli_module, "_write_json", write_json),
            patch.object(
                cli_module.os,
                "environ",
                {"master_agent_entra_app_client_secret": ambient_secret},
            ),
            redirect_stdout(terminal),
        ):
            result = _readiness(
                integrations_path=None,
                capabilities_path=None,
                governance_path=None,
                oauth_path=None,
                identities_path=None,
                credentials_file=None,
                egress_checks=(),
                output=output,
            )

        self.assertEqual(result, 0)
        payload = write_json.call_args.args[1]
        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn(_SECRET, rendered)
        self.assertNotIn(ambient_secret, rendered)
        self.assertIn("MASTER_AGENT_ENTRA_APP_CLIENT_SECRET", rendered)
        self.assertIn("credential_sources", rendered)
        self.assertNotIn(_SECRET, terminal.getvalue())
        self.assertNotIn(ambient_secret, terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
