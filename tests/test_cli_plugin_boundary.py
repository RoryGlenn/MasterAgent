"""CLI regressions for the disabled connector-plugin execution boundary."""

from __future__ import annotations

import json
import os
import unittest
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from importlib import metadata
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.cli import main
from master_agent.config import IntegrationConfig
from master_agent.config_sources import ConfigSnapshot, ConfigSource
from master_agent.execution_context import build_execution_context
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.plugins import (
    CONNECTOR_ENTRY_POINT_GROUP,
    PluginLock,
    discover_connector_plugins,
)
from tests.helpers import private_temporary_directory


@dataclass
class _FakeDistribution:
    name: str
    version: str
    root: Path
    files: tuple[Path, ...]

    def locate_file(self, relative: Path) -> Path:
        return self.root / relative


class CliPluginBoundaryTests(unittest.TestCase):
    """Prove CLI apply never crosses the in-process plugin boundary."""

    def test_plugin_marker_is_absent_with_valid_or_invalid_approval(self) -> None:
        for valid_approval in (True, False):
            with self.subTest(valid_approval=valid_approval):
                self._assert_plugin_apply_is_disabled(valid_approval=valid_approval)

    def test_approval_authority_file_is_parsed_from_trusted_snapshot(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            action = _read_action()
            plan = ChangePlan(
                goal="approve a reviewed plan",
                actions=(action,),
                created_by="test",
            )
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
            authorities = root / "approval-authorities.toml"
            authorities.write_text(
                "[authorities.operator]\n"
                'subject = "trusted@example.test"\n'
                'issuer = "master-agent.test"\n'
                'tenant = "test-tenant"\n'
                'roles = ["change-approver"]\n'
                'secret_env = "TRUSTED_APPROVAL_SECRET"\n',
                encoding="utf-8",
            )
            output = root / "approval.json"
            original_loader = HmacApprovalAuthenticator.from_toml
            observed_snapshot = False

            def replace_file_after_snapshot(
                source: ConfigSource,
                *,
                environ: Mapping[str, str] | None = None,
            ) -> HmacApprovalAuthenticator:
                nonlocal observed_snapshot
                observed_snapshot = isinstance(source, ConfigSnapshot)
                authorities.write_text(
                    "[authorities.operator]\n"
                    'subject = "attacker@example.test"\n'
                    'issuer = "master-agent.test"\n'
                    'tenant = "test-tenant"\n'
                    'roles = ["change-approver"]\n'
                    'secret_env = "ATTACKER_APPROVAL_SECRET"\n',
                    encoding="utf-8",
                )
                return original_loader(source, environ=environ)

            with (
                patch.dict(
                    os.environ,
                    {
                        "TRUSTED_APPROVAL_SECRET": "t" * 32,
                        "ATTACKER_APPROVAL_SECRET": "a" * 32,
                    },
                    clear=False,
                ),
                patch.object(
                    HmacApprovalAuthenticator,
                    "from_toml",
                    side_effect=replace_file_after_snapshot,
                ),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                status = main(
                    [
                        "approve",
                        str(plan_path),
                        "--actions",
                        str(action.action_id),
                        "--key-id",
                        "operator",
                        "--expected-fingerprint",
                        plan.fingerprint,
                        "--approval-authorities",
                        str(authorities),
                        "--output",
                        str(output),
                    ]
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(status, 0)
            self.assertTrue(observed_snapshot)
            self.assertEqual(payload["approved_by"], "trusted@example.test")

    def _assert_plugin_apply_is_disabled(self, *, valid_approval: bool) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            marker = root / "plugin-imported.marker"
            module_name = f"master_agent_marker_plugin_{uuid4().hex}"
            module_path = root / f"{module_name}.py"
            module_path.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n"
                "from master_agent.connectors.mock import MockConnector\n"
                "def build():\n"
                "    return MockConnector(\n"
                "        'servicenow',\n"
                "        capabilities={'servicenow.ticket.read'},\n"
                "    )\n",
                encoding="utf-8",
            )
            distribution = _FakeDistribution(
                name=f"master-agent-marker-{uuid4().hex}",
                version="1.0.0",
                root=root,
                files=(Path(module_path.name),),
            )
            entry = metadata.EntryPoint(
                name="marker",
                value=f"{module_name}:build",
                group=CONNECTOR_ENTRY_POINT_GROUP,
            )._for(distribution)  # type: ignore[attr-defined]
            descriptor = discover_connector_plugins(entries=(entry,))[0]
            plugin_lock = root / "plugin-lock.json"
            plugin_lock.write_text(
                json.dumps(PluginLock(plugins=(descriptor,)).to_dict()),
                encoding="utf-8",
            )

            integrations_path = root / "integrations.toml"
            integrations_path.write_text("[connectors]\n", encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)
            unbound = ChangePlan(
                goal="exercise a reviewed connector plugin",
                actions=(_read_action(),),
                created_by="test",
            )
            plan = replace(
                unbound,
                execution_context=build_execution_context(
                    integrations,
                    plugin_descriptors=(descriptor,),
                ),
            )
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")

            capabilities = root / "capabilities.toml"
            capabilities.write_text(
                '[capabilities."servicenow.ticket.read"]\n'
                "enabled = true\n"
                'authentication = "configured_connector"\n'
                'risk = "read_only"\n',
                encoding="utf-8",
            )
            authorities_path = root / "approval-authorities.toml"
            authorities_path.write_text(
                "[authorities.operator]\n"
                'subject = "operator@example.test"\n'
                'issuer = "master-agent.test"\n'
                'tenant = "test-tenant"\n'
                'roles = ["change-approver"]\n'
                'secret_env = "PLUGIN_TEST_APPROVAL_SECRET"\n',
                encoding="utf-8",
            )
            authenticator = HmacApprovalAuthenticator(
                {
                    "operator": ApprovalAuthority(
                        key_id="operator",
                        subject="operator@example.test",
                        secret=b"plugin-boundary-test-secret-32-bytes",
                        issuer="master-agent.test",
                        tenant="test-tenant",
                        roles=("change-approver",),
                    )
                }
            )
            issued = datetime.now(UTC)
            approval = authenticator.issue(
                plan=plan,
                approved_action_ids=tuple(action.action_id for action in plan.actions),
                key_id="operator",
                issued_at=issued,
                expires_at=issued + timedelta(minutes=5),
            )
            if not valid_approval:
                approval = replace(approval, signature="0" * 64)
            approval_path = root / "approval.json"
            approval_path.write_text(
                json.dumps(approval.to_dict()),
                encoding="utf-8",
            )
            stderr = StringIO()

            with (
                patch.dict(
                    os.environ,
                    {
                        "PLUGIN_TEST_APPROVAL_SECRET": (
                            "plugin-boundary-test-secret-32-bytes"
                        )
                    },
                    clear=False,
                ),
                patch(
                    "master_agent.plugins.metadata.entry_points",
                    return_value=metadata.EntryPoints((entry,)),
                ) as entry_points,
                redirect_stdout(StringIO()),
                redirect_stderr(stderr),
            ):
                status = main(
                    [
                        "run",
                        str(plan_path),
                        "--apply",
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(integrations_path),
                        "--capabilities",
                        str(capabilities),
                        "--approval",
                        str(approval_path),
                        "--approval-authorities",
                        str(authorities_path),
                        "--plugin",
                        "marker",
                        "--plugin-lock",
                        str(plugin_lock),
                        "--database",
                        str(root / "audit.sqlite3"),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn(
                "in-process connector plugin execution is disabled", stderr.getvalue()
            )
            entry_points.assert_not_called()
            self.assertFalse(marker.exists())


def _read_action() -> AgentAction:
    return AgentAction(
        capability="servicenow.ticket.read",
        target=ResourceRef(
            system="servicenow",
            resource_type="ticket",
            resource_id="INC-1",
        ),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="plugin-marker-read",
        justification="test plugin activation boundary",
    )


if __name__ == "__main__":
    unittest.main()
