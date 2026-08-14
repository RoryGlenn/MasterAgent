"""Approval-bound live execution context tests."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from master_agent.cli import main
from master_agent.config import IntegrationConfig
from master_agent.connectors.factory import build_live_registry
from master_agent.errors import ConfigurationError
from master_agent.execution_context import (
    build_execution_context,
    enforce_execution_context,
)
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.registry import ConnectorRegistry


class ExecutionContextTests(unittest.TestCase):
    """Verify approvals cover runtime destinations and trust roots."""

    def test_changed_resolved_origin_is_rejected_before_connector_construction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(
                json.dumps(_plan().to_dict()),
                encoding="utf-8",
            )
            bound_plan = root / "bound-plan.json"

            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"},
                ),
                redirect_stdout(io.StringIO()),
            ):
                result = main(
                    [
                        "bind-context",
                        str(source_plan),
                        "--integrations",
                        str(integrations_path),
                        "--output",
                        str(bound_plan),
                    ]
                )
            self.assertEqual(result, 0)

            error_output = io.StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_JIRA_BASE_URL": ("https://tenant-b.atlassian.net")},
                ),
                patch("master_agent.cli.build_live_registry") as build_registry,
                redirect_stderr(error_output),
            ):
                result = main(
                    [
                        "run",
                        str(bound_plan),
                        "--apply",
                        "--connector-mode",
                        "live",
                        "--integrations",
                        str(integrations_path),
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("connector origin or CA identity", error_output.getvalue())
            build_registry.assert_not_called()

    def test_ca_bundle_content_and_path_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_CA_CONFIG, encoding="utf-8")
            first_ca = root / "first.pem"
            second_ca = root / "second.pem"
            first_ca.write_text("FIRST CA\n", encoding="utf-8")
            second_ca.write_text("SECOND CA\n", encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)

            first = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(first_ca)},
            )
            changed_content = first_ca.write_text("CHANGED CA\n", encoding="utf-8")
            self.assertGreater(changed_content, 0)
            second = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(first_ca)},
            )
            moved = build_execution_context(
                integrations,
                environ={"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(second_ca)},
            )

            self.assertNotEqual(first.connectors, second.connectors)
            self.assertNotEqual(second.connectors, moved.connectors)

    def test_origin_change_after_construction_is_rejected_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            source_plan = root / "plan.json"
            source_plan.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
            bound_plan = root / "bound-plan.json"

            with patch.dict(
                os.environ,
                {"MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"},
            ):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(
                            [
                                "bind-context",
                                str(source_plan),
                                "--integrations",
                                str(integrations_path),
                                "--output",
                                str(bound_plan),
                            ]
                        ),
                        0,
                    )

                def change_origin(
                    *_args: object, **_kwargs: object
                ) -> ConnectorRegistry:
                    os.environ["MASTER_AGENT_JIRA_BASE_URL"] = (
                        "https://tenant-b.atlassian.net"
                    )
                    return ConnectorRegistry()

                with (
                    patch(
                        "master_agent.cli.build_live_registry",
                        side_effect=change_origin,
                    ) as build_registry,
                    patch("master_agent.cli._orchestrator") as orchestrator,
                    redirect_stderr(io.StringIO()),
                ):
                    result = main(
                        [
                            "run",
                            str(bound_plan),
                            "--apply",
                            "--connector-mode",
                            "live",
                            "--integrations",
                            str(integrations_path),
                            "--draft-output-dir",
                            str(root / "drafts"),
                        ]
                    )

            self.assertEqual(result, 1)
            build_registry.assert_called_once()
            self.assertIsNotNone(
                build_registry.call_args.kwargs["approved_execution_context"]
            )
            orchestrator.assert_not_called()

    def test_factory_rejects_each_changed_approved_connector_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_CA_CONFIG, encoding="utf-8")
            ca_bundle = root / "approved.pem"
            ca_bundle.write_text("APPROVED CA\n", encoding="ascii")
            environ = {"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(ca_bundle)}
            integrations = IntegrationConfig.from_toml(integrations_path)
            approved = build_execution_context(integrations, environ=environ)
            binding = approved.connectors[0]
            changed_bindings = (
                (
                    "config identity",
                    replace(binding, config_identity_sha256="0" * 64),
                ),
                (
                    "base URL",
                    replace(
                        binding,
                        resolved_base_url="https://other.atlassian.net",
                    ),
                ),
                (
                    "origin",
                    replace(binding, resolved_origin="https://other.atlassian.net"),
                ),
                (
                    "CA path",
                    replace(binding, ca_bundle_path=str(root / "other.pem")),
                ),
                (
                    "CA digest",
                    replace(binding, ca_bundle_sha256="0" * 64),
                ),
            )

            for expected_detail, changed in changed_bindings:
                with self.subTest(expected_detail=expected_detail):
                    changed_context = replace(approved, connectors=(changed,))
                    with self.assertRaisesRegex(ConfigurationError, expected_detail):
                        build_live_registry(
                            integrations,
                            environ=environ,
                            systems={"jira"},
                            approved_execution_context=changed_context,
                        )

            changed_integrations = replace(approved, integrations_sha256="0" * 64)
            with self.assertRaisesRegex(ConfigurationError, "integrations bundle"):
                build_live_registry(
                    integrations,
                    environ=environ,
                    systems={"jira"},
                    approved_execution_context=changed_integrations,
                )

    def test_tls_uses_approved_bytes_during_ca_path_swap_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            integrations_path = root / "integrations.toml"
            integrations_path.write_text(_JIRA_CA_CONFIG, encoding="utf-8")
            ca_bundle = root / "active.pem"
            replacement = root / "replacement.pem"
            saved = root / "saved.pem"
            approved_bytes = b"APPROVED CA\n"
            attacker_bytes = b"ATTACKER CA\n"
            ca_bundle.write_bytes(approved_bytes)
            replacement.write_bytes(attacker_bytes)
            environ = {"MASTER_AGENT_ENTERPRISE_CA_BUNDLE": str(ca_bundle)}
            integrations = IntegrationConfig.from_toml(integrations_path)
            approved = build_execution_context(integrations, environ=environ)
            before_build = build_execution_context(integrations, environ=environ)
            during_swap = []

            def swap_path_then_restore(*args: object, **kwargs: object) -> MagicMock:
                self.assertEqual(args, ())
                ca_bundle.replace(saved)
                replacement.replace(ca_bundle)
                try:
                    during_swap.append(
                        build_execution_context(integrations, environ=environ)
                    )
                finally:
                    ca_bundle.replace(replacement)
                    saved.replace(ca_bundle)
                return MagicMock()

            with patch(
                "master_agent.http.ssl.create_default_context",
                side_effect=swap_path_then_restore,
            ) as create_context:
                registry = build_live_registry(
                    integrations,
                    environ=environ,
                    systems={"jira"},
                    approved_execution_context=approved,
                )

            after_build = build_execution_context(integrations, environ=environ)
            self.assertIn("jira", registry.systems())
            self.assertEqual(before_build, approved)
            self.assertEqual(after_build, approved)
            self.assertEqual(len(during_swap), 1)
            self.assertNotEqual(during_swap[0], approved)
            create_context.assert_called_once_with(
                cadata=approved_bytes.decode("ascii")
            )
            self.assertEqual(ca_bundle.read_bytes(), approved_bytes)

    def test_context_round_trip_is_part_of_plan_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations_path = Path(directory) / "integrations.toml"
            integrations_path.write_text(_JIRA_ENV_CONFIG, encoding="utf-8")
            integrations = IntegrationConfig.from_toml(integrations_path)
            context = build_execution_context(
                integrations,
                environ={
                    "MASTER_AGENT_JIRA_BASE_URL": "https://tenant-a.atlassian.net"
                },
            )
            original = _plan()
            bound = ChangePlan.from_dict(
                {**original.to_dict(), "execution_context": context.to_dict()}
            )
            round_tripped = ChangePlan.from_dict(bound.to_dict())

        self.assertNotEqual(original.fingerprint, bound.fingerprint)
        self.assertEqual(round_tripped.execution_context, context)
        self.assertEqual(round_tripped.fingerprint, bound.fingerprint)
        with self.assertRaisesRegex(ConfigurationError, "bind-context"):
            enforce_execution_context(original, context)


def _plan() -> ChangePlan:
    action = AgentAction(
        capability="jira.issue.read",
        target=ResourceRef(
            system="jira",
            resource_type="issue",
            resource_id="ENG-1",
        ),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="execution-context-test",
        justification="test live identity binding",
    )
    return ChangePlan(
        goal="test execution context", actions=(action,), created_by="test"
    )


_JIRA_ENV_CONFIG = """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url_env = "MASTER_AGENT_JIRA_BASE_URL"
auth_mode = "none"
""".strip()


_JIRA_CA_CONFIG = """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://tenant-a.atlassian.net"
auth_mode = "none"
ca_bundle_env = "MASTER_AGENT_ENTERPRISE_CA_BUNDLE"
""".strip()


if __name__ == "__main__":
    unittest.main()
