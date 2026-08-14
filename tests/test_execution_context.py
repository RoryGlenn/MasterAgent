"""Approval-bound live execution context tests."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from master_agent.cli import main
from master_agent.config import IntegrationConfig
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
            orchestrator.assert_not_called()

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
