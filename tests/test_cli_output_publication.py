"""Adversarial coverage for create-only CLI JSON publication."""

from __future__ import annotations

import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from master_agent import approval_handoff
from master_agent.approval_handoff import write_restricted_json
from master_agent.cli import main
from master_agent.errors import ConfigurationError
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    CompensationDescriptor,
    CompensationMode,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.planners.static import build_weekly_status_plan
from tests.helpers import private_temporary_directory


class RestrictedPublicationTests(unittest.TestCase):
    """Prove the shared output primitive is no-follow and create-only."""

    def test_create_only_output_is_private_and_refuses_existing_destination(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            output = Path(directory) / "result.json"

            write_restricted_json(output, {"safe": True})

            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            before = output.read_bytes()
            with self.assertRaisesRegex(ConfigurationError, "already exists"):
                write_restricted_json(output, {"safe": False})
            self.assertEqual(output.read_bytes(), before)

    def test_symlink_destination_never_modifies_target(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            victim = root / "victim.json"
            victim.write_text('{"safe":true}\n', encoding="utf-8")
            output = root / "output.json"
            output.symlink_to(victim.name)

            with self.assertRaisesRegex(ConfigurationError, "already exists"):
                write_restricted_json(output, {"safe": False})

            self.assertTrue(output.is_symlink())
            self.assertEqual(victim.read_text(encoding="utf-8"), '{"safe":true}\n')

    def test_parent_replacement_rolls_back_through_pinned_descriptor(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            approved = root / "approved"
            displaced = root / "displaced"
            approved.mkdir(mode=0o700)
            output = approved / "result.json"
            real_publish = approval_handoff._publish_restricted_bytes

            def replace_parent(directory, name, payload, *, reuse_identical):
                approved.rename(displaced)
                approved.mkdir(mode=0o700)
                return real_publish(
                    directory,
                    name,
                    payload,
                    reuse_identical=reuse_identical,
                )

            with (
                patch.object(
                    approval_handoff,
                    "_publish_restricted_bytes",
                    side_effect=replace_parent,
                ),
                self.assertRaisesRegex(ConfigurationError, "path was replaced"),
            ):
                write_restricted_json(output, {"safe": True})

            self.assertEqual(tuple(approved.iterdir()), ())
            self.assertEqual(tuple(displaced.iterdir()), ())

    def test_chmod_failure_leaves_no_partial_output(self) -> None:
        with private_temporary_directory() as directory:
            output = Path(directory) / "result.json"
            with (
                patch(
                    "master_agent.approval_handoff.os.fchmod",
                    side_effect=PermissionError("simulated chmod failure"),
                ),
                self.assertRaisesRegex(ConfigurationError, "destination changed"),
            ):
                write_restricted_json(output, {"secret": "canary"})

            self.assertFalse(output.exists())


class ActiveCliCallerTests(unittest.TestCase):
    """Every security-relevant CLI export refuses a final-component symlink."""

    def test_active_plan_approval_plugin_and_workflow_exports_share_primitive(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            victim = root / "victim.json"
            victim.write_text('{"safe":true}\n', encoding="utf-8")
            plan = build_weekly_status_plan()
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
            state = root / "state"
            drafts = root / "drafts"
            state.mkdir(mode=0o700)
            drafts.mkdir(mode=0o700)
            authorities = root / "approval-authorities.toml"
            authorities.write_text(
                "[authorities.operator]\n"
                'subject = "operator@example.test"\n'
                'issuer = "master-agent.test"\n'
                'tenant = "test-tenant"\n'
                'roles = ["change-approver"]\n'
                'secret_env = "OUTPUT_TEST_APPROVAL_SECRET"\n',
                encoding="utf-8",
            )
            compensation_plan, report = _compensation_inputs()
            compensation_plan_path = root / "compensation-source-plan.json"
            compensation_report_path = root / "compensation-report.json"
            compensation_plan_path.write_text(
                json.dumps(compensation_plan.to_dict()),
                encoding="utf-8",
            )
            compensation_report_path.write_text(
                json.dumps(report.to_dict()),
                encoding="utf-8",
            )
            cases = {
                "sample-plan": ["sample-plan"],
                "bind-context": [
                    "bind-context",
                    str(plan_path),
                    "--connector-mode",
                    "mock",
                    "--database",
                    str(state / "audit.sqlite3"),
                    "--draft-output-dir",
                    str(drafts),
                ],
                "approve": [
                    "approve",
                    str(plan_path),
                    "--actions",
                    str(plan.actions[0].action_id),
                    "--key-id",
                    "operator",
                    "--expected-fingerprint",
                    plan.fingerprint,
                    "--approval-authorities",
                    str(authorities),
                ],
                "plugin-lock": ["plugins"],
                "compensation-plan": [
                    "compensation-plan",
                    "--plan",
                    str(compensation_plan_path),
                    "--report",
                    str(compensation_report_path),
                ],
                "weekly-status-plan": ["weekly-status-plan"],
                "communication-context-plan": ["communication-context-plan"],
            }

            for label, arguments in cases.items():
                with self.subTest(label=label):
                    output = root / f"{label}.json"
                    output.symlink_to(victim.name)
                    status, _stdout, stderr = _run_cli(
                        [*arguments, "--output", str(output)],
                        environ={"OUTPUT_TEST_APPROVAL_SECRET": "s" * 32},
                    )
                    self.assertEqual(status, 1, stderr)
                    self.assertIn("already exists", stderr)
                    self.assertTrue(output.is_symlink())
                    self.assertEqual(
                        victim.read_text(encoding="utf-8"),
                        '{"safe":true}\n',
                    )


def _compensation_inputs() -> tuple[ChangePlan, RunReport]:
    action = AgentAction(
        capability="example.resource.update",
        target=ResourceRef("example", "resource", "42"),
        parameters={"value": "new"},
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key="output-test-compensation",
        justification="Exercise compensation-plan publication.",
    )
    plan = ChangePlan(
        goal="Exercise compensation plan output.",
        actions=(action,),
        created_by="test",
    )
    result = ExecutionResult(
        action_id=action.action_id,
        state=ActionState.SUCCEEDED,
        before={"value": "old"},
        after={"value": "new"},
        compensation=CompensationDescriptor(
            kind="restore_previous_value",
            mode=CompensationMode.PLAN,
            capability="example.resource.restore",
            parameters={"value": "old"},
            expected_version="2",
        ),
    )
    report = RunReport(
        run_id=uuid4(),
        plan_id=plan.plan_id,
        plan_fingerprint=plan.fingerprint,
        dry_run=False,
        actions=(
            ActionReport(
                action_id=action.action_id,
                capability=action.capability,
                state=ActionState.VERIFIED,
                message="verified",
                result=result,
            ),
        ),
    )
    return plan, report


def _run_cli(
    arguments: list[str],
    *,
    environ: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    selected_environ = environ or {}
    with (
        patch.dict(os.environ, selected_environ, clear=False),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()
