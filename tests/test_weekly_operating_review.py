"""Reference Weekly Operating Review workflow tests."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.cli import main
from master_agent.connectors.mock import MockConnector
from master_agent.models import ActionState, RiskLevel
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.recurring import (
    OccurrenceStatus,
    RecurringConfig,
    RecurringStateStore,
)
from master_agent.recurring_occurrence import load_occurrence
from master_agent.registry import ConnectorRegistry
from master_agent.workflows.weekly_operating_review import (
    WeeklyOperatingReviewSettings,
    build_weekly_operating_review_plan,
    render_weekly_operating_review,
)

ROOT = Path(__file__).resolve().parents[1]


class WeeklyOperatingReviewTests(unittest.TestCase):
    """Prove the reference workflow is local-only, cited, and create-only."""

    def test_reference_plan_reads_three_systems_and_generates_locally(self) -> None:
        settings = WeeklyOperatingReviewSettings.from_toml(
            ROOT / "config/weekly-operating-review.toml"
        )
        plan = build_weekly_operating_review_plan(settings)

        self.assertEqual(
            tuple(action.capability for action in plan.actions),
            (
                "jira.issue.search",
                "github.pull_request.search",
                "confluence.page.read",
                "powerpoint.presentation.generate",
            ),
        )
        self.assertEqual(
            tuple(action.risk for action in plan.actions),
            (
                RiskLevel.READ_ONLY,
                RiskLevel.READ_ONLY,
                RiskLevel.READ_ONLY,
                RiskLevel.LOCAL_GENERATION,
            ),
        )
        self.assertFalse(any(action.requires_approval for action in plan.actions))

    def test_reference_renderer_publishes_occurrence_keyed_private_package(
        self,
    ) -> None:
        settings = WeeklyOperatingReviewSettings.from_toml(
            ROOT / "config/weekly-operating-review.toml"
        )
        plan = build_weekly_operating_review_plan(settings)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            output = root / "artifacts"
            output.mkdir(mode=0o700)
            audit = AuditLog(root / "audit.sqlite3")
            registry = ConnectorRegistry()
            registry.register(
                MockConnector(
                    "jira",
                    {
                        settings.jira_project_id: {
                            "schema": "master-agent/jira-issues@1",
                            "issues": [
                                {
                                    "key": "EXAMPLE-1",
                                    "summary": "Resolve blocker",
                                    "status": "In Progress",
                                    "blocked": True,
                                }
                            ],
                            "source_urls": ["https://jira.example/EXAMPLE-1"],
                        }
                    },
                )
            )
            registry.register(
                MockConnector(
                    "github",
                    {
                        f"{settings.github_owner}/{settings.github_repository}": {
                            "schema": "master-agent/github-pull-requests@1",
                            "pull_requests": [
                                {"id": 7, "title": "Finish review", "state": "open"}
                            ],
                            "source_urls": ["https://github.example/pull/7"],
                        }
                    },
                )
            )
            registry.register(
                MockConnector(
                    "confluence",
                    {
                        settings.confluence_page_id: {
                            "schema": "master-agent/confluence-page@1",
                            "page": {"title": "Decisions", "version": "3"},
                            "source_urls": ["https://confluence.example/page"],
                        }
                    },
                )
            )
            registry.register(MockConnector("powerpoint"))
            orchestrator = WorkflowOrchestrator(
                policy=PolicyEngine(
                    PolicyConfig.from_toml(ROOT / "config/policy.toml")
                ),
                sources=SourceOfTruthRegistry.from_toml(
                    ROOT / "config/sources_of_truth.toml"
                ),
                connectors=registry,
                audit=audit,
            )
            try:
                report = orchestrator.run(plan, dry_run=False)
            finally:
                audit.close()
            self.assertTrue(report.successful)
            self.assertTrue(
                all(item.state is ActionState.VERIFIED for item in report.actions)
            )
            execution_key = "d" * 64
            artifacts = render_weekly_operating_review(
                report,
                settings,
                output_root=output,
                execution_key=execution_key,
            )

            self.assertIn(execution_key[:20], artifacts.markdown.name)
            self.assertIn("## Blockers and risks", artifacts.markdown.read_text())
            for path in (
                artifacts.evidence_json,
                artifacts.markdown,
                artifacts.manifest_json,
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_exact_occurrence_runs_reference_plan_through_governed_cli(self) -> None:
        environment = patch.dict(
            os.environ,
            {
                "MASTER_AGENT_JIRA_USERNAME": "recurring-test@example.test",
                "MASTER_AGENT_JIRA_TOKEN": "jira-recurring-test-token",
                "MASTER_AGENT_CONFLUENCE_USERNAME": "recurring-test@example.test",
                "MASTER_AGENT_CONFLUENCE_TOKEN": "confluence-recurring-test-token",
                "MASTER_AGENT_GITHUB_TOKEN": "github-recurring-test-token",
            },
            clear=False,
        )
        environment.start()
        self.addCleanup(environment.stop)
        temp_root = Path(tempfile.gettempdir()).resolve()
        with tempfile.TemporaryDirectory(dir=temp_root) as raw:
            root = Path(raw).resolve()
            for name in (
                "claim",
                "locks",
                "occurrences",
                "audit",
                "artifacts",
                "workspace",
                "results",
                "workflow-output",
            ):
                (root / name).mkdir(mode=0o700)
            copied = (
                "capabilities.toml",
                "governance.toml",
                "identities.toml",
                "integrations.toml",
                "policy.toml",
                "retention.toml",
                "sources_of_truth.toml",
                "weekly-operating-review.toml",
            )
            for name in copied:
                (root / name).write_bytes((ROOT / "config" / name).read_bytes())
            authorities = root / "approval-authorities.toml"
            authorities.write_text(
                "[authorities.test]\n"
                'subject = "reviewer@example.test"\n'
                'issuer = "master-agent.test"\n'
                'tenant = "test"\n'
                'roles = ["change-approver"]\n'
                'secret_env = "TEST_RECURRING_APPROVAL_SECRET"\n',
                encoding="utf-8",
            )
            settings = WeeklyOperatingReviewSettings.from_toml(
                root / "weekly-operating-review.toml"
            )
            plan = build_weekly_operating_review_plan(settings)
            plan_path = root / "plan.json"
            bound_path = root / "bound-plan.json"
            plan_path.write_text(
                json.dumps(plan.to_dict()),
                encoding="utf-8",
            )
            bind_args = [
                "bind-context",
                str(plan_path),
                "--connector-mode",
                "mock",
                "--integrations",
                str(root / "integrations.toml"),
                "--approval-authorities",
                str(authorities),
                "--database",
                str(root / "audit" / "audit.sqlite3"),
                "--result-json",
                str(root / "results" / "result.json"),
                "--retention",
                str(root / "retention.toml"),
                "--identities",
                str(root / "identities.toml"),
                "--workspace-root",
                str(root / "workspace"),
                "--draft-output-dir",
                str(root / "artifacts"),
                "--policy",
                str(root / "policy.toml"),
                "--sources-of-truth",
                str(root / "sources_of_truth.toml"),
                "--capabilities",
                str(root / "capabilities.toml"),
                "--governance",
                str(root / "governance.toml"),
                "--output",
                str(bound_path),
            ]
            self.assertEqual(_quiet_main(bind_args), 0)

            local_now = datetime.now(ZoneInfo("America/New_York"))
            recurring_path = root / "recurring.toml"
            recurring_path.write_text(
                _recurring_text(root, local_now),
                encoding="utf-8",
            )
            artifact = root / "occurrences" / "review.json"
            recurring_bind_args = [
                "recurring-bind",
                "weekly_operating_review",
                "--occurrence",
                local_now.replace(second=0, microsecond=0, tzinfo=None).isoformat(),
                "--plan",
                str(bound_path),
                "--recurring",
                str(recurring_path),
                "--approval-authorities",
                str(authorities),
                "--capabilities",
                str(root / "capabilities.toml"),
                "--governance",
                str(root / "governance.toml"),
                "--policy",
                str(root / "policy.toml"),
                "--sources-of-truth",
                str(root / "sources_of_truth.toml"),
                "--output",
                str(artifact),
            ]
            self.assertEqual(_quiet_main(recurring_bind_args), 0)
            occurrence = load_occurrence(artifact)
            self.assertEqual(
                _quiet_main(
                    [
                        "recurring-run",
                        str(artifact),
                        "--recurring",
                        str(recurring_path),
                        "--dry-run",
                    ]
                ),
                0,
            )
            self.assertEqual(
                _quiet_main(
                    [
                        "recurring-run",
                        str(artifact),
                        "--recurring",
                        str(recurring_path),
                        "--apply",
                    ]
                ),
                0,
            )
            config = RecurringConfig.from_toml(recurring_path)
            store = RecurringStateStore(config.state_database)
            try:
                self.assertIs(
                    store.authenticate_occurrence_artifact(
                        workflow_name=occurrence.workflow_name,
                        scheduled_at=occurrence.scheduled_at,
                        artifact_fingerprint=occurrence.fingerprint,
                        artifact_sha256=occurrence.artifact_sha256,
                        registration_digest=occurrence.registration_digest,
                        execution_key=occurrence.execution_key,
                    ),
                    OccurrenceStatus.SUCCEEDED,
                )
            finally:
                store.close()
            self.assertTrue(
                (
                    root
                    / "artifacts"
                    / f"weekly-operating-review-{occurrence.execution_key[:20]}.md"
                ).exists()
            )


def _quiet_main(arguments: list[str]) -> int:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    if status != 0:
        raise AssertionError(stderr.getvalue() or stdout.getvalue())
    return status


def _recurring_text(root: Path, local_now: datetime) -> str:
    return f"""
[scheduler]
state_database = "{root / "claim" / "state.sqlite3"}"
lock_dir = "{root / "locks"}"
occurrence_root = "{root / "occurrences"}"

[workflows.weekly_operating_review]
enabled = true
revoked = false
generation = 1
kind = "weekly_operating_review"
delivery_mode = "local_only"
weekday = {local_now.weekday()}
hour = {local_now.hour}
minute = {local_now.minute}
timezone = "America/New_York"
dst_fold = "reject"
max_lateness_minutes = 120
catch_up_policy = "latest_only"
approval_resume_minutes = 240
output_dir = "{root / "workflow-output"}"
integration_config = "{root / "integrations.toml"}"
workflow_config = "{root / "weekly-operating-review.toml"}"
identity_config = "{root / "identities.toml"}"
retention_config = "{root / "retention.toml"}"
allowed_capabilities = [
  "jira.issue.search",
  "github.pull_request.search",
  "confluence.page.read",
  "powerpoint.presentation.generate",
]
allowed_recipients = []
canonical_sources = [
  "jira://EXAMPLE",
  "github://example-owner/example-repository",
  "confluence://123456789",
]
"""


if __name__ == "__main__":
    unittest.main()
