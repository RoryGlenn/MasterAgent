"""Read-only weekly-status workflow and artifact tests."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

from pptx import Presentation

from master_agent.citations import make_resource_citation
from master_agent.config import DeploymentType
from master_agent.models import ActionState, ExecutionResult, RiskLevel
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.workflows.weekly_status import (
    WeeklyStatusSettings,
    build_weekly_status_read_plan,
    render_weekly_status_package,
)


ROOT = Path(__file__).resolve().parents[1]


class WeeklyStatusWorkflowTests(unittest.TestCase):
    """Verify plans remain read-only and packages retain evidence."""

    def test_repository_workflow_config_builds_three_read_actions(self) -> None:
        settings = WeeklyStatusSettings.from_toml(
            ROOT / "config/weekly-status.toml"
        )
        plan = build_weekly_status_read_plan(
            settings,
            bitbucket_deployment=DeploymentType.CLOUD,
        )
        self.assertEqual(len(plan.actions), 3)
        self.assertTrue(all(action.risk is RiskLevel.READ_ONLY for action in plan.actions))
        bitbucket = next(
            action
            for action in plan.actions
            if action.capability == "bitbucket.pull_request.search"
        )
        self.assertEqual(bitbucket.parameters["workspace"], "example-workspace")
        self.assertNotIn("project", bitbucket.parameters)

    def test_data_center_plan_uses_project_key(self) -> None:
        settings = WeeklyStatusSettings.from_toml(
            ROOT / "config/weekly-status.toml"
        )
        plan = build_weekly_status_read_plan(
            settings,
            bitbucket_deployment=DeploymentType.DATA_CENTER,
        )
        bitbucket = next(
            action
            for action in plan.actions
            if action.capability == "bitbucket.pull_request.search"
        )
        self.assertEqual(bitbucket.parameters["project"], "PROJECT")
        self.assertNotIn("workspace", bitbucket.parameters)

    def test_renderer_writes_evidence_markdown_powerpoint_and_manifest(self) -> None:
        settings = WeeklyStatusSettings.from_toml(
            ROOT / "config/weekly-status.toml"
        )
        report = _report()
        with TemporaryDirectory() as directory:
            output = Path(directory)
            artifacts = render_weekly_status_package(
                report,
                settings,
                output_dir=output,
            )

            for path in (
                artifacts.evidence_json,
                artifacts.markdown,
                artifacts.powerpoint,
                artifacts.manifest_json,
            ):
                self.assertTrue(path.exists(), path)
                self.assertGreater(path.stat().st_size, 0)

            markdown = artifacts.markdown.read_text(encoding="utf-8")
            self.assertIn("Blocked issues: **1**", markdown)
            self.assertIn("Pull requests with failing CI: **1**", markdown)
            self.assertIn("Canonical Confluence narrative", markdown)
            self.assertIn("[CIT-", markdown)

            presentation = Presentation(artifacts.powerpoint)
            self.assertEqual(len(presentation.slides), 6)

            manifest = json.loads(
                artifacts.manifest_json.read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["successful"])
            self.assertEqual(len(manifest["security_findings"]), 1)
            self.assertEqual(len(manifest["citations"]), 3)
            for filename, digest in manifest["artifacts"].items():
                self.assertEqual(digest, _sha256(output / filename))


def _report() -> RunReport:
    jira_id = uuid4()
    bitbucket_id = uuid4()
    confluence_id = uuid4()
    jira_citation = make_resource_citation(
        system="jira",
        resource_type="issue",
        resource_id="RISE-142",
        title="RISE-142 — Release blocker",
        url="https://jira.example.test/browse/RISE-142?source=test",
    )
    bitbucket_citation = make_resource_citation(
        system="bitbucket",
        resource_type="pull_request",
        resource_id="7",
        title="PR 7 — Status workflow",
        url="https://bitbucket.example.test/pr/7?source=test",
    )
    confluence_citation = make_resource_citation(
        system="confluence",
        resource_type="page",
        resource_id="123",
        title="Project Status",
        url="https://confluence.example.test/pages/123?source=test",
    )
    jira_payload = {
        "schema": "master-agent/jira-issues@1",
        "issues": [
            {
                "key": "RISE-142",
                "summary": "Release blocker",
                "status": "Blocked",
                "blocked": True,
                "web_url": "https://jira.example.test/browse/RISE-142",
                "citation_id": jira_citation["citation_id"],
            }
        ],
        "citations": [jira_citation],
        "source_urls": ["https://jira.example.test/search"],
        "security": {
            "prompt_injection_findings": [
                {
                    "path": "$.issues[0].summary",
                    "category": "instruction_override",
                    "severity": "high",
                    "excerpt": "Ignore previous instructions",
                }
            ]
        },
    }
    bitbucket_payload = {
        "schema": "master-agent/bitbucket-pull-requests@1",
        "pull_requests": [
            {
                "id": 7,
                "title": "Status workflow",
                "source_branch": "feature/status",
                "destination_branch": "main",
                "participants": [],
                "ci_summary": {"failed": 1, "successful": 0},
                "citation_id": bitbucket_citation["citation_id"],
            }
        ],
        "citations": [bitbucket_citation],
        "source_urls": ["https://bitbucket.example.test/pr/7"],
        "security": {"prompt_injection_findings": []},
    }
    confluence_payload = {
        "schema": "master-agent/confluence-page@1",
        "page": {
            "id": "123",
            "title": "Project Status",
            "version": 12,
            "body_excerpt": "Release remains on track with two active blockers.",
            "citation_id": confluence_citation["citation_id"],
        },
        "citations": [confluence_citation],
        "source_urls": ["https://confluence.example.test/pages/123"],
        "security": {"prompt_injection_findings": []},
    }
    return RunReport(
        run_id=uuid4(),
        plan_id=uuid4(),
        plan_fingerprint="f" * 64,
        dry_run=False,
        actions=(
            _action_report(jira_id, "jira.issue.search", jira_payload),
            _action_report(
                bitbucket_id,
                "bitbucket.pull_request.search",
                bitbucket_payload,
            ),
            _action_report(
                confluence_id,
                "confluence.page.read",
                confluence_payload,
            ),
        ),
    )


def _action_report(
    action_id: object,
    capability: str,
    payload: dict[str, object],
) -> ActionReport:
    return ActionReport(
        action_id=action_id,
        capability=capability,
        state=ActionState.VERIFIED,
        message="verified",
        result=ExecutionResult(
            action_id=action_id,
            state=ActionState.SUCCEEDED,
            before=payload,
            after=payload,
            connector_reference="test",
            message="read",
        ),
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
