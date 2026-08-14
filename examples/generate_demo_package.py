"""Generate a synthetic Phase 2 weekly-status package without live credentials."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from master_agent.citations import make_resource_citation
from master_agent.models import ActionState, ExecutionResult
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.workflows.weekly_status import (
    WeeklyStatusSettings,
    render_weekly_status_package,
)


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Render deterministic demonstration artifacts."""

    jira_id = UUID("00000000-0000-4000-8000-000000000101")
    bitbucket_id = UUID("00000000-0000-4000-8000-000000000102")
    confluence_id = UUID("00000000-0000-4000-8000-000000000103")

    jira = {
        "schema": "master-agent/jira-issues@1",
        "returned": 5,
        "issues": [
            {
                "key": "RISE-142",
                "summary": "Resolve release-blocking authentication regression",
                "status": "Blocked",
                "blocked": True,
                "priority": "Highest",
                "assignee": "Engineer A",
                "web_url": "https://jira.example.test/browse/RISE-142",
            },
            {
                "key": "RISE-151",
                "summary": "Raise backend coverage to 80 percent",
                "status": "In Progress",
                "blocked": False,
                "priority": "High",
                "assignee": "Engineer B",
                "web_url": "https://jira.example.test/browse/RISE-151",
            },
            {
                "key": "RISE-155",
                "summary": "Complete frontend regression suite",
                "status": "In Review",
                "blocked": False,
                "priority": "High",
                "assignee": "Engineer A",
                "web_url": "https://jira.example.test/browse/RISE-155",
            },
            {
                "key": "RISE-160",
                "summary": "Publish deployment runbook",
                "status": "To Do",
                "blocked": False,
                "priority": "Medium",
                "assignee": "Project Lead",
                "web_url": "https://jira.example.test/browse/RISE-160",
            },
            {
                "key": "RISE-138",
                "summary": "Cache dashboard section data",
                "status": "Done",
                "blocked": False,
                "priority": "Medium",
                "assignee": "Project Lead",
                "web_url": "https://jira.example.test/browse/RISE-138",
            },
        ],
        "source_urls": ["https://jira.example.test/issues/?jql=example"],
        "evidence": {"content_digest": "sha256:demo-jira"},
        "security": {"prompt_injection_findings": []},
    }
    bitbucket = {
        "schema": "master-agent/bitbucket-pull-requests@1",
        "returned": 3,
        "pull_requests": [
            {
                "id": 293,
                "title": "Fix authentication refresh race",
                "source_branch": "fix/auth-refresh-race",
                "destination_branch": "main",
                "author": "Engineer A",
                "participants": [{"display_name": "Reviewer", "approved": False}],
                "ci_summary": {"successful": 12, "failed": 1, "in_progress": 0},
                "web_url": "https://bitbucket.example.test/projects/RISE/repos/app/pull-requests/293",
            },
            {
                "id": 296,
                "title": "Add backend coverage tests",
                "source_branch": "test/backend-coverage",
                "destination_branch": "main",
                "author": "Engineer B",
                "participants": [{"display_name": "Reviewer", "approved": True}],
                "ci_summary": {"successful": 13, "failed": 0, "in_progress": 0},
                "web_url": "https://bitbucket.example.test/projects/RISE/repos/app/pull-requests/296",
            },
            {
                "id": 298,
                "title": "Update release runbook",
                "source_branch": "docs/release-runbook",
                "destination_branch": "main",
                "author": "Project Lead",
                "participants": [],
                "ci_summary": {"successful": 4, "failed": 0, "in_progress": 1},
                "web_url": "https://bitbucket.example.test/projects/RISE/repos/app/pull-requests/298",
            },
        ],
        "source_urls": [
            "https://bitbucket.example.test/projects/RISE/repos/app/pull-requests"
        ],
        "evidence": {"content_digest": "sha256:demo-bitbucket"},
        "security": {"prompt_injection_findings": []},
    }
    confluence = {
        "schema": "master-agent/confluence-page@1",
        "page": {
            "id": "123456789",
            "title": "RISE Release Status",
            "version": 14,
            "body_excerpt": (
                "The release remains conditionally on track. Authentication is the "
                "only active release blocker. Backend coverage work is progressing, "
                "and the deployment runbook must be published before the release gate."
            ),
            "web_url": "https://confluence.example.test/display/RISE/Release+Status",
        },
        "source_urls": [
            "https://confluence.example.test/display/RISE/Release+Status"
        ],
        "evidence": {"content_digest": "sha256:demo-confluence"},
        "security": {"prompt_injection_findings": []},
    }

    jira_citations = []
    for issue in jira["issues"]:
        citation = make_resource_citation(
            system="jira",
            resource_type="issue",
            resource_id=str(issue["key"]),
            title=f"{issue['key']} — {issue['summary']}",
            url=str(issue["web_url"]),
        )
        issue["citation_id"] = citation["citation_id"]
        jira_citations.append(citation)
    jira["citations"] = jira_citations

    bitbucket_citations = []
    for pull_request in bitbucket["pull_requests"]:
        citation = make_resource_citation(
            system="bitbucket",
            resource_type="pull_request",
            resource_id=str(pull_request["id"]),
            title=f"PR {pull_request['id']} — {pull_request['title']}",
            url=str(pull_request["web_url"]),
        )
        pull_request["citation_id"] = citation["citation_id"]
        bitbucket_citations.append(citation)
    bitbucket["citations"] = bitbucket_citations

    confluence_citation = make_resource_citation(
        system="confluence",
        resource_type="page",
        resource_id=str(confluence["page"]["id"]),
        title=str(confluence["page"]["title"]),
        url=str(confluence["page"]["web_url"]),
    )
    confluence["page"]["citation_id"] = confluence_citation["citation_id"]
    confluence["citations"] = [confluence_citation]

    report = RunReport(
        run_id=UUID("00000000-0000-4000-8000-000000000201"),
        plan_id=UUID("00000000-0000-4000-8000-000000000202"),
        plan_fingerprint="demo-phase-2-fingerprint",
        dry_run=False,
        actions=(
            _verified(jira_id, "jira.issue.search", jira),
            _verified(bitbucket_id, "bitbucket.pull_request.search", bitbucket),
            _verified(confluence_id, "confluence.page.read", confluence),
        ),
    )
    settings = WeeklyStatusSettings.from_toml(ROOT / "config/weekly-status.toml")
    output = ROOT / "examples/phase2-demo"
    artifacts = render_weekly_status_package(report, settings, output_dir=output)
    for path in (
        artifacts.evidence_json,
        artifacts.markdown,
        artifacts.powerpoint,
        artifacts.manifest_json,
    ):
        print(path.relative_to(ROOT))


def _verified(
    action_id: UUID,
    capability: str,
    payload: dict[str, object],
) -> ActionReport:
    """Create one verified synthetic action report.

    Parameters
    ----------
    action_id
        Stable demonstration action identifier.
    capability
        Capability represented by the result.
    payload
        Normalized connector payload.

    Returns
    -------
    ActionReport
        Verified action report suitable for the renderer.
    """

    return ActionReport(
        action_id=action_id,
        capability=capability,
        state=ActionState.VERIFIED,
        message="Synthetic read verified for the Phase 2 demonstration.",
        result=ExecutionResult(
            action_id=action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=payload,
            connector_reference=f"demo:{capability}",
            message="Synthetic evidence collected.",
        ),
    )


if __name__ == "__main__":
    main()
