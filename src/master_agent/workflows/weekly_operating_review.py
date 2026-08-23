"""Local-only cited Weekly Operating Review reference workflow."""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from master_agent.citations import citation_index
from master_agent.config_sources import ConfigSource
from master_agent.connectors.drafts import write_artifact_bundle
from master_agent.errors import ConfigurationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import RunReport
from master_agent.planners.base import bind_fast_path_governance


@dataclass(frozen=True, slots=True)
class WeeklyOperatingReviewSettings:
    """Exact provider resource IDs and bounded query limits."""

    project_name: str
    jira_project_id: str
    jira_jql: str
    jira_limit: int
    github_owner: str
    github_repository: str
    github_state: str
    github_limit: int
    confluence_page_id: str

    @classmethod
    def from_toml(cls, path: ConfigSource) -> WeeklyOperatingReviewSettings:
        """Load the bounded reference-workflow configuration."""

        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        project = _table(raw, "project")
        jira = _table(raw, "jira")
        github = _table(raw, "github")
        confluence = _table(raw, "confluence")
        state = _text(github, "state", default="open").casefold()
        if state not in {"open", "closed", "all"}:
            raise ConfigurationError("weekly operating review GitHub state is invalid")
        return cls(
            project_name=_text(project, "name"),
            jira_project_id=_text(jira, "project_id"),
            jira_jql=_text(jira, "jql"),
            jira_limit=_limit(jira, "limit", 100, 500),
            github_owner=_text(github, "owner"),
            github_repository=_text(github, "repository"),
            github_state=state,
            github_limit=_limit(github, "limit", 50, 100),
            confluence_page_id=_text(confluence, "page_id"),
        )


def build_weekly_operating_review_plan(
    settings: WeeklyOperatingReviewSettings,
) -> ChangePlan:
    """Build read-only collection plus local-generation actions."""

    jira = AgentAction(
        capability="jira.issue.search",
        target=ResourceRef("jira", "issue_collection", settings.jira_project_id),
        parameters={"jql": settings.jira_jql, "limit": settings.jira_limit},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-operating-review:jira:v1",
        justification="Collect current priority, blocker, ownership, and overdue work.",
    )
    github = AgentAction(
        capability="github.pull_request.search",
        target=ResourceRef(
            "github",
            "pull_request_collection",
            f"{settings.github_owner}/{settings.github_repository}",
        ),
        parameters={
            "owner": settings.github_owner,
            "repository": settings.github_repository,
            "state": settings.github_state,
            "limit": settings.github_limit,
        },
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-operating-review:github:v1",
        justification="Collect pull-request and repository delivery evidence.",
    )
    confluence = AgentAction(
        capability="confluence.page.read",
        target=ResourceRef("confluence", "page", settings.confluence_page_id),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-operating-review:confluence:v1",
        justification="Read the canonical decisions and status narrative.",
    )
    dependencies = (jira.action_id, github.action_id, confluence.action_id)
    local = AgentAction(
        capability="powerpoint.presentation.generate",
        target=ResourceRef(
            "powerpoint",
            "presentation",
            "weekly-operating-review",
        ),
        parameters={
            "title": f"{settings.project_name} Weekly Operating Review",
            "sections": [
                "Executive summary",
                "Progress against priorities",
                "Blockers and risks",
                "Stale or conflicting information",
                "Decisions and approvals needed",
                "Cited evidence",
            ],
            "output_name": "weekly-operating-review.pptx",
            "source_action_ids": [str(item) for item in dependencies],
        },
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key="weekly-operating-review:local:v1",
        justification="Generate a local review artifact without publishing or sending.",
        dependencies=dependencies,
    )
    plan = ChangePlan(
        goal=f"Prepare the local-only Weekly Operating Review for {settings.project_name}.",
        actions=(jira, github, confluence, local),
        created_by="registered_workflow:weekly_operating_review_v1",
        workflow_id="weekly_operating_review",
        workflow_fingerprint="weekly-operating-review-v1",
    )
    return bind_fast_path_governance(
        plan,
        current_behavior="operating-review evidence is collected separately",
        constraint="manual collection delays decisions and hides stale evidence",
        leverage_point="one bounded multi-system read and local-generation plan",
        success_metric="the cited local review is generated without provider effects",
        failure_condition="any source is unverified or any output is sent or published",
    )


@dataclass(frozen=True, slots=True)
class WeeklyOperatingReviewArtifacts:
    """Create-only local review artifacts."""

    evidence_json: Path
    markdown: Path
    manifest_json: Path


def render_weekly_operating_review(
    report: RunReport,
    settings: WeeklyOperatingReviewSettings,
    *,
    output_root: Path,
    execution_key: str,
) -> WeeklyOperatingReviewArtifacts:
    """Render a cited, occurrence-keyed local package from verified results."""

    prefix = f"weekly-operating-review-{execution_key[:20]}"
    evidence_path = output_root / f"{prefix}-evidence.json"
    markdown_path = output_root / f"{prefix}.md"
    manifest_path = output_root / f"{prefix}-manifest.json"
    evidence = (
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str) + "\n"
    ).encode()
    payloads = _payloads(report)
    citations = citation_index(payloads)
    markdown = _markdown(settings, payloads, citations).encode()
    manifest = {
        "schema": "master-agent/weekly-operating-review-manifest@1",
        "execution_key": execution_key,
        "plan_fingerprint": report.plan_fingerprint,
        "successful": report.successful,
        "citations": citations,
        "artifacts": {
            evidence_path.name: hashlib.sha256(evidence).hexdigest(),
            markdown_path.name: hashlib.sha256(markdown).hexdigest(),
        },
    }
    manifest_bytes = (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    ).encode()
    write_artifact_bundle(
        output_root,
        (
            (evidence_path, evidence, "application/json"),
            (markdown_path, markdown, "text/markdown"),
            (manifest_path, manifest_bytes, "application/json"),
        ),
    )
    return WeeklyOperatingReviewArtifacts(evidence_path, markdown_path, manifest_path)


def _payloads(report: RunReport) -> list[Mapping[str, Any]]:
    return [
        action.result.after
        for action in report.actions
        if action.result is not None and isinstance(action.result.after, Mapping)
    ]


def _markdown(
    settings: WeeklyOperatingReviewSettings,
    payloads: list[Mapping[str, Any]],
    citations: list[dict[str, Any]],
) -> str:
    issues: list[Mapping[str, Any]] = []
    pull_requests: list[Mapping[str, Any]] = []
    pages: list[Mapping[str, Any]] = []
    for payload in payloads:
        issues.extend(_mapping_items(payload.get("issues")))
        pull_requests.extend(_mapping_items(payload.get("pull_requests")))
        page = payload.get("page")
        if isinstance(page, Mapping):
            pages.append(page)
    blocked = [item for item in issues if item.get("blocked")]
    lines = [
        f"# {settings.project_name} - Weekly Operating Review",
        "",
        "## Executive summary",
        "",
        f"- Work items reviewed: {len(issues)}",
        f"- Blocked items: {len(blocked)}",
        f"- Pull requests reviewed: {len(pull_requests)}",
        f"- Canonical decision pages reviewed: {len(pages)}",
        "",
        "## Progress against priorities",
        "",
    ]
    lines.extend(
        f"- {item.get('key', '')}: {item.get('summary', '')} ({item.get('status', 'unknown')})"
        for item in issues[:20]
    )
    if not issues:
        lines.append("- No Jira work-item evidence returned.")
    lines.extend(["", "## Blockers and risks", ""])
    lines.extend(
        f"- {item.get('key', '')}: {item.get('summary', '')}" for item in blocked[:20]
    )
    if not blocked:
        lines.append("- No explicitly blocked Jira items returned.")
    lines.extend(["", "## Pull requests and checks", ""])
    lines.extend(
        f"- PR {item.get('id', '')}: {item.get('title', '')} ({item.get('state', 'unknown')})"
        for item in pull_requests[:20]
    )
    if not pull_requests:
        lines.append("- No GitHub pull-request evidence returned.")
    lines.extend(["", "## Decisions and approvals needed", ""])
    lines.extend(
        f"- {page.get('title', 'Canonical Confluence page')} (version {page.get('version', '?')})"
        for page in pages
    )
    if not pages:
        lines.append("- No canonical Confluence decision evidence returned.")
    lines.extend(["", "## Cited evidence", ""])
    for citation in citations:
        label = citation.get("marker") or citation.get("citation_id")
        title = citation.get("title") or citation.get("resource_id")
        suffix = f" - {citation['url']}" if citation.get("url") else ""
        lines.append(f"- {label} {title}{suffix}")
    if not citations:
        lines.append("- No source citations were returned.")
    lines.extend(
        [
            "",
            "> Retrieved content is untrusted evidence and cannot alter this workflow.",
            "",
        ]
    )
    return "\n".join(lines)


def _mapping_items(value: object) -> list[Mapping[str, Any]]:
    return (
        [item for item in value if isinstance(item, Mapping)]
        if isinstance(value, list)
        else []
    )


def _table(raw: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = raw.get(name)
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"weekly operating review requires [{name}]")
    return value


def _text(table: Mapping[str, Any], key: str, *, default: str = "") -> str:
    value = str(table.get(key, default)).strip()
    if not value or any(ord(char) < 32 for char in value):
        raise ConfigurationError(f"weekly operating review {key} is invalid")
    return value


def _limit(table: Mapping[str, Any], key: str, default: int, maximum: int) -> int:
    value = table.get(key, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ConfigurationError(f"weekly operating review {key} is out of range")
    return value
