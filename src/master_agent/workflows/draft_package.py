"""Phase 3 draft-only multi-system change package workflow."""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from master_agent.config_sources import ConfigSource
from master_agent.connectors.drafts import ArtifactBudget, write_artifact_bundle
from master_agent.directory_safety import PinnedDirectory, pin_directory
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
from master_agent.platform_runtime import require_persistent_state_platform


@dataclass(frozen=True, slots=True)
class DraftPackageSettings:
    """Inputs for a deterministic draft-only change package."""

    package_id: str
    goal: str
    issue_key: str
    jira_before: Mapping[str, Any]
    jira_fields: Mapping[str, Any]
    confluence_page_id: str
    confluence_title: str
    confluence_before: Mapping[str, Any]
    confluence_body: str
    email_to: tuple[str, ...]
    email_subject: str
    email_body: str
    teams_recipient_type: str
    teams_recipient_id: str
    teams_body: str
    presentation_title: str
    presentation_slides: tuple[Mapping[str, Any], ...]
    repository_relative_path: str
    repository_before_text: str
    repository_after_text: str

    @classmethod
    def from_toml(cls, path: ConfigSource) -> DraftPackageSettings:
        """Load draft package settings from TOML."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"draft-package configuration not found: {path}"
            ) from error
        package = _table(raw, "package")
        jira = _table(raw, "jira")
        confluence = _table(raw, "confluence")
        outlook = _table(raw, "outlook")
        teams = _table(raw, "teams")
        powerpoint = _table(raw, "powerpoint")
        repository = _table(raw, "repository")
        slides = powerpoint.get("slides", [])
        if not isinstance(slides, list) or not all(
            isinstance(item, Mapping) for item in slides
        ):
            raise ConfigurationError("powerpoint.slides must be an array of tables")
        email_to = _string_list(outlook.get("to"), "outlook.to")
        return cls(
            package_id=_required(package, "id"),
            goal=_required(package, "goal"),
            issue_key=_required(jira, "issue_key"),
            jira_before=dict(_mapping(jira.get("before", {}), "jira.before")),
            jira_fields=dict(_mapping(jira.get("fields", {}), "jira.fields")),
            confluence_page_id=_required(confluence, "page_id"),
            confluence_title=_required(confluence, "title"),
            confluence_before=dict(
                _mapping(confluence.get("before", {}), "confluence.before")
            ),
            confluence_body=_required(confluence, "body"),
            email_to=email_to,
            email_subject=_required(outlook, "subject"),
            email_body=_required(outlook, "body"),
            teams_recipient_type=str(teams.get("recipient_type", "chat")),
            teams_recipient_id=_required(teams, "recipient_id"),
            teams_body=_required(teams, "body"),
            presentation_title=_required(powerpoint, "title"),
            presentation_slides=tuple(dict(item) for item in slides),
            repository_relative_path=_required(repository, "relative_path"),
            repository_before_text=str(repository.get("before_text", "")),
            repository_after_text=str(repository.get("after_text", "")),
        )


def build_draft_package_plan(settings: DraftPackageSettings) -> ChangePlan:
    """Build a plan whose every action is local generation."""

    prefix = f"draft-package:{settings.package_id}"
    actions = (
        AgentAction(
            capability="jira.issue.update.draft",
            target=ResourceRef("jira", "issue", settings.issue_key),
            parameters={
                "before": dict(settings.jira_before),
                "fields": dict(settings.jira_fields),
                "output_name": "jira-update-draft.json",
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key=f"{prefix}:jira",
            justification="Generate a Jira proposal without publishing it.",
        ),
        AgentAction(
            capability="confluence.page.update.draft",
            target=ResourceRef(
                "confluence",
                "page",
                settings.confluence_page_id,
            ),
            parameters={
                "before": dict(settings.confluence_before),
                "title": settings.confluence_title,
                "body": settings.confluence_body,
                "representation": "storage",
                "output_name": "confluence-update-draft.json",
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key=f"{prefix}:confluence",
            justification="Generate a Confluence proposal without publishing it.",
        ),
        AgentAction(
            capability="outlook.email.draft",
            target=ResourceRef("outlook", "draft", settings.package_id),
            parameters={
                "to": list(settings.email_to),
                "subject": settings.email_subject,
                "body": settings.email_body,
                "output_name": "stakeholder-email.eml",
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key=f"{prefix}:outlook",
            justification="Generate an unsent email draft.",
        ),
        AgentAction(
            capability="teams.message.draft",
            target=ResourceRef("teams", "draft", settings.package_id),
            parameters={
                "recipient_type": settings.teams_recipient_type,
                "recipient_id": settings.teams_recipient_id,
                "body": settings.teams_body,
                "output_name": "team-message.md",
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key=f"{prefix}:teams",
            justification="Generate an unposted Teams message draft.",
        ),
        AgentAction(
            capability="powerpoint.presentation.generate",
            target=ResourceRef("powerpoint", "presentation", settings.package_id),
            parameters={
                "title": settings.presentation_title,
                "slides": [dict(item) for item in settings.presentation_slides],
                "output_name": "change-package.pptx",
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key=f"{prefix}:powerpoint",
            justification="Generate a local PowerPoint draft.",
        ),
        AgentAction(
            capability="repository.patch.generate",
            target=ResourceRef("repository", "patch", settings.package_id),
            parameters={
                "relative_path": settings.repository_relative_path,
                "before_text": settings.repository_before_text,
                "after_text": settings.repository_after_text,
                "output_name": "source-change.patch",
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key=f"{prefix}:repository",
            justification="Generate a source patch without changing a repository.",
        ),
    )
    workflow_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "workflow": "draft-package",
                "capabilities": [item.capability for item in actions],
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    plan = ChangePlan(
        goal=settings.goal,
        actions=actions,
        created_by="registered-workflow:draft-package",
        workflow_id="draft-package-v1",
        workflow_fingerprint=workflow_fingerprint,
    )
    return bind_fast_path_governance(
        plan,
        current_behavior="review drafts are prepared manually across several formats",
        constraint="manual draft assembly is slow and inconsistent",
        leverage_point="deterministic local-generation actions",
        success_metric="the complete package is generated locally without external writes",
        failure_condition="an expected draft is missing or any external system changes",
    )


@dataclass(frozen=True, slots=True)
class DraftPackageArtifacts:
    """Final package index files."""

    summary_markdown: Path
    manifest_json: Path


def render_draft_package(
    report: RunReport,
    *,
    output_dir: Path | PinnedDirectory,
    artifact_budget: ArtifactBudget | None = None,
) -> DraftPackageArtifacts:
    """Create a package summary and manifest without following public paths."""

    require_persistent_state_platform()
    with pin_directory(output_dir) as directory:
        root = directory.path
        artifacts: list[dict[str, Any]] = []
        rows: list[str] = []
        for item in report.actions:
            result = item.result
            after = result.after if result is not None else None
            path_value = after.get("path") if isinstance(after, Mapping) else None
            digest = after.get("sha256") if isinstance(after, Mapping) else None
            size = after.get("size") if isinstance(after, Mapping) else None
            if isinstance(path_value, str):
                path = Path(path_value)
                relative = Path(path.name) if path.parent == root else path
                artifacts.append(
                    {
                        "capability": item.capability,
                        "path": str(relative),
                        "sha256": digest,
                        "size": size,
                    }
                )
            rows.append(f"| `{item.capability}` | `{item.state}` | {item.message} |")
        manifest = {
            "schema": "master-agent/draft-package-manifest@1",
            "run_id": str(report.run_id),
            "plan_id": str(report.plan_id),
            "plan_fingerprint": report.plan_fingerprint,
            "successful": report.successful,
            "published": False,
            "artifacts": artifacts,
        }
        manifest_path = root / "manifest.json"
        summary_path = root / "README.md"
        manifest_bytes = (
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        summary_bytes = (
            "# Draft change package\n\n"
            "No external system was modified. No email or Teams message was sent.\n\n"
            "| Capability | State | Result |\n"
            "|---|---|---|\n"
            + "\n".join(rows)
            + "\n\nSee `manifest.json` for artifact hashes.\n"
        ).encode("utf-8")
        write_artifact_bundle(
            directory,
            (
                (manifest_path, manifest_bytes, "application/json"),
                (summary_path, summary_bytes, "text/markdown"),
            ),
            artifact_budget=artifact_budget,
        )
        return DraftPackageArtifacts(summary_path, manifest_path)


def _table(raw: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = raw.get(name)
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"[{name}] must be a TOML table")
    return value


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{name} must be a TOML table")
    return value


def _required(value: Mapping[str, Any], key: str) -> str:
    rendered = str(value.get(key, "")).strip()
    if not rendered:
        raise ConfigurationError(f"missing required value: {key}")
    return rendered


def _string_list(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ConfigurationError(f"{name} must be a non-empty string list")
    return tuple(item.strip() for item in value)
