"""Exact native-connector Engineering Work Item Review workflow."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from master_agent.citations import citation_index, make_resource_citation
from master_agent.config import DeploymentType
from master_agent.config_sources import ConfigSource
from master_agent.connectors.drafts import write_artifact_bundle
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import ActionReport, RunReport
from master_agent.planners.base import bind_fast_path_governance
from master_agent.provider_egress import ProviderDataRoute

WORKFLOW_ID = "T1-EWIR-001"
WORKFLOW_FINGERPRINT = hashlib.sha256(
    b"master-agent/T1-EWIR-001/engineering-work-item-review@1"
).hexdigest()
WORKFLOW_SCHEMA = "master-agent/engineering-work-item-review@1"
MANIFEST_SCHEMA = "master-agent/engineering-work-item-review-manifest@1"
_ISSUE_KEY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,29}-[1-9][0-9]*")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
_PAGE_ID_PATTERN = re.compile(r"[1-9][0-9]{0,39}")
_MAX_CONFLUENCE_PAGES = 3
_MAX_BUILD_STATUSES = 100
_MAX_DIFFSTAT_CHANGES = 100
_JIRA_REVIEW_FIELDS = (
    "id",
    "key",
    "summary",
    "status",
    "status_category",
    "assignee",
    "priority",
    "issue_type",
    "project_key",
    "labels",
    "blocked",
    "updated_at",
    "resolved_at",
    "web_url",
    "description",
    "acceptance_criteria",
    "issue_links",
    "external_relations",
)
_CORE_CAPABILITIES = frozenset(
    {
        "jira.issue.review_context.read",
        "bitbucket.repository.read",
        "bitbucket.pull_request.read",
        "bitbucket.build_status.read",
    }
)
_VERIFIED_STATES = frozenset({ActionState.VERIFIED})


class EngineeringReviewOutcome(StrEnum):
    """Fixed honest outcome vocabulary for the private review bundle."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class EngineeringWorkItemReviewSettings:
    """Trusted exact scope for one `T1-EWIR-001` run."""

    configuration_sha256: str
    data_classification: DataClassification
    bitbucket_deployment: DeploymentType
    bitbucket_origin: str
    bitbucket_workspace: str
    bitbucket_project: str
    bitbucket_repository: str
    bitbucket_pull_request_id: str
    build_status_limit: int
    diffstat_limit: int
    include_diffstat: bool
    confluence_origin: str
    confluence_space_id: str
    confluence_space_key: str
    confluence_page_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if _SHA256_PATTERN.fullmatch(self.configuration_sha256) is None:
            raise ConfigurationError(
                "engineering review configuration digest is invalid"
            )
        if not isinstance(self.data_classification, DataClassification):
            raise ConfigurationError(
                "engineering review data classification must be known"
            )
        if not isinstance(self.bitbucket_deployment, DeploymentType):
            raise ConfigurationError(
                "engineering review Bitbucket deployment is unsupported"
            )
        _require_origin(self.bitbucket_origin, "bitbucket.origin")
        _require_origin(self.confluence_origin, "confluence.origin")
        _require_identifier(self.bitbucket_repository, "bitbucket.repository")
        if self.bitbucket_deployment is DeploymentType.CLOUD:
            _require_identifier(self.bitbucket_workspace, "bitbucket.workspace")
            if self.bitbucket_project:
                raise ConfigurationError(
                    "Cloud engineering review configuration forbids bitbucket.project"
                )
        else:
            _require_identifier(self.bitbucket_project, "bitbucket.project")
            if self.bitbucket_workspace:
                raise ConfigurationError(
                    "Data Center engineering review configuration forbids "
                    "bitbucket.workspace"
                )
        if (
            not self.bitbucket_pull_request_id.isdecimal()
            or str(int(self.bitbucket_pull_request_id))
            != self.bitbucket_pull_request_id
            or int(self.bitbucket_pull_request_id) <= 0
        ):
            raise ConfigurationError(
                "engineering review pull_request_id must be a canonical positive integer"
            )
        if (
            isinstance(self.build_status_limit, bool)
            or not 1 <= self.build_status_limit <= _MAX_BUILD_STATUSES
        ):
            raise ConfigurationError(
                "engineering review build_status_limit must be between 1 and 100"
            )
        if (
            isinstance(self.diffstat_limit, bool)
            or not 1 <= self.diffstat_limit <= _MAX_DIFFSTAT_CHANGES
        ):
            raise ConfigurationError(
                "engineering review diffstat_limit must be between 1 and 100"
            )
        if not isinstance(self.include_diffstat, bool):
            raise ConfigurationError(
                "engineering review include_diffstat must be a boolean"
            )
        _require_identifier(self.confluence_space_id, "confluence.space_id")
        _require_identifier(self.confluence_space_key, "confluence.space_key")
        page_ids = tuple(self.confluence_page_ids)
        if len(page_ids) > _MAX_CONFLUENCE_PAGES:
            raise ConfigurationError(
                "engineering review accepts at most three Confluence pages"
            )
        if len(page_ids) != len(set(page_ids)) or any(
            _PAGE_ID_PATTERN.fullmatch(page_id) is None for page_id in page_ids
        ):
            raise ConfigurationError(
                "engineering review Confluence page IDs must be unique canonical "
                "positive integers"
            )
        object.__setattr__(self, "confluence_page_ids", page_ids)

    @property
    def bitbucket_owner(self) -> str:
        """Return the selected Cloud workspace or Data Center project."""

        return (
            self.bitbucket_workspace
            if self.bitbucket_deployment is DeploymentType.CLOUD
            else self.bitbucket_project
        )

    @classmethod
    def from_toml(cls, source: ConfigSource) -> EngineeringWorkItemReviewSettings:
        """Load one exact private workflow configuration snapshot."""

        with source.open("rb") as handle:
            payload = handle.read()
        try:
            raw = tomllib.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise ConfigurationError(
                "engineering review configuration is not valid UTF-8 TOML"
            ) from error
        _reject_unknown(raw, {"case", "bitbucket", "confluence"}, "top level")
        case = _table(raw, "case")
        bitbucket = _table(raw, "bitbucket")
        confluence = _table(raw, "confluence")
        _reject_unknown(case, {"id", "data_classification"}, "[case]")
        _reject_unknown(
            bitbucket,
            {
                "deployment",
                "origin",
                "workspace",
                "project",
                "repository",
                "pull_request_id",
                "build_status_limit",
                "diffstat_limit",
                "include_diffstat",
            },
            "[bitbucket]",
        )
        _reject_unknown(
            confluence,
            {"origin", "space_id", "space_key", "page_ids"},
            "[confluence]",
        )
        case_id = _required_text(case, "id")
        if case_id != WORKFLOW_ID:
            raise ConfigurationError(
                f"engineering review case.id must be {WORKFLOW_ID}"
            )
        try:
            classification = DataClassification(
                _required_text(case, "data_classification")
            )
            deployment = DeploymentType(_required_text(bitbucket, "deployment"))
        except ValueError as error:
            raise ConfigurationError(
                "engineering review classification or deployment is unsupported"
            ) from error
        raw_pages = confluence.get("page_ids", [])
        if not isinstance(raw_pages, list) or not all(
            isinstance(item, str) for item in raw_pages
        ):
            raise ConfigurationError("confluence.page_ids must be a string list")
        return cls(
            configuration_sha256=hashlib.sha256(payload).hexdigest(),
            data_classification=classification,
            bitbucket_deployment=deployment,
            bitbucket_origin=_required_text(bitbucket, "origin").rstrip("/"),
            bitbucket_workspace=_optional_text(bitbucket, "workspace"),
            bitbucket_project=_optional_text(bitbucket, "project"),
            bitbucket_repository=_required_text(bitbucket, "repository"),
            bitbucket_pull_request_id=_required_text(
                bitbucket,
                "pull_request_id",
            ),
            build_status_limit=_bounded_int(
                bitbucket,
                "build_status_limit",
                default=50,
                maximum=_MAX_BUILD_STATUSES,
            ),
            diffstat_limit=_bounded_int(
                bitbucket,
                "diffstat_limit",
                default=50,
                maximum=_MAX_DIFFSTAT_CHANGES,
            ),
            include_diffstat=_strict_bool(
                bitbucket,
                "include_diffstat",
                default=False,
            ),
            confluence_origin=_required_text(confluence, "origin").rstrip("/"),
            confluence_space_id=_required_text(confluence, "space_id"),
            confluence_space_key=_required_text(confluence, "space_key"),
            confluence_page_ids=tuple(raw_pages),
        )


@dataclass(frozen=True, slots=True)
class EngineeringWorkItemReviewArtifacts:
    """The exact three files produced by the Tier-1 renderer."""

    review_json: Path
    review_markdown: Path
    manifest_json: Path
    outcome: EngineeringReviewOutcome


def build_engineering_work_item_review_plan(
    issue_key: str,
    settings: EngineeringWorkItemReviewSettings,
) -> ChangePlan:
    """Build the immutable, read-only `T1-EWIR-001` provider plan."""

    if _ISSUE_KEY_PATTERN.fullmatch(issue_key) is None:
        raise ConfigurationError(
            "engineering review requires an exact canonical Jira issue key"
        )
    actions = _workflow_actions(issue_key, settings)
    plan = ChangePlan(
        goal=f"Produce the private cited Engineering Work Item Review for {issue_key}.",
        actions=actions,
        created_by="registered_workflow:t1_ewir_001_v1",
        workflow_id=WORKFLOW_ID,
        workflow_fingerprint=WORKFLOW_FINGERPRINT,
    )
    return bind_fast_path_governance(
        plan,
        current_behavior="engineering evidence is reviewed separately across providers",
        constraint="manual comparison delays decisions and can hide stale evidence",
        leverage_point="one exact verified native-connector review plan",
        success_metric="the private cited review is complete and digest verified",
        failure_condition=(
            "required evidence is missing, stale, ambiguous, unverified, or exceeds scope"
        ),
    )


def validate_engineering_work_item_review_plan(
    plan: ChangePlan,
    settings: EngineeringWorkItemReviewSettings,
) -> None:
    """Revalidate the registered workflow and exact frozen settings before render."""

    if plan.workflow_id != WORKFLOW_ID:
        raise ValidationError("engineering review plan has the wrong workflow ID")
    if plan.workflow_fingerprint != WORKFLOW_FINGERPRINT:
        raise ValidationError(
            "engineering review plan differs from its registered implementation"
        )
    jira_actions = [
        action
        for action in plan.actions
        if action.capability == "jira.issue.review_context.read"
    ]
    if len(jira_actions) != 1:
        raise ValidationError("engineering review plan must contain one Jira target")
    expected = _workflow_actions(jira_actions[0].target.resource_id, settings)
    if _action_shape(plan.actions) != _action_shape(expected):
        raise ValidationError(
            "engineering review plan action shape differs from the registered workflow"
        )


def render_engineering_work_item_review(
    report: RunReport,
    plan: ChangePlan,
    settings: EngineeringWorkItemReviewSettings,
    *,
    output_root: PinnedDirectory,
) -> EngineeringWorkItemReviewArtifacts:
    """Publish one verified, create-only JSON/Markdown/manifest bundle."""

    validate_engineering_work_item_review_plan(plan, settings)
    _validate_output_root(plan, output_root)
    action_by_id = {action.action_id: action for action in plan.actions}
    _validate_report_binding(
        report,
        plan=plan,
        settings=settings,
        action_by_id=action_by_id,
    )
    all_verified = _verified_payloads(report, action_by_id)
    stale_evidence = _evidence_staleness(
        all_verified,
        plan=plan,
        settings=settings,
        action_by_id=action_by_id,
    )
    verified = _reportable_verified_payloads(
        all_verified,
        stale_evidence=stale_evidence,
        action_by_id=action_by_id,
    )
    citations, citation_by_action = _verified_citations(
        verified,
        action_by_id=action_by_id,
    )
    failures = _failure_records(
        report,
        action_by_id=action_by_id,
        stale_evidence=stale_evidence,
    )
    ambiguities = _relation_ambiguities(verified, settings)
    outcome = _classify_outcome(
        report,
        action_by_id,
        ambiguities,
        stale_evidence=stale_evidence,
    )
    findings = _findings(
        verified,
        settings=settings,
        ambiguities=ambiguities,
        stale_evidence=stale_evidence,
        citation_by_action=citation_by_action,
    )
    evidence = _evidence_payloads(verified)
    review = {
        "schema": WORKFLOW_SCHEMA,
        "workflow_id": WORKFLOW_ID,
        "workflow_configuration_sha256": settings.configuration_sha256,
        "outcome": str(outcome),
        "complete": outcome is EngineeringReviewOutcome.COMPLETE,
        "run_id": str(report.run_id),
        "plan_id": str(report.plan_id),
        "plan_fingerprint": report.plan_fingerprint,
        "scope": {
            "jira_issue_key": _jira_issue_key(plan),
            "bitbucket": {
                "deployment": str(settings.bitbucket_deployment),
                "owner_or_project": settings.bitbucket_owner,
                "repository": settings.bitbucket_repository,
                "pull_request_id": settings.bitbucket_pull_request_id,
            },
            "confluence": {
                "space_id": settings.confluence_space_id,
                "space_key": settings.confluence_space_key,
                "page_ids": list(settings.confluence_page_ids),
            },
            "data_classification": str(settings.data_classification),
        },
        "evidence": evidence,
        "findings": findings,
        "failures": failures,
        "stale_evidence": stale_evidence,
        "ambiguities": ambiguities,
        "citations": citations,
        "citation_ids": [item["citation_id"] for item in citations],
        "security_findings": _security_findings(verified),
    }
    review_bytes = _json_bytes(review)
    markdown_bytes = _render_markdown(
        review,
        verified=verified,
        citation_by_action=citation_by_action,
    ).encode("utf-8")
    review_path = output_root.path / "engineering-work-item-review.json"
    markdown_path = output_root.path / "engineering-work-item-review.md"
    manifest_path = output_root.path / "manifest.json"
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "workflow_id": WORKFLOW_ID,
        "outcome": str(outcome),
        "complete": outcome is EngineeringReviewOutcome.COMPLETE,
        "run_id": str(report.run_id),
        "plan_fingerprint": report.plan_fingerprint,
        "artifacts": [
            _artifact_record(review_path.name, review_bytes),
            _artifact_record(markdown_path.name, markdown_bytes),
        ],
        "verification": "create-only readback SHA-256",
    }
    manifest_bytes = _json_bytes(manifest)
    published = write_artifact_bundle(
        output_root,
        (
            (review_path, review_bytes, "application/json"),
            (markdown_path, markdown_bytes, "text/markdown"),
            (manifest_path, manifest_bytes, "application/json"),
        ),
    )
    expected = {
        review_path.name: (len(review_bytes), hashlib.sha256(review_bytes).hexdigest()),
        markdown_path.name: (
            len(markdown_bytes),
            hashlib.sha256(markdown_bytes).hexdigest(),
        ),
        manifest_path.name: (
            len(manifest_bytes),
            hashlib.sha256(manifest_bytes).hexdigest(),
        ),
    }
    observed = {item.path.name: (item.size, item.sha256) for item in published}
    if observed != expected:  # pragma: no cover - publisher contract guard.
        raise ValidationError("engineering review artifact readback differs")
    return EngineeringWorkItemReviewArtifacts(
        review_json=review_path,
        review_markdown=markdown_path,
        manifest_json=manifest_path,
        outcome=outcome,
    )


def _workflow_actions(
    issue_key: str,
    settings: EngineeringWorkItemReviewSettings,
) -> tuple[AgentAction, ...]:
    coordinates = {
        "repository": settings.bitbucket_repository,
        (
            "workspace"
            if settings.bitbucket_deployment is DeploymentType.CLOUD
            else "project"
        ): settings.bitbucket_owner,
    }
    jira = AgentAction(
        capability="jira.issue.review_context.read",
        target=ResourceRef("jira", "issue", issue_key),
        parameters={
            "fields": list(_JIRA_REVIEW_FIELDS),
            "workflow_configuration_sha256": settings.configuration_sha256,
            "bitbucket_origin": settings.bitbucket_origin,
            "bitbucket_owner": settings.bitbucket_owner,
            "bitbucket_repository": settings.bitbucket_repository,
            "bitbucket_pull_request_id": settings.bitbucket_pull_request_id,
            "confluence_origin": settings.confluence_origin,
            "confluence_space_id": settings.confluence_space_id,
            "confluence_space_key": settings.confluence_space_key,
            "confluence_page_ids": list(settings.confluence_page_ids),
        },
        idempotency_key=f"{WORKFLOW_ID}:jira:{issue_key}",
        justification="Read and independently verify the exact Jira review context.",
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        data_classification=settings.data_classification,
    )
    repository = AgentAction(
        capability="bitbucket.repository.read",
        target=ResourceRef(
            "bitbucket",
            "repository",
            f"{settings.bitbucket_owner}/{settings.bitbucket_repository}",
        ),
        parameters=coordinates,
        idempotency_key=(
            f"{WORKFLOW_ID}:repository:{settings.bitbucket_owner}/"
            f"{settings.bitbucket_repository}"
        ),
        justification="Read and independently verify the configured repository.",
        dependencies=(jira.action_id,),
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        data_classification=settings.data_classification,
    )
    pull_request = AgentAction(
        capability="bitbucket.pull_request.read",
        target=ResourceRef(
            "bitbucket",
            "pull_request",
            settings.bitbucket_pull_request_id,
        ),
        parameters=coordinates,
        idempotency_key=(
            f"{WORKFLOW_ID}:pull-request:{settings.bitbucket_owner}/"
            f"{settings.bitbucket_repository}:{settings.bitbucket_pull_request_id}"
        ),
        justification="Read and independently verify the exact related pull request.",
        dependencies=(repository.action_id,),
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        data_classification=settings.data_classification,
    )
    build_status = AgentAction(
        capability="bitbucket.build_status.read",
        target=ResourceRef(
            "bitbucket",
            "pull_request",
            settings.bitbucket_pull_request_id,
        ),
        parameters={
            **coordinates,
            "pull_request_id": settings.bitbucket_pull_request_id,
            "limit": settings.build_status_limit,
        },
        idempotency_key=(
            f"{WORKFLOW_ID}:build:{settings.bitbucket_owner}/"
            f"{settings.bitbucket_repository}:{settings.bitbucket_pull_request_id}"
        ),
        justification=(
            "Read and independently verify build evidence for the current PR head."
        ),
        dependencies=(pull_request.action_id,),
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        data_classification=settings.data_classification,
    )
    actions: list[AgentAction] = [jira, repository, pull_request, build_status]
    if settings.include_diffstat:
        actions.append(
            AgentAction(
                capability="bitbucket.pull_request.diffstat",
                target=ResourceRef(
                    "bitbucket",
                    "pull_request",
                    settings.bitbucket_pull_request_id,
                ),
                parameters={**coordinates, "limit": settings.diffstat_limit},
                idempotency_key=(
                    f"{WORKFLOW_ID}:diffstat:{settings.bitbucket_owner}/"
                    f"{settings.bitbucket_repository}:"
                    f"{settings.bitbucket_pull_request_id}"
                ),
                justification="Read the optional bounded pull-request diff summary.",
                dependencies=(pull_request.action_id,),
                risk=RiskLevel.READ_ONLY,
                authority_source=AuthoritySource.REGISTERED_WORKFLOW,
                requires_approval=False,
                data_classification=settings.data_classification,
            )
        )
    for page_id in settings.confluence_page_ids:
        actions.append(
            AgentAction(
                capability="confluence.page.read",
                target=ResourceRef("confluence", "page", page_id),
                parameters={
                    "space_id": settings.confluence_space_id,
                    "space_key": settings.confluence_space_key,
                },
                idempotency_key=f"{WORKFLOW_ID}:confluence:{page_id}",
                justification=(
                    "Read and independently verify one exact requirements or decision page."
                ),
                dependencies=(build_status.action_id,),
                risk=RiskLevel.READ_ONLY,
                authority_source=AuthoritySource.REGISTERED_WORKFLOW,
                requires_approval=False,
                data_classification=settings.data_classification,
            )
        )
    return tuple(actions)


def _action_shape(actions: Sequence[AgentAction]) -> list[dict[str, Any]]:
    index_by_id = {action.action_id: index for index, action in enumerate(actions)}
    if len(index_by_id) != len(actions):
        raise ValidationError("engineering review action IDs must be unique")
    return [
        {
            "capability": action.capability,
            "target": {
                "system": action.target.system,
                "resource_type": action.target.resource_type,
                "resource_id": action.target.resource_id,
                "expected_version": action.target.expected_version,
            },
            "parameters": dict(action.parameters),
            "risk": str(action.risk),
            "authority_source": str(action.authority_source),
            "requires_approval": action.requires_approval,
            "idempotency_key": action.idempotency_key,
            "justification": action.justification,
            "data_classification": str(action.data_classification),
            "dependencies": [index_by_id[item] for item in action.dependencies],
        }
        for action in actions
    ]


def _validate_report_binding(
    report: RunReport,
    *,
    plan: ChangePlan,
    settings: EngineeringWorkItemReviewSettings,
    action_by_id: Mapping[Any, AgentAction],
) -> None:
    """Reject a dry, incomplete, foreign, or post-verification-mutated report."""

    if report.dry_run:
        raise ValidationError("engineering review cannot render a dry-run report")
    if report.plan_id != plan.plan_id or report.plan_fingerprint != plan.fingerprint:
        raise ValidationError("engineering review report differs from the exact plan")
    context = plan.execution_context
    if context is None or context.runtime is None:
        raise ValidationError(
            "engineering review requires an approval-bound execution context"
        )
    connector_by_system = {item.system: item for item in context.connectors}
    expected_systems = {action.target.system for action in plan.actions}
    if set(connector_by_system) != expected_systems:
        raise ValidationError(
            "engineering review connector bindings differ from selected systems"
        )
    bitbucket_connector = connector_by_system.get("bitbucket")
    if bitbucket_connector is None or (
        str(bitbucket_connector.deployment) != str(settings.bitbucket_deployment)
    ):
        raise ValidationError(
            "engineering review Bitbucket deployment differs from its exact configuration"
        )
    report_ids = [action.action_id for action in report.actions]
    if len(report_ids) != len(set(report_ids)) or set(report_ids) != set(action_by_id):
        raise ValidationError(
            "engineering review report must contain every planned action exactly once"
        )
    for action_report in report.actions:
        action = action_by_id[action_report.action_id]
        if action_report.capability != action.capability:
            raise ValidationError(
                "engineering review report capability differs from its planned action"
            )
        if action_report.state is ActionState.REUSED:
            raise ValidationError("engineering review provider reads cannot be reused")
        if action_report.result is not None:
            if action_report.result.action_id != action_report.action_id:
                raise ValidationError(
                    "engineering review result differs from its planned action"
                )
            action_report.result.validate_integrity()
        if action_report.state is ActionState.VERIFIED:
            if (
                action_report.result is None
                or action_report.result.state is not ActionState.SUCCEEDED
                or not isinstance(action_report.result.after, Mapping)
            ):
                raise ValidationError(
                    "engineering review verified action has no successful result"
                )
            egress = action_report.egress
            connector = connector_by_system[action.target.system]
            payload = action_report.result.after
            if str(payload.get("system") or "") != action.target.system or str(
                payload.get("deployment") or ""
            ) != str(connector.deployment):
                raise ValidationError(
                    "engineering review provider envelope differs from its connector"
                )
            if egress is None or (
                egress.provider != action.target.system
                or egress.capability != action.capability
                or egress.action_fingerprint != action.effect_fingerprint
                or egress.data_classification is not action.data_classification
                or egress.route is not ProviderDataRoute.AUDITED
                or egress.connector_configuration_sha256
                != connector.config_identity_sha256
                or egress.output_schema
                != str(action_report.result.after.get("schema", ""))
            ):
                raise ValidationError(
                    "engineering review provider-data binding differs from its action"
                )


def _validate_output_root(plan: ChangePlan, output_root: PinnedDirectory) -> None:
    """Require the live descriptor to match the exact bound artifact root."""

    context = plan.execution_context
    runtime = context.runtime if context is not None else None
    if runtime is None:
        raise ValidationError(
            "engineering review requires an approval-bound artifact root"
        )
    binding = next(
        (item for item in runtime.runtime_paths if item.name == "artifact.root"),
        None,
    )
    output_root.validate()
    if (
        binding is None
        or output_root.path != Path(runtime.artifact_root)
        or binding.path != runtime.artifact_root
        or binding.platform_identity != output_root.object_identity
    ):
        raise ValidationError(
            "engineering review output differs from the bound artifact root"
        )


def _verified_payloads(
    report: RunReport,
    action_by_id: Mapping[Any, AgentAction],
) -> list[tuple[ActionReport, Mapping[str, Any]]]:
    verified: list[tuple[ActionReport, Mapping[str, Any]]] = []
    for action_report in report.actions:
        if action_report.action_id not in action_by_id:
            raise ValidationError(
                "engineering review report contains an unknown action"
            )
        after = action_report.result.after if action_report.result is not None else None
        if action_report.state in _VERIFIED_STATES and isinstance(after, Mapping):
            verified.append((action_report, after))
    return verified


def _verified_citations(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    *,
    action_by_id: Mapping[Any, AgentAction],
) -> tuple[list[dict[str, Any]], dict[Any, str]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_action: dict[Any, str] = {}
    for action_report, payload in verified:
        action = action_by_id[action_report.action_id]
        reference = (
            action_report.result.connector_reference
            if action_report.result is not None
            else None
        )
        if action.capability == "bitbucket.build_status.read":
            candidates = [
                make_resource_citation(
                    system="bitbucket",
                    resource_type="build_status",
                    resource_id=f"pull-request:{action.target.resource_id}",
                    title=f"Build status for pull request {action.target.resource_id}",
                    url=reference,
                )
            ]
        elif action.capability == "bitbucket.pull_request.diffstat":
            candidates = [
                make_resource_citation(
                    system="bitbucket",
                    resource_type="pull_request_diffstat",
                    resource_id=action.target.resource_id,
                    title=f"Diffstat for pull request {action.target.resource_id}",
                    url=reference,
                )
            ]
        else:
            candidates = citation_index([payload])
        if not candidates:
            candidates = [
                make_resource_citation(
                    system=action.target.system,
                    resource_type=action.target.resource_type,
                    resource_id=action.target.resource_id,
                    title=action.target.uri,
                    url=reference,
                    version=action.target.expected_version,
                )
            ]
        for citation in candidates:
            citation_id = citation.get("citation_id")
            if isinstance(citation_id, str) and citation_id:
                by_id.setdefault(citation_id, dict(citation))
        selected = next(
            (
                item
                for item in candidates
                if str(item.get("resource_id", "")) == action.target.resource_id
            ),
            candidates[0],
        )
        by_action[action_report.action_id] = str(selected["citation_id"])
    return list(by_id.values()), by_action


def _failure_records(
    report: RunReport,
    *,
    action_by_id: Mapping[Any, AgentAction],
    stale_evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    records = [
        {
            "capability": action.capability,
            "state": str(action.state),
            "stage": "provider_read_and_independent_verification",
            "system": action_by_id[action.action_id].target.system,
            "resource_type": action_by_id[action.action_id].target.resource_type,
            "resource_id": action_by_id[action.action_id].target.resource_id,
            "message": "configured evidence was not independently verified",
        }
        for action in report.actions
        if action.state not in _VERIFIED_STATES
    ]
    capability_by_kind = {
        "jira_issue_identity": "jira.issue.review_context.read",
        "bitbucket_repository_identity": "bitbucket.repository.read",
        "bitbucket_pull_request_identity": "bitbucket.pull_request.read",
        "bitbucket_build_pull_request_identity": "bitbucket.build_status.read",
        "pull_request_build_head": "bitbucket.build_status.read",
        "bitbucket_diffstat_pull_request_identity": "bitbucket.pull_request.diffstat",
        "pull_request_diffstat_commits": "bitbucket.pull_request.diffstat",
        "confluence_page_identity": "confluence.page.read",
    }
    for stale in stale_evidence:
        kind = str(stale.get("kind") or "")
        capability = capability_by_kind.get(kind)
        if capability is None:
            continue
        resource_id = str(stale.get("resource_id") or "")
        action = next(
            (
                item
                for item in action_by_id.values()
                if item.capability == capability
                and (not resource_id or item.target.resource_id == resource_id)
            ),
            None,
        )
        if action is None:  # pragma: no cover - plan validation binds every kind.
            continue
        if kind in {"pull_request_build_head", "pull_request_diffstat_commits"}:
            binding = "exact pull-request head"
        elif kind in {
            "bitbucket_build_pull_request_identity",
            "bitbucket_diffstat_pull_request_identity",
        }:
            binding = "exact pull-request identity"
        else:
            binding = "exact configured target identity"
        records.append(
            {
                "capability": action.capability,
                "state": "quarantined",
                "stage": "post_verification_identity_binding",
                "system": action.target.system,
                "resource_type": action.target.resource_type,
                "resource_id": action.target.resource_id,
                "message": (
                    "independently verified evidence failed the workflow's "
                    f"{binding} binding and was quarantined"
                ),
            }
        )
    return records


def _classify_outcome(
    report: RunReport,
    action_by_id: Mapping[Any, AgentAction],
    ambiguities: Sequence[Mapping[str, Any]],
    *,
    stale_evidence: Sequence[Mapping[str, Any]],
) -> EngineeringReviewOutcome:
    if stale_evidence or any(_is_stale(action) for action in report.actions):
        return EngineeringReviewOutcome.STALE
    if ambiguities:
        return EngineeringReviewOutcome.AMBIGUOUS
    core_failed = any(
        action_by_id[action.action_id].capability in _CORE_CAPABILITIES
        and (
            action.state not in _VERIFIED_STATES
            or action.result is None
            or not isinstance(action.result.after, Mapping)
        )
        for action in report.actions
    )
    if core_failed:
        return EngineeringReviewOutcome.FAILED
    if any(
        action.state not in _VERIFIED_STATES
        or action.result is None
        or not isinstance(action.result.after, Mapping)
        for action in report.actions
    ):
        return EngineeringReviewOutcome.PARTIAL
    return EngineeringReviewOutcome.COMPLETE


def _is_stale(action: ActionReport) -> bool:
    message = action.message.casefold()
    return action.state in {ActionState.INDETERMINATE, ActionState.CONFLICTED} or any(
        marker in message
        for marker in ("changed between retrieval", "version conflict", "stale")
    )


def _relation_ambiguities(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    settings: EngineeringWorkItemReviewSettings,
) -> list[dict[str, Any]]:
    jira = _payload_for(verified, "jira.issue.review_context.read")
    issue = jira.get("issue") if jira is not None else None
    relations = issue.get("external_relations") if isinstance(issue, Mapping) else None
    if not isinstance(relations, list):
        return []
    bitbucket_relations = sorted(
        {
            (
                str(item.get("owner_or_project") or ""),
                str(item.get("repository") or ""),
                str(item.get("pull_request_id") or ""),
            )
            for item in relations
            if isinstance(item, Mapping) and item.get("provider") == "bitbucket"
        }
    )
    confluence_relations = sorted(
        {
            (
                str(item.get("space") or ""),
                str(item.get("page_id") or ""),
            )
            for item in relations
            if isinstance(item, Mapping) and item.get("provider") == "confluence"
        }
    )
    ambiguities: list[dict[str, Any]] = []
    configured_bitbucket = (
        settings.bitbucket_owner,
        settings.bitbucket_repository,
        settings.bitbucket_pull_request_id,
    )
    if bitbucket_relations and any(
        observed != configured_bitbucket for observed in bitbucket_relations
    ):
        ambiguities.append(
            {
                "kind": "bitbucket_relation",
                "configured": {
                    "owner_or_project": configured_bitbucket[0],
                    "repository": configured_bitbucket[1],
                    "pull_request_id": configured_bitbucket[2],
                },
                "observed": [
                    {
                        "owner_or_project": owner,
                        "repository": repository,
                        "pull_request_id": pull_request_id,
                    }
                    for owner, repository, pull_request_id in bitbucket_relations
                ],
            }
        )
    configured_pages = set(settings.confluence_page_ids)
    if confluence_relations and any(
        space != settings.confluence_space_key or page_id not in configured_pages
        for space, page_id in confluence_relations
    ):
        ambiguities.append(
            {
                "kind": "confluence_relation",
                "configured": {
                    "space": settings.confluence_space_key,
                    "page_ids": sorted(configured_pages),
                },
                "observed": [
                    {"space": space, "page_id": page_id}
                    for space, page_id in confluence_relations
                ],
            }
        )
    return ambiguities


def _evidence_staleness(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    *,
    plan: ChangePlan,
    settings: EngineeringWorkItemReviewSettings,
    action_by_id: Mapping[Any, AgentAction],
) -> list[dict[str, str]]:
    stale: list[dict[str, str]] = []
    jira_payload = _payload_for(verified, "jira.issue.review_context.read")
    jira = _mapping(jira_payload.get("issue")) if jira_payload is not None else None
    if jira_payload is not None and (
        jira is None or str(jira.get("key") or "") != _jira_issue_key(plan)
    ):
        stale.append({"kind": "jira_issue_identity"})
    repository_payload = _payload_for(verified, "bitbucket.repository.read")
    repository = (
        _mapping(repository_payload.get("repository"))
        if repository_payload is not None
        else None
    )
    repository_identity_matches = (
        repository_payload is not None
        and repository is not None
        and (
            str(repository.get("slug") or "") == settings.bitbucket_repository
            and str(repository.get("owner_or_project") or "")
            == settings.bitbucket_owner
        )
    )
    if repository_payload is not None and not repository_identity_matches:
        stale.append({"kind": "bitbucket_repository_identity"})
    pull_request_payload = _payload_for(verified, "bitbucket.pull_request.read")
    pull_request = (
        _mapping(pull_request_payload.get("pull_request"))
        if pull_request_payload is not None
        else None
    )
    build = _payload_for(verified, "bitbucket.build_status.read")
    diffstat = _payload_for(verified, "bitbucket.pull_request.diffstat")
    pull_request_identity_matches = (
        pull_request_payload is not None
        and pull_request is not None
        and (str(pull_request.get("id") or "") == settings.bitbucket_pull_request_id)
    )
    if pull_request_payload is not None and not pull_request_identity_matches:
        stale.append({"kind": "bitbucket_pull_request_identity"})
    build_pull_request_identity_matches = build is not None and (
        str(build.get("pull_request_id") or "") == settings.bitbucket_pull_request_id
    )
    if build is not None and not build_pull_request_identity_matches:
        stale.append({"kind": "bitbucket_build_pull_request_identity"})
    diffstat_pull_request_identity_matches = diffstat is not None and (
        str(diffstat.get("pull_request_id") or "") == settings.bitbucket_pull_request_id
    )
    if diffstat is not None and not diffstat_pull_request_identity_matches:
        stale.append({"kind": "bitbucket_diffstat_pull_request_identity"})
    if (
        pull_request_identity_matches
        and build_pull_request_identity_matches
        and pull_request is not None
        and build is not None
    ):
        pull_request_commit = _exact_string(pull_request.get("source_commit"))
        build_commit = _exact_string(build.get("commit"))
        if (
            pull_request_commit is None
            or build_commit is None
            or pull_request_commit != build_commit
        ):
            stale.append({"kind": "pull_request_build_head"})
    if diffstat_pull_request_identity_matches and diffstat is not None:
        if not pull_request_identity_matches or pull_request is None:
            stale.append({"kind": "pull_request_diffstat_commits"})
        else:
            pull_request_source = _exact_string(pull_request.get("source_commit"))
            pull_request_destination = _exact_string(
                pull_request.get("destination_commit")
            )
            diffstat_source = _exact_string(diffstat.get("source_commit"))
            diffstat_destination = _exact_string(diffstat.get("destination_commit"))
            if (
                pull_request_source is None
                or pull_request_destination is None
                or diffstat_source is None
                or diffstat_destination is None
                or pull_request_source != diffstat_source
                or pull_request_destination != diffstat_destination
            ):
                stale.append({"kind": "pull_request_diffstat_commits"})
    for action_report, payload in verified:
        if action_report.capability != "confluence.page.read":
            continue
        action = action_by_id[action_report.action_id]
        page = _mapping(payload.get("page"))
        if (
            page is None
            or str(page.get("id") or "") != action.target.resource_id
            or str(page.get("space_id") or "") != settings.confluence_space_id
            or str(page.get("space_key") or "") != settings.confluence_space_key
        ):
            stale.append(
                {
                    "kind": "confluence_page_identity",
                    "resource_id": action.target.resource_id,
                }
            )
    return stale


def _reportable_verified_payloads(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    *,
    stale_evidence: Sequence[Mapping[str, Any]],
    action_by_id: Mapping[Any, AgentAction],
) -> list[tuple[ActionReport, Mapping[str, Any]]]:
    """Quarantine verified envelopes whose resource identity is not exact."""

    stale_kinds = {str(item.get("kind") or "") for item in stale_evidence}
    stale_page_ids = {
        str(item.get("resource_id") or "")
        for item in stale_evidence
        if item.get("kind") == "confluence_page_identity"
    }
    capability_kind = {
        "jira.issue.review_context.read": "jira_issue_identity",
        "bitbucket.repository.read": "bitbucket_repository_identity",
        "bitbucket.pull_request.read": "bitbucket_pull_request_identity",
    }
    reportable: list[tuple[ActionReport, Mapping[str, Any]]] = []
    for action_report, payload in verified:
        action = action_by_id[action_report.action_id]
        if capability_kind.get(action.capability) in stale_kinds:
            continue
        if action.capability == "bitbucket.build_status.read" and stale_kinds & {
            "bitbucket_build_pull_request_identity",
            "pull_request_build_head",
        }:
            continue
        if action.capability == "bitbucket.pull_request.diffstat" and stale_kinds & {
            "bitbucket_diffstat_pull_request_identity",
            "pull_request_diffstat_commits",
        }:
            continue
        if (
            action.capability == "confluence.page.read"
            and action.target.resource_id in stale_page_ids
        ):
            continue
        reportable.append((action_report, payload))
    return reportable


def _findings(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    *,
    settings: EngineeringWorkItemReviewSettings,
    ambiguities: Sequence[Mapping[str, Any]],
    stale_evidence: Sequence[Mapping[str, Any]],
    citation_by_action: Mapping[Any, str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    jira_record = _record_for(verified, "jira.issue.review_context.read", "issue")
    pr_record = _record_for(verified, "bitbucket.pull_request.read", "pull_request")
    build_payload = _payload_for(verified, "bitbucket.build_status.read")
    jira_citation = _citation_for_capability(
        verified,
        "jira.issue.review_context.read",
        citation_by_action,
    )
    pr_citation = _citation_for_capability(
        verified,
        "bitbucket.pull_request.read",
        citation_by_action,
    )
    build_citation = _citation_for_capability(
        verified,
        "bitbucket.build_status.read",
        citation_by_action,
    )
    if jira_record is not None:
        acceptance = jira_record.get("acceptance_criteria")
        if not isinstance(acceptance, list) or not any(
            isinstance(item, Mapping) and str(item.get("text", "")).strip()
            for item in acceptance
        ):
            findings.append(
                _finding(
                    "missing_acceptance_criteria",
                    "Jira returned no non-empty configured acceptance criteria.",
                    (jira_citation,),
                )
            )
    if jira_record is not None and pr_record is not None:
        issue_key = str(jira_record.get("key", ""))
        pr_text = " ".join(
            str(pr_record.get(name) or "") for name in ("title", "description")
        )
        if issue_key and issue_key.casefold() not in pr_text.casefold():
            findings.append(
                _finding(
                    "pull_request_traceability",
                    "The pull-request title and description do not reference the exact Jira key.",
                    (jira_citation, pr_citation),
                )
            )
    if build_payload is not None:
        summary = build_payload.get("summary")
        if isinstance(summary, Mapping):
            if int(summary.get("failed", 0) or 0) > 0:
                findings.append(
                    _finding(
                        "failing_build",
                        "Bitbucket reports one or more failed build statuses.",
                        (build_citation,),
                    )
                )
            if int(summary.get("other", 0) or 0) > 0:
                findings.append(
                    _finding(
                        "non_success_build_state",
                        "Bitbucket reports one or more build statuses in another "
                        "terminal or provider-defined state.",
                        (build_citation,),
                    )
                )
    if settings.confluence_page_ids and not any(
        action.capability == "confluence.page.read" for action, _payload in verified
    ):
        findings.append(
            {
                "kind": "missing_confluence_evidence",
                "summary": "No configured Confluence evidence is reportable.",
                "citation_ids": [],
            }
        )
    for ambiguity in ambiguities:
        findings.append(
            _finding(
                "ambiguous_relation",
                f"Verified Jira relation evidence conflicts with {ambiguity['kind']} scope.",
                (jira_citation,),
            )
        )
    for stale in stale_evidence:
        kind = str(stale.get("kind") or "")
        citation_ids: Sequence[str | None]
        if kind == "pull_request_build_head":
            summary = (
                "Build evidence failed the workflow's exact pull-request head "
                "binding and was quarantined."
            )
            citation_ids = ()
        elif kind == "bitbucket_build_pull_request_identity":
            summary = (
                "Build evidence was quarantined because its pull-request identity "
                "did not match the exact configured target."
            )
            citation_ids = ()
        elif kind == "pull_request_diffstat_commits":
            summary = (
                "Diffstat evidence failed the workflow's exact pull-request commit "
                "binding and was quarantined."
            )
            citation_ids = ()
        elif kind == "bitbucket_diffstat_pull_request_identity":
            summary = (
                "Diffstat evidence was quarantined because its pull-request identity "
                "did not match the exact configured target."
            )
            citation_ids = ()
        elif kind == "confluence_page_identity":
            resource_id = str(stale.get("resource_id") or "configured page")
            summary = (
                f"Confluence evidence for page {resource_id} was quarantined because "
                "its page or space identity was not exact."
            )
            citation_ids = ()
        elif kind == "jira_issue_identity":
            summary = "Jira evidence was quarantined because its issue identity was not exact."
            citation_ids = ()
        elif kind == "bitbucket_repository_identity":
            summary = (
                "Bitbucket repository evidence was quarantined because its identity "
                "was not exact."
            )
            citation_ids = ()
        elif kind == "bitbucket_pull_request_identity":
            summary = (
                "Bitbucket pull-request evidence was quarantined because its identity "
                "was not exact."
            )
            citation_ids = ()
        else:
            summary = "Verified provider evidence differs from its exact target."
            citation_ids = ()
        findings.append(
            _finding(
                f"stale_{kind or 'provider_identity'}",
                summary,
                citation_ids,
            )
        )
    return findings


def _finding(
    kind: str,
    summary: str,
    citation_ids: Sequence[str | None],
) -> dict[str, Any]:
    return {
        "kind": kind,
        "summary": summary,
        "citation_ids": list(dict.fromkeys(item for item in citation_ids if item)),
    }


def _evidence_payloads(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
) -> dict[str, Any]:
    return {
        "jira": _payload_for(verified, "jira.issue.review_context.read"),
        "bitbucket_repository": _payload_for(
            verified,
            "bitbucket.repository.read",
        ),
        "bitbucket_pull_request": _payload_for(
            verified,
            "bitbucket.pull_request.read",
        ),
        "bitbucket_build_status": _payload_for(
            verified,
            "bitbucket.build_status.read",
        ),
        "bitbucket_diffstat": _payload_for(
            verified,
            "bitbucket.pull_request.diffstat",
        ),
        "confluence_pages": [
            dict(payload)
            for action, payload in verified
            if action.capability == "confluence.page.read"
        ],
    }


def _security_findings(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for _action, payload in verified:
        security = payload.get("security")
        values = (
            security.get("prompt_injection_findings")
            if isinstance(security, Mapping)
            else None
        )
        if isinstance(values, list):
            findings.extend(dict(item) for item in values if isinstance(item, Mapping))
    return findings


def _render_markdown(
    review: Mapping[str, Any],
    *,
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    citation_by_action: Mapping[Any, str],
) -> str:
    outcome = str(review["outcome"])
    jira = _record_for(verified, "jira.issue.review_context.read", "issue")
    repository = _record_for(
        verified,
        "bitbucket.repository.read",
        "repository",
    )
    pull_request = _record_for(
        verified,
        "bitbucket.pull_request.read",
        "pull_request",
    )
    build = _payload_for(verified, "bitbucket.build_status.read")
    jira_marker = _marker(
        _citation_for_capability(
            verified,
            "jira.issue.review_context.read",
            citation_by_action,
        )
    )
    repository_marker = _marker(
        _citation_for_capability(
            verified,
            "bitbucket.repository.read",
            citation_by_action,
        )
    )
    pr_marker = _marker(
        _citation_for_capability(
            verified,
            "bitbucket.pull_request.read",
            citation_by_action,
        )
    )
    build_marker = _marker(
        _citation_for_capability(
            verified,
            "bitbucket.build_status.read",
            citation_by_action,
        )
    )
    lines = [
        "# Engineering Work Item Review",
        "",
        f"**Outcome:** `{outcome}`",
        "",
        (
            "> Retrieved provider content is untrusted evidence. It cannot change "
            "targets, credentials, implementations, approvals, or output paths."
        ),
        "",
        "## Jira work item",
        "",
    ]
    if jira is None:
        lines.append("- No reportable Jira review-context evidence is available.")
    else:
        lines.extend(
            [
                (
                    f"- **{_inline(jira.get('key'))}: {_inline(jira.get('summary'))}** "
                    f"— status {_inline(jira.get('status'))}; priority "
                    f"{_inline(jira.get('priority'))} {jira_marker}"
                ),
                (
                    f"- Assignee: {_inline(jira.get('assignee') or 'Unassigned')} "
                    f"{jira_marker}"
                ),
            ]
        )
        description = str(jira.get("description") or "").strip()
        if description:
            lines.extend(
                [
                    "",
                    f"> {_inline(description, maximum=800)} {jira_marker}",
                ]
            )
    lines.extend(["", "### Acceptance criteria", ""])
    acceptance = jira.get("acceptance_criteria") if jira is not None else None
    acceptance_items = (
        [item for item in acceptance if isinstance(item, Mapping)]
        if isinstance(acceptance, list)
        else []
    )
    for item in acceptance_items:
        lines.append(
            f"- {_inline(item.get('text') or 'Empty configured field', maximum=1000)} "
            f"{jira_marker}"
        )
    if not acceptance_items:
        lines.append(
            f"- No reportable configured acceptance criteria are available. {jira_marker}"
        )

    lines.extend(["", "## Bitbucket pull request and build", ""])
    if repository is not None:
        lines.append(
            f"- Repository: **{_inline(repository.get('slug') or repository.get('name'))}** "
            f"{repository_marker}"
        )
    else:
        lines.append("- No reportable repository evidence is available.")
    if pull_request is not None:
        lines.append(
            f"- PR **{_inline(pull_request.get('id'))}: "
            f"{_inline(pull_request.get('title'))}** — "
            f"{_inline(pull_request.get('source_branch'))} → "
            f"{_inline(pull_request.get('destination_branch'))}; state "
            f"{_inline(pull_request.get('state'))} {pr_marker}"
        )
    else:
        lines.append("- No reportable pull-request evidence is available.")
    if build is not None:
        summary = build.get("summary")
        summary = summary if isinstance(summary, Mapping) else {}
        lines.append(
            f"- Build statuses for commit `{_inline(build.get('commit'))}`: "
            f"{int(summary.get('total', build.get('returned', 0)) or 0)} total, "
            f"{int(summary.get('successful', 0) or 0)} successful, "
            f"{int(summary.get('failed', 0) or 0)} failed, "
            f"{int(summary.get('in_progress', 0) or 0)} in progress, "
            f"{int(summary.get('other', 0) or 0)} other "
            f"{build_marker}"
        )
    else:
        lines.append("- No reportable build evidence is available.")

    lines.extend(["", "## Confluence requirements and decisions", ""])
    pages = [
        _mapping(payload.get("page"))
        for action, payload in verified
        if action.capability == "confluence.page.read"
    ]
    pages = [page for page in pages if page is not None]
    for action_report, payload in verified:
        if action_report.capability != "confluence.page.read":
            continue
        page = _mapping(payload.get("page"))
        if page is None:
            continue
        marker = _marker(citation_by_action.get(action_report.action_id))
        lines.extend(
            [
                (
                    f"- **{_inline(page.get('title'))}** — version "
                    f"{_inline(page.get('version'))} {marker}"
                ),
                f"  - {_inline(page.get('body_excerpt') or 'No excerpt returned', maximum=800)} {marker}",
            ]
        )
    if not pages:
        lines.append(
            "- No reportable configured Confluence page evidence is available."
        )

    lines.extend(["", "## Evidence-backed checks", ""])
    findings = review.get("findings")
    finding_items = (
        [item for item in findings if isinstance(item, Mapping)]
        if isinstance(findings, list)
        else []
    )
    for finding in finding_items:
        markers = " ".join(
            _marker(str(item))
            for item in finding.get("citation_ids", [])
            if isinstance(item, str)
        )
        lines.append(
            f"- {_inline(finding.get('summary'), maximum=1000)} {markers}".rstrip()
        )
    if (
        not finding_items
        and outcome == str(EngineeringReviewOutcome.COMPLETE)
        and verified
    ):
        verified_markers = " ".join(
            _marker(citation_by_action.get(action.action_id))
            for action, _payload in verified
        )
        lines.append(
            "- No inconsistency was identified in the verified bounded fields. "
            f"{verified_markers}".rstrip()
        )
    elif not finding_items:
        lines.append("- No evidence-backed consistency conclusion is available.")

    lines.extend(["", "## Missing or unverifiable evidence", ""])
    failures = review.get("failures")
    failure_items = (
        [item for item in failures if isinstance(item, Mapping)]
        if isinstance(failures, list)
        else []
    )
    for failure in failure_items:
        lines.append(
            f"- `{_inline(failure.get('capability'))}`: "
            f"{_inline(failure.get('state'))} — "
            f"{_inline(failure.get('system'))}:"
            f"{_inline(failure.get('resource_type'))}:"
            f"{_inline(failure.get('resource_id'))}; stage "
            f"{_inline(failure.get('stage'))} — "
            f"{_inline(failure.get('message'), maximum=1000)}"
        )
    if not failure_items:
        lines.append("- None in the configured scope.")

    lines.extend(["", "## Decisions or follow-up needed", ""])
    if outcome == EngineeringReviewOutcome.COMPLETE:
        lines.append("- Review the evidence-backed checks above; no source is missing.")
    else:
        lines.append(
            "- Resolve the explicit missing, stale, or ambiguous item above and rerun "
            "the same exact case."
        )
    lines.extend(["", "## Sources", ""])
    for citation in review.get("citations", []):
        if not isinstance(citation, Mapping):
            continue
        label = citation.get("marker") or _marker(str(citation.get("citation_id", "")))
        line = (
            f"- {label} {_inline(citation.get('title') or citation.get('resource_id'))}"
        )
        if citation.get("url"):
            line += f" — {_inline(citation['url'], maximum=600)}"
        lines.append(line)
    if not review.get("citations"):
        lines.append("- No verified provider citation was available.")
    lines.append("")
    return "\n".join(lines)


def _payload_for(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    capability: str,
) -> Mapping[str, Any] | None:
    return next(
        (payload for action, payload in verified if action.capability == capability),
        None,
    )


def _record_for(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    capability: str,
    field: str,
) -> Mapping[str, Any] | None:
    payload = _payload_for(verified, capability)
    return _mapping(payload.get(field)) if payload is not None else None


def _citation_for_capability(
    verified: Sequence[tuple[ActionReport, Mapping[str, Any]]],
    capability: str,
    citation_by_action: Mapping[Any, str],
) -> str | None:
    return next(
        (
            citation_by_action.get(action.action_id)
            for action, _payload in verified
            if action.capability == capability
        ),
        None,
    )


def _jira_issue_key(plan: ChangePlan) -> str:
    return next(
        action.target.resource_id
        for action in plan.actions
        if action.capability == "jira.issue.review_context.read"
    )


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _exact_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    rendered = value.strip()
    return rendered or None


def _artifact_record(filename: str, payload: bytes) -> dict[str, Any]:
    return {
        "filename": filename,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, default=str)
        + "\n"
    ).encode("utf-8")


def _marker(citation_id: str | None) -> str:
    return f"[{citation_id}]" if citation_id else "[unverified]"


def _inline(value: object, *, maximum: int = 400) -> str:
    rendered = " ".join(str(value or "").split())[:maximum]
    for character in ("\\", "`", "*", "_", "[", "]", "<", ">"):
        rendered = rendered.replace(character, f"\\{character}")
    return rendered or "Unknown"


def _table(raw: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = raw.get(name)
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"engineering review requires [{name}]")
    return value


def _reject_unknown(
    value: Mapping[str, Any],
    allowed: set[str],
    context: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigurationError(
            f"engineering review {context} contains unknown fields: "
            + ", ".join(unknown)
        )


def _required_text(table: Mapping[str, Any], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"engineering review {key} is required")
    rendered = value.strip()
    if len(rendered) > 2048 or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in rendered
    ):
        raise ConfigurationError(f"engineering review {key} is invalid")
    return rendered


def _optional_text(table: Mapping[str, Any], key: str) -> str:
    value = table.get(key, "")
    if value == "":
        return ""
    if not isinstance(value, str):
        raise ConfigurationError(f"engineering review {key} must be a string")
    rendered = value.strip()
    if not rendered or len(rendered) > 2048:
        raise ConfigurationError(f"engineering review {key} is invalid")
    return rendered


def _bounded_int(
    table: Mapping[str, Any],
    key: str,
    *,
    default: int,
    maximum: int,
) -> int:
    value = table.get(key, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ConfigurationError(f"engineering review {key} is out of range")
    return value


def _strict_bool(
    table: Mapping[str, Any],
    key: str,
    *,
    default: bool,
) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigurationError(f"engineering review {key} must be a boolean")
    return value


def _require_identifier(value: str, name: str) -> None:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ConfigurationError(f"engineering review {name} is invalid")


def _require_origin(value: str, name: str) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(f"engineering review {name} is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise ConfigurationError(
            f"engineering review {name} must be a credential-free HTTPS origin"
        )
