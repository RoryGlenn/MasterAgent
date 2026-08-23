"""Command-line interface for the governed runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from pathlib import Path
from threading import Event, Thread
from urllib.parse import urlsplit
from uuid import UUID

from master_agent import __version__
from master_agent.approval_handoff import (
    ApprovalRequest,
    ApprovalRunInvocation,
    load_approval_request,
    publish_approval_request,
    write_restricted_json,
)
from master_agent.approvals import HmacApprovalAuthenticator
from master_agent.audit import AuditLog, IdempotencyClaimState, implemented_audit_sink
from master_agent.auth import AuthMode
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.capability_import import (
    inspect_agent_capabilities,
    quarantine_selected_ability,
)
from master_agent.capability_routing import (
    CapabilityCard,
    CapabilityRouter,
    RoutingDecision,
)
from master_agent.capsule_authorities import load_capsule_authorities
from master_agent.capsule_promotion import CapabilityPromotionService
from master_agent.capsule_runtime import (
    CapsuleValidator,
    CapsuleWorker,
    activate_capsule,
    context_with_capsules,
)
from master_agent.capsules import (
    CapsuleManifest,
    CapsuleRole,
    CapsuleState,
    CapsuleStore,
    CapsuleTrustStore,
    LicensePolicy,
    advance_manifest,
)
from master_agent.citations import find_citations
from master_agent.compensation import build_compensation_plan
from master_agent.config import (
    ConnectorConfig,
    ConnectorCredentialProvider,
    DeploymentType,
    IntegrationConfig,
    ResolvedExecutionTarget,
    is_placeholder_provider_url,
)
from master_agent.config_sources import (
    ConfigSnapshot,
    ConfigSource,
    resolve_config_source,
    snapshot_explicit_file,
)
from master_agent.connectors.base import ClosableConnector
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.drafts import ArtifactBudget
from master_agent.connectors.factory import (
    build_draft_registry,
    build_live_registry,
    configured_builtin_capabilities,
    installed_builtin_capabilities,
    register_draft_connectors,
)
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.connectors.mock import MockConnector
from master_agent.connectors.read_only import ReadOnlyConnector
from master_agent.credentials import (
    CredentialStoreSnapshot,
    canonical_credential_store_path,
    normalize_credential_environment,
)
from master_agent.direct_read import (
    DirectReadReport,
    DirectReadSession,
    preflight_direct_read_plan,
)
from master_agent.directory_safety import PinnedDirectory
from master_agent.discovery import (
    DiscoveryStatus,
    discover_integrations,
    preflight_probe_provider_egress,
)
from master_agent.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    MasterAgentError,
    StructuredDataTypeError,
    ValidationError,
)
from master_agent.execution_context import (
    build_execution_context,
    build_runtime_execution_binding,
    capture_connector_executions,
    capture_runtime_execution_paths,
    enforce_execution_context,
)
from master_agent.governance import ApprovalTier, EnvironmentKind, GovernanceProfile
from master_agent.http import HttpTransport
from master_agent.identity import IdentityRegistry
from master_agent.models import (
    ActionState,
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    DataClassification,
    ExecutionContext,
    ResourceRef,
    RiskLevel,
    StrategyActionIntent,
    StrategyKernel,
    SystemsAssessment,
)
from master_agent.oauth import EntraDeviceCodeProvider, write_token_file
from master_agent.oauth_config import OAuthFlow, OAuthProfiles
from master_agent.operating import (
    ConnectorMode,
    OperatingFailureCategory,
    OperatingIssue,
    OperatingValidationError,
    OrganizationProfile,
    ReadinessLevel,
    allocate_operating_run,
    assess_operating_readiness,
    build_operating_support_bundle,
    default_organization_profile_path,
    install_organization_profile,
    load_organization_profile,
    require_operating_plan,
)
from master_agent.orchestrator import RunReport, WorkflowOrchestrator
from master_agent.planners.base import (
    bind_fast_path_governance,
    bind_static_intervention_governance,
)
from master_agent.planners.static import build_weekly_status_plan
from master_agent.platform_paths import current_user_product_root
from master_agent.platform_runtime import (
    LockMode,
    PlatformContract,
    PlatformRuntimeStatus,
    get_atomic_publication_recovery_backend,
    get_credential_storage_backend,
    get_cross_process_locking_backend,
    get_secure_filesystem_backend,
    platform_runtime_status,
    require_persistent_state_platform,
    require_platform_contract,
)
from master_agent.plugins import (
    PluginLock,
    discover_connector_plugins,
    resolve_locked_plugin_descriptors,
)
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.provider_egress import (
    ProviderDataRoute,
    preflight_provider_data_egress,
)
from master_agent.readiness import (
    assess_readiness,
    provider_data_egress_policy_denials,
)
from master_agent.recurring import (
    OccurrenceStatus,
    RecurringConfig,
    RecurringRunner,
    RecurringRunResult,
    RecurringStateStore,
    RegisteredWorkflow,
    WorkflowKind,
    validate_plan_scope,
)
from master_agent.recurring_occurrence import (
    RecurringOccurrence,
    authenticate_occurrence,
    bind_local_occurrence,
    current_runtime_identity,
    load_occurrence,
    occurrence_summary,
    registration_snapshot,
)
from master_agent.registry import ConnectorRegistry
from master_agent.resource_limits import MAX_PLAN_BYTES
from master_agent.retention import (
    RetainedJSONReservation,
    RetentionConfig,
    purge_expired_evidence,
    repair_orphaned_evidence,
    write_retained_json,
)
from master_agent.security import PromptInjectionGuard
from master_agent.terminal import (
    MAX_TERMINAL_EXCERPT_CHARACTERS,
    MAX_TERMINAL_FIELD_CHARACTERS,
    render_terminal_text,
)
from master_agent.work_memory import WorkEventKind, WorkMemory, WorkStage
from master_agent.workflows.communication_context import (
    CommunicationContextSettings,
    build_communication_context_plan,
    render_communication_context_package,
)
from master_agent.workflows.draft_package import (
    DraftPackageSettings,
    build_draft_package_plan,
    render_draft_package,
)
from master_agent.workflows.weekly_operating_review import (
    WeeklyOperatingReviewSettings,
    build_weekly_operating_review_plan,
    render_weekly_operating_review,
)
from master_agent.workflows.weekly_status import (
    WeeklyStatusSettings,
    build_weekly_status_read_plan,
    render_weekly_status_package,
)

_DISABLED_LOCAL_GIT_MUTATIONS = frozenset(
    {
        "bitbucket.branch.push",
        "repository.branch.create",
        "repository.branch.push",
        "repository.commit.create",
        "repository.patch.apply",
    }
)

_DISABLED_NON_MANIFEST_EXECUTIONS = frozenset(
    {"communication-context", "recurring-run", "weekly-status"}
)

_CONNECT_CONFIGURATION_BY_SYSTEM = {
    "jira": "jira",
    "confluence": "confluence",
    "bitbucket": "bitbucket",
    "github": "github",
    "microsoft": "microsoft",
    "sharepoint": "microsoft",
    "outlook": "microsoft",
    "teams": "microsoft",
    "onenote": "microsoft",
    "reddit": "reddit",
}
_MAX_DIRECT_READ_TERMINAL_PAYLOAD_CHARACTERS = 8 * 1024


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _preflight_cli_persistent_output(args)
        if args.command == "setup":
            return _setup(
                profile_path=args.profile,
                non_interactive=args.non_interactive,
            )
        if args.command == "doctor":
            return _doctor(
                profile_path=args.profile,
                require_level=args.require_level,
                output=args.output,
            )
        if args.command == "support-bundle":
            return _support_bundle(
                profile_path=args.profile,
                output=args.output,
            )
        if args.command == "execute":
            return _execute(
                plan_path=args.plan,
                profile_path=args.profile,
                request_path=args.resume,
                approval_paths=args.approval,
            )
        if args.command == "demo":
            return _demo()
        if args.command == "sample-plan":
            return _sample_plan(args.output)
        if args.command == "inspect":
            return _inspect(args.plan)
        if args.command == "bind-context":
            return _bind_context(
                plan_path=args.plan,
                integrations_path=args.integrations,
                plugin_names=args.plugin,
                plugin_lock_path=args.plugin_lock,
                connector_mode=args.connector_mode,
                approval_authorities=args.approval_authorities,
                database=args.database,
                result_json=args.result_json,
                retention_path=args.retention,
                evidence_type=args.evidence_type,
                identities_path=args.identities,
                include_writes=args.enable_writes,
                include_communications=args.enable_communications,
                workspace_root=args.workspace_root,
                draft_output_dir=args.draft_output_dir,
                policy_path=args.policy,
                sources_of_truth_path=args.sources_of_truth,
                capabilities_path=args.capabilities,
                governance_path=args.governance,
                credentials_file=args.credentials_file,
                credential_mappings=args.credential_map,
                connector_urls=args.connector_url,
                output=args.output,
            )
        if args.command == "approve":
            return _approve(
                plan_path=args.plan,
                actions=args.actions,
                key_id=args.key_id,
                expected_fingerprint=args.expected_fingerprint,
                approval_authorities=args.approval_authorities,
                output=args.output,
                ttl_minutes=args.ttl_minutes,
            )
        if args.command == "inspect-approval-request":
            return _inspect_approval_request(args.request)
        if args.command == "approve-request":
            return _approve_request(
                request_path=args.request,
                key_id=args.key_id,
                expected_fingerprint=args.expected_fingerprint,
                output=args.output,
                ttl_minutes=args.ttl_minutes,
            )
        if args.command == "resume-approval":
            return _resume_approval(
                request_path=args.request,
                expected_fingerprint=args.expected_fingerprint,
                approval_paths=args.approval,
            )
        if args.command == "run":
            return _run(
                plan_path=args.plan,
                apply=args.apply,
                direct_read=args.direct_read,
                approval_paths=args.approval,
                approval_authorities=args.approval_authorities,
                database=args.database,
                connector_mode=args.connector_mode,
                integrations_path=args.integrations,
                result_json=args.result_json,
                retention_path=args.retention,
                evidence_type=args.evidence_type,
                identities_path=args.identities,
                include_writes=args.enable_writes,
                include_communications=args.enable_communications,
                workspace_root=args.workspace_root,
                draft_output_dir=args.draft_output_dir,
                capabilities_path=args.capabilities,
                governance_path=args.governance,
                policy_path=args.policy,
                sources_of_truth_path=args.sources_of_truth,
                plugin_names=args.plugin,
                plugin_lock_path=args.plugin_lock,
                credentials_file=args.credentials_file,
                credential_mappings=args.credential_map,
                connector_urls=args.connector_url,
            )
        if args.command == "plugins":
            return _plugins(output=args.output)
        if args.command == "capability-import":
            return _capability_import(
                source_path=args.source,
                capabilities_path=args.capabilities,
                dependency_licenses_path=args.dependency_licenses,
                ability_name=args.select,
                expected_source_sha256=args.expected_source_sha256,
                capsule_store=args.capsule_store,
                capsule_authorities=args.capsule_authorities,
                environment=args.environment,
                worker_sha256=args.worker_sha256,
                output=args.output,
            )
        if args.command == "capability-promote":
            return _capability_promote(
                capability_id=args.capability_id,
                version=args.version,
                capsule_store=args.capsule_store,
                capsule_authorities=args.capsule_authorities,
                dependency_licenses_path=args.dependency_licenses,
                environment=args.environment,
                output=args.output,
            )
        if args.command == "capability-status":
            return _capability_status(
                capability_id=args.capability_id,
                version=args.version,
                capsule_store=args.capsule_store,
                capsule_authorities=args.capsule_authorities,
                output=args.output,
            )
        if args.command == "capability-route":
            return _capability_route(
                intent=args.intent,
                capsule_refs=tuple(args.capsule),
                capsule_store=args.capsule_store,
                capsule_authorities=args.capsule_authorities,
                policy_path=args.policy,
                governance_path=args.governance,
                output=args.output,
            )
        if args.command == "capability-run":
            return _capability_run(
                intent=args.intent,
                capsule_refs=tuple(args.capsule),
                request_path=args.request,
                capsule_store=args.capsule_store,
                capsule_authorities=args.capsule_authorities,
                policy_path=args.policy,
                governance_path=args.governance,
                capabilities_path=args.capabilities,
                sources_of_truth_path=args.sources_of_truth,
                database=args.database,
                principal=args.principal,
                agent_identity=args.agent_identity,
                tenant_id=args.tenant_id,
                output=args.output,
            )
        if args.command in {"capability-disable", "capability-revoke"}:
            return _capability_transition(
                capability_id=args.capability_id,
                version=args.version,
                capsule_store=args.capsule_store,
                capsule_authorities=args.capsule_authorities,
                target=(
                    CapsuleState.DEPRECATED
                    if args.command == "capability-disable"
                    else CapsuleState.REVOKED
                ),
                output=args.output,
            )
        if args.command == "readiness":
            return _readiness(
                integrations_path=args.integrations,
                capabilities_path=args.capabilities,
                governance_path=args.governance,
                oauth_path=args.oauth,
                identities_path=args.identities,
                credentials_file=args.credentials_file,
                egress_checks=tuple(args.egress_check),
                output=args.output,
            )
        if args.command == "oauth-device-code":
            return _oauth_device_code(
                oauth_path=args.oauth,
                profile_name=args.profile,
                token_file=args.token_file,
            )
        if args.command == "draft-package":
            return _draft_package(
                workflow_path=args.workflow,
                output_dir=args.output_dir,
                database=args.database,
            )
        if args.command == "compensation-plan":
            return _compensation_plan(
                plan_path=args.plan,
                report_path=args.report,
                created_by=args.created_by,
                output=args.output,
            )
        if args.command == "recurring-status":
            return _recurring_status(
                recurring_path=args.recurring,
                output=args.output,
            )
        if args.command == "recurring-bind":
            return _recurring_bind(
                name=args.name,
                occurrence_text=args.occurrence,
                plan_path=args.plan,
                recurring_path=args.recurring,
                approval_authorities=args.approval_authorities,
                capabilities_path=args.capabilities,
                governance_path=args.governance,
                policy_path=args.policy,
                sources_of_truth_path=args.sources_of_truth,
                organization_profile_path=args.organization_profile,
                credential_mappings=tuple(args.credential_map),
                connector_urls=tuple(args.connector_url),
                output=args.output,
            )
        if args.command == "recurring-inspect":
            return _recurring_inspect(
                artifact_path=args.artifact,
                expected_fingerprint=args.expected_fingerprint,
            )
        if args.command == "recurring-recover":
            return _recurring_recover(
                artifact_path=args.artifact,
                recurring_path=args.recurring,
                expected_fingerprint=args.expected_fingerprint,
            )
        if args.command == "recurring-reconcile":
            return _recurring_reconcile(
                artifact_path=args.artifact,
                recurring_path=args.recurring,
                expected_fingerprint=args.expected_fingerprint,
            )
        if args.command == "recurring-cancel":
            return _recurring_cancel(
                artifact_path=args.artifact,
                recurring_path=args.recurring,
                expected_fingerprint=args.expected_fingerprint,
            )
        if args.command == "recurring-run":
            if (
                args.recurring is None
                or args.legacy_force
                or args.legacy_connector_mode is not None
            ):
                _reject_non_manifest_execution("recurring-run")
            return _recurring_apply(
                artifact_path=args.artifact,
                recurring_path=args.recurring,
                apply=args.apply,
                approval_paths=tuple(args.approval),
                expected_fingerprint=args.expected_fingerprint,
            )
        if args.command == "discover":
            return _discover(
                integrations_path=args.integrations,
                governance_path=args.governance,
                credentials_file=args.credentials_file,
                probe=args.probe,
                require_ready=args.require_ready,
                systems=_parse_systems(args.systems),
                data_classification=args.data_classification,
                output=args.output,
            )
        if args.command == "connect":
            return _connect(
                integrations_path=args.integrations,
                governance_path=args.governance,
                credentials_file=args.credentials_file,
                credential_mappings=tuple(args.credential_map),
                connector_urls=tuple(args.connector_url),
                systems=_parse_systems(args.systems) or set(),
                data_classification=args.data_classification,
                output=args.output,
            )
        if args.command == "github-repositories":
            return _github_repositories(
                credentials_file=args.credentials_file,
                limit=args.limit,
                visibility=args.visibility,
                output=args.output,
                username=args.username,
            )
        if args.command == "bitbucket-repositories":
            return _bitbucket_repositories(
                workspace=args.workspace,
                limit=args.limit,
                output=args.output,
            )
        if args.command == "weekly-status-plan":
            return _weekly_status_plan(
                integrations_path=args.integrations,
                workflow_path=args.workflow,
                output=args.output,
            )
        if args.command == "weekly-operating-review-plan":
            return _weekly_operating_review_plan(
                workflow_path=args.workflow,
                output=args.output,
            )
        if args.command == "weekly-status":
            return _weekly_status(
                integrations_path=args.integrations,
                workflow_path=args.workflow,
                output_dir=args.output_dir,
                database=args.database,
            )
        if args.command == "identity-resolve":
            return _identity_resolve(
                query=args.query,
                system=args.system,
                identities_path=args.identities,
                output=args.output,
            )
        if args.command == "retain-evidence":
            return _retain_evidence(
                input_path=args.input,
                output_path=args.output,
                evidence_type=args.evidence_type,
                retention_path=args.retention,
                include_content=args.include_content,
            )
        if args.command == "evidence-prune":
            return _evidence_prune(
                root=args.root,
                apply=args.apply,
                output=args.output,
            )
        if args.command == "evidence-repair":
            return _evidence_repair(
                root=args.root,
                apply=args.apply,
                output=args.output,
            )
        if args.command == "work-memory":
            return _work_memory(
                action=args.work_memory_command,
                database=args.database,
                work_id=getattr(args, "work_id", None),
                issue=getattr(args, "issue", None),
                kind=getattr(args, "kind", None),
                stage=getattr(args, "stage", None),
                summary=getattr(args, "summary", None),
                reference=getattr(args, "reference", None),
                output=args.output,
            )
        if args.command == "citations":
            return _citations(args.file, output=args.output)
        if args.command == "communication-context-plan":
            return _communication_context_plan(
                workflow_path=args.workflow,
                identities_path=args.identities,
                output=args.output,
            )
        if args.command == "communication-context":
            return _communication_context(
                integrations_path=args.integrations,
                workflow_path=args.workflow,
                identities_path=args.identities,
                retention_path=args.retention,
                output_dir=args.output_dir,
                database=args.database,
            )
        if args.command == "scan":
            return _scan(text=args.text, file=args.file)
        if args.command == "audit-verify":
            return _audit_verify(args.database)
        parser.error("unknown command")
    except OperatingValidationError as error:
        category = render_terminal_text(str(error.category), max_characters=80)
        message = render_terminal_text(
            str(error),
            max_characters=MAX_TERMINAL_FIELD_CHARACTERS,
        )
        print(f"error: {category}: {message}", file=sys.stderr)
        return 2
    except (
        KeyError,
        MasterAgentError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        if args.command in {"setup", "doctor", "execute"}:
            category = OperatingFailureCategory.RUNTIME_DEFECT
            if isinstance(error, AuthenticationError):
                category = OperatingFailureCategory.MISSING_USER_AUTHENTICATION
            elif isinstance(error, AuthorizationError):
                category = OperatingFailureCategory.BLOCKED_POLICY
            error_message = render_terminal_text(
                str(error),
                max_characters=MAX_TERMINAL_FIELD_CHARACTERS,
            )
            print(f"error: {category}: {error_message}", file=sys.stderr)
            return 2
        error_type = render_terminal_text(type(error).__name__, max_characters=80)
        error_message = render_terminal_text(
            str(error),
            max_characters=MAX_TERMINAL_FIELD_CHARACTERS,
        )
        print(f"error: {error_type}: {error_message}", file=sys.stderr)
        return 1


def _preflight_cli_persistent_output(args: argparse.Namespace) -> None:
    """Admit explicit CLI output paths before any protected input is loaded."""

    if any(
        getattr(args, name, None) is not None
        for name in ("output", "output_dir", "token_file")
    ):
        require_persistent_state_platform()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="master-agent",
        description="Governed enterprise-agent orchestration runtime.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup = subparsers.add_parser(
        "setup",
        help="install or validate a private organization profile without connecting",
    )
    setup.add_argument("--profile", type=Path)
    interaction = setup.add_mutually_exclusive_group()
    interaction.add_argument(
        "--interactive", dest="non_interactive", action="store_false"
    )
    interaction.add_argument(
        "--non-interactive",
        dest="non_interactive",
        action="store_true",
    )
    setup.set_defaults(non_interactive=None)

    doctor = subparsers.add_parser(
        "doctor",
        help="report capability-scoped readiness without network access",
    )
    doctor.add_argument("--profile", type=Path)
    doctor.add_argument(
        "--require-level",
        choices=("install", "read", "draft", "effect", "enterprise"),
        default="install",
    )
    doctor.add_argument("--output", type=Path)

    support_bundle = subparsers.add_parser(
        "support-bundle",
        help="write one private redacted offline helpdesk artifact",
    )
    support_bundle.add_argument("--profile", type=Path)
    support_bundle.add_argument("--output", type=Path, required=True)

    execute = subparsers.add_parser(
        "execute",
        help="run one reviewed plan or resume its exact approval handoff",
    )
    execute.add_argument("plan", type=Path, nargs="?")
    execute.add_argument("--profile", type=Path)
    execute.add_argument("--resume", type=Path)
    execute.add_argument(
        "--approval",
        type=Path,
        action="append",
        default=[],
        help="authenticated approval artifact; repeat for dual approval",
    )

    subparsers.add_parser(
        "demo",
        help="run a credential-free local demonstration in a fresh private workspace",
    )

    sample = subparsers.add_parser("sample-plan", help="write the mock sample plan")
    sample.add_argument(
        "--output",
        type=Path,
        default=Path("examples/weekly-status-plan.json"),
    )

    inspect = subparsers.add_parser("inspect", help="inspect a plan")
    inspect.add_argument("plan", type=Path)

    bind_context = subparsers.add_parser(
        "bind-context",
        help="bind the complete reviewed apply-time runtime into a plan",
    )
    bind_context.add_argument("plan", type=Path)
    bind_context.add_argument("--integrations", type=Path, default=None)
    bind_context.add_argument(
        "--connector-mode",
        choices=("mock", "live"),
        default="live",
    )
    bind_context.add_argument("--approval-authorities", type=Path)
    bind_context.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/audit.sqlite3"),
    )
    bind_context.add_argument("--result-json", type=Path)
    bind_context.add_argument("--retention", type=Path, default=None)
    bind_context.add_argument("--evidence-type", default="run-result/full")
    bind_context.add_argument("--identities", type=Path, default=None)
    bind_context.add_argument("--enable-writes", action="store_true")
    bind_context.add_argument("--enable-communications", action="store_true")
    bind_context.add_argument("--workspace-root", type=Path)
    bind_context.add_argument(
        "--draft-output-dir",
        type=Path,
        default=Path(".master-agent/drafts"),
    )
    bind_context.add_argument("--policy", type=Path, default=None)
    bind_context.add_argument("--sources-of-truth", type=Path, default=None)
    bind_context.add_argument("--capabilities", type=Path, default=None)
    bind_context.add_argument("--governance", type=Path, default=None)
    bind_context.add_argument("--credentials-file", type=Path)
    bind_context.add_argument(
        "--credential-map",
        action="append",
        default=[],
        metavar="FILE_KEY=DECLARED_NAME",
        help="select or rename a private credential field for this invocation",
    )
    bind_context.add_argument(
        "--connector-url",
        action="append",
        default=[],
        metavar="SYSTEM=URL",
        help="use an operator-supplied Atlassian Cloud URL for this invocation",
    )
    bind_context.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="exact connector entry-point name to bind",
    )
    bind_context.add_argument(
        "--plugin-lock",
        type=Path,
        help="explicit operator-reviewed plugin lock produced by 'plugins --output'",
    )
    bind_context.add_argument("--output", type=Path, required=True)

    approve = subparsers.add_parser(
        "approve",
        help="create an approval bound to an exact plan and action IDs",
    )
    approve.add_argument("plan", type=Path)
    approve.add_argument("--actions", required=True)
    approve.add_argument("--key-id", required=True)
    approve.add_argument("--expected-fingerprint", required=True)
    approve.add_argument("--approval-authorities", type=Path, required=True)
    approve.add_argument("--output", type=Path, required=True)
    approve.add_argument("--ttl-minutes", type=int, default=30)

    inspect_approval = subparsers.add_parser(
        "inspect-approval-request",
        help="inspect an exact private approval handoff",
    )
    inspect_approval.add_argument("request", type=Path)

    approve_request = subparsers.add_parser(
        "approve-request",
        help="sign every pending action in an inspected approval handoff",
    )
    approve_request.add_argument("request", type=Path)
    approve_request.add_argument("--key-id", required=True)
    approve_request.add_argument("--expected-fingerprint", required=True)
    approve_request.add_argument("--output", type=Path, required=True)
    approve_request.add_argument("--ttl-minutes", type=int, default=30)

    resume_approval = subparsers.add_parser(
        "resume-approval",
        help="resume an exact bound run with authenticated approval artifacts",
    )
    resume_approval.add_argument("request", type=Path)
    resume_approval.add_argument("--expected-fingerprint", required=True)
    resume_approval.add_argument(
        "--approval",
        type=Path,
        action="append",
        required=True,
        help="authenticated approval artifact; repeat for dual approval",
    )

    run = subparsers.add_parser("run", help="evaluate or apply a plan")
    run.add_argument("plan", type=Path)
    run.add_argument("--apply", action="store_true")
    run.add_argument(
        "--direct-read",
        action="store_true",
        help=(
            "run one direct-user, single-provider typed read-only plan in memory; "
            "never writes an audit, artifact, or result file"
        ),
    )
    run.add_argument(
        "--connector-mode",
        choices=("mock", "live"),
        default="mock",
    )
    run.add_argument("--integrations", type=Path, default=None)
    run.add_argument("--identities", type=Path, default=None)
    run.add_argument("--approval", type=Path, action="append", default=[])
    run.add_argument(
        "--approval-authorities",
        type=Path,
        help="explicit trusted approval-authority key ring",
    )
    run.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/audit.sqlite3"),
    )
    run.add_argument(
        "--result-json",
        type=Path,
        help="explicitly persist the full run report and retrieved content",
    )
    run.add_argument("--retention", type=Path, default=None)
    run.add_argument("--evidence-type", default="run-result/full")
    run.add_argument(
        "--enable-writes",
        action="store_true",
        help="construct provider write connectors that are also enabled in integrations.toml",
    )
    run.add_argument(
        "--enable-communications",
        action="store_true",
        help="construct provider send connectors that are also enabled in integrations.toml",
    )
    run.add_argument(
        "--workspace-root",
        type=Path,
        help="approved root containing local Git workspaces",
    )
    run.add_argument(
        "--draft-output-dir",
        type=Path,
        default=Path(".master-agent/drafts"),
        help="root for local draft artifacts in live mode",
    )
    run.add_argument("--capabilities", type=Path, default=None)
    run.add_argument("--governance", type=Path, default=None)
    run.add_argument("--credentials-file", type=Path)
    run.add_argument(
        "--credential-map",
        action="append",
        default=[],
        metavar="FILE_KEY=DECLARED_NAME",
        help="select or rename a private credential field for this invocation",
    )
    run.add_argument(
        "--connector-url",
        action="append",
        default=[],
        metavar="SYSTEM=URL",
        help="use an operator-supplied Atlassian Cloud URL for this invocation",
    )
    run.add_argument("--policy", type=Path, default=None)
    run.add_argument("--sources-of-truth", type=Path, default=None)
    run.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="explicit connector entry-point name to load during --apply",
    )
    run.add_argument(
        "--plugin-lock",
        type=Path,
        help="explicit operator-reviewed lock for every selected connector plugin",
    )

    plugins = subparsers.add_parser(
        "plugins",
        help="list installed connector plugins without importing plugin code",
    )
    plugins.add_argument("--output", type=Path)

    capability_import = subparsers.add_parser(
        "capability-import",
        help="inspect or explicitly quarantine one custom-agent capability",
    )
    capability_import.add_argument("source", type=Path)
    capability_import.add_argument("--capabilities", type=Path, default=None)
    capability_import.add_argument(
        "--dependency-licenses",
        type=Path,
        default=None,
        help="dependency license policy used for compatibility classification",
    )
    capability_import.add_argument(
        "--select",
        help="explicitly select one safely importable ability for quarantine",
    )
    capability_import.add_argument(
        "--expected-source-sha256",
        help="exact source digest returned by the read-only inspection",
    )
    capability_import.add_argument("--capsule-store", type=Path)
    capability_import.add_argument("--capsule-authorities", type=Path)
    capability_import.add_argument(
        "--environment",
        choices=tuple(str(item) for item in EnvironmentKind),
        default=str(EnvironmentKind.NON_PRODUCTION),
    )
    capability_import.add_argument(
        "--worker-sha256",
        help=("exact promotion-worker digest; defaults to the current isolated worker"),
    )
    capability_import.add_argument("--output", type=Path)

    capability_promote = subparsers.add_parser(
        "capability-promote",
        help="validate, independently sign, publish, and enable one quarantine",
    )
    capability_promote.add_argument("capability_id")
    capability_promote.add_argument("version")
    capability_promote.add_argument("--capsule-store", type=Path, required=True)
    capability_promote.add_argument("--capsule-authorities", type=Path, required=True)
    capability_promote.add_argument("--dependency-licenses", type=Path)
    capability_promote.add_argument(
        "--environment",
        choices=tuple(str(item) for item in EnvironmentKind),
        default=str(EnvironmentKind.NON_PRODUCTION),
    )
    capability_promote.add_argument("--output", type=Path)

    capability_status = subparsers.add_parser(
        "capability-status",
        help="verify and show one capsule's complete immutable state chain",
    )
    capability_status.add_argument("capability_id")
    capability_status.add_argument("version")
    capability_status.add_argument("--capsule-store", type=Path, required=True)
    capability_status.add_argument("--capsule-authorities", type=Path, required=True)
    capability_status.add_argument("--output", type=Path)

    capability_route = subparsers.add_parser(
        "capability-route",
        help="policy-filter an intent against explicitly selected enabled capsules",
    )
    capability_route.add_argument("intent")
    capability_route.add_argument(
        "--capsule",
        action="append",
        required=True,
        metavar="CAPABILITY_ID@VERSION",
    )
    capability_route.add_argument("--capsule-store", type=Path, required=True)
    capability_route.add_argument("--capsule-authorities", type=Path, required=True)
    capability_route.add_argument("--policy", type=Path)
    capability_route.add_argument("--governance", type=Path)
    capability_route.add_argument("--output", type=Path)

    capability_run = subparsers.add_parser(
        "capability-run",
        help="route and execute one enabled pure capsule through normal governance",
    )
    capability_run.add_argument("intent")
    capability_run.add_argument(
        "--capsule",
        action="append",
        required=True,
        metavar="CAPABILITY_ID@VERSION",
    )
    capability_run.add_argument("--request", type=Path, required=True)
    capability_run.add_argument("--capsule-store", type=Path, required=True)
    capability_run.add_argument("--capsule-authorities", type=Path, required=True)
    capability_run.add_argument("--policy", type=Path)
    capability_run.add_argument("--governance", type=Path)
    capability_run.add_argument("--capabilities", type=Path)
    capability_run.add_argument("--sources-of-truth", type=Path)
    capability_run.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/capsule-audit.sqlite3"),
    )
    capability_run.add_argument("--principal", default="local:operator")
    capability_run.add_argument("--agent-identity", default="master-agent")
    capability_run.add_argument("--tenant-id", default="local")
    capability_run.add_argument("--output", type=Path)

    capability_disable = subparsers.add_parser(
        "capability-disable",
        help="append signed deprecation so an enabled capsule stops routing",
    )
    capability_disable.add_argument("capability_id")
    capability_disable.add_argument("version")
    capability_disable.add_argument("--capsule-store", type=Path, required=True)
    capability_disable.add_argument("--capsule-authorities", type=Path, required=True)
    capability_disable.add_argument("--output", type=Path)

    capability_revoke = subparsers.add_parser(
        "capability-revoke",
        help="append signed revocation while retaining immutable history",
    )
    capability_revoke.add_argument("capability_id")
    capability_revoke.add_argument("version")
    capability_revoke.add_argument("--capsule-store", type=Path, required=True)
    capability_revoke.add_argument("--capsule-authorities", type=Path, required=True)
    capability_revoke.add_argument("--output", type=Path)

    readiness = subparsers.add_parser(
        "readiness",
        help="assess governance, connector, OAuth, and permission readiness without network access",
    )
    readiness.add_argument("--integrations", type=Path, default=None)
    readiness.add_argument("--capabilities", type=Path, default=None)
    readiness.add_argument("--governance", type=Path, default=None)
    readiness.add_argument("--oauth", type=Path, default=None)
    readiness.add_argument("--identities", type=Path, default=None)
    readiness.add_argument("--credentials-file", type=Path)
    readiness.add_argument(
        "--egress-check",
        action="append",
        default=[],
        metavar="PROVIDER:CLASSIFICATION",
        help=(
            "offline-check whether one provider/data class can use the active "
            "model destination and tenancy"
        ),
    )
    readiness.add_argument("--output", type=Path)

    oauth_device = subparsers.add_parser(
        "oauth-device-code",
        help="run an explicitly configured Microsoft delegated device-code flow",
    )
    oauth_device.add_argument("--oauth", type=Path, default=None)
    oauth_device.add_argument("--profile", default="microsoft_delegated")
    oauth_device.add_argument("--token-file", type=Path, required=True)

    drafts = subparsers.add_parser(
        "draft-package",
        help="generate the complete Phase 3 local draft package",
    )
    drafts.add_argument("--workflow", type=Path, default=None)
    drafts.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".master-agent/draft-package"),
    )
    drafts.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/audit.sqlite3"),
    )

    compensate = subparsers.add_parser(
        "compensation-plan",
        help="build an approval-bound rollback plan from a completed run report",
    )
    compensate.add_argument("--plan", type=Path, required=True)
    compensate.add_argument("--report", type=Path, required=True)
    compensate.add_argument("--created-by", default="operator")
    compensate.add_argument("--output", type=Path, required=True)

    recurring_status = subparsers.add_parser(
        "recurring-status",
        help="show due state for registered Phase 6 workflows",
    )
    recurring_status.add_argument("--recurring", type=Path, default=None)
    recurring_status.add_argument("--output", type=Path)

    recurring_bind = subparsers.add_parser(
        "recurring-bind",
        help="bind and authenticate one exact registered workflow occurrence",
    )
    recurring_bind.add_argument("name")
    recurring_bind.add_argument("--occurrence", required=True)
    recurring_bind.add_argument("--plan", type=Path, required=True)
    recurring_bind.add_argument("--recurring", type=Path, required=True)
    recurring_bind.add_argument("--approval-authorities", type=Path, required=True)
    recurring_bind.add_argument("--capabilities", type=Path)
    recurring_bind.add_argument("--governance", type=Path)
    recurring_bind.add_argument("--policy", type=Path)
    recurring_bind.add_argument("--sources-of-truth", type=Path)
    recurring_bind.add_argument("--organization-profile", type=Path)
    recurring_bind.add_argument(
        "--credential-map",
        action="append",
        default=[],
        metavar="FILE_KEY=DECLARED_NAME",
    )
    recurring_bind.add_argument(
        "--connector-url",
        action="append",
        default=[],
        metavar="SYSTEM=URL",
    )
    recurring_bind.add_argument("--output", type=Path, required=True)

    recurring_inspect = subparsers.add_parser(
        "recurring-inspect",
        help="inspect an occurrence without credentials, providers, or state",
    )
    recurring_inspect.add_argument("artifact", type=Path)
    recurring_inspect.add_argument("--expected-fingerprint")

    recurring_recover = subparsers.add_parser(
        "recurring-recover",
        help="review and permit retry of one certified pre-effect failure",
    )
    recurring_recover.add_argument("artifact", type=Path)
    recurring_recover.add_argument("--recurring", type=Path, required=True)
    recurring_recover.add_argument("--expected-fingerprint", required=True)

    recurring_reconcile = subparsers.add_parser(
        "recurring-reconcile",
        help="reconcile one expired occurrence from exact idempotency records",
    )
    recurring_reconcile.add_argument("artifact", type=Path)
    recurring_reconcile.add_argument("--recurring", type=Path, required=True)
    recurring_reconcile.add_argument("--expected-fingerprint", required=True)

    recurring_cancel = subparsers.add_parser(
        "recurring-cancel",
        help="cancel one pending exact occurrence and invalidate its fence",
    )
    recurring_cancel.add_argument("artifact", type=Path)
    recurring_cancel.add_argument("--recurring", type=Path, required=True)
    recurring_cancel.add_argument("--expected-fingerprint", required=True)

    recurring_run = subparsers.add_parser(
        "recurring-run",
        help="dry-run or apply one authenticated exact occurrence artifact",
    )
    recurring_run.add_argument("artifact", type=Path)
    recurring_run.add_argument("--recurring", type=Path)
    recurring_run.add_argument(
        "--force",
        action="store_true",
        dest="legacy_force",
        help=argparse.SUPPRESS,
    )
    recurring_run.add_argument(
        "--connector-mode",
        dest="legacy_connector_mode",
        help=argparse.SUPPRESS,
    )
    recurring_mode = recurring_run.add_mutually_exclusive_group()
    recurring_mode.add_argument("--dry-run", action="store_true")
    recurring_mode.add_argument("--apply", action="store_true")
    recurring_run.add_argument(
        "--approval",
        type=Path,
        action="append",
        default=[],
    )
    recurring_run.add_argument("--expected-fingerprint")

    discover = subparsers.add_parser(
        "discover",
        help="inspect connector configuration and optionally probe live APIs",
    )
    discover.add_argument("--integrations", type=Path, default=None)
    discover.add_argument("--governance", type=Path, default=None)
    discover.add_argument("--credentials-file", type=Path)
    discover.add_argument("--probe", action="store_true")
    discover.add_argument(
        "--require-ready",
        action="store_true",
        help=(
            "return nonzero when an enabled selected connector lacks required "
            "configuration or credentials"
        ),
    )
    discover.add_argument("--systems")
    discover.add_argument(
        "--data-classification",
        type=DataClassification,
        choices=tuple(DataClassification),
        help=(
            "classify live probe output; development may use the explicitly "
            "configured nonproduction default"
        ),
    )
    discover.add_argument("--output", type=Path)

    connect = subparsers.add_parser(
        "connect",
        help=(
            "select requested read connectors and verify them without "
            "changing persistent configuration"
        ),
    )
    connect.add_argument("--integrations", type=Path, default=None)
    connect.add_argument("--governance", type=Path, default=None)
    connect.add_argument("--credentials-file", type=Path)
    connect.add_argument(
        "--credential-map",
        action="append",
        default=[],
        metavar="FILE_KEY=DECLARED_NAME",
        help=(
            "resolve an ambiguous flat credential key for this invocation "
            "without rewriting the credential file"
        ),
    )
    connect.add_argument(
        "--connector-url",
        action="append",
        default=[],
        metavar="SYSTEM=URL",
        help="normalize an operator-supplied Atlassian Cloud URL in memory",
    )
    connect.add_argument("--systems", required=True)
    connect.add_argument(
        "--data-classification",
        type=DataClassification,
        choices=tuple(DataClassification),
        help=(
            "classify live probe output; development may use the explicitly "
            "configured nonproduction default"
        ),
    )
    connect.add_argument("--output", type=Path)

    github_repositories = subparsers.add_parser(
        "github-repositories",
        help=(
            "list one user's public repositories anonymously, or verify GitHub "
            "and list repositories visible to the authenticated user"
        ),
    )
    github_repositories.add_argument("--credentials-file", type=Path)
    github_repositories.add_argument(
        "--username",
        help=(
            "GitHub username whose public repositories should be listed without "
            "credentials"
        ),
    )
    github_repositories.add_argument("--limit", type=int, default=100)
    github_repositories.add_argument(
        "--visibility",
        choices=("all", "public", "private"),
        default=None,
        help=(
            "authenticated-user visibility (default: all); public-user listing "
            "accepts only public"
        ),
    )
    github_repositories.add_argument("--output", type=Path)

    bitbucket_repositories = subparsers.add_parser(
        "bitbucket-repositories",
        help="list a Bitbucket Cloud workspace's public repositories anonymously",
    )
    bitbucket_repositories.add_argument(
        "--workspace",
        required=True,
        help="Bitbucket Cloud workspace slug",
    )
    bitbucket_repositories.add_argument("--limit", type=int, default=100)
    bitbucket_repositories.add_argument("--output", type=Path)

    weekly_plan = subparsers.add_parser(
        "weekly-status-plan",
        help="build a live read-only weekly-status plan",
    )
    weekly_plan.add_argument("--integrations", type=Path, default=None)
    weekly_plan.add_argument("--workflow", type=Path, default=None)
    weekly_plan.add_argument(
        "--output",
        type=Path,
        default=Path("examples/weekly-status-live-plan.json"),
    )

    operating_review_plan = subparsers.add_parser(
        "weekly-operating-review-plan",
        help="build the local-only exact recurring reference workflow plan",
    )
    operating_review_plan.add_argument("--workflow", type=Path, default=None)
    operating_review_plan.add_argument(
        "--output",
        type=Path,
        default=Path("examples/weekly-operating-review-plan.json"),
    )

    weekly = subparsers.add_parser(
        "weekly-status",
        help="disabled pending manifest-bound descriptor-safe rendering",
    )
    weekly.add_argument("--integrations", type=Path, default=None)
    weekly.add_argument("--workflow", type=Path, default=None)
    weekly.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".master-agent/weekly-status"),
    )
    weekly.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/audit.sqlite3"),
    )

    identity = subparsers.add_parser(
        "identity-resolve",
        help="resolve a person to configured cross-system identifiers",
    )
    identity.add_argument("query")
    identity.add_argument("--system")
    identity.add_argument("--identities", type=Path, default=None)
    identity.add_argument("--output", type=Path)

    retain = subparsers.add_parser(
        "retain-evidence",
        help="persist evidence under the configured retention policy",
    )
    retain.add_argument("--input", type=Path, required=True)
    retain.add_argument("--output", type=Path, required=True)
    retain.add_argument("--evidence-type", required=True)
    retain.add_argument("--retention", type=Path, default=None)
    retain.add_argument("--include-content", action="store_true")

    prune = subparsers.add_parser(
        "evidence-prune",
        help="preview or explicitly delete validated expired evidence",
    )
    prune.add_argument("--root", type=Path, default=Path(".master-agent"))
    prune.add_argument("--apply", action="store_true")
    prune.add_argument("--output", type=Path)

    repair = subparsers.add_parser(
        "evidence-repair",
        help="detect or recoverably quarantine orphaned retained evidence",
    )
    repair.add_argument("--root", type=Path, default=Path(".master-agent"))
    repair.add_argument("--apply", action="store_true")
    repair.add_argument("--output", type=Path)

    work_memory = subparsers.add_parser(
        "work-memory",
        help="keep bounded local issue-to-merge work metadata",
    )
    work_memory.add_argument(
        "work_memory_command",
        choices=("start", "record", "show", "verify"),
        metavar="{start,record,show,verify}",
    )
    work_memory.add_argument("--database", type=Path, required=True)
    work_memory.add_argument("--work-id")
    work_memory.add_argument("--issue")
    work_memory.add_argument(
        "--kind",
        choices=(
            WorkEventKind.DECISION.value,
            WorkEventKind.CHECKPOINT.value,
            WorkEventKind.REFERENCE.value,
        ),
    )
    work_memory.add_argument(
        "--stage",
        choices=tuple(stage.value for stage in WorkStage),
    )
    work_memory.add_argument("--summary")
    work_memory.add_argument("--reference")
    work_memory.add_argument("--output", type=Path)

    citations = subparsers.add_parser(
        "citations",
        help="list resource-level citations found in a result JSON file",
    )
    citations.add_argument("file", type=Path)
    citations.add_argument("--output", type=Path)

    communication_plan = subparsers.add_parser(
        "communication-context-plan",
        help="build a read-only Outlook and Teams context plan",
    )
    communication_plan.add_argument("--workflow", type=Path, default=None)
    communication_plan.add_argument("--identities", type=Path, default=None)
    communication_plan.add_argument(
        "--output",
        type=Path,
        default=Path("examples/communication-context-live-plan.json"),
    )

    communication = subparsers.add_parser(
        "communication-context",
        help="disabled pending manifest-bound descriptor-safe rendering",
    )
    communication.add_argument("--integrations", type=Path, default=None)
    communication.add_argument("--workflow", type=Path, default=None)
    communication.add_argument("--identities", type=Path, default=None)
    communication.add_argument("--retention", type=Path, default=None)
    communication.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".master-agent/communication-context"),
    )
    communication.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/audit.sqlite3"),
    )

    scan = subparsers.add_parser("scan", help="scan untrusted content")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--file", type=Path)

    audit = subparsers.add_parser("audit-verify", help="verify audit hash chain")
    audit.add_argument(
        "--database",
        type=Path,
        default=Path(".master-agent/audit.sqlite3"),
    )
    return parser


def _setup(*, profile_path: Path | None, non_interactive: bool | None) -> int:
    """Install or validate one user-private organization profile."""

    require_persistent_state_platform()
    destination = profile_path or default_organization_profile_path()
    destination = destination.expanduser()
    if not destination.is_absolute():
        destination = Path.cwd() / destination
    exists = os.path.lexists(destination)
    source = resolve_config_source(
        destination if exists else None,
        "organization-profile.toml",
    )
    preview = OrganizationProfile.from_snapshot(source, installed_path=destination)
    interactive = (
        (sys.stdin.isatty() and sys.stdout.isatty())
        if non_interactive is None
        else not non_interactive
    )
    if interactive and not exists:
        print(
            f"organization: {_terminal_field(preview.organization, max_characters=256)}"
        )
        print(f"mode: {preview.mode}")
        safe_destination = _terminal_field(destination)
        try:
            answer = input(f"Install private profile at {safe_destination}? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().casefold() not in {"y", "yes"}:
            print("setup cancelled; no profile or state was created")
            return 2
    result = install_organization_profile(source, destination=destination)
    print(f"profile: {_terminal_field(result.profile.source_path)}")
    print(f"mode: {_terminal_field(result.profile.mode, max_characters=80)}")
    print(f"state root: {_terminal_field(result.state.state_root)}")
    print("provider connections: none")
    print("write actions: disabled unless separately profile- and policy-enabled")
    print("setup status: ready")
    return 0


def _doctor_assessment(
    profile_path: Path | None,
) -> tuple[dict[str, object], PlatformRuntimeStatus]:
    """Build the shared offline doctor assessment without rendering it."""

    selected_platform = platform_runtime_status()
    selected = profile_path or default_organization_profile_path()
    selected = selected.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if not os.path.lexists(selected):
        issue = OperatingIssue(
            OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
            "organization profile is not installed; run master-agent setup",
        )
        payload: dict[str, object] = {
            "schema": "master-agent/operating-readiness@1",
            "mode": None,
            "profile_fingerprint": None,
            "profile_source": str(selected),
            "platform_runtime": selected_platform.to_dict(),
            "levels": {
                str(ReadinessLevel.INSTALL): True,
                str(ReadinessLevel.READ): False,
                str(ReadinessLevel.DRAFT): False,
                str(ReadinessLevel.EFFECT): False,
                str(ReadinessLevel.ENTERPRISE): False,
            },
            "enterprise_blocker": (
                "enterprise readiness requires organization trust controls"
            ),
            "capabilities": [],
            "issues": [issue.to_dict()],
        }
    else:
        profile = _load_active_organization_profile(selected)
        catalog = _operating_catalog(profile)
        integrations, integrations_issue = _doctor_integrations(profile)
        governance = _doctor_governance(profile)
        policy = _doctor_policy(profile)
        approval_required_reads = _doctor_approval_required_read_capabilities(
            profile,
            catalog=catalog,
            governance=governance,
            policy=policy,
        )
        read_capabilities = frozenset(
            capability
            for capability in profile.capabilities
            if (definition := catalog.definitions.get(capability)) is not None
            and definition.risk is RiskLevel.READ_ONLY
        )
        applied_read_capabilities = frozenset(
            capability
            for capability in read_capabilities
            if catalog.definitions[capability].target_system
            not in _CONNECT_CONFIGURATION_BY_SYSTEM
        )
        if governance is not None and not governance.metadata.get(
            "allow_ephemeral_direct_reads",
            False,
        ):
            applied_read_capabilities = read_capabilities
        applied_read_capabilities |= approval_required_reads
        filesystem_backed_read_capabilities = _filesystem_backed_read_capabilities(
            read_capabilities,
            catalog=catalog,
            integrations=integrations,
        )
        readiness_catalog = _doctor_readiness_catalog(
            catalog,
            applied_read_capabilities=applied_read_capabilities,
        )
        payload = assess_operating_readiness(
            profile=profile,
            catalog=readiness_catalog,
            integrations=integrations,
            environ=os.environ,
            runtime_capabilities=_operating_runtime_capabilities(
                profile,
                integrations,
            ),
            policy_blocked_capabilities=_operating_policy_blocked_capabilities(
                profile,
                integrations,
                include_provider_gates=integrations_issue is None,
            ),
            state_backed_read_capabilities=applied_read_capabilities,
            filesystem_backed_read_capabilities=(filesystem_backed_read_capabilities),
            platform_status=selected_platform,
        ).to_dict()
        state_issue = _offline_operating_state_issue(profile)
        if state_issue is not None:
            raw_levels = payload.get("levels")
            if isinstance(raw_levels, dict):
                raw_levels[str(ReadinessLevel.INSTALL)] = False
                raw_levels[str(ReadinessLevel.DRAFT)] = False
                raw_levels[str(ReadinessLevel.EFFECT)] = False
            payload["issues"] = [state_issue.to_dict()]
            _apply_doctor_capability_issue(
                payload,
                state_issue,
                affected_levels=(ReadinessLevel.DRAFT, ReadinessLevel.EFFECT),
            )
            _apply_doctor_capability_issue(
                payload,
                state_issue,
                affected_levels=(ReadinessLevel.READ,),
                capability_names=applied_read_capabilities,
            )
        _apply_doctor_configuration_readiness(
            payload,
            profile,
            catalog=catalog,
            integrations=integrations,
            integrations_valid=integrations_issue is None,
            applied_read_capabilities=applied_read_capabilities,
        )
        if integrations_issue is not None:
            _apply_doctor_integrations_issue(
                payload,
                integrations_issue,
                catalog=catalog,
            )
        _apply_doctor_approval_readiness(
            payload,
            profile,
            approval_required_reads=approval_required_reads,
        )
        _recompute_doctor_operational_levels(payload)
    return payload, selected_platform


def _doctor(
    *,
    profile_path: Path | None,
    require_level: str,
    output: Path | None,
) -> int:
    """Report progressive readiness without provider or credential I/O."""

    if output is not None:
        require_persistent_state_platform()
    payload, selected_platform = _doctor_assessment(profile_path)
    levels = payload["levels"]
    if not isinstance(levels, Mapping):  # pragma: no cover - typed report invariant.
        raise ValidationError("operating readiness levels are malformed")
    print(
        f"mode: {_terminal_field(payload.get('mode') or 'not configured', max_characters=80)}"
    )
    _print_platform_runtime(selected_platform)
    for level in ReadinessLevel:
        print(f"{level}: {bool(levels.get(str(level), False))}")
    capability_items = payload.get("capabilities", [])
    if isinstance(capability_items, list):
        for item in capability_items:
            if not isinstance(item, Mapping):
                continue
            for raw_issue in item.get("issues", []):
                if isinstance(raw_issue, Mapping):
                    category = _terminal_field(
                        raw_issue.get("category", "runtime_defect"), max_characters=80
                    )
                    capability = _terminal_field(
                        raw_issue.get("capability", "installation"), max_characters=256
                    )
                    message = _terminal_field(raw_issue.get("message", "readiness gap"))
                    print(f"{category}: {capability}: {message}")
    general_issues = payload.get("issues", [])
    if isinstance(general_issues, list):
        for raw_issue in general_issues:
            if isinstance(raw_issue, Mapping):
                category = _terminal_field(
                    raw_issue.get("category", "runtime_defect"), max_characters=80
                )
                message = _terminal_field(raw_issue.get("message", "readiness gap"))
                print(f"{category}: {message}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {_terminal_field(output)}")
    required_key = f"{require_level}_ready"
    return 0 if bool(levels.get(required_key, False)) else 2


def _support_bundle(*, profile_path: Path | None, output: Path) -> int:
    """Write one private, bounded, redacted offline helpdesk artifact."""

    require_persistent_state_platform()
    payload, _selected_platform = _doctor_assessment(profile_path)
    support_id = str(UUID(bytes=secrets.token_bytes(16), version=4))
    created_at = (
        datetime.now(UTC)
        .isoformat(timespec="seconds")
        .replace(
            "+00:00",
            "Z",
        )
    )
    bundle = build_operating_support_bundle(
        payload,
        support_id=support_id,
        created_at=created_at,
        master_agent_version=__version__,
        python_version=(
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
    )
    _write_json(output, bundle)
    print(f"support ID: {_terminal_field(support_id, max_characters=80)}")
    print(f"wrote {_terminal_field(output)}")
    print("upload: none; share only through the approved helpdesk channel")
    return 0


def _filesystem_backed_read_capabilities(
    capabilities: Iterable[str],
    *,
    catalog: CapabilityCatalog,
    integrations: IntegrationConfig,
) -> frozenset[str]:
    """Return reads whose selected connector consumes filesystem trust state."""

    selected: set[str] = set()
    for capability in capabilities:
        definition = catalog.definitions.get(capability)
        if definition is None:
            continue
        configuration_name = _CONNECT_CONFIGURATION_BY_SYSTEM.get(
            definition.target_system
        )
        if configuration_name is None:
            continue
        connector = integrations.connectors.get(configuration_name)
        if connector is None:
            continue
        oauth_flow = str(connector.extra.get("oauth_flow", "environment")).strip()
        ca_bundle_selected = bool(
            connector.ca_bundle_env
            and os.environ.get(connector.ca_bundle_env, "").strip()
        )
        if ca_bundle_selected or oauth_flow == "token_file":
            selected.add(capability)
    return frozenset(selected)


def _execute(
    *,
    plan_path: Path | None,
    profile_path: Path | None,
    request_path: Path | None,
    approval_paths: Sequence[Path],
) -> int:
    """Run or resume one profile-admitted plan through existing runtimes."""

    if request_path is not None:
        require_persistent_state_platform()
        if plan_path is not None:
            raise ValueError("execute accepts either PLAN or --resume, not both")
        if profile_path is not None:
            raise ValueError(
                "execute --resume restores the bound organization profile; "
                "omit --profile"
            )
        if not approval_paths:
            raise ValueError("execute --resume requires at least one --approval")
        return _execute_approval_resume(request_path, approval_paths)
    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    if plan_path is None:
        raise ValueError("execute requires PLAN or --resume REQUEST")
    if approval_paths:
        raise ValueError("--approval is accepted only with execute --resume")

    selected_profile = profile_path or default_organization_profile_path()
    profile, profile_source = _capture_active_organization_profile(selected_profile)
    plan = _load_operating_plan(plan_path)
    direct_read_candidate = _eligible_direct_operating_read(plan, profile=profile)
    captured_sources = _capture_operating_execution_sources(
        profile,
        profile_source,
        plan=plan,
        applied=not direct_read_candidate,
    )
    catalog = CapabilityCatalog.from_toml(captured_sources["capabilities"])
    integrations = IntegrationConfig.from_toml(captured_sources["integrations"])
    operating_policy = PolicyConfig.from_toml(captured_sources["policy"])
    operating_governance = GovernanceProfile.from_toml(captured_sources["governance"])
    direct_read = (
        direct_read_candidate
        and operating_governance.allows_direct_read_session(plan)[0]
        and not _plan_requires_authenticated_approval(
            plan,
            policy_source=captured_sources["policy"],
            governance=operating_governance,
        )
    )
    if direct_read_candidate and not direct_read:
        captured_sources = _capture_operating_execution_sources(
            profile,
            profile_source,
            plan=plan,
            applied=True,
        )
        catalog = CapabilityCatalog.from_toml(captured_sources["capabilities"])
        integrations = IntegrationConfig.from_toml(captured_sources["integrations"])
        operating_policy = PolicyConfig.from_toml(captured_sources["policy"])
        operating_governance = GovernanceProfile.from_toml(
            captured_sources["governance"]
        )
    require_operating_plan(
        plan,
        profile=profile,
        catalog=catalog,
        integrations=integrations,
        environ=os.environ,
        runtime_capabilities=_operating_runtime_capabilities(profile, integrations),
        policy_blocked_capabilities=_operating_policy_blocked_capabilities(
            profile,
            integrations,
            catalog=catalog,
            policy=operating_policy,
            governance=operating_governance,
        ),
    )
    _require_operating_policy_preflight(
        plan=plan,
        catalog=catalog,
        governance=operating_governance,
        policy=operating_policy,
        sources=SourceOfTruthRegistry.from_toml(captured_sources["sources_of_truth"]),
    )
    if not direct_read:
        try:
            _preflight_applied_provider_reads(
                plan=plan,
                catalog=catalog,
                governance=operating_governance,
                enforce_non_provider=profile.connector_mode is ConnectorMode.LIVE,
            )
        except ConfigurationError as error:
            raise OperatingValidationError(
                (
                    OperatingIssue(
                        OperatingFailureCategory.BLOCKED_POLICY,
                        str(error),
                    ),
                )
            ) from error
    configuration = profile.configuration_path
    if direct_read:
        return _run(
            plan_path=plan_path,
            apply=False,
            direct_read=True,
            approval_paths=[],
            approval_authorities=None,
            database=Path(".master-agent/audit.sqlite3"),
            connector_mode="live",
            integrations_path=configuration("integrations"),
            result_json=None,
            retention_path=None,
            evidence_type="run-result/full",
            identities_path=None,
            include_writes=False,
            include_communications=False,
            workspace_root=None,
            draft_output_dir=Path(".master-agent/drafts"),
            capabilities_path=configuration("capabilities"),
            governance_path=configuration("governance"),
            policy_path=configuration("policy"),
            sources_of_truth_path=configuration("sources_of_truth"),
            plugin_names=[],
            plugin_lock_path=None,
            credentials_file=None,
            organization_profile_path=profile.source_path,
            high_level=True,
            loaded_plan=plan,
            expected_plan_fingerprint=plan.fingerprint,
            expected_profile_fingerprint=profile.fingerprint,
            captured_configuration_sources=captured_sources,
        )

    require_persistent_state_platform()
    approval_required = _plan_requires_authenticated_approval(
        plan,
        policy_source=captured_sources["policy"],
        governance=operating_governance,
    )
    selected_approval_authorities = configuration("approval_authorities")
    if approval_required and selected_approval_authorities is None:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                    "the organization profile must select approval authorities "
                    "for this effect",
                ),
            )
        )
    approval_authorities = selected_approval_authorities if approval_required else None
    if approval_authorities is not None:
        approval_source = _resolve_operating_configuration(
            profile,
            "approval_authorities",
            "approval-authorities.toml",
        )
        try:
            _validate_approval_authorities_offline(approval_source)
        except ConfigurationError as error:
            raise OperatingValidationError(
                (
                    OperatingIssue(
                        OperatingFailureCategory.RUNTIME_DEFECT,
                        f"organization approval configuration is invalid: {error}",
                    ),
                )
            ) from error
        captured_sources["approval_authorities"] = approval_source
    run_paths = allocate_operating_run(profile)
    _write_json(run_paths.plan, plan.to_dict())
    bind_status = _bind_context(
        plan_path=run_paths.plan,
        integrations_path=configuration("integrations"),
        plugin_names=[],
        plugin_lock_path=None,
        connector_mode=str(profile.connector_mode),
        approval_authorities=approval_authorities,
        database=run_paths.audit_database,
        result_json=run_paths.result,
        retention_path=configuration("retention"),
        evidence_type="run-result/full",
        identities_path=configuration("identities"),
        include_writes=profile.writes_enabled,
        include_communications=profile.communications_enabled,
        workspace_root=run_paths.workspace,
        draft_output_dir=run_paths.artifacts,
        policy_path=configuration("policy"),
        sources_of_truth_path=configuration("sources_of_truth"),
        capabilities_path=configuration("capabilities"),
        governance_path=configuration("governance"),
        credentials_file=None,
        output=run_paths.bound_plan,
        organization_profile_path=profile.source_path,
        expected_plan_fingerprint=plan.fingerprint,
        expected_profile_fingerprint=profile.fingerprint,
        organization_run_root=run_paths.run_root,
        captured_configuration_sources=captured_sources,
    )
    if bind_status:
        return bind_status
    bound = _load_operating_plan(run_paths.bound_plan)
    if bound.execution_context is None or bound.execution_context.runtime is None:
        raise ValidationError("execute did not produce a bound runtime plan")
    print(f"prepared plan: {bound.fingerprint}")
    return _run(
        plan_path=run_paths.bound_plan,
        apply=True,
        approval_paths=[],
        approval_authorities=approval_authorities,
        database=run_paths.audit_database,
        connector_mode=str(profile.connector_mode),
        integrations_path=configuration("integrations"),
        result_json=run_paths.result,
        retention_path=configuration("retention"),
        evidence_type="run-result/full",
        identities_path=configuration("identities"),
        include_writes=profile.writes_enabled,
        include_communications=profile.communications_enabled,
        workspace_root=run_paths.workspace,
        draft_output_dir=run_paths.artifacts,
        capabilities_path=configuration("capabilities"),
        governance_path=configuration("governance"),
        policy_path=configuration("policy"),
        sources_of_truth_path=configuration("sources_of_truth"),
        plugin_names=[],
        plugin_lock_path=None,
        credentials_file=None,
        organization_profile_path=profile.source_path,
        high_level=True,
        expected_plan_fingerprint=bound.fingerprint,
        expected_profile_fingerprint=profile.fingerprint,
        organization_run_root=run_paths.run_root,
        captured_configuration_sources=captured_sources,
    )


def _execute_approval_resume(
    request_path: Path,
    approval_paths: Sequence[Path],
) -> int:
    """Resume without accepting any replacement profile or runtime input."""

    request = load_approval_request(request_path)
    profile_value = request.run.organization_profile
    if profile_value is None:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                    "approval request has no bound organization profile",
                ),
            )
        )
    runtime = request.execution_context.runtime
    if runtime is None:  # pragma: no cover - approval request invariant.
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    "approval request has no bound runtime",
                ),
            )
        )
    approved_profile_path_fingerprint = next(
        (
            item.sha256
            for item in runtime.configurations
            if item.name == "organization_profile_path"
        ),
        None,
    )
    observed_profile_path_fingerprint = hashlib.sha256(
        _organization_profile_path_snapshot(Path(profile_value)).payload
    ).hexdigest()
    if approved_profile_path_fingerprint != observed_profile_path_fingerprint:
        _raise_profile_selection_error("profile path")
    profile = _load_active_organization_profile(Path(profile_value))
    bound_plan = _load_operating_plan(Path(request.run.plan_path))
    request.validate_plan(bound_plan)
    approved_profile_fingerprint = next(
        (
            item.sha256
            for item in runtime.configurations
            if item.name == "organization_profile"
        ),
        None,
    )
    if approved_profile_fingerprint != profile.fingerprint:
        _raise_profile_selection_error("profile fingerprint")
    catalog, integrations = _operating_plan_catalog_and_integrations(
        profile,
        replace(bound_plan, execution_context=None),
    )
    require_operating_plan(
        replace(bound_plan, execution_context=None),
        profile=profile,
        catalog=catalog,
        integrations=integrations,
        environ=os.environ,
        runtime_capabilities=_operating_runtime_capabilities(profile, integrations),
        policy_blocked_capabilities=_operating_policy_blocked_capabilities(
            profile,
            integrations,
        ),
    )
    return _resume_approval(
        request_path=request_path,
        expected_fingerprint=request.fingerprint,
        approval_paths=approval_paths,
        high_level=True,
        expected_profile_fingerprint=profile.fingerprint,
    )


def _offline_operating_state_issue(
    profile: OrganizationProfile,
) -> OperatingIssue | None:
    """Validate profile-owned state paths without creating or changing them."""

    state_root = profile.state_root
    runs_root = state_root / "runs"
    if not os.path.lexists(state_root) or not os.path.lexists(runs_root):
        return OperatingIssue(
            OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
            "private operating state is not installed; run master-agent setup",
        )
    try:
        with PinnedDirectory.open(state_root), PinnedDirectory.open(runs_root):
            pass
    except ConfigurationError:
        return OperatingIssue(
            OperatingFailureCategory.RUNTIME_DEFECT,
            "private operating state failed ownership, permission, or path checks",
        )
    return None


def _apply_doctor_configuration_readiness(
    payload: dict[str, object],
    profile: OrganizationProfile,
    *,
    catalog: CapabilityCatalog,
    integrations: IntegrationConfig,
    integrations_valid: bool,
    applied_read_capabilities: frozenset[str],
) -> None:
    """Validate the offline configuration slice consumed by each level."""

    checks = (
        (
            "policy",
            "policy.toml",
            True,
        ),
        (
            "governance",
            "governance.toml",
            True,
        ),
        (
            "sources_of_truth",
            "sources_of_truth.toml",
            True,
        ),
        (
            "identities",
            "identities.toml",
            False,
        ),
        (
            "retention",
            "retention.toml",
            False,
        ),
    )
    invalid_names: set[str] = set()
    for name, filename, affects_all_reads in checks:
        issue = _doctor_configuration_issue(profile, name=name, filename=filename)
        if issue is None:
            continue
        invalid_names.add(name)
        affected_levels: Sequence[ReadinessLevel] = (
            ReadinessLevel.DRAFT,
            ReadinessLevel.EFFECT,
        )
        if affects_all_reads:
            affected_levels = (ReadinessLevel.READ, *affected_levels)
        raw_levels = payload.get("levels")
        if isinstance(raw_levels, dict):
            for level in affected_levels:
                raw_levels[str(level)] = False
        _append_doctor_issue(payload, issue)
        _apply_doctor_capability_issue(
            payload,
            issue,
            affected_levels=affected_levels,
        )
        if not affects_all_reads:
            _apply_doctor_capability_issue(
                payload,
                issue,
                affected_levels=(ReadinessLevel.READ,),
                capability_names=applied_read_capabilities,
            )
    if not {"policy", "governance"} & invalid_names:
        policy = PolicyConfig.from_toml(
            _resolve_operating_configuration(profile, "policy", "policy.toml")
        )
        governance = GovernanceProfile.from_toml(
            _resolve_operating_configuration(
                profile,
                "governance",
                "governance.toml",
            )
        )
        _apply_doctor_policy_blocks(
            payload,
            _operating_policy_blocked_capabilities(
                profile,
                integrations,
                catalog=catalog,
                policy=policy,
                governance=governance,
                include_provider_gates=integrations_valid,
            ),
        )


def _apply_doctor_integrations_issue(
    payload: dict[str, object],
    issue: OperatingIssue,
    *,
    catalog: CapabilityCatalog,
) -> None:
    """Attach an integrations failure only to selected provider capabilities."""

    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        return
    for raw_capability in raw_capabilities:
        if not isinstance(raw_capability, dict):
            continue
        capability = raw_capability.get("capability")
        if not isinstance(capability, str):
            continue
        definition = catalog.definitions.get(capability)
        if definition is None or definition.authentication in {"local", "local_git"}:
            continue
        raw_issues = raw_capability.get("issues")
        issues = raw_issues if isinstance(raw_issues, list) else []
        issues = [
            raw_issue
            for raw_issue in issues
            if not (
                isinstance(raw_issue, Mapping)
                and raw_issue.get("message")
                == "live capability has no enabled typed connector configuration"
            )
        ]
        capability_issue = OperatingIssue(
            issue.category,
            issue.message,
            capability,
        ).to_dict()
        if capability_issue not in issues:
            issues.append(capability_issue)
        raw_capability["issues"] = issues
        risk = raw_capability.get("risk")
        if risk == str(RiskLevel.READ_ONLY):
            raw_capability[str(ReadinessLevel.READ)] = False
        elif risk == str(RiskLevel.LOCAL_GENERATION):
            raw_capability[str(ReadinessLevel.DRAFT)] = False
        else:
            raw_capability[str(ReadinessLevel.EFFECT)] = False


def _doctor_configuration_issue(
    profile: OrganizationProfile,
    *,
    name: str,
    filename: str,
) -> OperatingIssue | None:
    """Return one stable issue for a selected, offline-only config parser."""

    try:
        source = _resolve_operating_configuration(profile, name, filename)
        if name == "policy":
            PolicyConfig.from_toml(source)
        elif name == "governance":
            governance = GovernanceProfile.from_toml(source)
            if not isinstance(
                governance.metadata.get("allow_ephemeral_direct_reads", False),
                bool,
            ):
                raise ConfigurationError(
                    "allow_ephemeral_direct_reads must be a boolean"
                )
        elif name == "sources_of_truth":
            SourceOfTruthRegistry.from_toml(source)
        elif name == "identities":
            IdentityRegistry.from_toml(source)
        elif name == "retention":
            RetentionConfig.from_toml(source)
        elif name == "approval_authorities":
            _validate_approval_authorities_offline(source)
        else:  # pragma: no cover - fixed internal table.
            raise ConfigurationError(f"unsupported doctor configuration: {name}")
    except OperatingValidationError as error:
        return error.issues[0]
    except (
        ConfigurationError,
        TypeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ) as error:
        return OperatingIssue(
            OperatingFailureCategory.RUNTIME_DEFECT,
            f"organization {name} configuration is invalid: {error}",
        )
    return None


def _validate_approval_authorities_offline(source: ConfigSnapshot) -> None:
    """Validate authority structure with synthetic values, never real secrets."""

    try:
        raw = tomllib.loads(source.payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(
            "approval authority configuration is not valid UTF-8 TOML"
        ) from error
    synthetic: dict[str, str] = {}
    authorities = raw.get("authorities")
    if isinstance(authorities, Mapping):
        for item in authorities.values():
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("secret_env", "")).strip()
            if name:
                synthetic[name] = "offline-validation-secret-" + "x" * 32
    HmacApprovalAuthenticator.from_toml(source, environ=synthetic)


def _append_doctor_issue(
    payload: dict[str, object],
    issue: OperatingIssue,
) -> None:
    raw_issues = payload.get("issues")
    issues = raw_issues if isinstance(raw_issues, list) else []
    serialized = issue.to_dict()
    if serialized not in issues:
        issues.append(serialized)
    payload["issues"] = issues


def _apply_doctor_capability_issue(
    payload: dict[str, object],
    issue: OperatingIssue,
    *,
    affected_levels: Sequence[ReadinessLevel],
    capability_prefix: str | None = None,
    capability_names: frozenset[str] | None = None,
) -> None:
    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        return
    for raw_capability in raw_capabilities:
        if not isinstance(raw_capability, dict):
            continue
        capability = raw_capability.get("capability")
        risk = raw_capability.get("risk")
        for level in affected_levels:
            applies = (
                (level is ReadinessLevel.READ and risk == str(RiskLevel.READ_ONLY))
                or (
                    level is ReadinessLevel.DRAFT
                    and risk == str(RiskLevel.LOCAL_GENERATION)
                )
                or (
                    level is ReadinessLevel.EFFECT
                    and risk
                    not in {
                        None,
                        str(RiskLevel.READ_ONLY),
                        str(RiskLevel.LOCAL_GENERATION),
                    }
                )
            )
            if (
                applies
                and capability_prefix is not None
                and level is ReadinessLevel.READ
                and (
                    not isinstance(capability, str)
                    or not capability.startswith(capability_prefix)
                )
            ):
                applies = False
            if (
                applies
                and capability_names is not None
                and (
                    not isinstance(capability, str)
                    or capability not in capability_names
                )
            ):
                applies = False
            if not applies:
                continue
            raw_capability[str(level)] = False
            raw_issues = raw_capability.get("issues")
            issues = raw_issues if isinstance(raw_issues, list) else []
            capability_issue = OperatingIssue(
                issue.category,
                issue.message,
                capability if isinstance(capability, str) else None,
            ).to_dict()
            if capability_issue not in issues:
                issues.append(capability_issue)
            raw_capability["issues"] = issues


def _recompute_doctor_operational_levels(payload: dict[str, object]) -> None:
    raw_levels = payload.get("levels")
    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_levels, dict) or not isinstance(raw_capabilities, list):
        return
    for level in (ReadinessLevel.READ, ReadinessLevel.DRAFT, ReadinessLevel.EFFECT):
        raw_levels[str(level)] = bool(raw_levels.get(str(level), False)) and any(
            isinstance(item, Mapping) and bool(item.get(str(level), False))
            for item in raw_capabilities
        )


def _apply_doctor_policy_blocks(
    payload: dict[str, object],
    blocked_capabilities: frozenset[str],
) -> None:
    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        return
    for raw_capability in raw_capabilities:
        if not isinstance(raw_capability, dict):
            continue
        capability = raw_capability.get("capability")
        if not isinstance(capability, str) or capability not in blocked_capabilities:
            continue
        issue = OperatingIssue(
            OperatingFailureCategory.BLOCKED_POLICY,
            "capability is disabled by the selected organization policy or provider gate",
            capability,
        )
        risk = raw_capability.get("risk")
        if risk == str(RiskLevel.READ_ONLY):
            levels = (ReadinessLevel.READ,)
        elif risk == str(RiskLevel.LOCAL_GENERATION):
            levels = (ReadinessLevel.DRAFT,)
        else:
            levels = (ReadinessLevel.EFFECT,)
        _apply_doctor_capability_issue(
            payload,
            issue,
            affected_levels=levels,
        )


def _apply_doctor_approval_readiness(
    payload: dict[str, object],
    profile: OrganizationProfile,
    *,
    approval_required_reads: frozenset[str] = frozenset(),
) -> None:
    """Keep approval-gated readiness false without a selected authority."""

    selected = profile.configuration_path("approval_authorities")
    approval_issue = (
        OperatingIssue(
            OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
            "approval-required capability needs selected approval authorities",
        )
        if selected is None
        else _doctor_configuration_issue(
            profile,
            name="approval_authorities",
            filename="approval-authorities.toml",
        )
    )
    if approval_issue is None:
        return
    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        return
    affected_levels: set[ReadinessLevel] = set()
    for raw_capability in raw_capabilities:
        if not isinstance(raw_capability, dict):
            continue
        risk = raw_capability.get("risk")
        if risk is None or risk == str(RiskLevel.LOCAL_GENERATION):
            continue
        if risk == str(RiskLevel.READ_ONLY):
            capability = raw_capability.get("capability")
            if (
                not isinstance(capability, str)
                or capability not in approval_required_reads
            ):
                continue
        level = (
            ReadinessLevel.READ
            if risk == str(RiskLevel.READ_ONLY)
            else ReadinessLevel.EFFECT
        )
        affected_levels.add(level)
        raw_capability[str(level)] = False
        raw_issues = raw_capability.get("issues")
        issues = raw_issues if isinstance(raw_issues, list) else []
        issues.append(
            OperatingIssue(
                approval_issue.category,
                approval_issue.message,
                (
                    str(raw_capability["capability"])
                    if isinstance(raw_capability.get("capability"), str)
                    else None
                ),
            ).to_dict()
        )
        raw_capability["issues"] = issues
    if affected_levels:
        _append_doctor_issue(payload, approval_issue)


def _load_active_organization_profile(path: Path) -> OrganizationProfile:
    profile, _snapshot = _capture_active_organization_profile(path)
    return profile


def _capture_active_organization_profile(
    path: Path,
) -> tuple[OrganizationProfile, ConfigSnapshot]:
    """Capture and parse one active profile from the same immutable bytes."""

    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if not os.path.lexists(selected):
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                    "organization profile is not installed; run master-agent setup",
                ),
            )
        )
    try:
        source = resolve_config_source(selected, "organization-profile.toml")
    except ConfigurationError as error:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    f"organization profile could not be loaded safely: {error}",
                ),
            )
        ) from error
    return load_organization_profile(source), source


def _operating_catalog_and_integrations(
    profile: OrganizationProfile,
) -> tuple[CapabilityCatalog, IntegrationConfig]:
    catalog = _operating_catalog(profile)
    try:
        integration_source = _resolve_operating_configuration(
            profile,
            "integrations",
            "integrations.toml",
        )
        return catalog, IntegrationConfig.from_toml(integration_source)
    except OperatingValidationError:
        raise
    except (ConfigurationError, TypeError, ValueError) as error:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    f"organization configuration is invalid: {error}",
                ),
            )
        ) from error


def _plan_requires_provider_integrations(
    plan: ChangePlan,
    catalog: CapabilityCatalog,
) -> bool:
    """Return whether any selected action needs a provider connector bundle."""

    return any(
        definition is not None
        and definition.authentication not in {"local", "local_git"}
        for action in plan.actions
        for definition in (catalog.definitions.get(action.capability),)
    )


def _empty_operating_integrations_source() -> ConfigSnapshot:
    """Return the approval-bound no-provider bundle for local-only work."""

    return ConfigSnapshot(
        display_path=Path("<local-only-integrations>"),
        payload=b"",
    )


def _operating_plan_catalog_and_integrations(
    profile: OrganizationProfile,
    plan: ChangePlan,
) -> tuple[CapabilityCatalog, IntegrationConfig]:
    """Load only the integration configuration needed by this exact plan."""

    catalog = _operating_catalog(profile)
    if not _plan_requires_provider_integrations(plan, catalog):
        return catalog, IntegrationConfig.from_toml(
            _empty_operating_integrations_source()
        )
    _catalog, integrations = _operating_catalog_and_integrations(profile)
    return catalog, integrations


def _operating_catalog(profile: OrganizationProfile) -> CapabilityCatalog:
    """Load the mandatory capability catalog with a stable failure category."""

    try:
        source = _resolve_operating_configuration(
            profile,
            "capabilities",
            "capabilities.toml",
        )
        return CapabilityCatalog.from_toml(source)
    except OperatingValidationError:
        raise
    except (ConfigurationError, TypeError, ValueError) as error:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    f"organization capabilities configuration is invalid: {error}",
                ),
            )
        ) from error


def _doctor_integrations(
    profile: OrganizationProfile,
) -> tuple[IntegrationConfig, OperatingIssue | None]:
    """Load optional provider setup without hiding local readiness."""

    try:
        source = _resolve_operating_configuration(
            profile,
            "integrations",
            "integrations.toml",
        )
        return IntegrationConfig.from_toml(source), None
    except OperatingValidationError as error:
        return IntegrationConfig({}), error.issues[0]
    except (ConfigurationError, TypeError, ValueError) as error:
        return IntegrationConfig({}), OperatingIssue(
            OperatingFailureCategory.RUNTIME_DEFECT,
            f"organization integrations configuration is invalid: {error}",
        )


def _doctor_governance(profile: OrganizationProfile) -> GovernanceProfile | None:
    """Return valid offline governance for route-specific readiness."""

    try:
        source = _resolve_operating_configuration(
            profile,
            "governance",
            "governance.toml",
        )
        governance = GovernanceProfile.from_toml(source)
        configured = governance.metadata.get("allow_ephemeral_direct_reads", False)
        if not isinstance(configured, bool):
            return None
        return governance
    except (OperatingValidationError, ConfigurationError, TypeError, ValueError):
        return None


def _doctor_policy(profile: OrganizationProfile) -> PolicyConfig | None:
    """Return valid offline policy for route-specific readiness."""

    try:
        source = _resolve_operating_configuration(profile, "policy", "policy.toml")
        return PolicyConfig.from_toml(source)
    except (OperatingValidationError, ConfigurationError, TypeError, ValueError):
        return None


def _doctor_approval_required_read_capabilities(
    profile: OrganizationProfile,
    *,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile | None,
    policy: PolicyConfig | None,
) -> frozenset[str]:
    """Return selected reads whose exact policy route requires approval."""

    if governance is None or policy is None:
        return frozenset()
    selected_reads = frozenset(
        capability
        for capability in profile.capabilities
        if (definition := catalog.definitions.get(capability)) is not None
        and definition.risk is RiskLevel.READ_ONLY
    )
    if (
        RiskLevel.READ_ONLY in policy.require_approval_risks
        or RiskLevel.READ_ONLY not in policy.auto_permit_risks
    ):
        return selected_reads
    required: set[str] = set()
    for capability in profile.capabilities:
        definition = catalog.definitions.get(capability)
        if definition is None or definition.risk is not RiskLevel.READ_ONLY:
            continue
        rule = governance.rule_for(capability)
        if rule is not None and rule.approval_tier in {
            ApprovalTier.SINGLE,
            ApprovalTier.DUAL,
        }:
            required.add(capability)
    return frozenset(required)


def _doctor_readiness_catalog(
    catalog: CapabilityCatalog,
    *,
    applied_read_capabilities: frozenset[str],
) -> CapabilityCatalog:
    """Require configured authentication when reads use the applied runtime."""

    if not applied_read_capabilities:
        return catalog
    return CapabilityCatalog(
        {
            capability: (
                replace(definition, authentication="configured_connector")
                if capability in applied_read_capabilities
                and definition.risk is RiskLevel.READ_ONLY
                and definition.authentication == "anonymous_or_configured_connector"
                else definition
            )
            for capability, definition in catalog.definitions.items()
        }
    )


def _capture_operating_execution_sources(
    profile: OrganizationProfile,
    profile_source: ConfigSnapshot,
    *,
    plan: ChangePlan,
    applied: bool,
) -> dict[str, ConfigSnapshot]:
    """Capture and parse every configuration needed before run allocation."""

    names = [
        ("capabilities", "capabilities.toml"),
        ("policy", "policy.toml"),
        ("governance", "governance.toml"),
        ("sources_of_truth", "sources_of_truth.toml"),
    ]
    if applied:
        names.extend(
            (
                ("identities", "identities.toml"),
                ("retention", "retention.toml"),
            )
        )
    sources = {
        name: _resolve_operating_configuration(profile, name, filename)
        for name, filename in names
    }
    catalog = CapabilityCatalog.from_toml(sources["capabilities"])
    provider_integrations_required = _plan_requires_provider_integrations(plan, catalog)
    sources["integrations"] = (
        _resolve_operating_configuration(
            profile,
            "integrations",
            "integrations.toml",
        )
        if provider_integrations_required
        else _empty_operating_integrations_source()
    )
    sources["organization_profile"] = profile_source
    sources["organization_profile_path"] = _organization_profile_path_snapshot(
        profile.source_path
    )
    try:
        IntegrationConfig.from_toml(sources["integrations"])
        PolicyConfig.from_toml(sources["policy"])
        GovernanceProfile.from_toml(sources["governance"])
        SourceOfTruthRegistry.from_toml(sources["sources_of_truth"])
        if applied:
            IdentityRegistry.from_toml(sources["identities"])
            RetentionConfig.from_toml(sources["retention"])
    except (ConfigurationError, ValueError, tomllib.TOMLDecodeError) as error:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    f"organization execution configuration is invalid: {error}",
                ),
            )
        ) from error
    return sources


def _operating_runtime_capabilities(
    profile: OrganizationProfile,
    integrations: IntegrationConfig,
) -> frozenset[str]:
    """Return built-in code whose optional runtime dependencies are installed."""

    del profile, integrations
    return installed_builtin_capabilities()


def _operating_policy_blocked_capabilities(
    profile: OrganizationProfile,
    integrations: IntegrationConfig,
    *,
    catalog: CapabilityCatalog | None = None,
    policy: PolicyConfig | None = None,
    governance: GovernanceProfile | None = None,
    include_provider_gates: bool = True,
) -> frozenset[str]:
    """Return installed routes disabled by the selected factory configuration."""

    installed = installed_builtin_capabilities()
    blocked: set[str] = set()
    if include_provider_gates:
        configured = configured_builtin_capabilities(
            integrations,
            connector_mode=str(profile.connector_mode),
            include_writes=profile.writes_enabled,
            include_communications=profile.communications_enabled,
        )
        blocked.update(
            capability
            for capability in profile.capabilities
            if capability in installed and capability not in configured
        )
    if catalog is not None and policy is not None and governance is not None:
        for capability in profile.capabilities:
            definition = catalog.definitions.get(capability)
            if definition is None:
                continue
            rule = governance.rule_for(capability)
            if (
                definition.risk in policy.prohibit_risks
                or any(
                    fnmatch(capability, pattern)
                    for pattern in policy.prohibited_capabilities
                )
                or rule is None
                or not rule.enabled
                or governance.environment not in rule.environments
                or not rule.data_classifications
                or rule.approval_tier is ApprovalTier.PROHIBITED
                or (
                    rule.approval_tier is ApprovalTier.AUTOMATIC
                    and definition.risk
                    not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
                )
            ):
                blocked.add(capability)
    return frozenset(blocked)


def _resolve_operating_configuration(
    profile: OrganizationProfile,
    name: str,
    default_filename: str,
) -> ConfigSnapshot:
    """Resolve one profile-selected configuration with a stable category."""

    selected = profile.configuration_path(name)
    try:
        return resolve_config_source(
            selected,
            default_filename,
            organization_trust=profile.configuration_trust_policy(name),
        )
    except ConfigurationError as error:
        category = (
            OperatingFailureCategory.MISSING_ORGANIZATION_SETUP
            if selected is not None and "not found" in str(error)
            else OperatingFailureCategory.RUNTIME_DEFECT
        )
        raise OperatingValidationError(
            (
                OperatingIssue(
                    category,
                    f"organization {name} configuration is unavailable: {error}",
                ),
            )
        ) from error


def _eligible_direct_operating_read(
    plan: ChangePlan,
    *,
    profile: OrganizationProfile,
) -> bool:
    if profile.connector_mode is not ConnectorMode.LIVE:
        return False
    if plan.execution_context is not None or plan.workflow_id is not None:
        return False
    if plan.workflow_fingerprint is not None or plan.compensate_on_failure:
        return False
    systems = {action.target.system for action in plan.actions}
    if len(systems) != 1 or not systems <= set(_CONNECT_CONFIGURATION_BY_SYSTEM):
        return False
    return all(
        action.risk is RiskLevel.READ_ONLY
        and action.authority_source is AuthoritySource.DIRECT_USER
        and not action.requires_approval
        for action in plan.actions
    )


def _require_organization_selection(
    plan: ChangePlan,
    *,
    organization_profile_path: Path,
    expected_profile_fingerprint: str | None = None,
    connector_mode: str,
    include_writes: bool,
    include_communications: bool,
    integrations_path: Path | None,
    approval_authorities: Path | None,
    retention_path: Path | None,
    identities_path: Path | None,
    policy_path: Path | None,
    sources_of_truth_path: Path | None,
    capabilities_path: Path | None,
    governance_path: Path | None,
    allow_bound_plan: bool,
    captured_configuration_sources: Mapping[str, ConfigSnapshot] | None = None,
) -> tuple[OrganizationProfile, ConfigSnapshot]:
    """Revalidate the current profile and every selected normal input."""

    profile, snapshot = _capture_active_organization_profile(organization_profile_path)
    if (
        expected_profile_fingerprint is not None
        and profile.fingerprint != expected_profile_fingerprint
    ):
        _raise_profile_selection_error("profile fingerprint")
    if connector_mode != str(profile.connector_mode):
        _raise_profile_selection_error("connector mode")
    if include_writes != profile.writes_enabled:
        _raise_profile_selection_error("write gate")
    if include_communications != profile.communications_enabled:
        _raise_profile_selection_error("communication gate")
    observed = {
        "approval_authorities": approval_authorities,
        "capabilities": capabilities_path,
        "governance": governance_path,
        "identities": identities_path,
        "integrations": integrations_path,
        "policy": policy_path,
        "retention": retention_path,
        "sources_of_truth": sources_of_truth_path,
    }
    for name, selected in observed.items():
        if (
            captured_configuration_sources is not None
            and name not in captured_configuration_sources
        ):
            continue
        expected = profile.configuration_path(name)
        if _normalized_optional_path(selected) != _normalized_optional_path(expected):
            _raise_profile_selection_error(f"{name} configuration")
    candidate = (
        replace(plan, execution_context=None)
        if allow_bound_plan and plan.execution_context is not None
        else plan
    )
    if captured_configuration_sources is None:
        catalog, integrations = _operating_plan_catalog_and_integrations(
            profile,
            candidate,
        )
    else:
        catalog = CapabilityCatalog.from_toml(
            captured_configuration_sources["capabilities"]
        )
        integrations = IntegrationConfig.from_toml(
            captured_configuration_sources["integrations"]
        )
    policy_source = (
        captured_configuration_sources["policy"]
        if captured_configuration_sources is not None
        else _resolve_operating_configuration(profile, "policy", "policy.toml")
    )
    governance_source = (
        captured_configuration_sources["governance"]
        if captured_configuration_sources is not None
        else _resolve_operating_configuration(
            profile,
            "governance",
            "governance.toml",
        )
    )
    operating_policy = PolicyConfig.from_toml(policy_source)
    operating_governance = GovernanceProfile.from_toml(governance_source)
    require_operating_plan(
        candidate,
        profile=profile,
        catalog=catalog,
        integrations=integrations,
        environ=os.environ,
        runtime_capabilities=_operating_runtime_capabilities(profile, integrations),
        policy_blocked_capabilities=_operating_policy_blocked_capabilities(
            profile,
            integrations,
            catalog=catalog,
            policy=operating_policy,
            governance=operating_governance,
        ),
    )
    return profile, snapshot


def _normalized_optional_path(path: Path | None) -> Path | None:
    if path is None:
        return None
    return path.expanduser().resolve(strict=False)


def _raise_profile_selection_error(name: str) -> None:
    raise OperatingValidationError(
        (
            OperatingIssue(
                OperatingFailureCategory.BLOCKED_POLICY,
                f"{name} differs from the active organization profile",
            ),
        )
    )


def _require_plan_fingerprint(
    plan: ChangePlan,
    expected_fingerprint: str | None,
) -> None:
    if expected_fingerprint is not None and plan.fingerprint != expected_fingerprint:
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.BLOCKED_POLICY,
                    "plan differs from the profile-admitted immutable snapshot",
                ),
            )
        )


def _require_operating_run_paths(
    *,
    profile: OrganizationProfile,
    run_root: Path,
    plan_path: Path,
    bound_plan_path: Path | None,
    database: Path,
    result_json: Path | None,
    workspace_root: Path | None,
    draft_output_dir: Path,
) -> None:
    """Require every high-level persistent path to remain in one profile run."""

    expected = {
        "run root": profile.state_root / "runs" / run_root.name,
        "plan": run_root / "plan.json",
        "audit database": run_root / "state" / "audit.sqlite3",
        "artifact root": run_root / "artifacts",
        "result": run_root / "results" / "result.json",
        "workspace": run_root / "workspace",
    }
    observed: dict[str, Path | None] = {
        "run root": run_root,
        "plan": plan_path,
        "audit database": database,
        "artifact root": draft_output_dir,
        "result": result_json,
        "workspace": workspace_root,
    }
    if bound_plan_path is not None:
        expected["bound plan"] = run_root / "bound-plan.json"
        observed["bound plan"] = bound_plan_path
    for name, expected_path in expected.items():
        actual = observed[name]
        if actual is None or actual != expected_path:
            _raise_profile_selection_error(f"{name} path")


def _sample_plan(output: Path) -> int:
    plan = build_weekly_status_plan()
    _write_json(output, plan.to_dict())
    print(f"wrote {_terminal_field(output)}")
    print(f"plan fingerprint: {plan.fingerprint}")
    return 0


def _inspect(path: Path) -> int:
    plan = _load_plan(path)
    print(f"goal: {plan.goal}")
    print(f"plan ID: {plan.plan_id}")
    print(f"fingerprint: {plan.fingerprint}")
    if plan.execution_context is None:
        print("execution context: unbound")
    else:
        print("execution context:")
        print(json.dumps(plan.execution_context.to_dict(), indent=2, ensure_ascii=True))
    print("actions:")
    for action in plan.actions:
        dependencies = ",".join(str(item) for item in action.dependencies) or "-"
        print(
            f"  {action.action_id}  {action.risk:<24} "
            f"{action.capability:<38} {action.target.uri} deps={dependencies}"
        )
        print(json.dumps(action.to_dict(), indent=4, ensure_ascii=True))
    return 0


def _bind_context(
    *,
    plan_path: Path,
    integrations_path: Path | None,
    plugin_names: list[str],
    plugin_lock_path: Path | None,
    connector_mode: str,
    approval_authorities: Path | None,
    database: Path,
    result_json: Path | None,
    retention_path: Path | None,
    evidence_type: str,
    identities_path: Path | None,
    include_writes: bool,
    include_communications: bool,
    workspace_root: Path | None,
    draft_output_dir: Path,
    policy_path: Path | None,
    sources_of_truth_path: Path | None,
    capabilities_path: Path | None,
    governance_path: Path | None,
    credentials_file: Path | None,
    output: Path,
    credential_mappings: Sequence[str] = (),
    connector_urls: Sequence[str] = (),
    organization_profile_path: Path | None = None,
    expected_plan_fingerprint: str | None = None,
    expected_profile_fingerprint: str | None = None,
    organization_run_root: Path | None = None,
    captured_configuration_sources: Mapping[str, ConfigSnapshot] | None = None,
) -> int:
    """Write a plan whose fingerprint covers the complete applied runtime."""

    require_persistent_state_platform()
    plan = (
        _load_operating_plan(plan_path)
        if organization_profile_path is not None
        else _load_plan(plan_path)
    )
    _require_plan_fingerprint(plan, expected_plan_fingerprint)
    organization_profile_source: ConfigSnapshot | None = None
    if organization_profile_path is not None:
        profile, organization_profile_source = _require_organization_selection(
            plan,
            organization_profile_path=organization_profile_path,
            expected_profile_fingerprint=expected_profile_fingerprint,
            connector_mode=connector_mode,
            include_writes=include_writes,
            include_communications=include_communications,
            integrations_path=integrations_path,
            approval_authorities=approval_authorities,
            retention_path=retention_path,
            identities_path=identities_path,
            policy_path=policy_path,
            sources_of_truth_path=sources_of_truth_path,
            capabilities_path=capabilities_path,
            governance_path=governance_path,
            allow_bound_plan=False,
            captured_configuration_sources=captured_configuration_sources,
        )
        if organization_run_root is not None:
            _require_operating_run_paths(
                profile=profile,
                run_root=organization_run_root,
                plan_path=plan_path,
                bound_plan_path=output,
                database=database,
                result_json=result_json,
                workspace_root=workspace_root,
                draft_output_dir=draft_output_dir,
            )
    integrations_source = (
        captured_configuration_sources["integrations"]
        if captured_configuration_sources is not None
        else resolve_config_source(integrations_path, "integrations.toml")
    )
    integrations = IntegrationConfig.from_toml(integrations_source)
    configuration_sources = _execution_configuration_sources(
        approval_authorities=approval_authorities,
        retention_path=retention_path,
        identities_path=identities_path,
        policy_path=policy_path,
        sources_of_truth_path=sources_of_truth_path,
        capabilities_path=capabilities_path,
        governance_path=governance_path,
        organization_profile_path=organization_profile_path,
        organization_profile_source=organization_profile_source,
        captured_sources=captured_configuration_sources,
    )
    governance = GovernanceProfile.from_toml(configuration_sources["governance"])
    capability_catalog = CapabilityCatalog.from_toml(
        configuration_sources["capabilities"]
    )
    _preflight_applied_provider_reads(
        plan=plan,
        catalog=capability_catalog,
        governance=governance,
        enforce_non_provider=connector_mode == "live",
    )
    live_systems = _live_systems_for_plan(
        plan,
        integrations,
        catalog=capability_catalog,
    )
    configurations = _configuration_names_for_systems(live_systems)
    integrations = _with_connector_url_overrides(
        integrations,
        connector_urls,
        selected_configurations=configurations,
    )
    if approval_authorities is None and _plan_requires_authenticated_approval(
        plan,
        policy_source=configuration_sources["policy"],
        governance=governance,
    ):
        raise ConfigurationError(
            "approval-required plans must bind --approval-authorities before "
            "the approval handoff can be prepared"
        )
    credential_store = _load_credential_store(
        credentials_file,
        integrations=integrations,
        governance=governance,
        connector_mode=connector_mode,
        credential_mappings=credential_mappings,
        systems=live_systems,
    )
    execution_environ = _credential_environment(
        credential_store,
        os.environ,
        declared_names=integrations.credential_environment_variables(),
        compatible_names=_atlassian_credential_compatibility(
            integrations,
            configurations=configurations,
        ),
    )
    plugin_lock = _load_plugin_lock(plugin_names, plugin_lock_path)
    descriptors = (
        resolve_locked_plugin_descriptors(
            enabled_names=plugin_names,
            trusted_lock=plugin_lock,
        )
        if plugin_lock is not None
        else ()
    )
    context = build_execution_context(
        integrations,
        environ=execution_environ,
        systems=live_systems,
        plugin_descriptors=descriptors,
        runtime=build_runtime_execution_binding(
            integrations,
            connector_mode=connector_mode,
            include_writes=include_writes,
            include_communications=include_communications,
            audit_database=database,
            artifact_root=draft_output_dir,
            workspace_root=workspace_root,
            result_json=result_json,
            evidence_type=evidence_type,
            configuration_sources=configuration_sources,
            credential_file=(credential_store.path if credential_store else None),
            environ=execution_environ,
        ),
        include_connectors=connector_mode == "live",
    )
    bound = replace(plan, execution_context=context)
    _write_json(output, bound.to_dict())
    print(f"wrote {output}")
    print(f"execution context fingerprint: {context.fingerprint}")
    print(f"plan fingerprint: {bound.fingerprint}")
    return 0


def _approve(
    *,
    plan_path: Path,
    actions: str,
    key_id: str,
    expected_fingerprint: str,
    approval_authorities: Path,
    output: Path,
    ttl_minutes: int,
) -> int:
    require_persistent_state_platform()
    if ttl_minutes <= 0:
        raise ValueError("ttl-minutes must be positive")
    plan = _load_plan(plan_path)
    if expected_fingerprint != plan.fingerprint:
        raise ValueError(
            "plan fingerprint does not match --expected-fingerprint; inspect "
            "the current file before approving"
        )
    requested = tuple(UUID(item.strip()) for item in actions.split(",") if item.strip())
    unknown = set(requested) - {action.action_id for action in plan.actions}
    if unknown:
        raise ValueError(f"approval references unknown action IDs: {unknown}")
    issued_at = datetime.now(UTC)
    authenticator = HmacApprovalAuthenticator.from_toml(
        resolve_config_source(
            approval_authorities,
            "approval-authorities.toml",
        ),
        environ=os.environ,
    )
    approval = authenticator.issue(
        plan=plan,
        approved_action_ids=requested,
        key_id=key_id,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=ttl_minutes),
    )
    _write_json(output, approval.to_dict())
    print(f"wrote {output}")
    print(f"approval ID: {approval.approval_id}")
    print(f"expires: {approval.expires_at.isoformat()}")
    return 0


def _inspect_approval_request(path: Path) -> int:
    """Render the complete secret-free review surface for one handoff."""

    request = load_approval_request(path)
    if request.run.recurring_occurrence is not None:
        occurrence = load_occurrence(Path(request.run.recurring_occurrence))
        if occurrence.fingerprint != request.run.recurring_fingerprint:
            raise ValidationError("approval request recurring fingerprint changed")
        plan = occurrence.plan
    else:
        plan = _load_plan(Path(request.run.plan_path))
    request.validate_plan(plan)
    print(f"goal: {request.goal}")
    print(f"plan fingerprint: {request.plan_fingerprint}")
    print(f"request fingerprint: {request.fingerprint}")
    print("execution context:")
    print(json.dumps(request.execution_context.to_dict(), indent=2, ensure_ascii=True))
    print("captured non-secret run:")
    print(json.dumps(request.run.to_dict(), indent=2, ensure_ascii=True))
    print("pending approval actions:")
    for item in request.required_approvals:
        print(f"  {item.action.action_id}  {_terminal_field(item.reason)}")
        print(json.dumps(item.action.to_dict(), indent=4, ensure_ascii=True))
    print(
        "This request is not approval. A trusted operator must use "
        "approve-request with the fingerprint shown above."
    )
    return 0


def _approve_request(
    *,
    request_path: Path,
    key_id: str,
    expected_fingerprint: str,
    output: Path,
    ttl_minutes: int,
) -> int:
    """Sign the pending actions in an already-inspected private handoff."""

    require_persistent_state_platform()
    if ttl_minutes <= 0:
        raise ValueError("ttl-minutes must be positive")
    request = load_approval_request(request_path)
    if expected_fingerprint != request.fingerprint:
        raise ValueError(
            "approval request fingerprint does not match --expected-fingerprint; "
            "inspect the current request before approving"
        )
    if request.run.recurring_occurrence is not None:
        occurrence = load_occurrence(Path(request.run.recurring_occurrence))
        if occurrence.fingerprint != request.run.recurring_fingerprint:
            raise ValidationError("approval request recurring fingerprint changed")
        plan = occurrence.plan
    else:
        plan = _load_plan(Path(request.run.plan_path))
    request.validate_plan(plan)
    authority_path = Path(request.run.approval_authorities)
    authority_source = resolve_config_source(
        authority_path,
        "approval-authorities.toml",
    )
    runtime = request.execution_context.runtime
    if runtime is None:  # pragma: no cover - ApprovalRequest invariant.
        raise ValidationError("approval request is missing its bound runtime")
    expected_digest = next(
        (
            item.sha256
            for item in runtime.configurations
            if item.name == "approval_authorities"
        ),
        None,
    )
    with authority_source.open("rb") as handle:
        observed_digest = hashlib.sha256(handle.read()).hexdigest()
    if expected_digest != observed_digest:
        raise ConfigurationError(
            "approval-authorities configuration differs from the bound plan"
        )
    authenticator = HmacApprovalAuthenticator.from_toml_for_key(
        authority_source,
        key_id=key_id,
        environ=os.environ,
    )
    issued_at = datetime.now(UTC)
    approval = authenticator.issue(
        plan=plan,
        approved_action_ids=request.action_ids,
        key_id=key_id,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=ttl_minutes),
    )
    write_restricted_json(output, approval.to_dict())
    print(f"wrote {output}")
    print(f"approval ID: {approval.approval_id}")
    print(f"plan fingerprint: {approval.plan_fingerprint}")
    print(f"expires: {approval.expires_at.isoformat()}")
    return 0


def _resume_approval(
    *,
    request_path: Path,
    expected_fingerprint: str,
    approval_paths: Sequence[Path],
    high_level: bool = False,
    expected_profile_fingerprint: str | None = None,
) -> int:
    """Retry the exact captured invocation with supplied approval artifacts."""

    require_persistent_state_platform()
    request = load_approval_request(request_path)
    if expected_fingerprint != request.fingerprint:
        raise ValueError(
            "approval request fingerprint does not match --expected-fingerprint; "
            "inspect the current request before resuming"
        )
    if request.run.recurring_occurrence is not None:
        if high_level:
            raise ValidationError(
                "recurring approval resume cannot use the high-level profile path"
            )
        if request.run.recurring_config is None:
            raise ValidationError("recurring approval request omitted its config")
        occurrence = load_occurrence(Path(request.run.recurring_occurrence))
        if occurrence.fingerprint != request.run.recurring_fingerprint:
            raise ValidationError("approval request recurring fingerprint changed")
        request.validate_plan(occurrence.plan)
        carried = tuple(Path(path) for path in request.run.approval_paths) + tuple(
            approval_paths
        )
        return _recurring_apply(
            artifact_path=Path(request.run.recurring_occurrence),
            recurring_path=Path(request.run.recurring_config),
            apply=True,
            approval_paths=carried,
            expected_fingerprint=occurrence.fingerprint,
            approval_request=request,
        )
    plan = (
        _load_operating_plan(Path(request.run.plan_path))
        if high_level
        else _load_plan(Path(request.run.plan_path))
    )
    request.validate_plan(plan)
    invocation = request.run.with_approvals(approval_paths)
    return _run(
        plan_path=Path(invocation.plan_path),
        apply=True,
        approval_paths=[Path(path) for path in invocation.approval_paths],
        approval_authorities=Path(invocation.approval_authorities),
        database=Path(invocation.database),
        connector_mode=invocation.connector_mode,
        integrations_path=_optional_path(invocation.integrations),
        result_json=_optional_path(invocation.result_json),
        retention_path=_optional_path(invocation.retention),
        evidence_type=invocation.evidence_type,
        identities_path=_optional_path(invocation.identities),
        include_writes=invocation.include_writes,
        include_communications=invocation.include_communications,
        workspace_root=_optional_path(invocation.workspace_root),
        draft_output_dir=Path(invocation.draft_output_dir),
        capabilities_path=_optional_path(invocation.capabilities),
        governance_path=_optional_path(invocation.governance),
        policy_path=_optional_path(invocation.policy),
        sources_of_truth_path=_optional_path(invocation.sources_of_truth),
        plugin_names=list(invocation.plugin_names),
        plugin_lock_path=_optional_path(invocation.plugin_lock),
        credentials_file=_optional_path(invocation.credentials_file),
        credential_mappings=invocation.credential_mappings,
        connector_urls=invocation.connector_urls,
        organization_profile_path=_optional_path(invocation.organization_profile),
        high_level=high_level,
        expected_plan_fingerprint=plan.fingerprint,
        expected_profile_fingerprint=expected_profile_fingerprint,
        organization_run_root=(
            Path(invocation.database).parent.parent if high_level else None
        ),
    )


def _run(
    *,
    plan_path: Path,
    apply: bool,
    direct_read: bool = False,
    approval_paths: list[Path],
    approval_authorities: Path | None,
    database: Path,
    connector_mode: str,
    integrations_path: Path | None,
    result_json: Path | None,
    retention_path: Path | None,
    evidence_type: str,
    identities_path: Path | None,
    include_writes: bool,
    include_communications: bool,
    workspace_root: Path | None,
    draft_output_dir: Path,
    capabilities_path: Path | None,
    governance_path: Path | None,
    policy_path: Path | None,
    sources_of_truth_path: Path | None,
    plugin_names: list[str],
    plugin_lock_path: Path | None,
    credentials_file: Path | None,
    credential_mappings: Sequence[str] = (),
    connector_urls: Sequence[str] = (),
    organization_profile_path: Path | None = None,
    high_level: bool = False,
    loaded_plan: ChangePlan | None = None,
    expected_plan_fingerprint: str | None = None,
    expected_profile_fingerprint: str | None = None,
    organization_run_root: Path | None = None,
    captured_configuration_sources: Mapping[str, ConfigSnapshot] | None = None,
    pre_effect_guard: Callable[[AgentAction], None] | None = None,
    report_observer: Callable[[RunReport, ApprovalRequest | None], None] | None = None,
    recurring_occurrence_path: Path | None = None,
    recurring_fingerprint: str | None = None,
    recurring_claim_generation: int | None = None,
    recurring_config_path: Path | None = None,
) -> int:
    """Evaluate or execute an immutable plan through explicitly selected layers."""

    if direct_read:
        return _run_direct_read(
            plan_path=plan_path,
            apply=apply,
            approval_paths=approval_paths,
            approval_authorities=approval_authorities,
            database=database,
            integrations_path=integrations_path,
            result_json=result_json,
            retention_path=retention_path,
            evidence_type=evidence_type,
            identities_path=identities_path,
            include_writes=include_writes,
            include_communications=include_communications,
            workspace_root=workspace_root,
            draft_output_dir=draft_output_dir,
            capabilities_path=capabilities_path,
            governance_path=governance_path,
            policy_path=policy_path,
            sources_of_truth_path=sources_of_truth_path,
            plugin_names=plugin_names,
            plugin_lock_path=plugin_lock_path,
            credentials_file=credentials_file,
            credential_mappings=credential_mappings,
            connector_urls=connector_urls,
            organization_profile_path=organization_profile_path,
            loaded_plan=loaded_plan,
            expected_plan_fingerprint=expected_plan_fingerprint,
            expected_profile_fingerprint=expected_profile_fingerprint,
            captured_configuration_sources=captured_configuration_sources,
        )

    require_persistent_state_platform()
    if apply and plugin_names:
        raise ConfigurationError(
            "in-process connector plugin execution is disabled pending an "
            "isolated worker with a locked dependency closure"
        )
    if apply and plugin_lock_path is not None:
        raise ValueError("--plugin-lock requires at least one --plugin")
    if not apply and result_json is not None:
        raise ValueError(
            "--result-json requires --apply and an approval-bound runtime manifest"
        )
    if not apply and credentials_file is not None:
        raise ValueError("--credentials-file requires --apply")
    if not apply and credential_mappings:
        raise ValueError("--credential-map requires --apply and --credentials-file")
    if not apply and connector_urls:
        raise ValueError("--connector-url requires --apply")
    plan = (
        loaded_plan
        if loaded_plan is not None
        else (_load_operating_plan(plan_path) if high_level else _load_plan(plan_path))
    )
    _require_plan_fingerprint(plan, expected_plan_fingerprint)
    organization_profile_source: ConfigSnapshot | None = None
    if organization_profile_path is not None:
        profile, organization_profile_source = _require_organization_selection(
            plan,
            organization_profile_path=organization_profile_path,
            expected_profile_fingerprint=expected_profile_fingerprint,
            connector_mode=connector_mode,
            include_writes=include_writes,
            include_communications=include_communications,
            integrations_path=integrations_path,
            approval_authorities=approval_authorities,
            retention_path=retention_path,
            identities_path=identities_path,
            policy_path=policy_path,
            sources_of_truth_path=sources_of_truth_path,
            capabilities_path=capabilities_path,
            governance_path=governance_path,
            allow_bound_plan=apply,
            captured_configuration_sources=captured_configuration_sources,
        )
        if organization_run_root is not None:
            _require_operating_run_paths(
                profile=profile,
                run_root=organization_run_root,
                plan_path=organization_run_root / "plan.json",
                bound_plan_path=plan_path,
                database=database,
                result_json=result_json,
                workspace_root=workspace_root,
                draft_output_dir=draft_output_dir,
            )
    approval_loader = _load_operating_approval if high_level else _load_approval
    approvals = tuple(approval_loader(path) for path in approval_paths)
    if approvals and approval_authorities is None:
        raise ValueError(
            "--approval-authorities is required when approval artifacts are supplied"
        )
    configuration_sources = _execution_configuration_sources(
        approval_authorities=approval_authorities,
        retention_path=retention_path,
        identities_path=identities_path,
        policy_path=policy_path,
        sources_of_truth_path=sources_of_truth_path,
        capabilities_path=capabilities_path,
        governance_path=governance_path,
        organization_profile_path=organization_profile_path,
        organization_profile_source=organization_profile_source,
        captured_sources=captured_configuration_sources,
    )
    capability_catalog = CapabilityCatalog.from_toml(
        configuration_sources["capabilities"]
    )
    approval_authenticator: HmacApprovalAuthenticator | None = None
    if not apply:
        # A policy-only dry run must not resolve credentials or construct live
        # clients. This makes plan review safe on unconfigured machines.
        connectors = ConnectorRegistry()
        if approval_authorities is not None and approvals:
            approval_authenticator = HmacApprovalAuthenticator.from_toml(
                configuration_sources["approval_authorities"],
                environ=os.environ,
            )
        # Policy preview is intentionally non-persistent. This prevents an
        # unbound review command from selecting an arbitrary audit/evidence
        # destination while preserving credential-free plan inspection.
        with tempfile.TemporaryDirectory(prefix="master-agent-dry-run-") as directory:
            ephemeral_audit = AuditLog(Path(directory) / "audit.sqlite3")
            try:
                report = _orchestrator(
                    connectors,
                    Path(directory) / "audit.sqlite3",
                    capabilities_path=capabilities_path,
                    governance_path=governance_path,
                    policy_source=configuration_sources["policy"],
                    sources_of_truth_source=configuration_sources["sources_of_truth"],
                    capabilities_source=configuration_sources["capabilities"],
                    capabilities=capability_catalog,
                    governance_source=configuration_sources["governance"],
                    approval_authenticator=approval_authenticator,
                    audit=ephemeral_audit,
                ).run(
                    plan,
                    approvals=approvals,
                    dry_run=True,
                )
            finally:
                ephemeral_audit.close()
        _print_report(report)
        return 0 if report.successful else 2

    with ExitStack() as runtime_resources:
        integrations_source = _execution_integrations_source(
            plan=plan,
            catalog=capability_catalog,
            integrations_path=integrations_path,
            high_level=high_level,
            captured_sources=captured_configuration_sources,
        )
        integration_config = IntegrationConfig.from_toml(integrations_source)
        approved_context = plan.execution_context
        if approved_context is None or approved_context.runtime is None:
            raise ConfigurationError(
                "applied execution requires an approval-bound runtime path identity"
            )
        _enforce_approved_configuration_inputs(
            plan,
            integrations=integration_config,
            configuration_sources=configuration_sources,
        )
        _enforce_approved_credential_file(
            approved_context.runtime.credential_file, credentials_file
        )
        governance = GovernanceProfile.from_toml(configuration_sources["governance"])
        _preflight_applied_provider_reads(
            plan=plan,
            catalog=capability_catalog,
            governance=governance,
            enforce_non_provider=connector_mode == "live",
        )
        live_systems = _live_systems_for_plan(
            plan,
            integration_config,
            catalog=capability_catalog,
        )
        configurations = _configuration_names_for_systems(live_systems)
        integration_config = _with_connector_url_overrides(
            integration_config,
            connector_urls,
            selected_configurations=configurations,
        )
        credential_store = _load_credential_store(
            credentials_file,
            integrations=integration_config,
            governance=governance,
            connector_mode=connector_mode,
            credential_mappings=credential_mappings,
            systems=live_systems,
        )
        compatibility = _atlassian_credential_compatibility(
            integration_config,
            configurations=configurations,
        )
        execution_environ = _credential_environment(
            credential_store,
            os.environ,
            declared_names=integration_config.credential_environment_variables(),
            compatible_names=compatibility,
        )
        approved_path_bindings = (
            *approved_context.runtime.runtime_paths,
            *approved_context.runtime.publication_roots,
        )
        captured_paths = capture_runtime_execution_paths(
            integration_config,
            connector_mode=connector_mode,
            include_writes=include_writes,
            audit_database=database,
            artifact_root=draft_output_dir,
            workspace_root=workspace_root,
            result_json=result_json,
            environ=execution_environ,
            approved_bindings=approved_path_bindings,
        )
        for captured in captured_paths:
            runtime_resources.callback(captured.close)
        observed_context = build_execution_context(
            integration_config,
            environ=execution_environ,
            systems=live_systems,
            runtime=build_runtime_execution_binding(
                integration_config,
                connector_mode=connector_mode,
                include_writes=include_writes,
                include_communications=include_communications,
                audit_database=database,
                artifact_root=draft_output_dir,
                workspace_root=workspace_root,
                result_json=result_json,
                evidence_type=evidence_type,
                configuration_sources=configuration_sources,
                credential_file=(credential_store.path if credential_store else None),
                environ=execution_environ,
                captured_paths=captured_paths,
            ),
            include_connectors=connector_mode == "live",
            approved_execution_context=approved_context,
        )
        enforce_execution_context(
            plan,
            observed_context,
        )
        disabled_git_actions = sorted(
            {
                action.capability
                for action in plan.actions
                if action.capability in _DISABLED_LOCAL_GIT_MUTATIONS
            }
        )
        if disabled_git_actions:
            raise ConfigurationError(
                "local Git mutation capabilities are disabled until all Git "
                "metadata transactions are descriptor-bound: "
                + ", ".join(disabled_git_actions)
            )
        approved_runtime = observed_context.runtime
        if approved_runtime is None:
            raise ConfigurationError(
                "applied execution context is missing its runtime path binding"
            )
        # The equality gate above proves these canonical paths are the exact
        # approved values. Never pass the original CLI spellings downstream:
        # they may contain a symlinked ancestor that can be rebound after this
        # check while still resolving to the approved path during comparison.
        database = Path(approved_runtime.audit_database)
        draft_output_dir = Path(approved_runtime.artifact_root)
        workspace_root = (
            Path(approved_runtime.workspace_root)
            if approved_runtime.workspace_root is not None
            else None
        )
        result_json = (
            Path(approved_runtime.result_json)
            if approved_runtime.result_json is not None
            else None
        )
        if approved_runtime.evidence_type is not None:
            evidence_type = approved_runtime.evidence_type

        pinned_paths = {
            captured.binding.name: runtime_resources.enter_context(
                captured.open_target()
            )
            for captured in captured_paths
        }
        for captured in captured_paths:
            captured.validate()
        for pinned in pinned_paths.values():
            pinned.validate()
        audit_parent = pinned_paths["audit.parent"]
        artifact_directory = pinned_paths["artifact.root"]
        result_parent = pinned_paths.get("result.parent")
        result_reservation: RetainedJSONReservation | None = None
        if result_json is not None:
            if result_parent is None:  # pragma: no cover - manifest invariant.
                raise ConfigurationError("applied result path has no pinned parent")
            retention = RetentionConfig.from_toml(configuration_sources["retention"])
            result_reservation = runtime_resources.enter_context(
                RetainedJSONReservation(
                    result_json,
                    evidence_type=evidence_type,
                    config=retention,
                    include_content=True,
                    parent_directory=result_parent,
                )
            )

        if approval_authorities is not None and approvals:
            approval_authenticator = HmacApprovalAuthenticator.from_toml(
                configuration_sources["approval_authorities"],
                environ=execution_environ,
            )
        if connector_mode == "mock":
            connectors = _mock_read_registry(plan, capability_catalog)
            register_draft_connectors(
                connectors,
                artifact_directory,
                catalog=capability_catalog,
            )
        else:
            connectors = build_live_registry(
                integration_config,
                environ=execution_environ,
                systems=live_systems,
                include_writes=include_writes,
                include_communications=include_communications,
                workspace_root=workspace_root,
                artifact_root=draft_output_dir,
                artifact_directory=artifact_directory,
                approved_execution_context=plan.execution_context,
            )
            register_draft_connectors(
                connectors,
                artifact_directory,
                catalog=capability_catalog,
            )
            identities = IdentityRegistry.from_toml(configuration_sources["identities"])
            if "identity" not in connectors.systems():
                connectors.register(IdentityMapConnector(identities))
        for connector in connectors.connectors():
            if isinstance(connector, ClosableConnector):
                runtime_resources.callback(connector.close)

        # Re-capture every path-backed policy input and non-secret environment
        # identity after connector construction. Connector clients use the
        # first immutable snapshots; this second gate prevents a concurrent
        # change from creating ambiguity about which reviewed runtime executed.
        current_configuration_sources = _execution_configuration_sources(
            approval_authorities=approval_authorities,
            retention_path=retention_path,
            identities_path=identities_path,
            policy_path=policy_path,
            sources_of_truth_path=sources_of_truth_path,
            capabilities_path=capabilities_path,
            governance_path=governance_path,
            organization_profile_path=organization_profile_path,
        )
        current_integrations = _with_connector_url_overrides(
            IntegrationConfig.from_toml(
                _execution_integrations_source(
                    plan=plan,
                    catalog=capability_catalog,
                    integrations_path=integrations_path,
                    high_level=high_level,
                    captured_sources=None,
                )
            ),
            connector_urls,
            selected_configurations=configurations,
        )
        _enforce_approved_configuration_inputs(
            plan,
            integrations=current_integrations,
            configuration_sources=current_configuration_sources,
        )
        if connector_mode == "live":
            capture_connector_executions(
                current_integrations,
                environ=os.environ,
                systems=live_systems,
                require_trusted_principal=False,
                include_resolved_credentials=False,
                approved_execution_context=approved_context,
            )
        for captured in captured_paths:
            captured.validate()
        for pinned in pinned_paths.values():
            pinned.validate()

        applied_audit = AuditLog(database, parent_directory=audit_parent)
        try:
            report = _orchestrator(
                connectors,
                database,
                capabilities_path=capabilities_path,
                governance_path=governance_path,
                policy_source=configuration_sources["policy"],
                sources_of_truth_source=configuration_sources["sources_of_truth"],
                capabilities_source=configuration_sources["capabilities"],
                capabilities=capability_catalog,
                governance_source=configuration_sources["governance"],
                approval_authenticator=approval_authenticator,
                audit=applied_audit,
                pre_effect_guard=pre_effect_guard,
            ).run(
                plan,
                approvals=approvals,
                dry_run=False,
            )
        finally:
            applied_audit.close()

        pending_approvals = tuple(
            (item.action_id, item.message)
            for item in report.actions
            if item.state is ActionState.APPROVAL_REQUIRED
        )
        if result_json is not None and not pending_approvals:
            if result_reservation is None:  # pragma: no cover - branch invariant.
                raise ConfigurationError("applied result path was not reserved")
            evidence, sidecar = result_reservation.commit(report.to_dict())
        approval_request_path: Path | None = None
        approval_request: ApprovalRequest | None = None
        if pending_approvals:
            if approval_authorities is None:
                raise ConfigurationError(
                    "approval is required, but the plan has no resumable approval "
                    "authority binding; rebind with --approval-authorities"
                )
            invocation = ApprovalRunInvocation.capture(
                plan_path=plan_path,
                approval_paths=approval_paths,
                approval_authorities=approval_authorities,
                database=database,
                connector_mode=connector_mode,
                integrations=integrations_path,
                result_json=result_json,
                retention=retention_path,
                evidence_type=evidence_type,
                identities=identities_path,
                include_writes=include_writes,
                include_communications=include_communications,
                workspace_root=workspace_root,
                draft_output_dir=draft_output_dir,
                capabilities=capabilities_path,
                governance=governance_path,
                policy=policy_path,
                sources_of_truth=sources_of_truth_path,
                plugin_names=plugin_names,
                plugin_lock=plugin_lock_path,
                credentials_file=credentials_file,
                credential_mappings=credential_mappings,
                connector_urls=connector_urls,
                organization_profile=organization_profile_path,
                recurring_occurrence=recurring_occurrence_path,
                recurring_fingerprint=recurring_fingerprint,
                recurring_claim_generation=recurring_claim_generation,
                recurring_config=recurring_config_path,
            )
            approval_request = ApprovalRequest.build(
                plan=plan,
                run=invocation,
                pending=pending_approvals,
            )
            approval_request_path = publish_approval_request(
                artifact_directory,
                approval_request,
            )
        if report_observer is not None:
            report_observer(report, approval_request)
        _print_report(report)
        if result_json is not None and not pending_approvals:
            print(f"full result written to {evidence}")
            print(f"retention sidecar written to {sidecar}")
        elif result_json is not None:
            print(
                "full result remains reserved for the approval-complete resume at "
                f"{result_json}"
            )
        if approval_request_path is not None and approval_request is not None:
            print(f"approval request: {approval_request_path}")
            print(f"request fingerprint: {approval_request.fingerprint}")
            if high_level:
                print(
                    "pending actions were not executed; a trusted operator must use "
                    "inspect-approval-request and approve-request, then resume with "
                    "execute --resume REQUEST --approval ARTIFACT"
                )
            else:
                print(
                    "pending actions were not executed; a trusted operator must use "
                    "inspect-approval-request and approve-request, then MasterAgent "
                    "can resume-approval without rebuilding this run"
                )
        return 0 if report.successful else 2


def _preflight_applied_provider_reads(
    *,
    plan: ChangePlan,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    enforce_non_provider: bool,
) -> None:
    """Authorize applied read shapes before connector identity or content I/O."""

    validated: list[tuple[AgentAction, CapabilityDefinition]] = []
    for action in plan.actions:
        definition = catalog.definition(action.capability)
        provider_read = (
            definition.risk is RiskLevel.READ_ONLY
            and definition.authentication != "local"
        )
        catalog_allowed, catalog_reason = catalog.validate_action(
            action,
            require_enabled=provider_read or enforce_non_provider,
        )
        if not catalog_allowed:
            raise ConfigurationError(catalog_reason)
        if provider_read or enforce_non_provider:
            governance_allowed, governance_reason = governance.validate_action(action)
            if not governance_allowed:
                raise ConfigurationError(governance_reason)
        validated.append((action, definition))
    reads = tuple(
        (action, definition)
        for action, definition in validated
        if definition.risk is RiskLevel.READ_ONLY
        and definition.authentication != "local"
    )
    if not reads:
        return
    if governance.model_context is None:
        raise ConfigurationError(
            "provider reads require configured model-context policy"
        )
    audit_available = implemented_audit_sink(governance.audit_sink) is not None
    for action, definition in reads:
        preflight_provider_data_egress(
            policy=governance.model_context,
            action=action,
            definition=definition,
            route=ProviderDataRoute.AUDITED,
            audit_available=audit_available,
        )


def _require_operating_policy_preflight(
    *,
    plan: ChangePlan,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    policy: PolicyConfig,
    sources: SourceOfTruthRegistry,
) -> None:
    """Reject every deterministic plan-policy denial before run allocation."""

    engine = PolicyEngine(policy)
    for action in plan.actions:
        checks = (
            catalog.validate_action(action),
            governance.validate_action(action),
            sources.validate(plan, action),
        )
        for allowed, reason in checks:
            if not allowed:
                raise OperatingValidationError(
                    (
                        OperatingIssue(
                            OperatingFailureCategory.BLOCKED_POLICY,
                            reason,
                            action.capability,
                        ),
                    )
                )
        decision = engine.evaluate(
            plan,
            action,
            minimum_distinct_approvers=governance.minimum_approvers(action.capability),
        )
        if not decision.permitted and not decision.approval_required:
            raise OperatingValidationError(
                (
                    OperatingIssue(
                        OperatingFailureCategory.BLOCKED_POLICY,
                        decision.reason,
                        action.capability,
                    ),
                )
            )


def _run_direct_read(
    *,
    plan_path: Path,
    apply: bool,
    approval_paths: Sequence[Path],
    approval_authorities: Path | None,
    database: Path,
    integrations_path: Path | None,
    result_json: Path | None,
    retention_path: Path | None,
    evidence_type: str,
    identities_path: Path | None,
    include_writes: bool,
    include_communications: bool,
    workspace_root: Path | None,
    draft_output_dir: Path,
    capabilities_path: Path | None,
    governance_path: Path | None,
    policy_path: Path | None,
    sources_of_truth_path: Path | None,
    plugin_names: Sequence[str],
    plugin_lock_path: Path | None,
    credentials_file: Path | None,
    credential_mappings: Sequence[str],
    connector_urls: Sequence[str],
    organization_profile_path: Path | None = None,
    loaded_plan: ChangePlan | None = None,
    expected_plan_fingerprint: str | None = None,
    expected_profile_fingerprint: str | None = None,
    captured_configuration_sources: Mapping[str, ConfigSnapshot] | None = None,
) -> int:
    """Run one stateless typed provider-read session.

    This intentionally sits outside the approval-bound ``--apply`` route.  It
    constructs one selected live read connector only after an entirely local
    plan preflight, retains no audit/idempotency/result state, and prints a
    bounded terminal representation of independently verified content.
    """

    _validate_direct_read_options(
        apply=apply,
        approval_paths=approval_paths,
        approval_authorities=approval_authorities,
        database=database,
        result_json=result_json,
        retention_path=retention_path,
        evidence_type=evidence_type,
        identities_path=identities_path,
        include_writes=include_writes,
        include_communications=include_communications,
        workspace_root=workspace_root,
        draft_output_dir=draft_output_dir,
        plugin_names=plugin_names,
        plugin_lock_path=plugin_lock_path,
    )
    plan = loaded_plan if loaded_plan is not None else _load_plan(plan_path)
    _require_plan_fingerprint(plan, expected_plan_fingerprint)
    if organization_profile_path is not None:
        profile = _load_active_organization_profile(organization_profile_path)
        _require_organization_selection(
            plan,
            organization_profile_path=organization_profile_path,
            expected_profile_fingerprint=expected_profile_fingerprint,
            connector_mode="live",
            include_writes=profile.writes_enabled,
            include_communications=profile.communications_enabled,
            integrations_path=integrations_path,
            approval_authorities=profile.configuration_path("approval_authorities"),
            retention_path=profile.configuration_path("retention"),
            identities_path=profile.configuration_path("identities"),
            policy_path=policy_path,
            sources_of_truth_path=sources_of_truth_path,
            capabilities_path=capabilities_path,
            governance_path=governance_path,
            allow_bound_plan=False,
            captured_configuration_sources=captured_configuration_sources,
        )
    capabilities_source = (
        captured_configuration_sources["capabilities"]
        if captured_configuration_sources is not None
        else resolve_config_source(capabilities_path, "capabilities.toml")
    )
    governance_source = (
        captured_configuration_sources["governance"]
        if captured_configuration_sources is not None
        else resolve_config_source(governance_path, "governance.toml")
    )
    policy_source = (
        captured_configuration_sources["policy"]
        if captured_configuration_sources is not None
        else resolve_config_source(policy_path, "policy.toml")
    )
    sources_source = (
        captured_configuration_sources["sources_of_truth"]
        if captured_configuration_sources is not None
        else resolve_config_source(sources_of_truth_path, "sources_of_truth.toml")
    )
    catalog = CapabilityCatalog.from_toml(capabilities_source)
    governance = GovernanceProfile.from_toml(governance_source)
    policy = PolicyEngine(PolicyConfig.from_toml(policy_source))
    sources = SourceOfTruthRegistry.from_toml(sources_source)

    # No credentials, principal-attestation calls, or connector construction
    # occur before this shape and policy preflight succeeds.
    provider = preflight_direct_read_plan(
        plan=plan,
        catalog=catalog,
        governance=governance,
        policy=policy,
        sources=sources,
    )
    if provider not in _CONNECT_CONFIGURATION_BY_SYSTEM:
        raise ConfigurationError(
            "direct read sessions require one built-in typed provider: " + provider
        )
    systems = {provider}
    configurations = _configuration_names_for_systems(systems)
    integration_source = (
        captured_configuration_sources["integrations"]
        if captured_configuration_sources is not None
        else resolve_config_source(integrations_path, "integrations.toml")
    )
    integrations = IntegrationConfig.from_toml(integration_source)
    integrations = _with_connector_url_overrides(
        integrations,
        connector_urls,
        selected_configurations=configurations,
    )
    integrations, anonymous = _adapt_anonymous_direct_read_integrations(
        plan,
        provider=provider,
        integrations=integrations,
        catalog=catalog,
    )
    credential_store = (
        None
        if anonymous
        else _load_credential_store(
            credentials_file,
            integrations=integrations,
            governance=governance,
            connector_mode="live",
            credential_mappings=credential_mappings,
            systems=systems,
        )
    )
    compatibility = (
        {}
        if anonymous
        else _atlassian_credential_compatibility(
            integrations,
            configurations=configurations,
        )
    )
    execution_environ = (
        _anonymous_direct_read_environment(
            integrations,
            configurations=configurations,
            environ=os.environ,
        )
        if anonymous
        else _credential_environment(
            credential_store,
            os.environ,
            declared_names=integrations.credential_environment_variables(),
            compatible_names=compatibility,
        )
    )
    captured = capture_connector_executions(
        integrations,
        environ=execution_environ,
        systems=systems,
    )
    binding_system = _CONNECT_CONFIGURATION_BY_SYSTEM[provider]
    bindings = [
        item.binding for item in captured if item.binding.system == binding_system
    ]
    if len(bindings) != 1:
        raise ConfigurationError(
            "direct read sessions require exactly one enabled connector binding for "
            + provider
        )

    with ExitStack() as runtime_resources:
        registry = build_live_registry(
            integrations,
            environ=execution_environ,
            systems=systems,
            include_writes=False,
            include_communications=False,
            captured_executions=captured,
        )
        connector = registry.resolve(provider, plan.actions[0].capability)
        if not isinstance(connector, ReadOnlyConnector):
            raise ConfigurationError(
                "direct read sessions require a typed ReadOnlyConnector"
            )
        for selected in registry.connectors():
            if isinstance(selected, ClosableConnector):
                runtime_resources.callback(selected.close)
        report = DirectReadSession(
            catalog=catalog,
            governance=governance,
            policy=policy,
            sources=sources,
            connector=connector,
            execution_binding=bindings[0],
        ).execute(plan)

    _print_direct_read_report(report)
    return 0 if report.successful else 2


def _adapt_anonymous_direct_read_integrations(
    plan: ChangePlan,
    *,
    provider: str,
    integrations: IntegrationConfig,
    catalog: CapabilityCatalog,
) -> tuple[IntegrationConfig, bool]:
    """Remove credential references for two exact reviewed public-read routes."""

    capabilities = {action.capability for action in plan.actions}
    if any(
        catalog.definition(action.capability).authentication
        != "anonymous_or_configured_connector"
        for action in plan.actions
    ):
        return integrations, False
    configuration_name: str | None = None
    if provider == "github" and capabilities == {"github.public_repository.list"}:
        configuration_name = "github"
    elif provider == "bitbucket" and capabilities == {
        "bitbucket.public_repository.list"
    }:
        configuration_name = "bitbucket"
    if configuration_name is None:
        return integrations, False
    selected = integrations.connector(configuration_name)
    if not selected.enabled:
        raise ConfigurationError(
            f"anonymous {provider} reads require the reviewed connector to be enabled"
        )
    if provider == "bitbucket" and selected.deployment is not DeploymentType.CLOUD:
        raise ConfigurationError(
            "Bitbucket public workspace repositories require Bitbucket Cloud"
        )
    connectors = dict(integrations.connectors)
    connectors[configuration_name] = replace(
        selected,
        auth_mode=AuthMode.NONE,
        username_env=None,
        secret_env=None,
    )
    return (
        IntegrationConfig(
            connectors=connectors,
            network_profiles=integrations.network_profiles,
            source_sha256=integrations.source_sha256,
        ),
        True,
    )


def _anonymous_direct_read_environment(
    integrations: IntegrationConfig,
    *,
    configurations: Iterable[str],
    environ: Mapping[str, str],
) -> dict[str, str]:
    """Copy only endpoint, network-profile, and trust values for anonymous reads."""

    selected: dict[str, str] = {}
    for name in configurations:
        connector = integrations.connector(name)
        network_variables = connector.network_profile.required_environment_variables()
        for variable in (
            connector.base_url_env,
            connector.ca_bundle_env,
            *network_variables,
        ):
            if variable is None:
                continue
            value = environ.get(variable)
            if value is not None:
                selected[variable] = value
    return selected


def _validate_direct_read_options(
    *,
    apply: bool,
    approval_paths: Sequence[Path],
    approval_authorities: Path | None,
    database: Path,
    result_json: Path | None,
    retention_path: Path | None,
    evidence_type: str,
    identities_path: Path | None,
    include_writes: bool,
    include_communications: bool,
    workspace_root: Path | None,
    draft_output_dir: Path,
    plugin_names: Sequence[str],
    plugin_lock_path: Path | None,
) -> None:
    """Reject effect-bound and persistence-oriented options in direct mode."""

    if apply:
        raise ValueError("--direct-read cannot be combined with --apply")
    if approval_paths or approval_authorities is not None:
        raise ValueError(
            "--direct-read does not accept approval artifacts or authorities"
        )
    if include_writes or include_communications:
        raise ValueError("--direct-read cannot enable writes or communications")
    if result_json is not None:
        raise ValueError("--direct-read never persists a result; omit --result-json")
    if retention_path is not None or evidence_type != "run-result/full":
        raise ValueError("--direct-read does not accept retention or evidence options")
    if identities_path is not None:
        raise ValueError("--direct-read does not use an identity-map configuration")
    if workspace_root is not None:
        raise ValueError("--direct-read does not use a workspace root")
    if database != Path(".master-agent/audit.sqlite3"):
        raise ValueError("--direct-read never opens an audit database")
    if draft_output_dir != Path(".master-agent/drafts"):
        raise ValueError("--direct-read never creates draft artifacts")
    if plugin_names or plugin_lock_path is not None:
        raise ValueError("--direct-read cannot load connector plugins")


def _plugins(*, output: Path | None) -> int:
    """List installed connector entry points without importing plugin modules."""

    plugins = discover_connector_plugins()
    for item in plugins:
        distribution = item.distribution or "unknown-distribution"
        name = _terminal_field(item.name, max_characters=80)
        safe_distribution = _terminal_field(distribution, max_characters=120)
        value = _terminal_field(item.value)
        print(f"{name:<24} {safe_distribution:<28} {value}")
    if not plugins:
        print("no connector plugins installed")
    if output is not None:
        _write_json(output, PluginLock(plugins=plugins).to_dict())
        print(f"wrote {output}")
    return 0


def _capability_import(
    *,
    source_path: Path,
    capabilities_path: Path | None,
    dependency_licenses_path: Path | None,
    ability_name: str | None,
    expected_source_sha256: str | None,
    capsule_store: Path | None,
    capsule_authorities: Path | None,
    environment: str,
    worker_sha256: str | None,
    output: Path | None,
) -> int:
    """Inspect an export or quarantine one explicit exact-digest selection."""

    source = snapshot_explicit_file(source_path)
    catalog = CapabilityCatalog.from_toml(
        resolve_config_source(capabilities_path, "capabilities.toml")
    )
    license_policy = LicensePolicy.from_toml(
        resolve_config_source(
            dependency_licenses_path,
            "dependency-licenses.toml",
        )
    )
    preview = inspect_agent_capabilities(
        source,
        catalog=catalog,
        license_policy=license_policy,
    )
    if ability_name is None:
        if any(
            value is not None
            for value in (
                expected_source_sha256,
                capsule_store,
                capsule_authorities,
                worker_sha256,
            )
        ):
            raise ValueError(
                "selection options require --select; preview itself is read-only"
            )
        return _emit_capability_payload(preview.to_dict(), output=output)
    if expected_source_sha256 is None:
        raise ValueError("--expected-source-sha256 is required with --select")
    if capsule_store is None or capsule_authorities is None:
        raise ValueError(
            "--capsule-store and --capsule-authorities are required with --select"
        )
    authorities, trust = load_capsule_authorities(
        snapshot_explicit_file(capsule_authorities),
        environ=os.environ,
        required_roles=(CapsuleRole.GENERATOR,),
    )
    selected_worker_sha256 = worker_sha256 or CapsuleWorker().identity_sha256
    imported = quarantine_selected_ability(
        source_path,
        expected_source_sha256=expected_source_sha256,
        ability_name=ability_name,
        catalog=catalog,
        license_policy=license_policy,
        store=CapsuleStore(capsule_store),
        authority=authorities[CapsuleRole.GENERATOR],
        trust=trust,
        environment=environment,
        worker_sha256=selected_worker_sha256,
    )
    payload = {
        "schema": "master-agent/capability-lifecycle-result@1",
        "operation": "quarantine",
        "source_sha256": imported.source_sha256,
        "ability_name": imported.ability_name,
        "capability_id": imported.manifest.spec.capability_id,
        "version": imported.manifest.spec.version,
        "state": str(imported.manifest.state),
        "manifest_sha256": imported.manifest.manifest_sha256,
        "worker_sha256": imported.manifest.worker_sha256,
        "routable": False,
        "next": "capability-promote",
    }
    return _emit_capability_payload(payload, output=output)


def _capability_promote(
    *,
    capability_id: str,
    version: str,
    capsule_store: Path,
    capsule_authorities: Path,
    dependency_licenses_path: Path | None,
    environment: str,
    output: Path | None,
) -> int:
    """Promote one exact latest quarantine through the signed lifecycle."""

    authorities, trust = load_capsule_authorities(
        snapshot_explicit_file(capsule_authorities),
        environ=os.environ,
    )
    store = CapsuleStore(capsule_store)
    current = _current_capsule_manifest(
        store,
        trust=trust,
        capability_id=capability_id,
        version=version,
    )
    bundle = store.load_bundle(capability_id, version)
    worker = CapsuleWorker()
    license_policy = LicensePolicy.from_toml(
        resolve_config_source(
            dependency_licenses_path,
            "dependency-licenses.toml",
        )
    )
    result = CapabilityPromotionService(
        store=store,
        trust=trust,
        worker=worker,
        validator=CapsuleValidator(worker=worker, license_policy=license_policy),
        authorities=authorities,
        environment=environment,
    ).promote_installed(bundle, current)
    payload = {
        "schema": "master-agent/capability-lifecycle-result@1",
        "operation": "promote",
        "capability_id": capability_id,
        "version": version,
        "states": [str(item.state) for item in result.manifests],
        "state": str(result.enabled.state),
        "manifest_sha256": result.enabled.manifest_sha256,
        "worker_sha256": result.enabled.worker_sha256,
        "routable": True,
        "next": "capability-route or capability-run",
    }
    return _emit_capability_payload(payload, output=output)


def _capability_status(
    *,
    capability_id: str,
    version: str,
    capsule_store: Path,
    capsule_authorities: Path,
    output: Path | None,
) -> int:
    """Verify and report one immutable capsule state chain."""

    _authorities, trust = load_capsule_authorities(
        snapshot_explicit_file(capsule_authorities),
        environ=os.environ,
    )
    manifests = CapsuleStore(capsule_store).manifests(
        capability_id,
        version,
        trust=trust,
    )
    if not manifests:
        raise ConfigurationError("capability capsule is not installed")
    current = manifests[-1]
    payload = {
        "schema": "master-agent/capability-status@1",
        "capability_id": capability_id,
        "version": version,
        "state": str(current.state),
        "manifest_sha256": current.manifest_sha256,
        "source_sha256": current.source_sha256,
        "worker_sha256": current.worker_sha256,
        "publisher": current.spec.publisher,
        "reviewer": current.reviewer,
        "routable": current.state is CapsuleState.ENABLED,
        "history": [
            {
                "sequence": item.sequence,
                "state": str(item.state),
                "actor": item.actor,
                "role": str(item.role),
                "manifest_sha256": item.manifest_sha256,
            }
            for item in manifests
        ],
    }
    return _emit_capability_payload(payload, output=output)


def _capability_route(
    *,
    intent: str,
    capsule_refs: tuple[str, ...],
    capsule_store: Path,
    capsule_authorities: Path,
    policy_path: Path | None,
    governance_path: Path | None,
    output: Path | None,
) -> int:
    """Route an intent only across exact, policy-permitted enabled capsules."""

    manifests, _trust = _enabled_capsule_manifests(
        capsule_refs=capsule_refs,
        capsule_store=capsule_store,
        capsule_authorities=capsule_authorities,
    )
    policy = PolicyEngine(
        PolicyConfig.from_toml(resolve_config_source(policy_path, "policy.toml"))
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
    )
    decision = _resolve_capsule_intent(
        intent,
        manifests=manifests,
        policy=policy,
        governance=governance,
        maximum_candidates=3,
    )
    payload = {
        "schema": "master-agent/capability-route@1",
        "intent_sha256": decision.normalized_intent_sha256,
        "binding_sha256": decision.binding_sha256,
        "candidates": [item.to_dict() for item in decision.cards],
    }
    return _emit_capability_payload(payload, output=output)


def _capability_run(
    *,
    intent: str,
    capsule_refs: tuple[str, ...],
    request_path: Path,
    capsule_store: Path,
    capsule_authorities: Path,
    policy_path: Path | None,
    governance_path: Path | None,
    capabilities_path: Path | None,
    sources_of_truth_path: Path | None,
    database: Path,
    principal: str,
    agent_identity: str,
    tenant_id: str,
    output: Path | None,
) -> int:
    """Route and execute one enabled pure capsule through the orchestrator."""

    require_persistent_state_platform()
    request = _load_capability_request(request_path)
    manifests, trust = _enabled_capsule_manifests(
        capsule_refs=capsule_refs,
        capsule_store=capsule_store,
        capsule_authorities=capsule_authorities,
    )
    policy = PolicyEngine(
        PolicyConfig.from_toml(resolve_config_source(policy_path, "policy.toml"))
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
    )
    decision = _resolve_capsule_intent(
        intent,
        manifests=manifests,
        policy=policy,
        governance=governance,
        maximum_candidates=1,
    )
    card = decision.cards[0]
    manifest = next(
        item
        for item in manifests
        if item.spec.capability_id == card.capability_id
        and item.spec.version == card.version
        and item.manifest_sha256 == card.manifest_sha256
    )
    worker = CapsuleWorker()
    base_catalog = CapabilityCatalog.from_toml(
        resolve_config_source(capabilities_path, "capabilities.toml")
    )
    context = context_with_capsules(
        ExecutionContext(hashlib.sha256(b"capsule-local-only").hexdigest()),
        (manifest,),
        authenticated_principal=principal,
        agent_identity=agent_identity,
        tenant_id=tenant_id,
    )
    binding = context.capsules[0]
    activated = activate_capsule(
        store=CapsuleStore(capsule_store),
        trust=trust,
        binding=binding,
        worker=worker,
        base_catalog=base_catalog,
    )
    registry = ConnectorRegistry()
    registry.register(activated.connector)
    request_sha256 = hashlib.sha256(
        json.dumps(
            request,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    action = AgentAction(
        capability=manifest.spec.capability_id,
        target=ResourceRef(
            system=manifest.spec.system,
            resource_type="capsule_request",
            resource_id=request_sha256,
        ),
        parameters=request,
        risk=manifest.spec.risk,
        data_classification=manifest.spec.data_classification,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=(
            f"capsule:{manifest.spec.capability_id}:{manifest.spec.version}:"
            f"{manifest.manifest_sha256}:{decision.normalized_intent_sha256}:"
            f"{request_sha256}"
        ),
        justification="The authenticated operator selected this routed capsule.",
    )
    plan = ChangePlan(
        goal=intent,
        actions=(action,),
        created_by=principal,
        execution_context=context,
    )
    plan = bind_static_intervention_governance(
        plan,
        SystemsAssessment.for_static_intervention(
            desired_outcome=intent,
            current_behavior="the selected capability has not yet processed the request",
            constraint="one authenticated request must remain bound to one promoted capsule",
            stocks=("selected capsule and provider target state",),
            flows=("authenticated request through the activated capsule",),
            feedback_loops=(
                "connector verification determines the final action state",
            ),
            delays=("provider response and independent verification latency",),
            leverage_point="the single governed capsule execution boundary",
            simplest_intervention="execute only the selected capsule action",
            success_metric="the action completes and its result verifies independently",
            failure_condition="policy, execution, or verification does not succeed",
            unintended_consequences=(
                "a provider-side effect could become indeterminate after a transport failure",
            ),
            removable_complexity=("the per-run capsule activation",),
            strategy_kernel=StrategyKernel(
                diagnosis=(
                    "The requested outcome is blocked at the single promoted capsule "
                    "execution boundary."
                ),
                guiding_policy=(
                    "Use only the authenticated, routed, and activated capsule selected "
                    "for this request."
                ),
                proximate_objective="Execute and verify the one selected capsule action.",
                tradeoffs=(
                    "Prefer one tightly bound capability over broader dynamic dispatch.",
                ),
                coherent_actions=(
                    StrategyActionIntent(
                        intent_id="execute_capsule",
                        description="Execute only the selected capsule action.",
                        expected_effect=(
                            "The selected action completes and verifies independently."
                        ),
                    ),
                ),
            ),
            reversible=manifest.spec.risk is not RiskLevel.DESTRUCTIVE,
            well_understood=True,
        ),
    )
    audit = AuditLog(database)
    try:
        report = WorkflowOrchestrator(
            policy=policy,
            sources=SourceOfTruthRegistry.from_toml(
                resolve_config_source(
                    sources_of_truth_path,
                    "sources_of_truth.toml",
                )
            ),
            connectors=registry,
            audit=audit,
            capabilities=activated.catalog,
            governance=governance,
        ).run(plan, dry_run=False)
    finally:
        audit.close()
    payload = report.to_dict()
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    _print_report(report, mode_label="capsule-apply")
    for item in report.actions:
        if item.result is not None:
            rendered = render_terminal_text(
                json.dumps(item.result.after, ensure_ascii=True, sort_keys=True),
                max_characters=_MAX_DIRECT_READ_TERMINAL_PAYLOAD_CHARACTERS,
            )
            print(f"  result: {rendered}")
    return 0 if report.successful else 2


def _capability_transition(
    *,
    capability_id: str,
    version: str,
    capsule_store: Path,
    capsule_authorities: Path,
    target: CapsuleState,
    output: Path | None,
) -> int:
    """Append a signed deprecation or revocation without deleting history."""

    authorities, trust = load_capsule_authorities(
        snapshot_explicit_file(capsule_authorities),
        environ=os.environ,
    )
    store = CapsuleStore(capsule_store)
    current = _current_capsule_manifest(
        store,
        trust=trust,
        capability_id=capability_id,
        version=version,
    )
    role = (
        CapsuleRole.PUBLISHER
        if target is CapsuleState.DEPRECATED
        else CapsuleRole.REVOKER
    )
    transitioned = advance_manifest(
        current,
        target,
        authority=authorities[role],
        trust=trust,
    )
    store.append_manifest(transitioned, trust=trust)
    payload = {
        "schema": "master-agent/capability-lifecycle-result@1",
        "operation": "disable" if target is CapsuleState.DEPRECATED else "revoke",
        "capability_id": capability_id,
        "version": version,
        "previous_state": str(current.state),
        "state": str(transitioned.state),
        "manifest_sha256": transitioned.manifest_sha256,
        "routable": False,
        "history_retained": True,
    }
    return _emit_capability_payload(payload, output=output)


def _enabled_capsule_manifests(
    *,
    capsule_refs: tuple[str, ...],
    capsule_store: Path,
    capsule_authorities: Path,
) -> tuple[tuple[CapsuleManifest, ...], CapsuleTrustStore]:
    """Load explicitly named latest enabled manifests and their trust store."""

    _authorities, trust = load_capsule_authorities(
        snapshot_explicit_file(capsule_authorities),
        environ=os.environ,
    )
    store = CapsuleStore(capsule_store)
    parsed = tuple(_parse_capsule_ref(item) for item in capsule_refs)
    if len(parsed) != len(set(parsed)):
        raise ValueError("--capsule references must be unique")
    manifests = tuple(
        _current_capsule_manifest(
            store,
            trust=trust,
            capability_id=capability_id,
            version=version,
        )
        for capability_id, version in parsed
    )
    disabled = tuple(
        f"{item.spec.capability_id}@{item.spec.version}:{item.state}"
        for item in manifests
        if item.state is not CapsuleState.ENABLED
    )
    if disabled:
        raise ConfigurationError(
            "routing requires latest enabled capsules: " + ", ".join(disabled)
        )
    return manifests, trust


def _resolve_capsule_intent(
    intent: str,
    *,
    manifests: tuple[CapsuleManifest, ...],
    policy: PolicyEngine,
    governance: GovernanceProfile,
    maximum_candidates: int,
) -> RoutingDecision:
    """Apply normal governance and policy before lexical capsule routing."""

    mismatched = tuple(
        f"{item.spec.capability_id}@{item.spec.version}:{item.environment}"
        for item in manifests
        if item.environment != str(governance.environment)
    )
    if mismatched:
        raise ConfigurationError(
            "capsule environment must match runtime governance "
            f"{governance.environment}: " + ", ".join(mismatched)
        )

    def policy_allows(card: CapabilityCard) -> bool:
        manifest = next(
            item
            for item in manifests
            if item.spec.capability_id == card.capability_id
            and item.spec.version == card.version
            and item.manifest_sha256 == card.manifest_sha256
        )
        action = AgentAction(
            capability=card.capability_id,
            target=ResourceRef(
                system=manifest.spec.system,
                resource_type="capsule_request",
                resource_id="routing-preview",
            ),
            parameters={},
            risk=card.risk,
            data_classification=card.data_classification,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key=f"capsule-routing:{card.manifest_sha256}",
            justification="Evaluate a promoted capsule for intent routing.",
        )
        context = context_with_capsules(
            ExecutionContext(hashlib.sha256(b"capsule-routing").hexdigest()),
            (manifest,),
        )
        plan = ChangePlan(
            goal=intent,
            actions=(action,),
            created_by="capability-router",
            execution_context=context,
        )
        governed, _reason = governance.validate_action(action)
        if not governed:
            return False
        decision = policy.evaluate(
            plan,
            action,
            minimum_distinct_approvers=governance.minimum_approvers(action.capability),
        )
        return decision.permitted and not decision.approval_required

    return CapabilityRouter().resolve(
        intent,
        tuple(CapabilityCard.from_manifest(item) for item in manifests),
        policy_allows=policy_allows,
        maximum_candidates=maximum_candidates,
    )


def _current_capsule_manifest(
    store: CapsuleStore,
    *,
    trust: CapsuleTrustStore,
    capability_id: str,
    version: str,
) -> CapsuleManifest:
    """Return one authenticated latest manifest or fail closed."""

    manifests = store.manifests(
        capability_id,
        version,
        trust=trust,
    )
    if not manifests:
        raise ConfigurationError("capability capsule is not installed")
    return manifests[-1]


def _parse_capsule_ref(value: str) -> tuple[str, str]:
    """Parse one explicit capability/version selector."""

    capability_id, separator, version = value.rpartition("@")
    if not separator or not capability_id or not version:
        raise ValueError("--capsule must be CAPABILITY_ID@VERSION")
    return capability_id, version


def _load_capability_request(path: Path) -> dict[str, object]:
    """Load one bounded owner-controlled JSON request with unique object keys."""

    source = snapshot_explicit_file(path)
    with source.open("rb") as handle:
        payload = handle.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValidationError("capability request exceeds the 1 MiB limit")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_capability_request_object,
            parse_constant=_reject_capability_request_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ValidationError("capability request is not bounded valid JSON") from error
    if not isinstance(value, dict):
        raise ValidationError("capability request must be a JSON object")
    return value


def _unique_capability_request_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_capability_request_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _emit_capability_payload(
    payload: Mapping[str, object], *, output: Path | None
) -> int:
    """Render one lifecycle result and optionally persist restricted JSON."""

    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=True))
    return 0


def _load_plugin_lock(
    plugin_names: Sequence[str],
    plugin_lock_path: Path | None,
) -> PluginLock | None:
    selected = tuple(name.strip() for name in plugin_names if name.strip())
    if not selected:
        if plugin_lock_path is not None:
            raise ValueError("--plugin-lock requires at least one --plugin")
        return None
    if plugin_lock_path is None:
        raise ValueError("--plugin-lock is required when --plugin is supplied")
    return PluginLock.from_json(
        resolve_config_source(plugin_lock_path, "plugin-lock.json")
    )


def _load_credential_store(
    path: Path | None,
    *,
    integrations: IntegrationConfig,
    governance: GovernanceProfile,
    connector_mode: str,
    credential_mappings: Sequence[str] = (),
    systems: set[str] | None = None,
) -> CredentialStoreSnapshot | None:
    """Load one reviewed JSON override or configured native credential source."""

    if credential_mappings and path is None:
        raise ConfigurationError("--credential-map requires --credentials-file")
    if connector_mode != "live" and path is not None:
        raise ConfigurationError(
            "--credentials-file is available only with live connectors"
        )
    configurations = (
        _configuration_names_for_systems(systems)
        if systems is not None
        else set(integrations.connectors)
    )
    if path is None:
        if connector_mode != "live":
            return None
        grouped: dict[tuple[str, str], set[str]] = {}
        for name in sorted(configurations):
            connector = integrations.connectors.get(name)
            if connector is None or not connector.enabled:
                continue
            provider = connector.credential_provider
            if provider is ConnectorCredentialProvider.ENVIRONMENT:
                continue
            target = connector.credential_target
            if target is None:  # pragma: no cover - constructor validates this.
                raise ConfigurationError(
                    f"connector {name} native credential target is missing"
                )
            names = connector.credential_environment_variables()
            grouped.setdefault((str(provider), target), set()).update(names)
        if not grouped:
            return None
        backend = get_credential_storage_backend()
        snapshots = tuple(
            CredentialStoreSnapshot.load_native(
                backend,
                provider=provider,
                target=target,
                allowed_names=tuple(sorted(names)),
            )
            for (provider, target), names in sorted(grouped.items())
        )
        return (
            snapshots[0]
            if len(snapshots) == 1
            else CredentialStoreSnapshot.combine(snapshots)
        )
    if governance.environment is not EnvironmentKind.DEVELOPMENT:
        raise ConfigurationError(
            "--credentials-file is restricted to the development environment; "
            "use the approved secret manager for non-development execution"
        )
    alias_configurations = configurations | _related_atlassian_configurations(
        integrations,
        configurations=configurations,
    )
    return CredentialStoreSnapshot.load_provider_compatible(
        path,
        allowed_names=integrations.credential_environment_variables(),
        aliases=_provider_credential_aliases(
            integrations,
            configurations=alias_configurations,
            systems=set(),
        ),
        explicit_mappings=_parse_credential_mappings(tuple(credential_mappings)),
    )


def _credential_environment(
    store: CredentialStoreSnapshot | None,
    environ: Mapping[str, str],
    *,
    declared_names: Sequence[str] = (),
    compatible_names: Mapping[str, str] | None = None,
) -> dict[str, str]:
    normalized = normalize_credential_environment(
        environ,
        declared_names=declared_names,
    )
    merged = store.overlay(normalized) if store is not None else normalized
    for destination, source in (compatible_names or {}).items():
        if not merged.get(destination) and merged.get(source):
            merged[destination] = merged[source]
    return merged


def _enforce_approved_credential_file(
    approved: str | None, selected: Path | None
) -> None:
    observed = str(canonical_credential_store_path(selected)) if selected else None
    if approved != observed:
        raise ConfigurationError(
            "applied execution context differs from the approved plan: "
            "credential file path binding"
        )


def _readiness(
    *,
    integrations_path: Path | None,
    capabilities_path: Path | None,
    governance_path: Path | None,
    oauth_path: Path | None,
    identities_path: Path | None,
    credentials_file: Path | None,
    egress_checks: tuple[str, ...],
    output: Path | None,
) -> int:
    """Assess Phase 0/2C configuration without performing network requests."""

    if output is not None:
        require_persistent_state_platform()
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
    )
    catalog = CapabilityCatalog.from_toml(
        resolve_config_source(capabilities_path, "capabilities.toml")
    )
    parsed_egress_checks = _parse_egress_checks(egress_checks)
    # A policy-denied selector is already unusable. Report it conservatively
    # without opening a credential file or overlaying ambient secret values.
    # Allowed selectors proceed to the credential-aware readiness assessment.
    policy_denials = provider_data_egress_policy_denials(
        catalog=catalog,
        governance=governance,
        integrations=integrations,
        egress_checks=parsed_egress_checks,
    )
    credential_store = (
        None
        if policy_denials
        else _load_credential_store(
            credentials_file,
            integrations=integrations,
            governance=governance,
            connector_mode="live",
        )
    )
    configurations = set(integrations.connectors)
    report = assess_readiness(
        catalog=catalog,
        governance=governance,
        integrations=integrations,
        oauth_profiles=OAuthProfiles.from_toml(
            resolve_config_source(oauth_path, "oauth.toml")
        ),
        identities=IdentityRegistry.from_toml(
            resolve_config_source(identities_path, "identities.toml")
        ),
        environ=(
            {}
            if policy_denials
            else _credential_environment(
                credential_store,
                os.environ,
                declared_names=integrations.credential_environment_variables(),
                compatible_names=_atlassian_credential_compatibility(
                    integrations,
                    configurations=configurations,
                ),
            )
        ),
        egress_checks=parsed_egress_checks,
    )
    if credential_store is not None and credential_store.source_bindings:
        shadowed = credential_store.shadowed_ambient_names(os.environ)
        report = replace(
            report,
            checks=(
                *report.checks,
                {
                    "name": "credential_sources",
                    "passed": True,
                    "sources": [
                        source.to_dict() for source in credential_store.source_bindings
                    ],
                },
            ),
            warnings=(
                *report.warnings,
                *(
                    "configured credential source overrides ambient variable: " + name
                    for name in shadowed
                ),
            ),
        )
    payload = report.to_dict()
    print(f"environment: {_terminal_field(report.environment, max_characters=80)}")
    print(f"ready: {report.ready}")
    _print_platform_runtime(report.platform_runtime)
    connector_checks = tuple(
        check
        for check in report.checks
        if str(check.get("name", "")).startswith("connector:")
    )
    if connector_checks:
        ready_connectors = sum(
            bool(check.get("credential_ready")) for check in connector_checks
        )
        print(
            f"live connectors: {len(connector_checks)} available, "
            f"{ready_connectors} credential-ready"
        )
    else:
        print("live connectors: 0 available")
    for check in report.checks:
        name = _terminal_field(check.get("name"), max_characters=240)
        print(f"  {'PASS' if check.get('passed') else 'FAIL'} {name}")
    for warning in report.warnings:
        print(f"warning: {_terminal_field(warning)}")
    for error in report.errors:
        print(f"error: {_terminal_field(error)}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 0 if report.ready else 2


def _print_platform_runtime(status: PlatformRuntimeStatus) -> None:
    """Print one secret-free deterministic native-backend status."""

    platform = _terminal_field(status.platform, max_characters=80)
    backend = _terminal_field(status.backend, max_characters=80)
    print(f"platform runtime: {platform} ({backend})")
    for item in status.capabilities:
        availability = "available" if item.available else "unavailable"
        item_backend = _terminal_field(item.backend, max_characters=80)
        line = f"  {item.contract}: {availability} ({item_backend})"
        if item.reason is not None:
            line += f": {_terminal_field(item.reason)}"
        print(line)


def _oauth_device_code(
    *,
    oauth_path: Path | None,
    profile_name: str,
    token_file: Path,
) -> int:
    """Run an explicitly selected delegated Entra device-code flow."""

    require_persistent_state_platform()
    profiles = OAuthProfiles.from_toml(resolve_config_source(oauth_path, "oauth.toml"))
    profile = profiles.profile(profile_name)
    if profile.flow is not OAuthFlow.ENTRA_DEVICE_CODE:
        raise ValueError("selected OAuth profile is not an Entra device-code flow")
    provider = profile.build_provider(environ=os.environ)
    if not isinstance(provider, EntraDeviceCodeProvider):
        raise TypeError("OAuth profile did not construct a device-code provider")

    def display_challenge(challenge: object) -> None:
        message = getattr(challenge, "message", "")
        verification_uri = getattr(challenge, "verification_uri", "")
        user_code = getattr(challenge, "user_code", "")
        display = message or f"Open {verification_uri} and enter code {user_code}"
        print(_terminal_field(display))

    provider.set_challenge_callback(display_challenge)
    token = provider.get_token()
    path = write_token_file(token_file, token)
    print(f"wrote restricted token file: {path}")
    print(f"expires: {token.expires_at.isoformat()}")
    return 0


def _demo() -> int:
    """Run the complete credential-free demonstration outside the source tree."""

    require_persistent_state_platform()
    workspace = _new_demo_workspace()
    artifacts = workspace / "artifacts"
    state = workspace / "state"
    atomic = get_atomic_publication_recovery_backend()
    if atomic.backend_id == "windows-handle-atomic-state":
        atomic.ensure_private_directory(artifacts)
        atomic.ensure_private_directory(state)
    else:
        workspace.chmod(0o700)
        artifacts.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
    database = state / "audit.sqlite3"

    print("mode: safe local demonstration (no credentials or provider writes)")
    print(f"demo workspace: {workspace}")
    status = _draft_package(
        workflow_path=None,
        output_dir=artifacts,
        database=database,
    )
    if status != 0:
        return status
    return _audit_verify(database)


def _new_demo_workspace() -> Path:
    """Create the private, unpredictable root used by the safe demonstration."""

    require_persistent_state_platform()
    product_root = current_user_product_root()
    atomic = get_atomic_publication_recovery_backend()
    if atomic.backend_id == "windows-handle-atomic-state":
        atomic.ensure_private_directory(product_root)
        return atomic.ensure_private_directory(
            product_root / f"demo-{secrets.token_hex(16)}"
        )
    product_root.parent.mkdir(mode=0o700, exist_ok=True)
    product_root.mkdir(mode=0o700, exist_ok=True)
    with PinnedDirectory.open(product_root) as pinned_root:
        workspace = Path(
            tempfile.mkdtemp(prefix="demo-", dir=pinned_root.path)
        ).resolve(strict=True)
        pinned_root.validate()
    return workspace


def _draft_package(
    *,
    workflow_path: Path | None,
    output_dir: Path,
    database: Path,
) -> int:
    """Generate all Phase 3 artifacts locally without provider writes."""

    require_persistent_state_platform()
    with ExitStack() as resources:
        output_directory = resources.enter_context(PinnedDirectory.open(output_dir))
        database_parent = resources.enter_context(
            PinnedDirectory.open(database.expanduser().absolute().parent)
        )
        if output_directory.object_identity == database_parent.object_identity:
            raise ConfigurationError(
                "draft artifact and audit database directories must be distinct"
            )
        if output_directory.object_identity.platform == "windows":
            atomic = get_atomic_publication_recovery_backend()
            resources.enter_context(
                atomic.open_transaction(
                    Path(
                        str(output_directory.path).rstrip("\\")
                        + "\\.master-agent-draft-package"
                    ),
                    max_bytes=0,
                    create=True,
                )
            )
            output_names = tuple(
                name
                for name in output_directory.list_children()
                if not _is_windows_atomic_metadata_name(name)
            )
        else:
            get_cross_process_locking_backend().acquire(
                output_directory.fileno(),
                mode=LockMode.EXCLUSIVE,
            )
            output_names = tuple(os.listdir(output_directory.fileno()))
        if output_names:
            raise ConfigurationError(
                "draft artifact directory must be empty; use a fresh directory"
            )
        canonical_database = database_parent.path / database.name
        settings = DraftPackageSettings.from_toml(
            resolve_config_source(workflow_path, "draft-package.toml")
        )
        plan = build_draft_package_plan(settings)
        capability_catalog = CapabilityCatalog.from_toml(
            resolve_config_source(None, "capabilities.toml")
        )
        artifact_budget = ArtifactBudget()
        registry = build_draft_registry(
            output_directory,
            catalog=capability_catalog,
            artifact_budget=artifact_budget,
        )
        for connector in registry.connectors():
            if isinstance(connector, ClosableConnector):
                resources.callback(connector.close)
        audit = AuditLog(canonical_database, parent_directory=database_parent)
        resources.callback(audit.close)
        report = _orchestrator(
            registry,
            canonical_database,
            capabilities=capability_catalog,
            audit=audit,
        ).run(plan, dry_run=False)
        artifacts = render_draft_package(
            report,
            output_dir=output_directory,
            artifact_budget=artifact_budget,
        )
        _print_report(report, mode_label="local generation")
        print(f"summary: {artifacts.summary_markdown}")
        print(f"manifest: {artifacts.manifest_json}")
        return 0 if report.successful else 2


def _compensation_plan(
    *,
    plan_path: Path,
    report_path: Path,
    created_by: str,
    output: Path,
) -> int:
    """Build a separately approvable plan from persisted compensation metadata."""

    require_persistent_state_platform()
    original = _load_plan(plan_path)
    raw = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise StructuredDataTypeError("run report must be a JSON object")
    report = RunReport.from_dict(raw)
    if (
        report.plan_id != original.plan_id
        or report.plan_fingerprint != original.fingerprint
    ):
        raise ValueError("run report does not belong to the supplied immutable plan")
    plan = build_compensation_plan(original, report, created_by=created_by)
    _write_json(output, plan.to_dict())
    print(f"wrote {output}")
    print(f"plan fingerprint: {plan.fingerprint}")
    return 0


def _recurring_status(
    *,
    recurring_path: Path | None,
    output: Path | None,
) -> int:
    """Report due state for every registered Phase 6 workflow."""

    config = RecurringConfig.from_toml(
        resolve_config_source(recurring_path, "recurring.toml")
    )
    runner = RecurringRunner(config)
    records = [
        runner.due_status(workflow).to_dict() for workflow in config.workflows.values()
    ]
    for record in records:
        name = _terminal_field(record["name"], max_characters=160)
        reason = _terminal_field(record["reason"])
        print(
            f"{name:<28} enabled={record['enabled']!s:<5} "
            f"due={record['due']!s:<5} {reason}"
        )
    if output is not None:
        _write_json(
            output,
            {"schema": "master-agent/recurring-status@1", "workflows": records},
        )
        print(f"wrote {output}")
    return 0


def _recurring_bind(
    *,
    name: str,
    occurrence_text: str,
    plan_path: Path,
    recurring_path: Path,
    approval_authorities: Path,
    capabilities_path: Path | None,
    governance_path: Path | None,
    policy_path: Path | None,
    sources_of_truth_path: Path | None,
    organization_profile_path: Path | None,
    credential_mappings: Sequence[str],
    connector_urls: Sequence[str],
    output: Path,
) -> int:
    """Publish and trusted-state-register one exact occurrence artifact."""

    require_persistent_state_platform()
    try:
        requested = datetime.fromisoformat(occurrence_text)
    except ValueError as error:
        raise ValueError("--occurrence must be an ISO local wall time") from error
    if requested.tzinfo is not None:
        raise ValueError("--occurrence must omit an offset; the registration owns it")
    recurring_source = resolve_config_source(recurring_path, "recurring.toml")
    config = RecurringConfig.from_toml(recurring_source)
    try:
        workflow = config.workflows[name]
    except KeyError as error:
        raise ConfigurationError(
            f"recurring workflow is not registered: {name}"
        ) from error
    plan = _load_plan(plan_path)
    if plan.execution_context is None or plan.execution_context.runtime is None:
        raise ConfigurationError("recurring-bind requires a bind-context plan")
    runtime = plan.execution_context.runtime
    bound_names = {item.name for item in runtime.configurations}
    if "approval_authorities" not in bound_names:
        raise ConfigurationError(
            "recurring-bind requires a plan bound with --approval-authorities"
        )
    invocation = ApprovalRunInvocation.capture(
        plan_path=plan_path,
        approval_paths=(),
        approval_authorities=approval_authorities,
        database=Path(runtime.audit_database),
        connector_mode=runtime.connector_mode,
        integrations=workflow.integration_config,
        result_json=_optional_path(runtime.result_json),
        retention=workflow.retention_config,
        evidence_type=runtime.evidence_type or "run-result/full",
        identities=workflow.identity_config,
        include_writes=runtime.include_writes,
        include_communications=runtime.include_communications,
        workspace_root=_optional_path(runtime.workspace_root),
        draft_output_dir=Path(runtime.artifact_root),
        capabilities=capabilities_path,
        governance=governance_path,
        policy=policy_path,
        sources_of_truth=sources_of_truth_path,
        plugin_names=(),
        plugin_lock=None,
        credentials_file=_optional_path(runtime.credential_file),
        credential_mappings=credential_mappings,
        connector_urls=connector_urls,
        organization_profile=organization_profile_path,
        recurring_config=recurring_path,
    )
    occurrence = bind_local_occurrence(
        config=config,
        workflow_name=name,
        requested_local_time=requested,
        plan=plan,
        invocation=invocation,
        output=output,
    )
    print(f"wrote {output.expanduser().resolve(strict=False)}")
    print(f"occurrence fingerprint: {occurrence.fingerprint}")
    print(f"execution key: {occurrence.execution_key}")
    return 0


def _recurring_inspect(
    *,
    artifact_path: Path,
    expected_fingerprint: str | None,
) -> int:
    """Inspect one occurrence without consulting credentials, providers, or state."""

    occurrence = load_occurrence(artifact_path)
    _require_occurrence_fingerprint(occurrence, expected_fingerprint)
    print(json.dumps(occurrence_summary(occurrence), indent=2, sort_keys=True))
    print(
        "This artifact authenticates only through separately configured trusted "
        "state; it is not approval."
    )
    return 0


def _recurring_recover(
    *,
    artifact_path: Path,
    recurring_path: Path,
    expected_fingerprint: str,
) -> int:
    """Explicitly permit retry of one authenticated pre-effect failure."""

    require_persistent_state_platform()
    occurrence = load_occurrence(artifact_path)
    _require_occurrence_fingerprint(occurrence, expected_fingerprint)
    config = RecurringConfig.from_toml(
        resolve_config_source(recurring_path, "recurring.toml")
    )
    store = authenticate_occurrence(occurrence, config=config)
    try:
        store.mark_occurrence_recoverable(
            artifact_fingerprint=occurrence.fingerprint,
        )
    finally:
        store.close()
    print(f"recovery authorized for occurrence: {occurrence.fingerprint}")
    print("Only the same authenticated artifact may now be reserved again.")
    return 0


def _recurring_reconcile(
    *,
    artifact_path: Path,
    recurring_path: Path,
    expected_fingerprint: str,
) -> int:
    """Conservatively reconcile an expired attempt from exact audit state."""

    require_persistent_state_platform()
    occurrence = load_occurrence(artifact_path)
    _require_occurrence_fingerprint(occurrence, expected_fingerprint)
    config = RecurringConfig.from_toml(
        resolve_config_source(recurring_path, "recurring.toml")
    )
    store = authenticate_occurrence(
        occurrence,
        config=config,
        allow_approval_resume=True,
    )
    audit_path = Path(occurrence.invocation.database)
    audit: AuditLog | None = None
    try:
        status = OccurrenceStatus.INDETERMINATE
        if audit_path.exists():
            audit = AuditLog(audit_path)
            chain_valid, _chain_message = audit.verify_chain()
            if chain_valid:
                outcomes = tuple(
                    audit.idempotency_outcome(
                        action.idempotency_key,
                        action_fingerprint=action.effect_fingerprint,
                    )
                    for action in occurrence.plan.actions
                    if action.risk
                    not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
                )
                uncertain = {
                    IdempotencyClaimState.IN_PROGRESS,
                    IdempotencyClaimState.INDETERMINATE,
                    IdempotencyClaimState.CONFLICT,
                }
                if not any(outcome in uncertain for outcome in outcomes):
                    status = OccurrenceStatus.RECOVERABLE
        store.reconcile_expired_occurrence(
            artifact_fingerprint=occurrence.fingerprint,
            status=status,
        )
    finally:
        if audit is not None:
            audit.close()
        store.close()
    print(f"reconciled occurrence as: {status}")
    if status is OccurrenceStatus.RECOVERABLE:
        print("Exact idempotency records permit a fenced re-run and re-verification.")
        return 0
    print("An effect may be in flight; provider-specific reconciliation is required.")
    return 2


def _recurring_cancel(
    *,
    artifact_path: Path,
    recurring_path: Path,
    expected_fingerprint: str,
) -> int:
    """Cancel one trusted pending occurrence without opening credentials."""

    require_persistent_state_platform()
    occurrence = load_occurrence(artifact_path)
    _require_occurrence_fingerprint(occurrence, expected_fingerprint)
    if Path(occurrence.invocation.recurring_config or "") != recurring_path.resolve():
        raise ConfigurationError("recurring configuration path changed")
    config = RecurringConfig.from_toml(
        resolve_config_source(recurring_path, "recurring.toml")
    )
    if str(config.state_database.parent) != occurrence.roots["claim"]:
        raise ConfigurationError("recurring claim root changed")
    store = RecurringStateStore(config.state_database)
    try:
        store.authenticate_occurrence_artifact(
            workflow_name=occurrence.workflow_name,
            scheduled_at=occurrence.scheduled_at,
            artifact_fingerprint=occurrence.fingerprint,
            artifact_sha256=occurrence.artifact_sha256,
            registration_digest=occurrence.registration_digest,
            execution_key=occurrence.execution_key,
        )
        status = store.cancel_occurrence(
            artifact_fingerprint=occurrence.fingerprint,
        )
    finally:
        store.close()
    print(f"recurring occurrence cancellation state: {status}")
    return 0 if status is OccurrenceStatus.CANCELLED else 2


def _recurring_apply(
    *,
    artifact_path: Path,
    recurring_path: Path,
    apply: bool,
    approval_paths: Sequence[Path],
    expected_fingerprint: str | None,
    approval_request: ApprovalRequest | None = None,
) -> int:
    """Inspect or execute one authenticated exact occurrence."""

    occurrence = load_occurrence(artifact_path)
    _require_occurrence_fingerprint(occurrence, expected_fingerprint)
    if not apply:
        if approval_paths:
            raise ValueError("--approval requires --apply")
        print(json.dumps(occurrence_summary(occurrence), indent=2, sort_keys=True))
        print("mode: dry-run (no claim, audit, credential, provider, or output access)")
        return 0

    require_persistent_state_platform()
    invocation = occurrence.invocation
    if invocation.recurring_config is None:
        raise ConfigurationError("recurring occurrence omitted its trusted config path")
    selected_config = recurring_path.expanduser().resolve(strict=False)
    if selected_config != Path(invocation.recurring_config):
        raise ConfigurationError("recurring configuration path changed")
    config = RecurringConfig.from_toml(
        resolve_config_source(recurring_path, "recurring.toml")
    )
    resume = approval_request is not None
    store = authenticate_occurrence(
        occurrence,
        config=config,
        allow_approval_resume=resume,
    )
    now = datetime.now(UTC)
    if approval_request is None:
        generation, token = store.reserve_occurrence(
            artifact_fingerprint=occurrence.fingerprint,
            started_at=now,
        )
    else:
        approval_request.validate_plan(occurrence.plan)
        request_run = approval_request.run
        if (
            request_run.recurring_occurrence
            != str(artifact_path.expanduser().resolve(strict=False))
            or request_run.recurring_fingerprint != occurrence.fingerprint
            or request_run.recurring_claim_generation is None
        ):
            store.close()
            raise ConfigurationError("approval request recurring occurrence changed")
        generation, token = store.resume_approval_blocked_occurrence(
            artifact_fingerprint=occurrence.fingerprint,
            prior_generation=request_run.recurring_claim_generation,
            request_fingerprint=approval_request.fingerprint,
            started_at=now,
        )

    stop_heartbeat = Event()
    heartbeat_errors: list[BaseException] = []
    effect_started = False
    local_output_started = False
    transitioned = False
    report_observed = False

    def heartbeat() -> None:
        interval = max(store._lease_duration.total_seconds() / 3, 0.1)
        while not stop_heartbeat.wait(interval):
            try:
                if not store.renew_occurrence_fence(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=generation,
                    claim_token=token,
                ):
                    raise ConfigurationError(
                        "recurring occurrence claim fence was lost"
                    )
            except (OSError, sqlite3.Error, ConfigurationError) as error:
                heartbeat_errors.append(error)
                return

    heartbeat_thread = Thread(target=heartbeat, daemon=True)
    heartbeat_thread.start()

    def pre_effect_guard(_action: AgentAction) -> None:
        nonlocal effect_started
        if heartbeat_errors:
            raise ConfigurationError(
                "recurring occurrence lease could not be renewed"
            ) from heartbeat_errors[0]
        fresh = RecurringConfig.from_toml(
            resolve_config_source(recurring_path, "recurring.toml")
        )
        try:
            workflow = fresh.workflows[occurrence.workflow_name]
        except KeyError as error:
            raise ConfigurationError("recurring registration disappeared") from error
        if (
            not workflow.enabled
            or workflow.revoked
            or registration_snapshot(workflow) != occurrence.registration
        ):
            raise ConfigurationError("recurring registration changed before effect")
        if current_runtime_identity() != occurrence.runtime_identity:
            raise ConfigurationError("recurring runtime changed before effect")
        if datetime.now(UTC) > occurrence.approval_resume_deadline:
            raise ConfigurationError("recurring approval-resume deadline expired")
        store.validate_occurrence_fence(
            artifact_fingerprint=occurrence.fingerprint,
            claim_generation=generation,
            claim_token=token,
        )
        effect_started = True

    def observe_report(
        report: RunReport,
        request: ApprovalRequest | None,
    ) -> None:
        nonlocal local_output_started, transitioned, report_observed
        report_observed = True
        stop_heartbeat.set()
        heartbeat_thread.join()
        by_action_id = {action.action_id: action for action in occurrence.plan.actions}
        local_output_started = any(
            item.state is ActionState.VERIFIED
            and by_action_id[item.action_id].risk is RiskLevel.LOCAL_GENERATION
            for item in report.actions
        )
        pending = any(
            item.state is ActionState.APPROVAL_REQUIRED for item in report.actions
        )
        if pending:
            if request is None:
                raise ConfigurationError(
                    "recurring approval-blocked run did not publish an exact request"
                )
            store.block_occurrence_for_approval(
                artifact_fingerprint=occurrence.fingerprint,
                claim_generation=generation,
                claim_token=token,
                request_fingerprint=request.fingerprint,
            )
            transitioned = True
            return
        fresh = RecurringConfig.from_toml(
            resolve_config_source(recurring_path, "recurring.toml")
        )
        try:
            fresh_workflow = fresh.workflows[occurrence.workflow_name]
        except KeyError as error:
            raise ConfigurationError("recurring registration disappeared") from error
        if registration_snapshot(fresh_workflow) != occurrence.registration:
            raise ConfigurationError("recurring registration changed before output")
        if (
            report.successful
            and fresh_workflow.kind is WorkflowKind.WEEKLY_OPERATING_REVIEW
        ):
            settings = WeeklyOperatingReviewSettings.from_toml(
                resolve_config_source(
                    fresh_workflow.workflow_config,
                    "weekly-operating-review.toml",
                )
            )
            render_weekly_operating_review(
                report,
                settings,
                output_root=Path(occurrence.roots["artifact"]),
                execution_key=occurrence.execution_key,
            )
            local_output_started = True
        status = (
            OccurrenceStatus.SUCCEEDED
            if report.successful
            else OccurrenceStatus.INDETERMINATE
            if any(item.state is ActionState.INDETERMINATE for item in report.actions)
            or effect_started
            or local_output_started
            else OccurrenceStatus.FAILED_PRE_EFFECT
        )
        store.finalize_occurrence(
            artifact_fingerprint=occurrence.fingerprint,
            claim_generation=generation,
            claim_token=token,
            status=status,
        )
        transitioned = True

    try:
        status = _run(
            plan_path=Path(invocation.plan_path),
            apply=True,
            approval_paths=[
                Path(path)
                for path in (
                    *invocation.approval_paths,
                    *(str(path) for path in approval_paths),
                )
            ],
            approval_authorities=Path(invocation.approval_authorities),
            database=Path(invocation.database),
            connector_mode=invocation.connector_mode,
            integrations_path=_optional_path(invocation.integrations),
            result_json=_optional_path(invocation.result_json),
            retention_path=_optional_path(invocation.retention),
            evidence_type=invocation.evidence_type,
            identities_path=_optional_path(invocation.identities),
            include_writes=invocation.include_writes,
            include_communications=invocation.include_communications,
            workspace_root=_optional_path(invocation.workspace_root),
            draft_output_dir=Path(invocation.draft_output_dir),
            capabilities_path=_optional_path(invocation.capabilities),
            governance_path=_optional_path(invocation.governance),
            policy_path=_optional_path(invocation.policy),
            sources_of_truth_path=_optional_path(invocation.sources_of_truth),
            plugin_names=list(invocation.plugin_names),
            plugin_lock_path=_optional_path(invocation.plugin_lock),
            credentials_file=_optional_path(invocation.credentials_file),
            credential_mappings=invocation.credential_mappings,
            connector_urls=invocation.connector_urls,
            organization_profile_path=_optional_path(invocation.organization_profile),
            loaded_plan=occurrence.plan,
            expected_plan_fingerprint=occurrence.plan.fingerprint,
            pre_effect_guard=pre_effect_guard,
            report_observer=observe_report,
            recurring_occurrence_path=artifact_path,
            recurring_fingerprint=occurrence.fingerprint,
            recurring_claim_generation=generation,
            recurring_config_path=recurring_path,
        )
        if not report_observed:
            raise RuntimeError("recurring governed run did not report its outcome")
        return status
    except BaseException:
        stop_heartbeat.set()
        heartbeat_thread.join()
        if not transitioned:
            terminal = (
                OccurrenceStatus.INDETERMINATE
                if effect_started or local_output_started
                else OccurrenceStatus.FAILED_PRE_EFFECT
            )
            try:
                store.finalize_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=generation,
                    claim_token=token,
                    status=terminal,
                )
            except ConfigurationError:
                pass
        raise
    finally:
        store.close()


def _require_occurrence_fingerprint(
    occurrence: RecurringOccurrence,
    expected: str | None,
) -> None:
    if expected is not None and expected != occurrence.fingerprint:
        raise ValueError("occurrence fingerprint does not match --expected-fingerprint")


def _recurring_run(
    *,
    name: str,
    recurring_path: Path | None,
    connector_mode: str,
    force: bool,
) -> int:
    """Execute one immutable, registered, local-output recurring workflow."""

    _reject_non_manifest_execution("recurring-run")

    config = RecurringConfig.from_toml(
        resolve_config_source(recurring_path, "recurring.toml")
    )
    runner = RecurringRunner(config)

    def callback(workflow: RegisteredWorkflow) -> RecurringRunResult:
        result = _execute_registered_workflow(workflow, connector_mode=connector_mode)
        return RecurringRunResult(
            successful=result[0],
            summary=result[1],
        )

    result = runner.run(name, callback, force=force)
    print(json.dumps(dict(result.summary), indent=2, default=str))
    return 0 if result.successful else 2


def _execute_registered_workflow(
    workflow: RegisteredWorkflow,
    *,
    connector_mode: str,
) -> tuple[bool, dict[str, object]]:
    """Execute one allowlisted built-in recurring workflow implementation."""

    _reject_non_manifest_execution("recurring-run")

    if workflow.kind is WorkflowKind.WEEKLY_STATUS_PACKAGE:
        integrations = IntegrationConfig.from_toml(workflow.integration_config)
        weekly_settings = WeeklyStatusSettings.from_toml(workflow.workflow_config)
        plan = build_weekly_status_read_plan(
            weekly_settings,
            bitbucket_deployment=integrations.connector("bitbucket").deployment,
        )
        validate_plan_scope(tuple(item.capability for item in plan.actions), workflow)
        capability_catalog = CapabilityCatalog.from_toml(
            resolve_config_source(None, "capabilities.toml")
        )
        if connector_mode == "mock":
            registry = _mock_read_registry(plan, capability_catalog)
        else:
            registry = build_live_registry(
                integrations,
                environ=os.environ,
                systems={"jira", "confluence", "bitbucket"},
            )
            _require_systems(
                registry,
                {"jira", "confluence", "bitbucket"},
                workflow.name,
            )
        database = workflow.output_dir / "audit.sqlite3"
        report = _orchestrator(
            registry,
            database,
            capabilities=capability_catalog,
        ).run(plan, dry_run=False)
        artifacts = render_weekly_status_package(
            report,
            weekly_settings,
            output_dir=workflow.output_dir,
        )
        return report.successful, {
            "workflow": workflow.name,
            "kind": str(workflow.kind),
            "successful": report.successful,
            "output_dir": str(workflow.output_dir),
            "manifest": str(artifacts.manifest_json),
            "powerpoint": str(artifacts.powerpoint),
        }

    if workflow.kind is WorkflowKind.COMMUNICATION_CONTEXT_PACKAGE:
        if workflow.identity_config is None or workflow.retention_config is None:
            raise ValueError(
                "communication context workflow requires identity and retention config"
            )
        integrations = IntegrationConfig.from_toml(workflow.integration_config)
        context_settings = CommunicationContextSettings.from_toml(
            workflow.workflow_config
        )
        identities = IdentityRegistry.from_toml(workflow.identity_config)
        retention = RetentionConfig.from_toml(workflow.retention_config)
        plan = build_communication_context_plan(context_settings, identities)
        validate_plan_scope(tuple(item.capability for item in plan.actions), workflow)
        capability_catalog = CapabilityCatalog.from_toml(
            resolve_config_source(None, "capabilities.toml")
        )
        if connector_mode == "mock":
            registry = _mock_read_registry(plan, capability_catalog)
            registry.register(IdentityMapConnector(identities))
        else:
            registry = build_live_registry(
                integrations,
                environ=os.environ,
                systems={"outlook", "teams"},
            )
            registry.register(IdentityMapConnector(identities))
            _require_systems(registry, {"identity", "outlook", "teams"}, workflow.name)
        database = workflow.output_dir / "audit.sqlite3"
        report = _orchestrator(
            registry,
            database,
            capabilities=capability_catalog,
        ).run(plan, dry_run=False)
        context_artifacts = render_communication_context_package(
            report,
            context_settings,
            output_dir=workflow.output_dir,
            retention=retention,
        )
        return report.successful, {
            "workflow": workflow.name,
            "kind": str(workflow.kind),
            "successful": report.successful,
            "output_dir": str(workflow.output_dir),
            "manifest": str(context_artifacts.manifest_json),
        }

    raise ValueError(f"unsupported recurring workflow kind: {workflow.kind}")


def _mock_read_registry(
    plan: ChangePlan,
    catalog: CapabilityCatalog,
) -> ConnectorRegistry:
    """Build one exact schema-shaped mock connector per planned capability."""

    grouped: dict[tuple[str, str], dict[str, dict[str, object]]] = {}
    for action in plan.actions:
        if (
            action.target.system == "identity"
            or action.risk is RiskLevel.LOCAL_GENERATION
        ):
            continue
        system = action.target.system
        definition = catalog.definition(action.capability)
        resources = grouped.setdefault((system, action.capability), {})
        version = action.target.expected_version or "1"
        if action.risk is not RiskLevel.READ_ONLY:
            if action.target.expected_version is not None:
                resources[action.target.resource_id] = {"version": version}
            continue
        payload = _synthetic_mock_read_payload(action, definition)
        if action.capability == "jira.issue.search":
            payload.update(
                {
                    "schema": "master-agent/jira-issues@1",
                    "issues": [],
                    "source_urls": [],
                }
            )
        elif action.capability == "bitbucket.pull_request.search":
            payload.update(
                {
                    "schema": "master-agent/bitbucket-pull-requests@1",
                    "pull_requests": [],
                    "source_urls": [],
                }
            )
        elif action.capability == "confluence.page.read":
            payload.update(
                {
                    "schema": "master-agent/confluence-page@1",
                    "page": {
                        "id": action.target.resource_id,
                        "title": "Synthetic project status",
                        "body_text": "Synthetic read-only recurring-workflow evidence.",
                        "version": version,
                    },
                    "source_urls": [],
                }
            )
        elif action.capability == "outlook.message.search":
            payload.update(
                {
                    "schema": "master-agent/outlook-messages@1",
                    "messages": [],
                    "citations": [],
                }
            )
        elif action.capability == "teams.chat.list":
            payload.update(
                {"schema": "master-agent/teams-chats@1", "chats": [], "citations": []}
            )
        elif action.capability == "teams.team.list":
            payload.update(
                {"schema": "master-agent/teams-teams@1", "teams": [], "citations": []}
            )
        resources[action.target.resource_id] = payload
    registry = ConnectorRegistry()
    for (system, capability), resources in sorted(grouped.items()):
        registry.register(
            MockConnector(
                system,
                resources,
                capabilities={capability},
            )
        )
    return registry


def _synthetic_mock_read_payload(
    action: AgentAction,
    definition: CapabilityDefinition,
) -> dict[str, object]:
    """Synthesize one harmless payload from the capability's exact contract."""

    if not definition.read_result_schema or not definition.read_result_resources:
        raise ConfigurationError(
            f"mock provider read {definition.name} has no read result contract"
        )
    payload: dict[str, object] = {"schema": definition.read_result_schema}
    for name, descriptor in definition.read_result_resources.items():
        if descriptor == "object":
            payload[name] = {}
        elif descriptor == "object_list":
            payload[name] = []
        elif descriptor == "value":
            payload[name] = False if name == "reachable" else "synthetic"
        else:  # pragma: no cover - catalog construction enforces this invariant.
            raise ConfigurationError(
                f"mock provider read {definition.name} has an invalid resource type"
            )
    for name in definition.read_result_metadata:
        if name == "source_urls":
            payload[name] = []
        elif name == "retention":
            payload[name] = {
                "content_kind": "synthetic",
                "evidence_type": "mock.provider.read",
                "persistence_requires_explicit_output": True,
            }
        elif name == "repository":
            payload[name] = {
                "name": "synthetic",
                "owner": "synthetic",
                "slug": "synthetic",
            }
        elif name in {"returned", "total"}:
            payload[name] = 0
        elif name == "members_may_be_truncated":
            payload[name] = False
        elif name == "system":
            payload[name] = action.target.system
        elif name == "deployment":
            payload[name] = "mock"
        else:
            payload[name] = "synthetic"
    return payload


def _discover(
    *,
    integrations_path: Path | None,
    governance_path: Path | None,
    credentials_file: Path | None,
    probe: bool,
    require_ready: bool,
    systems: set[str] | None,
    data_classification: DataClassification | None,
    output: Path | None,
) -> int:
    if output is not None:
        require_persistent_state_platform()
    config = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
    )
    if probe:
        preflight_probe_provider_egress(
            config,
            governance=governance,
            systems=systems,
            data_classification=data_classification,
        )
    credential_store = _load_credential_store(
        credentials_file,
        integrations=config,
        governance=governance,
        connector_mode="live",
        systems=systems,
    )
    configurations = (
        _configuration_names_for_systems(systems)
        if systems is not None
        else set(config.connectors)
    )
    records = discover_integrations(
        config,
        environ=_credential_environment(
            credential_store,
            os.environ,
            declared_names=config.credential_environment_variables(),
            compatible_names=_atlassian_credential_compatibility(
                config,
                configurations=configurations,
            ),
        ),
        probe=probe,
        systems=systems,
        governance=governance,
        data_classification=data_classification,
    )
    payload = {
        "schema": "master-agent/discovery@1",
        "records": [record.to_dict() for record in records],
    }
    for record in records:
        status = _terminal_field(record.status, max_characters=80)
        system = _terminal_field(record.system, max_characters=80)
        deployment = _terminal_field(record.deployment, max_characters=80)
        missing = _terminal_field(
            ",".join(record.missing_environment) or "-",
            max_characters=320,
        )
        print(
            f"{status:<20} {system:<12} deployment={deployment:<11} missing={missing}"
        )
        if record.error_message:
            error_type = _terminal_field(record.error_type, max_characters=80)
            error_message = _terminal_field(record.error_message)
            print(f"  {error_type}: {error_message}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    # Discovery is primarily an onboarding/reporting command.  Missing
    # credentials are expected before a provider is connected and should not
    # make a normal inventory command look broken.  CI/readiness checks can
    # request the former strict exit semantics explicitly; live probes remain
    # strict because a requested network operation did not complete.
    unavailable = {DiscoveryStatus.FAILED}
    if require_ready or probe:
        unavailable.add(DiscoveryStatus.MISSING_ENVIRONMENT)
    return 0 if all(record.status not in unavailable for record in records) else 2


def _connect(
    *,
    integrations_path: Path | None,
    governance_path: Path | None,
    credentials_file: Path | None,
    systems: set[str],
    output: Path | None,
    transport: HttpTransport | None = None,
    credential_mappings: tuple[str, ...] = (),
    connector_urls: tuple[str, ...] = (),
    data_classification: DataClassification | None = None,
) -> int:
    """Verify requested read connectors through an ephemeral configuration."""

    if output is not None:
        require_persistent_state_platform()
    _reject_output_aliases(
        output,
        credentials_file,
        integrations_path,
        governance_path,
    )
    if not systems:
        raise ConfigurationError("--systems must contain at least one system")
    unknown = sorted(systems - set(_CONNECT_CONFIGURATION_BY_SYSTEM))
    if unknown:
        raise ConfigurationError(
            "unsupported connection system(s): " + ", ".join(unknown)
        )
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
    )
    configurations = _configuration_names_for_systems(systems)
    integrations = _with_connector_url_overrides(
        integrations,
        connector_urls,
        selected_configurations=configurations,
    )
    connectors = dict(integrations.connectors)
    for name in configurations:
        unresolved = integrations.connector(name)
        if is_placeholder_provider_url(unresolved.effective_base_url(os.environ)):
            raise ConfigurationError(
                f"connector {name} still uses a placeholder provider URL; supply "
                "the organization's reviewed integrations file"
            )
        replace(unresolved, enabled=True).resolve_execution_target(os.environ)
        extra = dict(unresolved.extra)
        if name == "microsoft" and "onenote" in systems:
            extra["onenote_read_enabled"] = True
        connectors[name] = replace(unresolved, enabled=True, extra=extra)
    effective = IntegrationConfig(
        connectors=connectors,
        network_profiles=integrations.network_profiles,
        source_sha256=integrations.source_sha256,
    )

    preflight_probe_provider_egress(
        effective,
        governance=governance,
        systems=systems,
        data_classification=data_classification,
    )

    credential_compatibility = _atlassian_credential_compatibility(
        effective,
        configurations=configurations,
    )

    store = _load_credential_store(
        credentials_file,
        integrations=effective,
        governance=governance,
        connector_mode="live",
        credential_mappings=credential_mappings,
        systems=systems,
    )
    ambient: Mapping[str, str] = os.environ
    if store is not None and store.path is not None:
        # Preserve the existing connect-only JSON override behavior. Other
        # JSON consumers retain their collision check, and native configured
        # providers apply their explicit reviewed precedence in ``overlay``.
        ambient = {
            name: value for name, value in os.environ.items() if name not in store.names
        }
    environ = _credential_environment(
        store,
        ambient,
        declared_names=effective.credential_environment_variables(),
        compatible_names=credential_compatibility,
    )

    if "microsoft" in configurations:
        microsoft = effective.connector("microsoft")
        extra = dict(microsoft.extra)
        token_file_env = str(extra.get("token_file_env", ""))
        client_environment = tuple(
            str(extra.get(key, ""))
            for key in ("tenant_id_env", "client_id_env", "client_secret_env")
        )
        if token_file_env and environ.get(token_file_env):
            extra["oauth_flow"] = "token_file"
            microsoft = replace(
                microsoft,
                auth_mode=AuthMode.OAUTH_DELEGATED,
                extra=extra,
            )
        elif microsoft.secret_env and environ.get(microsoft.secret_env):
            extra["oauth_flow"] = "environment"
            identity_mode = str(extra.get("identity_mode", "delegated")).lower()
            microsoft = replace(
                microsoft,
                auth_mode=(
                    AuthMode.OAUTH_APPLICATION
                    if identity_mode == "application"
                    else AuthMode.OAUTH_DELEGATED
                ),
                extra=extra,
            )
        elif all(name and environ.get(name) for name in client_environment):
            extra["oauth_flow"] = "client_credentials"
            microsoft = replace(
                microsoft,
                auth_mode=AuthMode.OAUTH_APPLICATION,
                extra=extra,
            )
        connectors = dict(effective.connectors)
        connectors["microsoft"] = microsoft
        effective = IntegrationConfig(
            connectors=connectors,
            network_profiles=effective.network_profiles,
            source_sha256=effective.source_sha256,
        )

    records = discover_integrations(
        effective,
        environ=environ,
        probe=True,
        transport=transport,
        systems=systems,
        governance=governance,
        data_classification=data_classification,
    )
    payload = {
        "schema": "master-agent/connection@1",
        "persistent_configuration_changed": False,
        "records": [record.to_dict() for record in records],
    }
    for record in records:
        system = _terminal_field(record.system, max_characters=80)
        if record.status is DiscoveryStatus.REACHABLE:
            print(f"connected: {system}")
        else:
            status = _terminal_field(record.status, max_characters=80)
            missing = _terminal_field(
                ",".join(record.missing_environment) or "-",
                max_characters=320,
            )
            print(f"not connected: {system} ({status}; missing={missing})")
            if record.error_message:
                error_type = _terminal_field(record.error_type, max_characters=80)
                error_message = _terminal_field(record.error_message)
                print(f"  {error_type}: {error_message}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return (
        0
        if records
        and all(record.status is DiscoveryStatus.REACHABLE for record in records)
        else 2
    )


def _reject_output_aliases(output: Path | None, *inputs: Path | None) -> None:
    """Prevent a report path from overwriting credentials or selected config."""

    if output is None:
        return
    output_path = output.expanduser().resolve(strict=False)
    for selected in inputs:
        if selected is not None and output_path == selected.expanduser().resolve(
            strict=False
        ):
            raise ConfigurationError(
                "connection output must not replace credentials or configuration"
            )


def _configuration_names_for_systems(systems: set[str]) -> set[str]:
    """Return configured connector names backing the selected runtime systems."""

    return {
        _CONNECT_CONFIGURATION_BY_SYSTEM[system]
        for system in systems
        if system in _CONNECT_CONFIGURATION_BY_SYSTEM
    }


def _supports_shared_atlassian_credentials(connector: ConnectorConfig) -> bool:
    """Return whether an Atlassian account email/API token can be attempted."""

    return (
        connector.system in {"jira", "confluence"}
        and connector.deployment is DeploymentType.CLOUD
        and connector.auth_mode is AuthMode.BASIC
    )


def _requires_product_specific_atlassian_token(
    connector: ConnectorConfig,
) -> bool:
    """Return whether cross-product API-token reuse must stay disabled."""

    # A dynamic API root is resolved only after the selected credential overlay
    # exists. Treat it conservatively because it may name a scoped gateway.
    if connector.base_url_env:
        return True

    return _uses_resolved_atlassian_gateway(connector)


def _uses_resolved_atlassian_gateway(connector: ConnectorConfig) -> bool:
    """Return whether the currently resolved API root is a scoped gateway."""

    try:
        parsed = urlsplit(connector.effective_base_url(os.environ))
    except ValueError:
        return False
    return (parsed.hostname or "").casefold().rstrip(
        "."
    ) == "api.atlassian.com" and parsed.path.rstrip("/").startswith(
        ("/ex/jira/", "/ex/confluence/")
    )


def _related_atlassian_configurations(
    integrations: IntegrationConfig,
    *,
    configurations: set[str],
) -> set[str]:
    """Select related credential labels without activating their connectors."""

    related: set[str] = set()
    for target_name, source_name in (
        ("jira", "confluence"),
        ("confluence", "jira"),
    ):
        if target_name not in configurations:
            continue
        if not {target_name, source_name} <= set(integrations.connectors):
            continue
        target = integrations.connector(target_name)
        source = integrations.connector(source_name)
        if _supports_shared_atlassian_credentials(
            target
        ) and _supports_shared_atlassian_credentials(source):
            related.add(source_name)
    return related


def _atlassian_credential_compatibility(
    integrations: IntegrationConfig,
    *,
    configurations: set[str],
) -> dict[str, str]:
    """Map compatible missing Jira/Confluence account credential names."""

    compatible: dict[str, str] = {}
    for target_name, source_name in (
        ("jira", "confluence"),
        ("confluence", "jira"),
    ):
        if target_name not in configurations:
            continue
        if not {target_name, source_name} <= set(integrations.connectors):
            continue
        target = integrations.connector(target_name)
        source = integrations.connector(source_name)
        if not (
            _supports_shared_atlassian_credentials(target)
            and _supports_shared_atlassian_credentials(source)
        ):
            continue
        compatible_fields = [(target.username_env, source.username_env)]
        if not (
            _requires_product_specific_atlassian_token(target)
            or _requires_product_specific_atlassian_token(source)
        ):
            compatible_fields.append((target.secret_env, source.secret_env))
        for destination, fallback in compatible_fields:
            if destination and fallback and destination != fallback:
                compatible[destination] = fallback
    return compatible


def _with_connector_url_overrides(
    integrations: IntegrationConfig,
    values: Sequence[str],
    *,
    selected_configurations: set[str],
) -> IntegrationConfig:
    """Apply validated Atlassian Cloud tenant origins without editing config."""

    if not values:
        return integrations
    overrides: dict[str, str] = {}
    for value in values:
        system, separator, raw_url = value.partition("=")
        system = system.strip().casefold()
        raw_url = raw_url.strip()
        if not separator or not system or not raw_url:
            raise ConfigurationError("--connector-url must use SYSTEM=URL")
        if system not in {"jira", "confluence"}:
            raise ConfigurationError(
                "--connector-url currently supports Jira and Confluence Cloud only"
            )
        if system not in selected_configurations:
            raise ConfigurationError(
                "--connector-url names an unselected connector: " + system
            )
        if system in overrides:
            raise ConfigurationError("--connector-url repeats connector: " + system)
        connector = integrations.connector(system)
        overrides[system] = _normalize_atlassian_cloud_url(connector, raw_url)

    connectors = dict(integrations.connectors)
    for system, web_base_url in overrides.items():
        connector = connectors[system]
        if _uses_resolved_atlassian_gateway(connector):
            connectors[system] = replace(
                connector,
                web_base_url=web_base_url,
            )
        else:
            connectors[system] = replace(
                connector,
                base_url=web_base_url,
                base_url_env=None,
                web_base_url=web_base_url,
            )
    return IntegrationConfig(
        connectors=connectors,
        network_profiles=integrations.network_profiles,
        source_sha256=integrations.source_sha256,
    )


def _normalize_atlassian_cloud_url(
    connector: ConnectorConfig,
    value: str,
) -> str:
    """Normalize an Atlassian Cloud UI or API URL to its tenant origin."""

    if connector.deployment is not DeploymentType.CLOUD:
        raise ConfigurationError(
            "--connector-url cannot infer an Atlassian Data Center context root"
        )
    if not value.isprintable():
        raise ConfigurationError("--connector-url must contain printable characters")
    parsed = urlsplit(value)
    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        raise ConfigurationError("--connector-url requires an HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("--connector-url must not contain credentials")
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError("--connector-url has an invalid port") from error
    if port not in {None, 443}:
        raise ConfigurationError("--connector-url must use the HTTPS default port")
    hostname = parsed.hostname.casefold().rstrip(".")
    if not hostname.endswith(".atlassian.net") or hostname == "atlassian.net":
        raise ConfigurationError(
            "--connector-url Cloud target must be an atlassian.net tenant"
        )
    return f"https://{hostname}"


def _provider_credential_aliases(
    integrations: IntegrationConfig,
    *,
    configurations: set[str],
    systems: set[str],
) -> dict[str, dict[str, str]]:
    aliases: dict[str, dict[str, str]] = {}
    for name in configurations:
        connector = integrations.connector(name)
        fields: dict[str, str] = {}
        if connector.secret_env:
            fields["token"] = connector.secret_env
        if connector.username_env:
            fields["username"] = connector.username_env
        for field, key in (
            ("token_file", "token_file_env"),
            ("token_expires_at", "token_expires_at_env"),
            ("tenant_id", "tenant_id_env"),
            ("client_id", "client_id_env"),
            ("client_secret", "client_secret_env"),
        ):
            destination = connector.extra.get(key)
            if isinstance(destination, str) and destination.strip():
                fields[field] = destination.strip()
        aliases[name] = fields
        for system in systems:
            if _CONNECT_CONFIGURATION_BY_SYSTEM[system] == name:
                aliases[system] = fields
    return aliases


def _parse_credential_mappings(values: tuple[str, ...]) -> dict[str, str]:
    """Parse secret-free one-run mappings for ambiguous credential keys."""

    mappings: dict[str, str] = {}
    for value in values:
        source, separator, destination = value.partition("=")
        source = source.strip()
        destination = destination.strip()
        if not separator or not source or not destination:
            raise ConfigurationError("--credential-map must use FILE_KEY=DECLARED_NAME")
        if source in mappings:
            raise ConfigurationError(
                "--credential-map repeats a credential file key: " + source
            )
        if not source.isprintable() or not destination.isprintable():
            raise ConfigurationError(
                "--credential-map names must contain only printable characters"
            )
        mappings[source] = destination
    return mappings


def _github_repositories(
    *,
    credentials_file: Path | None,
    limit: int,
    visibility: str | None,
    output: Path | None,
    username: str | None = None,
    transport: HttpTransport | None = None,
) -> int:
    """Complete public-user or authenticated GitHub repository discovery.

    The packaged GitHub connector is available but inactive at rest. This
    command selects only that read connector for the request. With a
    username it uses GitHub's anonymous public-user endpoint and never loads or
    sends a credential. Without a username it attests the provider identity and
    lists repositories visible to that authenticated account. Both paths
    validate a typed action through catalog, governance, and policy and
    independently re-read the result without changing persistent configuration.
    """

    if output is not None:
        raise ConfigurationError(
            "stateless provider shortcuts do not permit persisted output"
        )
    _reject_output_aliases(output, credentials_file)
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(None, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(None, "governance.toml")
    )
    github = replace(integrations.connector("github"), enabled=True)
    if limit <= 0 or limit > github.max_items:
        raise ConfigurationError(
            f"GitHub repository limit must be between 1 and {github.max_items}"
        )
    public_username = username.strip() if username is not None else None
    if public_username == "":
        raise ConfigurationError("GitHub username must not be empty")
    if public_username is not None and credentials_file is not None:
        raise ConfigurationError(
            "--credentials-file is unnecessary and not accepted with --username; "
            "public GitHub repositories are read anonymously"
        )
    if public_username is not None and visibility not in {None, "public"}:
        raise ConfigurationError(
            "--username lists public repositories only; omit --visibility or use "
            "--visibility public"
        )
    effective_visibility = visibility or (
        "public" if public_username is not None else "all"
    )
    if effective_visibility not in {"all", "public", "private"}:
        raise ConfigurationError(
            "GitHub repository visibility must be all, public, or private"
        )
    if public_username is not None:
        capability = "github.public_repository.list"
        resource_type = "public_repository_collection"
        resource_id = public_username
        parameters: dict[str, object] = {
            "limit": limit,
            "username": public_username,
        }
        classification = DataClassification.PUBLIC
        idempotency_key = f"github:public-repositories:{public_username}:{limit}"
        justification = (
            "List public repositories owned by the directly requested GitHub user."
        )
        goal = f"List public repositories owned by GitHub user {public_username}."
    else:
        capability = "github.repository.list"
        resource_type = "repository_collection"
        resource_id = "authenticated-user"
        parameters = {"limit": limit, "visibility": effective_visibility}
        classification = DataClassification.INTERNAL
        idempotency_key = f"github:repositories:{effective_visibility}:{limit}"
        justification = (
            "List repositories visible to the directly requesting authenticated "
            "GitHub user."
        )
        goal = "List repositories visible to the authenticated GitHub user."

    action = AgentAction(
        capability=capability,
        target=ResourceRef(
            system="github",
            resource_type=resource_type,
            resource_id=resource_id,
        ),
        parameters=parameters,
        risk=RiskLevel.READ_ONLY,
        data_classification=classification,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=idempotency_key,
        justification=justification,
    )
    plan = ChangePlan(
        goal=goal,
        actions=(action,),
        created_by="direct-user",
    )
    plan = bind_fast_path_governance(
        plan,
        current_behavior="repository visibility is not yet listed for this request",
        constraint="one bounded GitHub repository query is required",
        leverage_point="the typed read-only GitHub connector",
        success_metric="the bounded repository list is returned and verified",
        failure_condition="the provider read is denied, incomplete, or unverified",
    )
    catalog = CapabilityCatalog.from_toml(
        resolve_config_source(None, "capabilities.toml")
    )
    policy = PolicyEngine(
        PolicyConfig.from_toml(resolve_config_source(None, "policy.toml"))
    )
    catalog_ok, catalog_reason = catalog.validate_action(action)
    if not catalog_ok:
        raise ConfigurationError(catalog_reason)
    governance_ok, governance_reason = governance.validate_action(action)
    if not governance_ok:
        raise ConfigurationError(governance_reason)
    decision = policy.evaluate(
        plan,
        action,
        minimum_distinct_approvers=governance.minimum_approvers(action.capability),
    )
    if not decision.permitted or decision.approval_required:
        raise ConfigurationError(decision.reason)
    preflight_direct_read_plan(
        plan=plan,
        catalog=catalog,
        governance=governance,
        policy=policy,
        sources=SourceOfTruthRegistry(()),
    )

    if public_username is not None:
        environ = dict(os.environ)
    elif credentials_file is not None:
        if governance.environment is not EnvironmentKind.DEVELOPMENT:
            raise ConfigurationError(
                "--credentials-file is restricted to development; use the approved "
                "secret manager for non-development execution"
            )
        store = CredentialStoreSnapshot.load_github_compatible(
            credentials_file,
            credential_name=github.secret_env or "MASTER_AGENT_GITHUB_TOKEN",
        )
        ambient = {
            name: value for name, value in os.environ.items() if name not in store.names
        }
        environ = store.overlay(ambient)
    else:
        environ = dict(os.environ)

    selected_github = (
        replace(github, auth_mode=AuthMode.NONE, secret_env=None)
        if public_username is not None
        else github
    )
    target = selected_github.capture_execution_target(environ)
    resolved = selected_github.resolve(
        environ,
        auth_transport=transport,
        execution_target=target,
    )
    connector = GitHubConnector(resolved, transport=transport)
    principal = None if public_username is not None else connector.attest_principal()
    binding = _standalone_connector_binding(
        selected_github,
        target=target,
        credential_identity=(principal.identity if principal is not None else None),
        credential_scopes=(principal.scopes if principal is not None else ()),
    )
    report = DirectReadSession(
        catalog=catalog,
        governance=governance,
        policy=policy,
        sources=SourceOfTruthRegistry(()),
        connector=connector,
        execution_binding=binding,
    ).execute(plan)
    returned = report.actions[0]
    payload: dict[str, object] = {
        **dict(returned.payload.to_dict()["data"]),
        "verified": returned.verification.verified,
        "egress": returned.egress.to_dict(),
    }
    if principal is None:
        payload["requested_user"] = {
            "login": public_username,
            "access": "anonymous_public",
        }
    repository_values = payload.get("repositories")
    repositories = (
        list(repository_values) if isinstance(repository_values, list) else []
    )

    if principal is not None:
        print("GitHub account: provider identity verified")
    else:
        print(
            "GitHub public user: "
            f"{_terminal_field(public_username, max_characters=160)}"
        )
    print(f"Repositories: {len(repositories)}")
    for repository in repositories:
        if not isinstance(repository, Mapping):
            continue
        name = _terminal_field(
            repository.get("full_name", "unknown"), max_characters=320
        )
        access = _terminal_field(
            repository.get("visibility") or "unknown",
            max_characters=80,
        )
        url = _terminal_field(repository.get("web_url") or "", max_characters=512)
        suffix = f" — {url}" if url else ""
        print(f"- {name} ({access}){suffix}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 0


def _bitbucket_repositories(
    *,
    workspace: str,
    limit: int,
    output: Path | None,
    transport: HttpTransport | None = None,
) -> int:
    """List public Bitbucket Cloud workspace repositories anonymously."""

    if output is not None:
        raise ConfigurationError(
            "stateless provider shortcuts do not permit persisted output"
        )
    workspace = workspace.strip()
    if not workspace:
        raise ConfigurationError("Bitbucket workspace must not be empty")
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(None, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(None, "governance.toml")
    )
    bitbucket = replace(
        integrations.connector("bitbucket"),
        enabled=True,
        auth_mode=AuthMode.NONE,
        username_env=None,
        secret_env=None,
    )
    if bitbucket.deployment is not DeploymentType.CLOUD:
        raise ConfigurationError(
            "Bitbucket public workspace repositories require Bitbucket Cloud"
        )
    if limit <= 0 or limit > bitbucket.max_items:
        raise ConfigurationError(
            f"Bitbucket repository limit must be between 1 and {bitbucket.max_items}"
        )
    action = AgentAction(
        capability="bitbucket.public_repository.list",
        target=ResourceRef(
            system="bitbucket",
            resource_type="public_repository_collection",
            resource_id=workspace,
        ),
        parameters={"workspace": workspace, "limit": limit},
        risk=RiskLevel.READ_ONLY,
        data_classification=DataClassification.PUBLIC,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"bitbucket:public-repositories:{workspace}:{limit}",
        justification=(
            "List public repositories in the directly requested Bitbucket workspace."
        ),
    )
    plan = ChangePlan(
        goal=f"List public repositories in Bitbucket workspace {workspace}.",
        actions=(action,),
        created_by="direct-user",
    )
    plan = bind_fast_path_governance(
        plan,
        current_behavior="public workspace repositories are not yet listed",
        constraint="one bounded anonymous Bitbucket query is required",
        leverage_point="the typed read-only Bitbucket connector",
        success_metric="the bounded public repository list is returned and verified",
        failure_condition="the provider read is denied, incomplete, or unverified",
    )
    catalog = CapabilityCatalog.from_toml(
        resolve_config_source(None, "capabilities.toml")
    )
    policy = PolicyEngine(
        PolicyConfig.from_toml(resolve_config_source(None, "policy.toml"))
    )
    catalog_ok, catalog_reason = catalog.validate_action(action)
    if not catalog_ok:
        raise ConfigurationError(catalog_reason)
    governance_ok, governance_reason = governance.validate_action(action)
    if not governance_ok:
        raise ConfigurationError(governance_reason)
    decision = policy.evaluate(
        plan,
        action,
        minimum_distinct_approvers=governance.minimum_approvers(action.capability),
    )
    if not decision.permitted or decision.approval_required:
        raise ConfigurationError(decision.reason)
    preflight_direct_read_plan(
        plan=plan,
        catalog=catalog,
        governance=governance,
        policy=policy,
        sources=SourceOfTruthRegistry(()),
    )

    target = bitbucket.capture_execution_target({})
    resolved = bitbucket.resolve(
        {},
        auth_transport=transport,
        execution_target=target,
    )
    connector = BitbucketConnector(resolved, transport=transport)
    binding = _standalone_connector_binding(
        bitbucket,
        target=target,
        credential_identity=None,
        credential_scopes=(),
    )
    report = DirectReadSession(
        catalog=catalog,
        governance=governance,
        policy=policy,
        sources=SourceOfTruthRegistry(()),
        connector=connector,
        execution_binding=binding,
    ).execute(plan)
    returned = report.actions[0]
    payload: dict[str, object] = {
        **dict(returned.payload.to_dict()["data"]),
        "verified": returned.verification.verified,
        "egress": returned.egress.to_dict(),
    }
    repository_values = payload.get("repositories")
    repositories = (
        list(repository_values) if isinstance(repository_values, list) else []
    )
    safe_workspace = _terminal_field(workspace, max_characters=160)
    print(f"Bitbucket public workspace: {safe_workspace}")
    print(f"Repositories: {len(repositories)}")
    for repository in repositories:
        if not isinstance(repository, Mapping):
            continue
        name = _terminal_field(repository.get("name", "unknown"), max_characters=320)
        slug = _terminal_field(repository.get("slug") or name, max_characters=320)
        url = _terminal_field(repository.get("web_url") or "", max_characters=512)
        suffix = f" - {url}" if url else ""
        print(f"- {safe_workspace}/{slug}{suffix}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 0


def _standalone_connector_binding(
    config: ConnectorConfig,
    *,
    target: ResolvedExecutionTarget,
    credential_identity: str | None,
    credential_scopes: tuple[str, ...],
) -> ConnectorExecutionBinding:
    """Bind a one-shot provider shortcut before its content request."""

    target_base_url = target.base_url
    parsed = urlsplit(target_base_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            "provider shortcut endpoint has an invalid port"
        ) from error
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != 443:
        rendered_host = f"{rendered_host}:{port}"
    return ConnectorExecutionBinding(
        system=config.system,
        deployment=str(config.deployment),
        config_identity_sha256=target.config_identity,
        resolved_base_url=target_base_url,
        resolved_origin=f"https://{rendered_host}",
        authentication_mode=str(config.auth_mode),
        credential_identity=credential_identity,
        credential_scopes=credential_scopes,
        ca_bundle_path=(
            str(target.ca_bundle.path) if target.ca_bundle is not None else None
        ),
        ca_bundle_sha256=(
            target.ca_bundle.sha256 if target.ca_bundle is not None else None
        ),
        network_profile_name=target.network_profile_name,
        network_profile_sha256=target.network_profile_sha256,
        proxy_origin=target.proxy_url,
    )


def _weekly_status_plan(
    *,
    integrations_path: Path | None,
    workflow_path: Path | None,
    output: Path,
) -> int:
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    workflow = WeeklyStatusSettings.from_toml(
        resolve_config_source(workflow_path, "weekly-status.toml")
    )
    plan = build_weekly_status_read_plan(
        workflow,
        bitbucket_deployment=integrations.connector("bitbucket").deployment,
    )
    _write_json(output, plan.to_dict())
    print(f"wrote {output}")
    print(f"plan fingerprint: {plan.fingerprint}")
    return 0


def _weekly_operating_review_plan(
    *,
    workflow_path: Path | None,
    output: Path,
) -> int:
    """Build the safe reference plan without executing any provider action."""

    settings = WeeklyOperatingReviewSettings.from_toml(
        resolve_config_source(workflow_path, "weekly-operating-review.toml")
    )
    plan = build_weekly_operating_review_plan(settings)
    _write_json(output, plan.to_dict())
    print(f"wrote {output}")
    print(f"plan fingerprint: {plan.fingerprint}")
    return 0


def _weekly_status(
    *,
    integrations_path: Path | None,
    workflow_path: Path | None,
    output_dir: Path,
    database: Path,
) -> int:
    _reject_non_manifest_execution("weekly-status")
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    workflow = WeeklyStatusSettings.from_toml(
        resolve_config_source(workflow_path, "weekly-status.toml")
    )
    plan = build_weekly_status_read_plan(
        workflow,
        bitbucket_deployment=integrations.connector("bitbucket").deployment,
    )
    registry = build_live_registry(
        integrations,
        environ=os.environ,
        systems={"jira", "confluence", "bitbucket"},
    )
    _require_systems(registry, {"jira", "confluence", "bitbucket"}, "weekly-status")
    report = _orchestrator(registry, database).run(plan, dry_run=False)
    _print_report(report)
    artifacts = render_weekly_status_package(report, workflow, output_dir=output_dir)
    print(f"evidence: {artifacts.evidence_json}")
    print(f"markdown: {artifacts.markdown}")
    print(f"powerpoint: {artifacts.powerpoint}")
    print(f"manifest: {artifacts.manifest_json}")
    return 0 if report.successful else 2


def _identity_resolve(
    *,
    query: str,
    system: str | None,
    identities_path: Path | None,
    output: Path | None,
) -> int:
    registry = IdentityRegistry.from_toml(
        resolve_config_source(identities_path, "identities.toml")
    )
    person = registry.resolve(query)
    payload = person.to_dict()
    if system is not None:
        payload["resolved_system"] = system
        payload["resolved_identifier"] = registry.resolve_identifier(query, system)
    person_key = _terminal_field(person.key, max_characters=160)
    display_name = _terminal_field(person.display_name, max_characters=320)
    print(f"identity: {person_key} — {display_name}")
    if system is not None:
        safe_system = _terminal_field(system, max_characters=80)
        identifier = _terminal_field(payload["resolved_identifier"], max_characters=320)
        print(f"{safe_system}: {identifier}")
    else:
        for name, value in sorted(person.identifiers.items()):
            safe_name = _terminal_field(name, max_characters=80)
            safe_value = _terminal_field(value, max_characters=320)
            print(f"{safe_name}: {safe_value}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 0


def _retain_evidence(
    *,
    input_path: Path,
    output_path: Path,
    evidence_type: str,
    retention_path: Path | None,
    include_content: bool,
) -> int:
    require_persistent_state_platform()
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise StructuredDataTypeError("retained evidence input must be a JSON object")
    config = RetentionConfig.from_toml(
        resolve_config_source(retention_path, "retention.toml")
    )
    evidence, sidecar = write_retained_json(
        output_path,
        payload,
        evidence_type=evidence_type,
        config=config,
        include_content=include_content,
    )
    print(f"evidence: {evidence}")
    print(f"retention: {sidecar}")
    return 0


def _evidence_prune(*, root: Path, apply: bool, output: Path | None) -> int:
    result = purge_expired_evidence(root, dry_run=not apply)
    payload = {
        "schema": "master-agent/evidence-prune@1",
        **result.to_dict(),
    }
    mode = "apply" if apply else "preview"
    print(f"mode: {mode}")
    print(f"scanned manifests: {result.scanned_manifests}")
    print(f"expired manifests: {result.expired_manifests}")
    for path in result.removed_files:
        print(f"{'deleted' if apply else 'would delete'}: {_terminal_field(path)}")
    for error in result.errors:
        print(f"error: {_terminal_field(error)}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 2 if result.errors else 0


def _evidence_repair(*, root: Path, apply: bool, output: Path | None) -> int:
    result = repair_orphaned_evidence(root, dry_run=not apply)
    payload = {
        "schema": "master-agent/evidence-repair@1",
        **result.to_dict(),
    }
    mode = "apply" if apply else "preview"
    print(f"mode: {mode}")
    print(f"scanned files: {result.scanned_files}")
    print(f"orphaned files: {len(result.orphaned_files)}")
    for path in result.quarantined_files:
        print(f"quarantined: {_terminal_field(repr(path))}")
    for error in result.errors:
        print(f"error: {_terminal_field(repr(error))}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 2 if result.errors else 0


def _work_memory(
    *,
    action: str,
    database: Path,
    work_id: str | None,
    issue: str | None,
    kind: str | None,
    stage: str | None,
    summary: str | None,
    reference: str | None,
    output: Path | None,
) -> int:
    """Run one explicit local persistent-work-memory operation."""

    if action == "verify":
        if any(
            value is not None
            for value in (work_id, issue, kind, stage, summary, reference)
        ):
            raise ValueError("work-memory verify accepts only --database and --output")
        verification = WorkMemory.verify_existing(database)
        _emit_work_memory_payload(verification.to_dict(), output=output)
        return 0 if verification.valid else 2
    if work_id is None:
        raise ValueError("work-memory operation requires --work-id")
    if action == "show":
        if any(value is not None for value in (issue, kind, stage, summary, reference)):
            raise ValueError(
                "work-memory show accepts only --database, --work-id, and --output"
            )
        snapshot = WorkMemory.show_existing(database, work_id)
    elif action == "start":
        if issue is None or summary is None:
            raise ValueError("work-memory start requires --issue and --summary")
        if any(value is not None for value in (kind, stage, reference)):
            raise ValueError("work-memory start received incompatible arguments")
        _preflight_work_memory_output(output)
        with WorkMemory(database) as memory:
            snapshot = memory.start(work_id=work_id, issue=issue, summary=summary)
    elif action == "record":
        if kind is None or summary is None:
            raise ValueError("work-memory record requires --kind and --summary")
        if issue is not None:
            raise ValueError("work-memory record does not accept --issue")
        _preflight_work_memory_output(output)
        with WorkMemory(database) as memory:
            snapshot = memory.record(
                work_id=work_id,
                kind=WorkEventKind(kind),
                stage=WorkStage(stage) if stage is not None else None,
                summary=summary,
                reference=reference,
            )
    else:
        raise ValueError("unknown work-memory operation")
    _emit_work_memory_payload(snapshot.to_dict(), output=output)
    return 0


def _preflight_work_memory_output(output: Path | None) -> None:
    """Reject an occupied create-only output before mutating the journal."""

    if output is None:
        return
    require_persistent_state_platform()
    selected = output.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if selected.name in {"", ".", ".."}:
        raise ConfigurationError("restricted artifact output path is invalid")
    with PinnedDirectory.open(selected.parent) as directory:
        requested_name = selected.name.casefold()
        if any(name.casefold() == requested_name for name in directory.list_children()):
            raise ConfigurationError(
                "restricted artifact already exists; use a fresh private output name"
            )


def _emit_work_memory_payload(
    payload: Mapping[str, object],
    *,
    output: Path | None,
) -> None:
    """Publish bounded work metadata as deterministic JSON."""

    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
        return
    print(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))


def _citations(path: Path, *, output: Path | None) -> int:
    if output is not None:
        require_persistent_state_platform()
    payload = json.loads(path.read_text(encoding="utf-8"))
    citations = find_citations(payload)
    if not citations:
        print("no citations found")
    for citation in citations:
        marker = _terminal_field(
            citation.get("marker") or citation.get("citation_id"),
            max_characters=160,
        )
        system = _terminal_field(citation.get("system"), max_characters=80)
        resource_type = _terminal_field(
            citation.get("resource_type"),
            max_characters=80,
        )
        title = _terminal_field(
            citation.get("title") or citation.get("resource_id"),
            max_characters=320,
        )
        url = _terminal_field(citation.get("url") or "-", max_characters=512)
        print(f"{marker} {system}:{resource_type} {title} — {url}")
    if output is not None:
        _write_json(
            output,
            {"schema": "master-agent/citations@1", "citations": citations},
        )
        print(f"wrote {output}")
    return 0


def _communication_context_plan(
    *,
    workflow_path: Path | None,
    identities_path: Path | None,
    output: Path,
) -> int:
    settings = CommunicationContextSettings.from_toml(
        resolve_config_source(workflow_path, "communication-context.toml")
    )
    identities = IdentityRegistry.from_toml(
        resolve_config_source(identities_path, "identities.toml")
    )
    plan = build_communication_context_plan(settings, identities)
    _write_json(output, plan.to_dict())
    print(f"wrote {output}")
    print(f"plan fingerprint: {plan.fingerprint}")
    return 0


def _communication_context(
    *,
    integrations_path: Path | None,
    workflow_path: Path | None,
    identities_path: Path | None,
    retention_path: Path | None,
    output_dir: Path,
    database: Path,
) -> int:
    _reject_non_manifest_execution("communication-context")
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    settings = CommunicationContextSettings.from_toml(
        resolve_config_source(workflow_path, "communication-context.toml")
    )
    identities = IdentityRegistry.from_toml(
        resolve_config_source(identities_path, "identities.toml")
    )
    retention = RetentionConfig.from_toml(
        resolve_config_source(retention_path, "retention.toml")
    )
    plan = build_communication_context_plan(settings, identities)
    registry = build_live_registry(
        integrations,
        environ=os.environ,
        systems={"outlook", "teams"},
    )
    registry.register(IdentityMapConnector(identities))
    _require_systems(
        registry, {"identity", "outlook", "teams"}, "communication-context"
    )
    report = _orchestrator(registry, database).run(plan, dry_run=False)
    _print_report(report)
    artifacts = render_communication_context_package(
        report,
        settings,
        output_dir=output_dir,
        retention=retention,
    )
    print(f"evidence: {artifacts.evidence_json}")
    print(f"evidence retention: {artifacts.evidence_retention_sidecar}")
    print(f"markdown: {artifacts.markdown}")
    print(f"markdown retention: {artifacts.markdown_retention_sidecar}")
    print(f"manifest: {artifacts.manifest_json}")
    return 0 if report.successful else 2


def _reject_non_manifest_execution(command: str) -> None:
    """Fail closed for workflows that bypass the bound execution manifest."""

    if command not in _DISABLED_NON_MANIFEST_EXECUTIONS:
        raise ValueError(f"unknown disabled execution command: {command}")
    raise ConfigurationError(
        f"{command} execution is disabled until its inputs, provider identity, "
        "targets, audit database, and output package are bound to one immutable "
        "execution manifest and descriptor-pinned for the full run"
    )


def _scan(*, text: str | None, file: Path | None) -> int:
    if text is not None:
        content = text
    elif file is not None:
        content = file.read_text(encoding="utf-8")
    else:
        raise ValueError("scan requires either text or a file")
    findings = PromptInjectionGuard().scan(content)
    if not findings:
        print("no heuristic findings; content remains untrusted data")
        return 0
    for finding in findings:
        severity = render_terminal_text(finding.severity, max_characters=16)
        category = render_terminal_text(finding.category, max_characters=80)
        rendered_excerpt = render_terminal_text(
            finding.excerpt,
            max_characters=MAX_TERMINAL_EXCERPT_CHARACTERS,
        )
        print(f"{severity:<6} {category}: {rendered_excerpt}")
    return 3


def _audit_verify(database: Path) -> int:
    valid, message = AuditLog.verify_existing(database)
    print(_terminal_field(message))
    return 0 if valid else 4


def _mock_registry() -> ConnectorRegistry:
    registry = ConnectorRegistry()
    registry.register(
        MockConnector(
            "jira",
            {
                "PROJECT-SPRINT": {
                    "version": "7",
                    "summary": "12 done, 3 in progress, 2 blocked",
                    "blockers": ["RISE-142", "RISE-155"],
                }
            },
        )
    )
    registry.register(
        MockConnector(
            "bitbucket",
            {
                "open-prs": {
                    "version": "4",
                    "count": 5,
                    "awaiting_review": 2,
                    "failing_ci": 1,
                }
            },
        )
    )
    registry.register(
        MockConnector(
            "confluence",
            {
                "project-status": {
                    "version": "12",
                    "narrative": "Release remains on track with two active blockers.",
                }
            },
        )
    )
    for system in ("powerpoint", "teams", "outlook"):
        registry.register(MockConnector(system))
    return registry


def _plan_requires_authenticated_approval(
    plan: ChangePlan,
    *,
    policy_source: ConfigSource,
    governance: GovernanceProfile,
) -> bool:
    """Return whether any otherwise-governed action needs human approval."""

    engine = PolicyEngine(PolicyConfig.from_toml(policy_source))
    for action in plan.actions:
        governed, _ = governance.validate_action(action)
        if not governed:
            continue
        decision = engine.evaluate(
            plan,
            action,
            minimum_distinct_approvers=governance.minimum_approvers(action.capability),
        )
        if decision.approval_required:
            return True
    return False


def _execution_configuration_sources(
    *,
    approval_authorities: Path | None,
    retention_path: Path | None,
    identities_path: Path | None,
    policy_path: Path | None,
    sources_of_truth_path: Path | None,
    capabilities_path: Path | None,
    governance_path: Path | None,
    organization_profile_path: Path | None = None,
    organization_profile_source: ConfigSnapshot | None = None,
    captured_sources: Mapping[str, ConfigSnapshot] | None = None,
) -> dict[str, ConfigSource]:
    """Capture the exact policy/configuration snapshots used by one run."""

    captured = captured_sources or {}
    sources: dict[str, ConfigSource] = {
        "policy": captured.get("policy")
        or resolve_config_source(policy_path, "policy.toml"),
        "sources_of_truth": captured.get("sources_of_truth")
        or resolve_config_source(sources_of_truth_path, "sources_of_truth.toml"),
        "capabilities": captured.get("capabilities")
        or resolve_config_source(capabilities_path, "capabilities.toml"),
        "governance": captured.get("governance")
        or resolve_config_source(governance_path, "governance.toml"),
        "identities": captured.get("identities")
        or resolve_config_source(identities_path, "identities.toml"),
        "retention": captured.get("retention")
        or resolve_config_source(retention_path, "retention.toml"),
    }
    if approval_authorities is not None:
        sources["approval_authorities"] = captured.get(
            "approval_authorities"
        ) or resolve_config_source(approval_authorities, "approval-authorities.toml")
    if organization_profile_source is not None:
        sources["organization_profile"] = organization_profile_source
    elif organization_profile_path is not None:
        sources["organization_profile"] = resolve_config_source(
            organization_profile_path,
            "organization-profile.toml",
        )
    if organization_profile_path is not None:
        sources["organization_profile_path"] = captured.get(
            "organization_profile_path"
        ) or _organization_profile_path_snapshot(organization_profile_path)
    elif organization_profile_source is not None:
        sources["organization_profile_path"] = captured.get(
            "organization_profile_path"
        ) or _organization_profile_path_snapshot(
            organization_profile_source.display_path
        )
    return sources


def _execution_integrations_source(
    *,
    plan: ChangePlan,
    catalog: CapabilityCatalog,
    integrations_path: Path | None,
    high_level: bool,
    captured_sources: Mapping[str, ConfigSnapshot] | None,
) -> ConfigSnapshot:
    """Select the exact provider bundle, or the bound empty local-only bundle."""

    if captured_sources is not None:
        return captured_sources["integrations"]
    if high_level and not _plan_requires_provider_integrations(plan, catalog):
        return _empty_operating_integrations_source()
    return resolve_config_source(integrations_path, "integrations.toml")


def _enforce_approved_configuration_inputs(
    plan: ChangePlan,
    *,
    integrations: IntegrationConfig,
    configuration_sources: Mapping[str, ConfigSource],
) -> None:
    """Reject configuration drift before credentials or provider I/O."""

    context = plan.execution_context
    if context is None or context.runtime is None:
        raise ConfigurationError(
            "applied execution requires an approval-bound runtime path identity"
        )
    if integrations.source_sha256 != context.integrations_sha256:
        raise ConfigurationError(
            "applied execution context differs from the approved plan: "
            "integrations bundle"
        )
    approved = {item.name: item.sha256 for item in context.runtime.configurations}
    observed = {
        name: _configuration_source_sha256(source)
        for name, source in configuration_sources.items()
    }
    if approved != observed:
        raise ConfigurationError(
            "applied execution context differs from the approved plan: "
            "runtime policy, principal, gate, or path binding"
        )


def _configuration_source_sha256(source: ConfigSource) -> str:
    """Hash one immutable trusted source for an early approval gate."""

    with source.open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _organization_profile_path_snapshot(path: Path) -> ConfigSnapshot:
    """Bind the canonical profile pathname into the approved runtime context."""

    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    canonical = selected.resolve(strict=False)
    return ConfigSnapshot(
        display_path=canonical,
        payload=os.fsencode(canonical),
    )


def _orchestrator(
    connectors: ConnectorRegistry,
    database: Path,
    *,
    capabilities_path: Path | None = None,
    governance_path: Path | None = None,
    policy_source: ConfigSource | None = None,
    sources_of_truth_source: ConfigSource | None = None,
    capabilities_source: ConfigSource | None = None,
    capabilities: CapabilityCatalog | None = None,
    governance_source: ConfigSource | None = None,
    approval_authenticator: HmacApprovalAuthenticator | None = None,
    audit: AuditLog | None = None,
    pre_effect_guard: Callable[[AgentAction], None] | None = None,
) -> WorkflowOrchestrator:
    """Build the governed runtime from repository or packaged defaults."""

    return WorkflowOrchestrator(
        policy=PolicyEngine(
            PolicyConfig.from_toml(
                policy_source or resolve_config_source(None, "policy.toml")
            ),
            approval_authenticator=approval_authenticator,
        ),
        sources=SourceOfTruthRegistry.from_toml(
            sources_of_truth_source
            or resolve_config_source(None, "sources_of_truth.toml")
        ),
        connectors=connectors,
        audit=audit if audit is not None else AuditLog(database),
        capabilities=(
            capabilities
            or CapabilityCatalog.from_toml(
                capabilities_source
                or resolve_config_source(capabilities_path, "capabilities.toml")
            )
        ),
        governance=GovernanceProfile.from_toml(
            governance_source
            or resolve_config_source(governance_path, "governance.toml")
        ),
        pre_effect_guard=pre_effect_guard,
    )


def _require_systems(
    registry: ConnectorRegistry,
    required: set[str],
    workflow: str,
) -> None:
    missing = required - set(registry.systems())
    if missing:
        raise ValueError(
            f"{workflow} requires enabled connectors: " + ", ".join(sorted(missing))
        )


def _live_systems_for_plan(
    plan: ChangePlan,
    integrations: IntegrationConfig,
    *,
    catalog: CapabilityCatalog | None = None,
) -> set[str]:
    """Select plan providers while preserving mismatched-config validation."""

    requested = {
        action.target.system
        for action in plan.actions
        if action.target.system in _CONNECT_CONFIGURATION_BY_SYSTEM
        and (
            catalog is None
            or catalog.definition(action.capability).authentication
            not in {"local", "local_git"}
        )
    }
    configured = set(integrations.connectors)
    requested_configurations = {
        _CONNECT_CONFIGURATION_BY_SYSTEM[system] for system in requested
    }
    if not requested:
        return set()
    if requested_configurations & configured:
        return requested
    return {
        system
        for system, configuration in _CONNECT_CONFIGURATION_BY_SYSTEM.items()
        if configuration in configured
    }


def _load_operating_plan(path: Path) -> ChangePlan:
    """Snapshot one high-level plan through a bounded no-follow file descriptor."""

    return _parse_plan_payload(
        _read_operating_private_payload(path, label="operating plan")
    )


def _load_operating_approval(path: Path) -> Approval:
    """Snapshot one high-level approval without blocking on special files."""

    payload = _read_operating_private_payload(path, label="approval artifact")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError) as error:
        raise ValidationError(
            "approval artifact is not bounded valid UTF-8 JSON"
        ) from error
    if not isinstance(raw, Mapping):
        raise ValidationError("approval artifact must be a JSON object")
    return Approval.from_dict(raw)


def _read_operating_private_payload(path: Path, *, label: str) -> bytes:
    """Return one bounded current-user private regular-file snapshot."""

    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if selected.name in {"", ".", ".."}:
        raise ConfigurationError(f"{label} path is invalid")
    if _uses_native_windows_paths():
        backend = get_secure_filesystem_backend()
        reader = getattr(backend, "read_restricted_file", None)
        if not callable(reader):
            raise ConfigurationError(f"secure {label} snapshots are unavailable")
        try:
            _, payload, _ = reader(
                selected,
                MAX_PLAN_BYTES + 1,
                require_private=True,
            )
        except OSError as error:
            raise ConfigurationError(f"{label} could not be opened safely") from error
        if not isinstance(payload, bytes):
            raise ConfigurationError(f"secure {label} snapshot is invalid")
        if len(payload) > MAX_PLAN_BYTES:
            raise ValidationError(
                f"{label} exceeds the {MAX_PLAN_BYTES}-byte file limit"
            )
        return payload
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not nonblocking or not no_follow:
        raise ConfigurationError(f"secure {label} snapshots are unavailable")
    descriptor = -1
    try:
        with PinnedDirectory.open(
            selected.parent,
            require_private=False,
        ) as directory:
            descriptor = os.open(
                selected.name,
                os.O_RDONLY | nonblocking | no_follow | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory.fileno(),
            )
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or (os.name == "posix" and before.st_uid != os.geteuid())
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_nlink != 1
            ):
                raise ConfigurationError(
                    f"{label} must be a current-user private regular file"
                )
            payload = _read_operating_descriptor(descriptor, label=label)
            after = os.fstat(descriptor)
            published = os.stat(
                selected.name,
                dir_fd=directory.fileno(),
                follow_symlinks=False,
            )
            if _operating_plan_file_identity(before) != _operating_plan_file_identity(
                after
            ) or _operating_plan_file_identity(after) != _operating_plan_file_identity(
                published
            ):
                raise ConfigurationError(f"{label} changed during snapshot")
            directory.validate()
    except OSError as error:
        raise ConfigurationError(f"{label} could not be opened safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return payload


def _uses_native_windows_paths() -> bool:
    """Return whether protected CLI inputs require the Win32 path adapter."""

    return os.name == "nt"


def _operating_plan_file_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Return identity and mutation metadata for one captured plan file."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_operating_descriptor(descriptor: int, *, label: str) -> bytes:
    """Read at most one bounded high-level input from a validated descriptor."""

    chunks: list[bytes] = []
    remaining = MAX_PLAN_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > MAX_PLAN_BYTES:
        raise ValidationError(f"{label} exceeds the {MAX_PLAN_BYTES}-byte file limit")
    return payload


def _load_plan(path: Path) -> ChangePlan:
    with path.open("rb") as handle:
        payload = handle.read(MAX_PLAN_BYTES + 1)
    return _parse_plan_payload(payload)


def _parse_plan_payload(payload: bytes) -> ChangePlan:
    if len(payload) > MAX_PLAN_BYTES:
        raise ValidationError(
            f"change plan exceeds the {MAX_PLAN_BYTES}-byte file limit"
        )
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError) as error:
        raise ValidationError("change plan is not bounded valid UTF-8 JSON") from error
    if not isinstance(raw, Mapping):
        raise ValidationError("change plan must be a JSON object")
    return ChangePlan.from_dict(raw)


def _load_approval(path: Path) -> Approval:
    return Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value is not None else None


def _is_windows_atomic_metadata_name(name: str) -> bool:
    """Return whether one child is private atomic-backend bookkeeping."""

    folded = name.casefold()
    return bool(
        re.fullmatch(r"\.master-agent-[0-9a-f]{32}\.(?:ledger|lock)", folded)
        or folded.startswith((".master-agent-ledger-", ".master-agent-tmp-"))
    )


def _terminal_field(
    value: object,
    *,
    max_characters: int = MAX_TERMINAL_FIELD_CHARACTERS,
) -> str:
    """Render one dynamic CLI field without terminal control effects."""

    return render_terminal_text(str(value), max_characters=max_characters)


def _write_json(
    path: Path,
    payload: object,
) -> None:
    if not isinstance(payload, Mapping):
        raise StructuredDataTypeError("JSON output must be an object")
    write_restricted_json(path, payload)


def _print_report(report: RunReport, *, mode_label: str | None = None) -> None:
    print(f"run ID: {report.run_id}")
    print(f"plan fingerprint: {report.plan_fingerprint}")
    print(f"mode: {mode_label or ('dry-run' if report.dry_run else 'apply')}")
    for item in report.actions:
        state = _terminal_field(item.state, max_characters=80)
        capability = _terminal_field(item.capability, max_characters=240)
        message = _terminal_field(item.message)
        print(f"{state:<20} {item.action_id!s:<36} {capability} — {message}")
    print(f"successful: {report.successful}")


def _print_direct_read_report(report: DirectReadReport) -> None:
    """Render verified direct-read data without durable result publication.

    Provider content is untrusted.  JSON escaping and terminal rendering keep
    control characters inert, while the per-action cap prevents a direct read
    from flooding an interactive terminal.  The session itself still retains
    the complete result only in process memory until this rendering finishes.
    """

    print("mode: direct-read")
    print(f"provider: {_terminal_field(report.provider, max_characters=80)}")
    print(f"plan fingerprint: {report.plan_fingerprint}")
    for action in report.actions:
        capability = _terminal_field(action.capability, max_characters=240)
        message = _terminal_field(action.message)
        print(f"verified {action.action_id!s:<36} {capability} — {message}")
        payload = json.dumps(
            action.payload.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
            default=str,
        )
        rendered = render_terminal_text(
            payload,
            max_characters=_MAX_DIRECT_READ_TERMINAL_PAYLOAD_CHARACTERS,
        )
        print(f"  result: {rendered}")
    print(
        "systems review: "
        f"metric={report.systems_review.metric_status}, "
        f"reassessment_required={report.systems_review.reassessment_required}"
    )
    print(f"successful: {report.successful}")


def _parse_systems(value: str | None) -> set[str] | None:
    if value is None:
        return None
    systems = {item.strip() for item in value.split(",") if item.strip()}
    if not systems:
        raise ValueError("--systems must contain at least one system")
    return systems


def _parse_egress_checks(
    values: tuple[str, ...],
) -> tuple[tuple[str, DataClassification], ...]:
    """Parse content-free readiness selectors."""

    parsed: list[tuple[str, DataClassification]] = []
    for value in values:
        provider, separator, raw_classification = value.partition(":")
        provider = provider.strip()
        raw_classification = raw_classification.strip()
        if (
            not separator
            or not provider
            or not raw_classification
            or ":" in raw_classification
        ):
            raise ConfigurationError("--egress-check must use PROVIDER:CLASSIFICATION")
        try:
            classification = DataClassification(raw_classification)
        except ValueError as error:
            raise ConfigurationError(
                "--egress-check classification must be public, internal, "
                "confidential, or restricted"
            ) from error
        item = (provider, classification)
        if item not in parsed:
            parsed.append(item)
    return tuple(parsed)


if __name__ == "__main__":
    raise SystemExit(main())
