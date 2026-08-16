"""Command-line interface for the governed runtime."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from master_agent.approval_handoff import (
    ApprovalRequest,
    ApprovalRunInvocation,
    load_approval_request,
    publish_approval_request,
    write_restricted_json,
)
from master_agent.approvals import HmacApprovalAuthenticator
from master_agent.audit import AuditLog
from master_agent.auth import AuthMode
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.citations import find_citations
from master_agent.compensation import build_compensation_plan
from master_agent.config import ConnectorConfig, DeploymentType, IntegrationConfig
from master_agent.config_sources import ConfigSource, resolve_config_source
from master_agent.connectors.base import ClosableConnector
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.factory import (
    build_draft_registry,
    build_live_registry,
    register_draft_connectors,
)
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.connectors.mock import MockConnector
from master_agent.credentials import (
    CredentialStoreSnapshot,
    canonical_credential_store_path,
)
from master_agent.directory_safety import PinnedDirectory
from master_agent.discovery import DiscoveryStatus, discover_integrations
from master_agent.errors import (
    ConfigurationError,
    MasterAgentError,
    StructuredDataTypeError,
    ValidationError,
)
from master_agent.execution_context import (
    build_execution_context,
    build_runtime_execution_binding,
    capture_runtime_execution_paths,
    enforce_execution_context,
)
from master_agent.governance import EnvironmentKind, GovernanceProfile
from master_agent.http import HttpTransport
from master_agent.identity import IdentityRegistry
from master_agent.models import (
    ActionState,
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.oauth import EntraDeviceCodeProvider, write_token_file
from master_agent.oauth_config import OAuthFlow, OAuthProfiles
from master_agent.orchestrator import RunReport, WorkflowOrchestrator
from master_agent.planners.static import build_weekly_status_plan
from master_agent.plugins import (
    PluginLock,
    discover_connector_plugins,
    resolve_locked_plugin_descriptors,
)
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.readiness import assess_readiness
from master_agent.recurring import (
    RecurringConfig,
    RecurringRunner,
    RecurringRunResult,
    RegisteredWorkflow,
    WorkflowKind,
    validate_plan_scope,
)
from master_agent.registry import ConnectorRegistry
from master_agent.retention import (
    RetainedJSONReservation,
    RetentionConfig,
    purge_expired_evidence,
    repair_orphaned_evidence,
    write_retained_json,
)
from master_agent.security import PromptInjectionGuard
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
}
_PLACEHOLDER_PROVIDER_URLS = frozenset({"https://example.atlassian.net"})


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
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
        if args.command == "readiness":
            return _readiness(
                integrations_path=args.integrations,
                capabilities_path=args.capabilities,
                governance_path=args.governance,
                oauth_path=args.oauth,
                identities_path=args.identities,
                credentials_file=args.credentials_file,
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
        if args.command == "recurring-run":
            return _recurring_run(
                name=args.name,
                recurring_path=args.recurring,
                connector_mode=args.connector_mode,
                force=args.force,
            )
        if args.command == "discover":
            return _discover(
                integrations_path=args.integrations,
                governance_path=args.governance,
                credentials_file=args.credentials_file,
                probe=args.probe,
                systems=_parse_systems(args.systems),
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
    except (
        KeyError,
        MasterAgentError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        print(f"error: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="master-agent",
        description="Governed enterprise-agent orchestration runtime.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    recurring_run = subparsers.add_parser(
        "recurring-run",
        help="disabled pending exact recurring target and runtime binding",
    )
    recurring_run.add_argument("name")
    recurring_run.add_argument("--recurring", type=Path, default=None)
    recurring_run.add_argument(
        "--connector-mode",
        choices=("mock", "live"),
        default="mock",
    )
    recurring_run.add_argument("--force", action="store_true")

    discover = subparsers.add_parser(
        "discover",
        help="inspect connector configuration and optionally probe live APIs",
    )
    discover.add_argument("--integrations", type=Path, default=None)
    discover.add_argument("--governance", type=Path, default=None)
    discover.add_argument("--credentials-file", type=Path)
    discover.add_argument("--probe", action="store_true")
    discover.add_argument("--systems")
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
        help="preview expired evidence; destructive apply is disabled",
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


def _sample_plan(output: Path) -> int:
    plan = build_weekly_status_plan()
    _write_json(output, plan.to_dict())
    print(f"wrote {output}")
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
) -> int:
    """Write a plan whose fingerprint covers the complete applied runtime."""

    plan = _load_plan(plan_path)
    integrations_source = resolve_config_source(integrations_path, "integrations.toml")
    integrations = IntegrationConfig.from_toml(integrations_source)
    live_systems = _live_systems_for_plan(plan, integrations)
    configurations = _configuration_names_for_systems(live_systems)
    integrations = _with_connector_url_overrides(
        integrations,
        connector_urls,
        selected_configurations=configurations,
    )
    configuration_sources = _execution_configuration_sources(
        approval_authorities=approval_authorities,
        retention_path=retention_path,
        identities_path=identities_path,
        policy_path=policy_path,
        sources_of_truth_path=sources_of_truth_path,
        capabilities_path=capabilities_path,
        governance_path=governance_path,
    )
    governance = GovernanceProfile.from_toml(configuration_sources["governance"])
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
        print(f"  {item.action.action_id}  {item.reason}")
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

    if ttl_minutes <= 0:
        raise ValueError("ttl-minutes must be positive")
    request = load_approval_request(request_path)
    if expected_fingerprint != request.fingerprint:
        raise ValueError(
            "approval request fingerprint does not match --expected-fingerprint; "
            "inspect the current request before approving"
        )
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
) -> int:
    """Retry the exact captured invocation with supplied approval artifacts."""

    request = load_approval_request(request_path)
    if expected_fingerprint != request.fingerprint:
        raise ValueError(
            "approval request fingerprint does not match --expected-fingerprint; "
            "inspect the current request before resuming"
        )
    plan = _load_plan(Path(request.run.plan_path))
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
    )


def _run(
    *,
    plan_path: Path,
    apply: bool,
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
) -> int:
    """Evaluate or execute an immutable plan through explicitly selected layers."""

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
    plan = _load_plan(plan_path)
    approvals = tuple(_load_approval(path) for path in approval_paths)
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
        integrations_source = resolve_config_source(
            integrations_path, "integrations.toml"
        )
        integration_config = IntegrationConfig.from_toml(integrations_source)
        live_systems = _live_systems_for_plan(plan, integration_config)
        configurations = _configuration_names_for_systems(live_systems)
        integration_config = _with_connector_url_overrides(
            integration_config,
            connector_urls,
            selected_configurations=configurations,
        )
        approved_context = plan.execution_context
        if approved_context is None or approved_context.runtime is None:
            raise ConfigurationError(
                "applied execution requires an approval-bound runtime path identity"
            )
        _enforce_approved_credential_file(
            approved_context.runtime.credential_file, credentials_file
        )
        governance = GovernanceProfile.from_toml(configuration_sources["governance"])
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
            connectors = _mock_registry()
            register_draft_connectors(connectors, artifact_directory)
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
            register_draft_connectors(connectors, artifact_directory)
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
        )
        current_integrations = _with_connector_url_overrides(
            IntegrationConfig.from_toml(
                resolve_config_source(integrations_path, "integrations.toml")
            ),
            connector_urls,
            selected_configurations=configurations,
        )
        current_environ = _credential_environment(
            credential_store,
            os.environ,
            compatible_names=compatibility,
        )
        enforce_execution_context(
            plan,
            build_execution_context(
                current_integrations,
                environ=current_environ,
                systems=live_systems,
                runtime=build_runtime_execution_binding(
                    current_integrations,
                    connector_mode=connector_mode,
                    include_writes=include_writes,
                    include_communications=include_communications,
                    audit_database=database,
                    artifact_root=draft_output_dir,
                    workspace_root=workspace_root,
                    result_json=result_json,
                    evidence_type=evidence_type,
                    configuration_sources=current_configuration_sources,
                    credential_file=(
                        credential_store.path if credential_store else None
                    ),
                    environ=current_environ,
                    captured_paths=captured_paths,
                ),
                include_connectors=connector_mode == "live",
            ),
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
                governance_source=configuration_sources["governance"],
                approval_authenticator=approval_authenticator,
                audit=applied_audit,
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
            print(
                "pending actions were not executed; a trusted operator must use "
                "inspect-approval-request and approve-request, then MasterAgent "
                "can resume-approval without rebuilding this run"
            )
        return 0 if report.successful else 2


def _plugins(*, output: Path | None) -> int:
    """List installed connector entry points without importing plugin modules."""

    plugins = discover_connector_plugins()
    for item in plugins:
        distribution = item.distribution or "unknown-distribution"
        print(f"{item.name:<24} {distribution:<28} {item.value}")
    if not plugins:
        print("no connector plugins installed")
    if output is not None:
        _write_json(output, PluginLock(plugins=plugins).to_dict())
        print(f"wrote {output}")
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
    """Load an explicitly selected development-only connector credential store."""

    if path is None:
        if credential_mappings:
            raise ConfigurationError("--credential-map requires --credentials-file")
        return None
    if connector_mode != "live":
        raise ConfigurationError(
            "--credentials-file is available only with live connectors"
        )
    if governance.environment is not EnvironmentKind.DEVELOPMENT:
        raise ConfigurationError(
            "--credentials-file is restricted to the development environment; "
            "use the approved secret manager for non-development execution"
        )
    configurations = (
        _configuration_names_for_systems(systems)
        if systems is not None
        else set(integrations.connectors)
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
    compatible_names: Mapping[str, str] | None = None,
) -> dict[str, str]:
    merged = store.overlay(environ) if store is not None else dict(environ)
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
    output: Path | None,
) -> int:
    """Assess Phase 0/2C configuration without performing network requests."""

    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
    )
    credential_store = _load_credential_store(
        credentials_file,
        integrations=integrations,
        governance=governance,
        connector_mode="live",
    )
    configurations = set(integrations.connectors)
    report = assess_readiness(
        catalog=CapabilityCatalog.from_toml(
            resolve_config_source(capabilities_path, "capabilities.toml")
        ),
        governance=governance,
        integrations=integrations,
        oauth_profiles=OAuthProfiles.from_toml(
            resolve_config_source(oauth_path, "oauth.toml")
        ),
        identities=IdentityRegistry.from_toml(
            resolve_config_source(identities_path, "identities.toml")
        ),
        environ=_credential_environment(
            credential_store,
            os.environ,
            compatible_names=_atlassian_credential_compatibility(
                integrations,
                configurations=configurations,
            ),
        ),
    )
    payload = report.to_dict()
    print(f"environment: {report.environment}")
    print(f"ready: {report.ready}")
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
        print(f"  {'PASS' if check.get('passed') else 'FAIL'} {check.get('name')}")
    for warning in report.warnings:
        print(f"warning: {warning}")
    for error in report.errors:
        print(f"error: {error}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 0 if report.ready else 2


def _oauth_device_code(
    *,
    oauth_path: Path | None,
    profile_name: str,
    token_file: Path,
) -> int:
    """Run an explicitly selected delegated Entra device-code flow."""

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
        print(message or f"Open {verification_uri} and enter code {user_code}")

    provider.set_challenge_callback(display_challenge)
    token = provider.get_token()
    path = write_token_file(token_file, token)
    print(f"wrote restricted token file: {path}")
    print(f"expires: {token.expires_at.isoformat()}")
    return 0


def _demo() -> int:
    """Run the complete credential-free demonstration outside the source tree."""

    workspace = _new_demo_workspace()
    workspace.chmod(0o700)
    artifacts = workspace / "artifacts"
    state = workspace / "state"
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

    runtime_root = Path.home() / ".master-agent"
    product_root = runtime_root / "MasterAgent"
    runtime_root.mkdir(mode=0o700, exist_ok=True)
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

    with ExitStack() as resources:
        output_directory = resources.enter_context(PinnedDirectory.open(output_dir))
        database_parent = resources.enter_context(
            PinnedDirectory.open(database.expanduser().absolute().parent)
        )
        if output_directory.identity == database_parent.identity:
            raise ConfigurationError(
                "draft artifact and audit database directories must be distinct"
            )
        fcntl.flock(output_directory.fileno(), fcntl.LOCK_EX)
        if os.listdir(output_directory.fileno()):
            raise ConfigurationError(
                "draft artifact directory must be empty; use a fresh directory"
            )
        canonical_database = database_parent.path / database.name
        settings = DraftPackageSettings.from_toml(
            resolve_config_source(workflow_path, "draft-package.toml")
        )
        plan = build_draft_package_plan(settings)
        registry = build_draft_registry(output_directory)
        for connector in registry.connectors():
            if isinstance(connector, ClosableConnector):
                resources.callback(connector.close)
        audit = AuditLog(canonical_database, parent_directory=database_parent)
        resources.callback(audit.close)
        report = _orchestrator(
            registry,
            canonical_database,
            audit=audit,
        ).run(plan, dry_run=False)
        artifacts = render_draft_package(report, output_dir=output_directory)
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
        print(
            f"{record['name']:<28} enabled={record['enabled']!s:<5} "
            f"due={record['due']!s:<5} {record['reason']}"
        )
    if output is not None:
        _write_json(
            output,
            {"schema": "master-agent/recurring-status@1", "workflows": records},
        )
        print(f"wrote {output}")
    return 0


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
        if connector_mode == "mock":
            registry = _mock_read_registry(plan)
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
        report = _orchestrator(registry, database).run(plan, dry_run=False)
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
        if connector_mode == "mock":
            registry = _mock_read_registry(plan)
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
        report = _orchestrator(registry, database).run(plan, dry_run=False)
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


def _mock_read_registry(plan: ChangePlan) -> ConnectorRegistry:
    """Build deterministic schema-shaped mock resources for a read-only plan."""

    by_system: dict[str, dict[str, dict[str, object]]] = {}
    capabilities: dict[str, set[str]] = {}
    for action in plan.actions:
        if action.target.system == "identity":
            continue
        if str(action.risk) != "read_only":
            continue
        system = action.target.system
        capabilities.setdefault(system, set()).add(action.capability)
        version = action.target.expected_version or "1"
        payload: dict[str, object] = {"version": version}
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
        by_system.setdefault(system, {})[action.target.resource_id] = payload
    registry = ConnectorRegistry()
    for system, resources in sorted(by_system.items()):
        registry.register(
            MockConnector(
                system,
                resources,
                capabilities=capabilities.get(system, set()),
            )
        )
    return registry


def _discover(
    *,
    integrations_path: Path | None,
    governance_path: Path | None,
    credentials_file: Path | None,
    probe: bool,
    systems: set[str] | None,
    output: Path | None,
) -> int:
    config = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    governance = GovernanceProfile.from_toml(
        resolve_config_source(governance_path, "governance.toml")
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
            compatible_names=_atlassian_credential_compatibility(
                config,
                configurations=configurations,
            ),
        ),
        probe=probe,
        systems=systems,
    )
    payload = {
        "schema": "master-agent/discovery@1",
        "records": [record.to_dict() for record in records],
    }
    for record in records:
        missing = ",".join(record.missing_environment) or "-"
        print(
            f"{record.status:<20} {record.system:<12} "
            f"deployment={record.deployment:<11} missing={missing}"
        )
        if record.error_message:
            print(f"  {record.error_type}: {record.error_message}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    unavailable = {DiscoveryStatus.MISSING_ENVIRONMENT, DiscoveryStatus.FAILED}
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
) -> int:
    """Verify requested read connectors through an ephemeral configuration."""

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
        if (unresolved.base_url or "").rstrip("/") in _PLACEHOLDER_PROVIDER_URLS:
            raise ConfigurationError(
                f"connector {name} still uses a placeholder provider URL; supply "
                "the organization's reviewed integrations file"
            )
        extra = dict(unresolved.extra)
        if name == "microsoft" and "onenote" in systems:
            extra["onenote_read_enabled"] = True
        connectors[name] = replace(unresolved, enabled=True, extra=extra)
    effective = IntegrationConfig(
        connectors=connectors,
        source_sha256=integrations.source_sha256,
    )

    related_configurations = _related_atlassian_configurations(
        effective,
        configurations=configurations,
    )
    credential_compatibility = _atlassian_credential_compatibility(
        effective,
        configurations=configurations,
    )

    if credentials_file is not None:
        if governance.environment is not EnvironmentKind.DEVELOPMENT:
            raise ConfigurationError(
                "--credentials-file is restricted to development; use the approved "
                "secret manager for non-development execution"
            )
        store = CredentialStoreSnapshot.load_provider_compatible(
            credentials_file,
            allowed_names=effective.credential_environment_variables(),
            aliases=_provider_credential_aliases(
                effective,
                configurations=configurations | related_configurations,
                systems=systems,
            ),
            explicit_mappings=_parse_credential_mappings(credential_mappings),
        )
        ambient = {
            name: value for name, value in os.environ.items() if name not in store.names
        }
        environ = _credential_environment(
            store,
            ambient,
            compatible_names=credential_compatibility,
        )
    else:
        if credential_mappings:
            raise ConfigurationError("--credential-map requires --credentials-file")
        environ = _credential_environment(
            None,
            os.environ,
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
        effective = IntegrationConfig(connectors=connectors)

    records = discover_integrations(
        effective,
        environ=environ,
        probe=True,
        transport=transport,
        systems=systems,
    )
    payload = {
        "schema": "master-agent/connection@1",
        "persistent_configuration_changed": False,
        "records": [record.to_dict() for record in records],
    }
    for record in records:
        if record.status is DiscoveryStatus.REACHABLE:
            print(f"connected: {record.system}")
        else:
            missing = ",".join(record.missing_environment) or "-"
            print(
                f"not connected: {record.system} ({record.status}; missing={missing})"
            )
            if record.error_message:
                print(f"  {record.error_type}: {record.error_message}")
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
    """Map missing Jira/Confluence names to the related Atlassian account pair."""

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
        for destination, fallback in (
            (target.username_env, source.username_env),
            (target.secret_env, source.secret_env),
        ):
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
    for system, base_url in overrides.items():
        connectors[system] = replace(
            connectors[system],
            base_url=base_url,
            base_url_env=None,
        )
    return IntegrationConfig(
        connectors=connectors,
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

    selected_github = (
        replace(github, auth_mode=AuthMode.NONE, secret_env=None)
        if public_username is not None
        else github
    )
    resolved = selected_github.resolve(environ, auth_transport=transport)
    connector = GitHubConnector(resolved, transport=transport)
    principal = None if public_username is not None else connector.attest_principal()
    result = connector.execute(action)
    verification = connector.verify(action, result)
    if not verification.verified:
        result = connector.execute(action)
        verification = connector.verify(action, result)
    if not verification.verified:
        raise ConfigurationError(
            "GitHub repositories changed during two verification attempts; retry "
            "the read"
        )
    repositories = list((result.after or {}).get("repositories", []))
    payload = {
        **dict(result.after or {}),
        "verified": True,
    }
    if principal is not None:
        payload["authenticated_user"] = {
            "login": principal.login,
            "user_id": principal.user_id,
            "identity": principal.identity,
        }
    else:
        payload["requested_user"] = {
            "login": public_username,
            "access": "anonymous_public",
        }

    if principal is not None:
        print(f"GitHub account: {principal.login}")
    else:
        print(f"GitHub public user: {public_username}")
    print(f"Repositories: {len(repositories)}")
    for repository in repositories:
        if not isinstance(repository, Mapping):
            continue
        name = str(repository.get("full_name", "unknown"))
        access = str(repository.get("visibility") or "unknown")
        url = str(repository.get("web_url") or "")
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

    resolved = bitbucket.resolve({}, auth_transport=transport)
    connector = BitbucketConnector(resolved, transport=transport)
    result = connector.execute(action)
    verification = connector.verify(action, result)
    if not verification.verified:
        result = connector.execute(action)
        verification = connector.verify(action, result)
    if not verification.verified:
        raise ConfigurationError(
            "Bitbucket repositories changed during two verification attempts; retry "
            "the read"
        )
    repositories = list((result.after or {}).get("repositories", []))
    payload = {**dict(result.after or {}), "verified": True}
    print(f"Bitbucket public workspace: {workspace}")
    print(f"Repositories: {len(repositories)}")
    for repository in repositories:
        if not isinstance(repository, Mapping):
            continue
        name = str(repository.get("name", "unknown"))
        slug = str(repository.get("slug") or name)
        url = str(repository.get("web_url") or "")
        suffix = f" - {url}" if url else ""
        print(f"- {workspace}/{slug}{suffix}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 0


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
    print(f"identity: {person.key} — {person.display_name}")
    if system is not None:
        print(f"{system}: {payload['resolved_identifier']}")
    else:
        for name, value in sorted(person.identifiers.items()):
            print(f"{name}: {value}")
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
        print(f"{'deleted' if apply else 'would delete'}: {path}")
    for error in result.errors:
        print(f"error: {error}")
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
        print(f"quarantined: {path!r}")
    for error in result.errors:
        print(f"error: {error!r}")
    if output is not None:
        _write_json(output, payload)
        print(f"wrote {output}")
    return 2 if result.errors else 0


def _citations(path: Path, *, output: Path | None) -> int:
    payload = json.loads(path.read_text(encoding="utf-8"))
    citations = find_citations(payload)
    if not citations:
        print("no citations found")
    for citation in citations:
        marker = citation.get("marker") or citation.get("citation_id")
        title = citation.get("title") or citation.get("resource_id")
        url = citation.get("url") or "-"
        print(
            f"{marker} {citation.get('system')}:{citation.get('resource_type')} "
            f"{title} — {url}"
        )
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
        print(f"{finding.severity:<6} {finding.category}: {finding.excerpt}")
    return 3


def _audit_verify(database: Path) -> int:
    valid, message = AuditLog.verify_existing(database)
    print(message)
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
) -> dict[str, ConfigSource]:
    """Capture the exact policy/configuration snapshots used by one run."""

    sources: dict[str, ConfigSource] = {
        "policy": resolve_config_source(policy_path, "policy.toml"),
        "sources_of_truth": resolve_config_source(
            sources_of_truth_path, "sources_of_truth.toml"
        ),
        "capabilities": resolve_config_source(capabilities_path, "capabilities.toml"),
        "governance": resolve_config_source(governance_path, "governance.toml"),
        "identities": resolve_config_source(identities_path, "identities.toml"),
        "retention": resolve_config_source(retention_path, "retention.toml"),
    }
    if approval_authorities is not None:
        sources["approval_authorities"] = resolve_config_source(
            approval_authorities,
            "approval-authorities.toml",
        )
    return sources


def _orchestrator(
    connectors: ConnectorRegistry,
    database: Path,
    *,
    capabilities_path: Path | None = None,
    governance_path: Path | None = None,
    policy_source: ConfigSource | None = None,
    sources_of_truth_source: ConfigSource | None = None,
    capabilities_source: ConfigSource | None = None,
    governance_source: ConfigSource | None = None,
    approval_authenticator: HmacApprovalAuthenticator | None = None,
    audit: AuditLog | None = None,
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
        capabilities=CapabilityCatalog.from_toml(
            capabilities_source
            or resolve_config_source(capabilities_path, "capabilities.toml")
        ),
        governance=GovernanceProfile.from_toml(
            governance_source
            or resolve_config_source(governance_path, "governance.toml")
        ),
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
    plan: ChangePlan, integrations: IntegrationConfig
) -> set[str]:
    """Select plan providers while preserving mismatched-config validation."""

    requested = {
        action.target.system
        for action in plan.actions
        if action.target.system in _CONNECT_CONFIGURATION_BY_SYSTEM
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


def _load_plan(path: Path) -> ChangePlan:
    return ChangePlan.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _load_approval(path: Path) -> Approval:
    return Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value is not None else None


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
        print(
            f"{item.state:<20} {item.action_id!s:<36} "
            f"{item.capability} — {item.message}"
        )
    print(f"successful: {report.successful}")


def _parse_systems(value: str | None) -> set[str] | None:
    if value is None:
        return None
    systems = {item.strip() for item in value.split(",") if item.strip()}
    if not systems:
        raise ValueError("--systems must contain at least one system")
    return systems


if __name__ == "__main__":
    raise SystemExit(main())
