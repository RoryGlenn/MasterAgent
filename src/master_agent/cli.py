"""Command-line interface for the governed runtime."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from master_agent.approvals import HmacApprovalAuthenticator
from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.citations import find_citations
from master_agent.compensation import build_compensation_plan
from master_agent.config import IntegrationConfig
from master_agent.config_sources import resolve_config_source
from master_agent.connectors.factory import (
    build_draft_registry,
    build_live_registry,
    register_draft_connectors,
)
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.connectors.mock import MockConnector
from master_agent.discovery import DiscoveryStatus, discover_integrations
from master_agent.errors import (
    ConfigurationError,
    MasterAgentError,
    StructuredDataTypeError,
)
from master_agent.execution_context import (
    build_execution_context,
    enforce_execution_context,
)
from master_agent.governance import GovernanceProfile
from master_agent.identity import IdentityRegistry
from master_agent.models import Approval, ChangePlan
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
    RetentionConfig,
    purge_expired_evidence,
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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
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
                plugin_names=args.plugin,
                plugin_lock_path=args.plugin_lock,
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
                probe=args.probe,
                systems=_parse_systems(args.systems),
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
        help="bind reviewed live connector and plugin identities into a plan",
    )
    bind_context.add_argument("plan", type=Path)
    bind_context.add_argument("--integrations", type=Path, default=None)
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
        help="run one registered narrow workflow",
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
    discover.add_argument("--probe", action="store_true")
    discover.add_argument("--systems")
    discover.add_argument("--output", type=Path)

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
        help="collect live evidence and render a local status package",
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
        help="preview or delete expired retained evidence",
    )
    prune.add_argument("--root", type=Path, default=Path(".master-agent"))
    prune.add_argument("--apply", action="store_true")
    prune.add_argument("--output", type=Path)

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
        help="collect Outlook and Teams context and render retained local evidence",
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
    output: Path,
) -> int:
    """Write a plan whose fingerprint covers exact live runtime identities."""

    plan = _load_plan(plan_path)
    integrations = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
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
        environ=os.environ,
        plugin_descriptors=descriptors,
    )
    bound = replace(plan, execution_context=context)
    _write_json(output, bound.to_dict(), restricted=True)
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
    plugin_names: list[str],
    plugin_lock_path: Path | None,
) -> int:
    """Evaluate or execute an immutable plan through explicitly selected layers."""

    if apply and plugin_names:
        raise ConfigurationError(
            "in-process connector plugin execution is disabled pending an "
            "isolated worker with a locked dependency closure"
        )
    if apply and plugin_lock_path is not None:
        raise ValueError("--plugin-lock requires at least one --plugin")
    plan = _load_plan(plan_path)
    approvals = tuple(_load_approval(path) for path in approval_paths)
    if approvals and approval_authorities is None:
        raise ValueError(
            "--approval-authorities is required when approval artifacts are supplied"
        )
    approval_authenticator = (
        HmacApprovalAuthenticator.from_toml(
            resolve_config_source(
                approval_authorities,
                "approval-authorities.toml",
            ),
            environ=os.environ,
        )
        if approval_authorities is not None
        else None
    )
    if not apply:
        # A policy-only dry run must not resolve credentials or construct live
        # clients. This makes plan review safe on unconfigured machines.
        connectors = ConnectorRegistry()
    elif connector_mode == "mock":
        connectors = _mock_registry()
        register_draft_connectors(connectors, draft_output_dir)
    else:
        execution_environ = dict(os.environ)
        integration_config = IntegrationConfig.from_toml(
            resolve_config_source(integrations_path, "integrations.toml")
        )
        enforce_execution_context(
            plan,
            build_execution_context(
                integration_config,
                environ=execution_environ,
            ),
        )
        connectors = build_live_registry(
            integration_config,
            environ=execution_environ,
            include_writes=include_writes,
            include_communications=include_communications,
            workspace_root=workspace_root,
            artifact_root=draft_output_dir,
            approved_execution_context=plan.execution_context,
        )
        register_draft_connectors(connectors, draft_output_dir)
        identities = IdentityRegistry.from_toml(
            resolve_config_source(identities_path, "identities.toml")
        )
        if "identity" not in connectors.systems():
            connectors.register(IdentityMapConnector(identities))
    if apply and connector_mode == "live":
        # Re-read identities immediately before execution. This catches an
        # integrations, environment-origin, or CA change that occurs after
        # client construction.
        current_integrations = IntegrationConfig.from_toml(
            resolve_config_source(integrations_path, "integrations.toml")
        )
        enforce_execution_context(
            plan,
            build_execution_context(
                current_integrations,
                environ=os.environ,
            ),
        )

    report = _orchestrator(
        connectors,
        database,
        capabilities_path=capabilities_path,
        governance_path=governance_path,
        approval_authenticator=approval_authenticator,
    ).run(
        plan,
        approvals=approvals,
        dry_run=not apply,
    )
    _print_report(report)
    if result_json is not None:
        retention = RetentionConfig.from_toml(
            resolve_config_source(retention_path, "retention.toml")
        )
        evidence, sidecar = write_retained_json(
            result_json,
            report.to_dict(),
            evidence_type=evidence_type,
            config=retention,
            include_content=True,
        )
        print(f"full result written to {evidence}")
        print(f"retention sidecar written to {sidecar}")
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
        _write_json(output, PluginLock(plugins=plugins).to_dict(), restricted=True)
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


def _readiness(
    *,
    integrations_path: Path | None,
    capabilities_path: Path | None,
    governance_path: Path | None,
    oauth_path: Path | None,
    identities_path: Path | None,
    output: Path | None,
) -> int:
    """Assess Phase 0/2C configuration without performing network requests."""

    report = assess_readiness(
        catalog=CapabilityCatalog.from_toml(
            resolve_config_source(capabilities_path, "capabilities.toml")
        ),
        governance=GovernanceProfile.from_toml(
            resolve_config_source(governance_path, "governance.toml")
        ),
        integrations=IntegrationConfig.from_toml(
            resolve_config_source(integrations_path, "integrations.toml")
        ),
        oauth_profiles=OAuthProfiles.from_toml(
            resolve_config_source(oauth_path, "oauth.toml")
        ),
        identities=IdentityRegistry.from_toml(
            resolve_config_source(identities_path, "identities.toml")
        ),
        environ=os.environ,
    )
    payload = report.to_dict()
    print(f"environment: {report.environment}")
    print(f"ready: {report.ready}")
    for check in report.checks:
        print(f"  {'PASS' if check.get('passed') else 'FAIL'} {check.get('name')}")
    for warning in report.warnings:
        print(f"warning: {warning}")
    for error in report.errors:
        print(f"error: {error}")
    if output is not None:
        _write_json(output, payload, restricted=True)
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


def _draft_package(
    *,
    workflow_path: Path | None,
    output_dir: Path,
    database: Path,
) -> int:
    """Generate all Phase 3 artifacts locally without provider writes."""

    settings = DraftPackageSettings.from_toml(
        resolve_config_source(workflow_path, "draft-package.toml")
    )
    plan = build_draft_package_plan(settings)
    registry = build_draft_registry(output_dir)
    report = _orchestrator(registry, database).run(plan, dry_run=False)
    _print_report(report)
    artifacts = render_draft_package(report, output_dir=output_dir)
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
    _write_json(output, plan.to_dict(), restricted=True)
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
            restricted=True,
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
    probe: bool,
    systems: set[str] | None,
    output: Path | None,
) -> int:
    config = IntegrationConfig.from_toml(
        resolve_config_source(integrations_path, "integrations.toml")
    )
    records = discover_integrations(
        config,
        environ=os.environ,
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
        _write_json(output, payload, restricted=True)
        print(f"wrote {output}")
    unavailable = {DiscoveryStatus.MISSING_ENVIRONMENT, DiscoveryStatus.FAILED}
    return 0 if all(record.status not in unavailable for record in records) else 2


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
        _write_json(output, payload, restricted=True)
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
        _write_json(output, payload, restricted=True)
        print(f"wrote {output}")
    return 2 if result.errors else 0


def _citations(path: Path, *, output: Path | None) -> int:
    payload = json.loads(path.read_text(encoding="utf-8"))
    citations = find_citations(payload)
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
            restricted=True,
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


def _orchestrator(
    connectors: ConnectorRegistry,
    database: Path,
    *,
    capabilities_path: Path | None = None,
    governance_path: Path | None = None,
    approval_authenticator: HmacApprovalAuthenticator | None = None,
) -> WorkflowOrchestrator:
    """Build the governed runtime from repository or packaged defaults."""

    return WorkflowOrchestrator(
        policy=PolicyEngine(
            PolicyConfig.from_toml(resolve_config_source(None, "policy.toml")),
            approval_authenticator=approval_authenticator,
        ),
        sources=SourceOfTruthRegistry.from_toml(
            resolve_config_source(None, "sources_of_truth.toml")
        ),
        connectors=connectors,
        audit=AuditLog(database),
        capabilities=CapabilityCatalog.from_toml(
            resolve_config_source(capabilities_path, "capabilities.toml")
        ),
        governance=GovernanceProfile.from_toml(
            resolve_config_source(governance_path, "governance.toml")
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


def _load_plan(path: Path) -> ChangePlan:
    return ChangePlan.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _load_approval(path: Path) -> Approval:
    return Approval.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _write_json(
    path: Path,
    payload: object,
    *,
    restricted: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    if restricted:
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _print_report(report: RunReport) -> None:
    print(f"run ID: {report.run_id}")
    print(f"plan fingerprint: {report.plan_fingerprint}")
    print(f"mode: {'dry-run' if report.dry_run else 'apply'}")
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
