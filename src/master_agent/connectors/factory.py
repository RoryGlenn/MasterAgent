"""Construct scoped connector registries from runtime configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import ConnectorConfig, IntegrationConfig
from master_agent.connectors.base import Connector
from master_agent.connectors.bitbucket import BitbucketConnector
from master_agent.connectors.bitbucket_write import BitbucketWriteConnector
from master_agent.connectors.communications import (
    OutlookSendConnector,
    TeamsSendConnector,
)
from master_agent.connectors.confluence import ConfluenceConnector
from master_agent.connectors.confluence_write import ConfluenceWriteConnector
from master_agent.connectors.drafts import (
    ArtifactBudget,
    ConfluenceDraftConnector,
    JiraDraftConnector,
    OutlookDraftConnector,
    PowerPointDraftConnector,
    RepositoryDraftConnector,
    TeamsDraftConnector,
)
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.github_write import (
    GitHubAdminConnector,
    GitHubWriteConnector,
)
from master_agent.connectors.identity import IdentityMapConnector
from master_agent.connectors.jira import JiraConnector
from master_agent.connectors.jira_write import JiraWriteConnector
from master_agent.connectors.microsoft import (
    MicrosoftIdentityConnector,
    SharePointConnector,
)
from master_agent.connectors.onenote import OneNoteReadConnector
from master_agent.connectors.outlook import OutlookConnector
from master_agent.connectors.sharepoint_write import SharePointWriteConnector
from master_agent.connectors.teams import TeamsConnector
from master_agent.directory_safety import PinnedDirectory, pin_directory
from master_agent.errors import ConfigurationError
from master_agent.execution_context import (
    CapturedConnectorExecution,
    capture_connector_executions,
)
from master_agent.http import HttpTransport
from master_agent.models import ExecutionContext
from master_agent.platform_runtime import require_persistent_state_platform
from master_agent.registry import ConnectorRegistry

_READ_SYSTEMS = frozenset(
    {
        "jira",
        "confluence",
        "github",
        "bitbucket",
        "microsoft",
        "sharepoint",
        "outlook",
        "teams",
        "onenote",
    }
)

_BUILTIN_CONNECTOR_TYPES = (
    JiraConnector,
    ConfluenceConnector,
    BitbucketConnector,
    GitHubConnector,
    MicrosoftIdentityConnector,
    SharePointConnector,
    OutlookConnector,
    TeamsConnector,
    OneNoteReadConnector,
    JiraWriteConnector,
    ConfluenceWriteConnector,
    BitbucketWriteConnector,
    GitHubWriteConnector,
    GitHubAdminConnector,
    SharePointWriteConnector,
    OutlookSendConnector,
    TeamsSendConnector,
    JiraDraftConnector,
    ConfluenceDraftConnector,
    OutlookDraftConnector,
    TeamsDraftConnector,
    PowerPointDraftConnector,
    RepositoryDraftConnector,
    IdentityMapConnector,
)


def installed_builtin_capabilities() -> frozenset[str]:
    """Return the pure, state-free capability set routed by this factory."""

    capabilities = frozenset(
        capability
        for connector_type in _BUILTIN_CONNECTOR_TYPES
        for capability in connector_type._CAPABILITIES
    )
    # PowerPoint generation performs an optional in-process import. Keep it
    # outside the employee/developer high-level admission set until that import
    # is isolated from ambient project/CWD module shadowing.
    return capabilities - PowerPointDraftConnector._CAPABILITIES


def configured_builtin_capabilities(
    config: IntegrationConfig,
    *,
    connector_mode: str,
    include_writes: bool,
    include_communications: bool,
) -> frozenset[str]:
    """Return capabilities the selected built-in factory can actually route."""

    installed = installed_builtin_capabilities()
    local_types = (
        JiraDraftConnector,
        ConfluenceDraftConnector,
        OutlookDraftConnector,
        TeamsDraftConnector,
        PowerPointDraftConnector,
        RepositoryDraftConnector,
    )
    capabilities = {
        capability
        for connector_type in local_types
        for capability in connector_type._CAPABILITIES
        if capability in installed
    }
    if connector_mode == "mock":
        return frozenset(
            capability
            for capability in installed
            if capability not in IdentityMapConnector._CAPABILITIES
        )
    if connector_mode != "live":
        raise ConfigurationError("connector mode must be live or mock")

    for name in sorted(config.connectors):
        connector = config.connectors[name]
        if not connector.enabled:
            continue
        if name == "jira":
            capabilities.update(JiraConnector._CAPABILITIES)
            if (
                include_writes
                and _feature_enabled(connector, "write_enabled")
                and _feature_enabled(connector, "writes_enabled")
            ):
                capabilities.update(JiraWriteConnector._CAPABILITIES)
        elif name == "confluence":
            capabilities.update(ConfluenceConnector._CAPABILITIES)
            if (
                include_writes
                and _feature_enabled(connector, "write_enabled")
                and _feature_enabled(connector, "writes_enabled")
            ):
                capabilities.update(ConfluenceWriteConnector._CAPABILITIES)
        elif name == "bitbucket":
            capabilities.update(BitbucketConnector._CAPABILITIES)
            if (
                include_writes
                and _feature_enabled(connector, "write_enabled")
                and _feature_enabled(connector, "pull_request_writes_enabled")
            ):
                capabilities.update(BitbucketWriteConnector._CAPABILITIES)
        elif name == "github":
            capabilities.update(GitHubConnector._CAPABILITIES)
            if include_writes and _feature_enabled(connector, "write_enabled"):
                if _feature_enabled(connector, "writes_enabled"):
                    capabilities.update(GitHubWriteConnector._CAPABILITIES)
                if _feature_enabled(connector, "admin_enabled"):
                    capabilities.update(GitHubAdminConnector._CAPABILITIES)
        elif name == "microsoft":
            capabilities.update(MicrosoftIdentityConnector._CAPABILITIES)
            capabilities.update(SharePointConnector._CAPABILITIES)
            capabilities.update(OutlookConnector._CAPABILITIES)
            capabilities.update(TeamsConnector._CAPABILITIES)
            if _feature_enabled(connector, "onenote_read_enabled"):
                capabilities.update(OneNoteReadConnector._CAPABILITIES)
            if (
                include_writes
                and _feature_enabled(connector, "write_enabled")
                and _feature_enabled(connector, "sharepoint_writes_enabled")
            ):
                capabilities.update(SharePointWriteConnector._CAPABILITIES)
            if include_communications and _feature_enabled(connector, "send_enabled"):
                if _feature_enabled(connector, "outlook_send_enabled"):
                    capabilities.update(OutlookSendConnector._CAPABILITIES)
                if _feature_enabled(connector, "teams_send_enabled"):
                    capabilities.update(TeamsSendConnector._CAPABILITIES)
    capabilities.update(IdentityMapConnector._CAPABILITIES)
    return frozenset(capabilities & installed)


def build_live_connectors(
    config: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    transport: HttpTransport | None = None,
    systems: set[str] | None = None,
    include_writes: bool = False,
    include_communications: bool = False,
    workspace_root: Path | None = None,
    artifact_root: Path | None = None,
    artifact_directory: PinnedDirectory | None = None,
    approved_execution_context: ExecutionContext | None = None,
    captured_executions: tuple[CapturedConnectorExecution, ...] | None = None,
) -> tuple[Connector, ...]:
    """Construct available live connectors selected for this operation.

    Provider mutation surfaces are double-gated: the caller must explicitly
    include them and the provider configuration must enable the corresponding
    feature flag. Read-only discovery never constructs a write connector.

    Parameters
    ----------
    config
        Parsed integration configuration.
    environ
        Environment mapping containing credential values.
    transport
        Optional injectable transport for deterministic contract testing.
    systems
        Runtime-system allowlist. ``None`` selects all read systems.
    include_writes
        Permit construction of reversible-write connectors.
    include_communications
        Permit construction of non-reversible communication connectors.
    workspace_root
        Manifest-bound compatibility input. Local Git mutation connectors are
        not registered.
    artifact_root
        Root containing generated files eligible for SharePoint publication.
    artifact_directory
        Optional descriptor-pinned form of the approved artifact root.
    approved_execution_context
        Optional plan-bound live identity. When supplied, every captured
        connector destination and CA snapshot must match it exactly.
    captured_executions
        Optional already-attested immutable targets. Probe routes use these to
        construct clients from the same endpoint and CA snapshot they bind.

    Returns
    -------
    tuple[Connector, ...]
        Deterministically ordered connector instances.
    """

    source = dict(environ if environ is not None else os.environ)
    selected = set(_READ_SYSTEMS) | {"repository"} if systems is None else set(systems)
    connectors: list[Connector] = []
    if captured_executions is None:
        captured = capture_connector_executions(
            config,
            environ=source,
            systems=selected,
            require_trusted_principal=approved_execution_context is not None,
            principal_transport=transport,
            approved_execution_context=approved_execution_context,
        )
    else:
        captured = tuple(captured_executions)
        _verify_supplied_captured_executions(config, captured, selected)
    if approved_execution_context is not None:
        _verify_approved_execution_context(
            config,
            captured,
            approved_execution_context,
        )
    missing_resolved = sorted(
        item.binding.system for item in captured if item.resolved is None
    )
    if missing_resolved:
        raise ConfigurationError(
            "live connector construction requires captured credentials for: "
            + ", ".join(missing_resolved)
        )
    resolved_configs = {
        item.binding.system: item.resolved
        for item in captured
        if item.resolved is not None
    }

    if include_writes:
        for unresolved in config.connectors.values():
            if (
                unresolved.enabled
                and unresolved.system == "bitbucket"
                and _connector_is_selected(unresolved.system, selected)
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "branch_push_enabled")
            ):
                raise ConfigurationError(
                    "Bitbucket local-Git branch publication is disabled until all "
                    "Git metadata transactions are descriptor-bound"
                )

    for name in sorted(config.connectors):
        unresolved = config.connectors[name]
        if not unresolved.enabled or not _connector_is_selected(
            unresolved.system, selected
        ):
            continue
        if name not in {"jira", "confluence", "bitbucket", "github", "microsoft"}:
            continue
        resolved = resolved_configs[unresolved.system]

        if name == "jira" and "jira" in selected:
            connectors.append(JiraConnector(resolved, transport=transport))
            if (
                include_writes
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "writes_enabled")
            ):
                connectors.append(JiraWriteConnector(resolved, transport=transport))
            continue

        if name == "confluence" and "confluence" in selected:
            connectors.append(ConfluenceConnector(resolved, transport=transport))
            if (
                include_writes
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "writes_enabled")
            ):
                connectors.append(
                    ConfluenceWriteConnector(resolved, transport=transport)
                )
            continue

        if name == "bitbucket" and "bitbucket" in selected:
            connectors.append(BitbucketConnector(resolved, transport=transport))
            if (
                include_writes
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "pull_request_writes_enabled")
            ):
                connectors.append(
                    BitbucketWriteConnector(resolved, transport=transport)
                )
            continue

        if name == "github" and "github" in selected:
            connectors.append(GitHubConnector(resolved, transport=transport))
            if (
                include_writes
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "writes_enabled")
            ):
                connectors.append(GitHubWriteConnector(resolved, transport=transport))
            if (
                include_writes
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "admin_enabled")
            ):
                connectors.append(GitHubAdminConnector(resolved, transport=transport))
            continue

        if name != "microsoft":
            continue

        if "microsoft" in selected:
            connectors.append(MicrosoftIdentityConnector(resolved, transport=transport))
        if "sharepoint" in selected:
            connectors.append(SharePointConnector(resolved, transport=transport))
            if (
                include_writes
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "sharepoint_writes_enabled")
            ):
                if artifact_root is None:
                    raise ConfigurationError(
                        "SharePoint writes require an explicit artifact_root"
                    )
                connectors.append(
                    SharePointWriteConnector(
                        resolved,
                        artifact_root=artifact_directory or artifact_root,
                        transport=transport,
                    )
                )
        if "outlook" in selected:
            connectors.append(OutlookConnector(resolved, transport=transport))
            if (
                include_communications
                and _feature_enabled(unresolved, "send_enabled")
                and _feature_enabled(unresolved, "outlook_send_enabled")
            ):
                connectors.append(OutlookSendConnector(resolved, transport=transport))
        if "teams" in selected:
            connectors.append(TeamsConnector(resolved, transport=transport))
            if (
                include_communications
                and _feature_enabled(unresolved, "send_enabled")
                and _feature_enabled(unresolved, "teams_send_enabled")
            ):
                connectors.append(TeamsSendConnector(resolved, transport=transport))
        if "onenote" in selected and _feature_enabled(
            unresolved,
            "onenote_read_enabled",
        ):
            connectors.append(OneNoteReadConnector(resolved, transport=transport))
    return tuple(connectors)


def build_live_registry(
    config: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    transport: HttpTransport | None = None,
    systems: set[str] | None = None,
    include_writes: bool = False,
    include_communications: bool = False,
    workspace_root: Path | None = None,
    artifact_root: Path | None = None,
    artifact_directory: PinnedDirectory | None = None,
    approved_execution_context: ExecutionContext | None = None,
    captured_executions: tuple[CapturedConnectorExecution, ...] | None = None,
) -> ConnectorRegistry:
    """Build a registry containing explicitly scoped live connectors."""

    registry = ConnectorRegistry()
    for connector in build_live_connectors(
        config,
        environ=environ,
        transport=transport,
        systems=systems,
        include_writes=include_writes,
        include_communications=include_communications,
        workspace_root=workspace_root,
        artifact_root=artifact_root,
        artifact_directory=artifact_directory,
        approved_execution_context=approved_execution_context,
        captured_executions=captured_executions,
    ):
        registry.register(connector)
    return registry


def register_draft_connectors(
    registry: ConnectorRegistry,
    output_root: Path | PinnedDirectory,
    *,
    catalog: CapabilityCatalog | None = None,
    artifact_budget: ArtifactBudget | None = None,
) -> ConnectorRegistry:
    """Register all local, non-publishing Phase 3 generators."""

    require_persistent_state_platform()
    root = pin_directory(output_root)
    budget = artifact_budget or ArtifactBudget()
    output_limits = catalog.local_generation_output_limits() if catalog else None
    try:
        for connector in (
            JiraDraftConnector(
                root, artifact_budget=budget, output_limits=output_limits
            ),
            ConfluenceDraftConnector(
                root, artifact_budget=budget, output_limits=output_limits
            ),
            OutlookDraftConnector(
                root, artifact_budget=budget, output_limits=output_limits
            ),
            TeamsDraftConnector(
                root, artifact_budget=budget, output_limits=output_limits
            ),
            PowerPointDraftConnector(
                root, artifact_budget=budget, output_limits=output_limits
            ),
            RepositoryDraftConnector(
                root, artifact_budget=budget, output_limits=output_limits
            ),
        ):
            registry.register(connector)
    finally:
        root.close()
    return registry


def build_draft_registry(
    output_root: Path | PinnedDirectory,
    *,
    catalog: CapabilityCatalog | None = None,
    artifact_budget: ArtifactBudget | None = None,
) -> ConnectorRegistry:
    """Build a registry containing only local draft generators."""

    return register_draft_connectors(
        ConnectorRegistry(),
        output_root,
        catalog=catalog,
        artifact_budget=artifact_budget,
    )


def _feature_enabled(config: ConnectorConfig, key: str) -> bool:
    value = config.extra.get(key, False)
    if not isinstance(value, bool):
        raise ConfigurationError(
            f"connector {config.system} setting {key} must be a boolean"
        )
    return value


def _connector_is_selected(system: str, selected: set[str]) -> bool:
    """Return whether a provider configuration backs a selected runtime system."""

    if system == "microsoft":
        return bool(
            selected & {"microsoft", "sharepoint", "outlook", "teams", "onenote"}
        )
    return system in selected


def _verify_approved_execution_context(
    config: IntegrationConfig,
    captured: tuple[CapturedConnectorExecution, ...],
    approved: ExecutionContext,
) -> None:
    """Require the factory's exact snapshots to equal the reviewed identities."""

    if not config.source_sha256 or config.source_sha256 != approved.integrations_sha256:
        raise ConfigurationError(
            "captured integrations bundle differs from the approved execution context"
        )
    observed = {item.binding.system: item.binding for item in captured}
    expected = {item.system: item for item in approved.connectors}
    if observed.keys() != expected.keys():
        raise ConfigurationError(
            "captured connector set differs from the approved execution context"
        )
    for system in sorted(observed):
        actual = observed[system]
        reviewed = expected[system]
        if actual.deployment != reviewed.deployment:
            detail = "deployment"
        elif actual.config_identity_sha256 != reviewed.config_identity_sha256:
            detail = "config identity"
        elif actual.resolved_base_url != reviewed.resolved_base_url:
            detail = "base URL"
        elif actual.resolved_origin != reviewed.resolved_origin:
            detail = "origin"
        elif actual.authentication_mode != reviewed.authentication_mode:
            detail = "authentication mode"
        elif actual.credential_scopes != reviewed.credential_scopes:
            detail = "credential scopes"
        elif actual.credential_identity != reviewed.credential_identity:
            detail = "credential identity"
        elif actual.ca_bundle_path != reviewed.ca_bundle_path:
            detail = "CA path"
        elif actual.ca_bundle_sha256 != reviewed.ca_bundle_sha256:
            detail = "CA digest"
        else:
            continue
        raise ConfigurationError(
            f"captured connector {system} {detail} differs from the approved "
            "execution context"
        )


def _verify_supplied_captured_executions(
    config: IntegrationConfig,
    captured: tuple[CapturedConnectorExecution, ...],
    selected: set[str],
) -> None:
    """Require supplied immutable targets to match the selected config exactly."""

    expected = {
        item.system: item
        for item in config.connectors.values()
        if item.enabled and _connector_is_selected(item.system, selected)
    }
    observed = {item.binding.system: item for item in captured}
    if observed.keys() != expected.keys() or len(observed) != len(captured):
        raise ConfigurationError(
            "captured connector set differs from selected integration configuration"
        )
    for system, item in observed.items():
        configured = expected[system]
        target = item.target
        binding = item.binding
        resolved = item.resolved
        ca_bundle = target.ca_bundle
        if item.config != configured:
            detail = "configuration"
        elif target.system != system or target.config_identity != configured.identity:
            detail = "target identity"
        elif binding.config_identity_sha256 != target.config_identity:
            detail = "config identity"
        elif binding.deployment != str(configured.deployment):
            detail = "deployment"
        elif binding.resolved_base_url != target.base_url:
            detail = "base URL"
        elif binding.resolved_origin != _captured_origin(target.base_url):
            detail = "origin"
        elif binding.authentication_mode != str(configured.auth_mode):
            detail = "authentication mode"
        elif resolved is None:
            detail = "resolved credentials"
        elif resolved.system != system or resolved.base_url != target.base_url:
            detail = "resolved target"
        elif str(resolved.auth.mode) != binding.authentication_mode:
            detail = "resolved authentication mode"
        elif resolved.config_identity != binding.config_identity_sha256:
            detail = "resolved config identity"
        elif (str(resolved.ca_bundle) if resolved.ca_bundle is not None else None) != (
            str(ca_bundle.path) if ca_bundle is not None else None
        ):
            detail = "resolved CA path"
        elif resolved.ca_bundle_sha256 != (
            ca_bundle.sha256 if ca_bundle is not None else None
        ):
            detail = "resolved CA digest"
        elif binding.ca_bundle_path != (
            str(ca_bundle.path) if ca_bundle is not None else None
        ):
            detail = "CA path"
        elif binding.ca_bundle_sha256 != (
            ca_bundle.sha256 if ca_bundle is not None else None
        ):
            detail = "CA digest"
        else:
            continue
        raise ConfigurationError(
            f"captured connector {system} {detail} differs from its immutable target"
        )


def _captured_origin(base_url: str) -> str:
    """Return the normalized origin represented by a captured base URL."""

    parsed = urlsplit(base_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            "captured connector has an invalid base URL"
        ) from error
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and not (parsed.scheme.lower() == "https" and port == 443):
        rendered_host = f"{rendered_host}:{port}"
    return f"{parsed.scheme.lower()}://{rendered_host}"
