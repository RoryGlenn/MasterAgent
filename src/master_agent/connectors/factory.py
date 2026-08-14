"""Construct scoped connector registries from runtime configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

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
    ConfluenceDraftConnector,
    JiraDraftConnector,
    OutlookDraftConnector,
    PowerPointDraftConnector,
    RepositoryDraftConnector,
    TeamsDraftConnector,
)
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
from master_agent.registry import ConnectorRegistry

_READ_SYSTEMS = frozenset(
    {
        "jira",
        "confluence",
        "bitbucket",
        "microsoft",
        "sharepoint",
        "outlook",
        "teams",
        "onenote",
    }
)


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
) -> tuple[Connector, ...]:
    """Construct explicitly enabled live connectors.

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

    Returns
    -------
    tuple[Connector, ...]
        Deterministically ordered connector instances.
    """

    source = dict(environ if environ is not None else os.environ)
    selected = systems or set(_READ_SYSTEMS) | {"repository"}
    connectors: list[Connector] = []
    captured = capture_connector_executions(
        config,
        environ=source,
        require_trusted_principal=approved_execution_context is not None,
    )
    if approved_execution_context is not None:
        _verify_approved_execution_context(
            config,
            captured,
            approved_execution_context,
        )
    targets = {item.binding.system: item.target for item in captured}

    if include_writes:
        for unresolved in config.connectors.values():
            if (
                unresolved.enabled
                and unresolved.system == "bitbucket"
                and _feature_enabled(unresolved, "write_enabled")
                and _feature_enabled(unresolved, "branch_push_enabled")
            ):
                raise ConfigurationError(
                    "Bitbucket local-Git branch publication is disabled until all "
                    "Git metadata transactions are descriptor-bound"
                )

    for name in sorted(config.connectors):
        unresolved = config.connectors[name]
        if not unresolved.enabled:
            continue
        if name not in {"jira", "confluence", "bitbucket", "microsoft"}:
            continue
        resolved = unresolved.resolve(
            source,
            auth_transport=transport,
            execution_target=targets[unresolved.system],
        )

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
    ):
        registry.register(connector)
    return registry


def register_draft_connectors(
    registry: ConnectorRegistry,
    output_root: Path | PinnedDirectory,
) -> ConnectorRegistry:
    """Register all local, non-publishing Phase 3 generators."""

    root = pin_directory(output_root)
    try:
        for connector in (
            JiraDraftConnector(root),
            ConfluenceDraftConnector(root),
            OutlookDraftConnector(root),
            TeamsDraftConnector(root),
            PowerPointDraftConnector(root),
            RepositoryDraftConnector(root),
        ):
            registry.register(connector)
    finally:
        root.close()
    return registry


def build_draft_registry(output_root: Path | PinnedDirectory) -> ConnectorRegistry:
    """Build a registry containing only local draft generators."""

    return register_draft_connectors(ConnectorRegistry(), output_root)


def _feature_enabled(config: ConnectorConfig, key: str) -> bool:
    value = config.extra.get(key, False)
    if not isinstance(value, bool):
        raise ConfigurationError(
            f"connector {config.system} setting {key} must be a boolean"
        )
    return value


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
        if actual.config_identity_sha256 != reviewed.config_identity_sha256:
            detail = "config identity"
        elif actual.resolved_base_url != reviewed.resolved_base_url:
            detail = "base URL"
        elif actual.resolved_origin != reviewed.resolved_origin:
            detail = "origin"
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
