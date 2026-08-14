"""Shared constructors and filesystem helpers for tests."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ResourceRef,
    RiskLevel,
)


def ensure_private_directory(path: Path) -> Path:
    """Create one test directory with private permissions."""

    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)
    return path


def copy_private_file(source: Path, destination: Path) -> Path:
    """Copy one fixture or config file into a private test-controlled path."""

    ensure_private_directory(destination.parent)
    destination.write_bytes(source.read_bytes())
    if os.name == "posix":
        destination.chmod(0o600)
    return destination


def resolved_config(
    system: str,
    *,
    deployment: DeploymentType = DeploymentType.CLOUD,
    base_url: str = "https://example.test",
    auth: ResolvedAuth | None = None,
    extra: Mapping[str, Any] | None = None,
    max_pages: int = 10,
    max_items: int = 200,
) -> ResolvedConnectorConfig:
    """Build an in-memory connector configuration."""

    return ResolvedConnectorConfig(
        system=system,
        deployment=deployment,
        base_url=base_url,
        auth=auth or ResolvedAuth(AuthMode.NONE),
        max_pages=max_pages,
        max_items=max_items,
        extra=dict(extra or {}),
    )


def read_action(
    capability: str,
    *,
    system: str,
    resource_type: str,
    resource_id: str,
    parameters: Mapping[str, Any] | None = None,
    expected_version: str | None = None,
) -> AgentAction:
    """Build an auto-permitted read-only action."""

    return AgentAction(
        capability=capability,
        target=ResourceRef(
            system=system,
            resource_type=resource_type,
            resource_id=resource_id,
            expected_version=expected_version,
        ),
        parameters=dict(parameters or {}),
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key=f"test:{capability}:{resource_id}",
        justification="Connector contract test.",
    )


def action_for(
    capability: str,
    *,
    system: str,
    resource_type: str,
    resource_id: str,
    risk: RiskLevel,
    parameters: Mapping[str, Any] | None = None,
    expected_version: str | None = None,
    requires_approval: bool | None = None,
) -> AgentAction:
    """Build a typed action for connector contract tests.

    Parameters
    ----------
    capability
        Dotted capability name.
    system
        Connector system.
    resource_type
        Target resource type.
    resource_id
        Target identifier.
    risk
        Required risk classification.
    parameters
        Capability parameters.
    expected_version
        Optional optimistic-concurrency precondition.
    requires_approval
        Override approval requirement. Writes and communications default to
        requiring approval.

    Returns
    -------
    AgentAction
        Test action.
    """

    approval = (
        risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
        if requires_approval is None
        else requires_approval
    )
    return AgentAction(
        capability=capability,
        target=ResourceRef(
            system=system,
            resource_type=resource_type,
            resource_id=resource_id,
            expected_version=expected_version,
        ),
        parameters=dict(parameters or {}),
        risk=risk,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=approval,
        idempotency_key=f"test:{capability}:{resource_id}",
        justification="Connector contract test.",
    )
