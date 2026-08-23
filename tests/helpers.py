"""Shared constructors for connector tests."""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from typing import Any

from master_agent.auth import AuthMode, ResolvedAuth
from master_agent.config import DeploymentType, ResolvedConnectorConfig
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
    SystemsAssessment,
)
from master_agent.planners.base import (
    bind_fast_path_governance,
    bind_systems_governance,
)


@contextmanager
def private_temporary_directory() -> Iterator[str]:
    """Create test fixtures under a restrictive process umask.

    Trusted configuration and runtime paths deliberately reject group- or
    world-writable inputs. Keep permission-sensitive fixtures deterministic
    when a developer's interactive shell uses a collaborative umask.
    """

    previous_umask = os.umask(0o077)
    try:
        with TemporaryDirectory() as directory:
            yield directory
    finally:
        os.umask(previous_umask)


def govern_test_plan(plan: ChangePlan) -> ChangePlan:
    """Return a governed copy of an executable test plan."""

    safe = all(
        action.risk in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
        for action in plan.actions
    )
    if safe:
        return bind_fast_path_governance(
            plan,
            current_behavior="the test action has not yet run",
            constraint="the runtime boundary must be exercised deterministically",
            leverage_point="the smallest typed test action",
            success_metric="the expected test state is observed",
            failure_condition="the expected test state is not observed",
        )
    return bind_systems_governance(
        plan,
        SystemsAssessment(
            desired_outcome=plan.goal,
            current_behavior="the effect-bearing test action has not yet run",
            constraint="the runtime effect must remain within the test fixture",
            stocks=("the isolated fixture state",),
            flows=("one typed action through the test connector",),
            feedback_loops=("verification determines the asserted final state",),
            delays=("connector execution and verification latency",),
            leverage_point="the isolated connector action",
            simplest_intervention="execute the smallest isolated test plan",
            success_metric="the asserted effect and verification state are observed",
            failure_condition="execution or verification differs from the assertion",
            unintended_consequences=("fixture state could become indeterminate",),
            removable_complexity=("the disposable test fixture",),
            low_risk=False,
            reversible=True,
            well_understood=True,
        ),
    )


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
