"""Build and enforce approval-bound live execution identities."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from master_agent.config import (
    ConnectorConfig,
    IntegrationConfig,
    ResolvedExecutionTarget,
)
from master_agent.errors import ConfigurationError
from master_agent.models import (
    ChangePlan,
    ConnectorExecutionBinding,
    ExecutionContext,
    PluginExecutionBinding,
)
from master_agent.plugins import PluginDescriptor


@dataclass(frozen=True, slots=True)
class CapturedConnectorExecution:
    """Immutable runtime material plus its secret-free approval binding."""

    config: ConnectorConfig
    target: ResolvedExecutionTarget
    binding: ConnectorExecutionBinding


def capture_connector_executions(
    integrations: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[CapturedConnectorExecution, ...]:
    """Capture all enabled connector destinations and CA bytes exactly once."""

    source = environ if environ is not None else os.environ
    captured: list[CapturedConnectorExecution] = []
    for config in integrations.connectors.values():
        if not config.enabled:
            continue
        target = config.capture_execution_target(source)
        ca_bundle = target.ca_bundle
        captured.append(
            CapturedConnectorExecution(
                config=config,
                target=target,
                binding=ConnectorExecutionBinding(
                    system=config.system,
                    deployment=str(config.deployment),
                    config_identity_sha256=target.config_identity,
                    resolved_base_url=target.base_url,
                    resolved_origin=_origin(target.base_url, system=config.system),
                    ca_bundle_path=(
                        str(ca_bundle.path) if ca_bundle is not None else None
                    ),
                    ca_bundle_sha256=(
                        ca_bundle.sha256 if ca_bundle is not None else None
                    ),
                ),
            )
        )
    return tuple(sorted(captured, key=lambda item: item.binding.system))


def build_execution_context(
    integrations: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    plugin_descriptors: Sequence[PluginDescriptor] = (),
) -> ExecutionContext:
    """Resolve a secret-free snapshot suitable for plan approval binding."""

    if not integrations.source_sha256:
        raise ConfigurationError(
            "live execution context requires a hashed integrations bundle"
        )
    connector_bindings = tuple(
        item.binding
        for item in capture_connector_executions(
            integrations,
            environ=environ,
        )
    )

    plugin_bindings: list[PluginExecutionBinding] = []
    for descriptor in plugin_descriptors:
        if not (
            descriptor.distribution
            and descriptor.distribution_version
            and descriptor.artifact_sha256
        ):
            raise ConfigurationError(
                f"connector plugin {descriptor.name} lacks an exact artifact identity"
            )
        plugin_bindings.append(
            PluginExecutionBinding(
                name=descriptor.name,
                group=descriptor.group,
                entry_point=descriptor.value,
                distribution=descriptor.distribution,
                distribution_version=descriptor.distribution_version,
                artifact_sha256=descriptor.artifact_sha256,
                identity_sha256=descriptor.identity_sha256,
            )
        )

    return ExecutionContext(
        integrations_sha256=integrations.source_sha256,
        connectors=connector_bindings,
        plugins=tuple(plugin_bindings),
    )


def enforce_execution_context(plan: ChangePlan, observed: ExecutionContext) -> None:
    """Reject live execution unless the observed context is exactly approved."""

    approved = plan.execution_context
    if approved is None:
        raise ConfigurationError(
            "live execution requires an approval-bound execution context; "
            "run bind-context before approval"
        )
    if approved != observed:
        changed: list[str] = []
        if approved.integrations_sha256 != observed.integrations_sha256:
            changed.append("integrations bundle")
        if approved.connectors != observed.connectors:
            changed.append("connector origin or CA identity")
        if approved.plugins != observed.plugins:
            changed.append("connector plugin identity")
        rendered = ", ".join(changed) or "execution context"
        raise ConfigurationError(
            f"live execution context differs from the approved plan: {rendered}"
        )


def _origin(base_url: str, *, system: str) -> str:
    parsed = urlsplit(base_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            f"connector {system} has an invalid base URL port"
        ) from error
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and not (parsed.scheme == "https" and port == 443):
        rendered_host = f"{rendered_host}:{port}"
    return f"{parsed.scheme.lower()}://{rendered_host}"
