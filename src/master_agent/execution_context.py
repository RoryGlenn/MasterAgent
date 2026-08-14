"""Build and enforce approval-bound live execution identities."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from master_agent.config import (
    ConnectorConfig,
    IntegrationConfig,
    ResolvedExecutionTarget,
)
from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.models import (
    ChangePlan,
    ConfigurationExecutionBinding,
    ConnectorExecutionBinding,
    ExecutionContext,
    PluginExecutionBinding,
    RuntimeExecutionBinding,
    RuntimePathExecutionBinding,
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
    require_trusted_principal: bool = True,
) -> tuple[CapturedConnectorExecution, ...]:
    """Capture enabled destinations and, when required, trusted principals."""

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
                    credential_identity=(
                        config.credential_identity(source)
                        if require_trusted_principal
                        else None
                    ),
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
    runtime: RuntimeExecutionBinding | None = None,
    include_connectors: bool = True,
) -> ExecutionContext:
    """Resolve a secret-free snapshot suitable for plan approval binding."""

    if not integrations.source_sha256:
        raise ConfigurationError(
            "applied execution context requires a hashed integrations bundle"
        )
    connector_bindings = (
        tuple(
            item.binding
            for item in capture_connector_executions(
                integrations,
                environ=environ,
            )
        )
        if include_connectors
        else ()
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
        runtime=runtime,
    )


def build_runtime_execution_binding(
    integrations: IntegrationConfig,
    *,
    connector_mode: str,
    include_writes: bool,
    include_communications: bool,
    audit_database: Path,
    artifact_root: Path,
    workspace_root: Path | None,
    result_json: Path | None,
    evidence_type: str,
    configuration_sources: Mapping[str, ConfigSource],
    environ: Mapping[str, str] | None = None,
) -> RuntimeExecutionBinding:
    """Capture every non-secret runtime input that can alter an applied run."""

    source = environ if environ is not None else os.environ
    normalized_workspace = _canonical_path(workspace_root)
    publication_roots: list[RuntimePathExecutionBinding] = []
    if connector_mode == "live" and include_writes:
        for config in integrations.connectors.values():
            if not config.enabled or config.system != "bitbucket":
                continue
            if not (
                _strict_extra_bool(config.extra, "write_enabled")
                and _strict_extra_bool(config.extra, "branch_push_enabled")
            ):
                continue
            variable = str(config.extra.get("repository_root_env", "")).strip()
            if variable:
                raw_root = source.get(variable, "").strip()
                if not raw_root:
                    raise ConfigurationError(
                        f"Bitbucket branch publication requires environment variable {variable}"
                    )
                selected_root = Path(raw_root)
            elif workspace_root is not None:
                selected_root = workspace_root
            else:
                raise ConfigurationError(
                    "Bitbucket branch publication requires workspace_root or "
                    "repository_root_env"
                )
            publication_roots.append(
                RuntimePathExecutionBinding(
                    name=f"{config.system}.branch_publication",
                    path=_canonical_path(selected_root) or "",
                )
            )

    configurations = tuple(
        ConfigurationExecutionBinding(
            name=name,
            sha256=_config_source_sha256(config_source),
        )
        for name, config_source in configuration_sources.items()
    )
    normalized_result = _canonical_path(result_json)
    return RuntimeExecutionBinding(
        connector_mode=connector_mode,
        include_writes=include_writes,
        include_communications=include_communications,
        audit_database=_canonical_path(audit_database) or "",
        artifact_root=_canonical_path(artifact_root) or "",
        workspace_root=normalized_workspace,
        result_json=normalized_result,
        evidence_type=evidence_type if normalized_result is not None else None,
        configurations=configurations,
        publication_roots=tuple(publication_roots),
    )


def enforce_execution_context(plan: ChangePlan, observed: ExecutionContext) -> None:
    """Reject live execution unless the observed context is exactly approved."""

    approved = plan.execution_context
    if approved is None:
        raise ConfigurationError(
            "applied execution requires an approval-bound execution context; "
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
        if approved.runtime != observed.runtime:
            changed.append("runtime policy, principal, gate, or path binding")
        rendered = ", ".join(changed) or "execution context"
        raise ConfigurationError(
            f"applied execution context differs from the approved plan: {rendered}"
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


def _config_source_sha256(source: ConfigSource) -> str:
    """Hash one already trusted configuration snapshot without interpreting it."""

    with source.open("rb") as handle:
        payload = handle.read()
    return hashlib.sha256(payload).hexdigest()


def _canonical_path(path: Path | None) -> str | None:
    if path is None:
        return None
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    return str(selected.resolve(strict=False))


def _strict_extra_bool(extra: Mapping[str, object], key: str) -> bool:
    value = extra.get(key, False)
    if not isinstance(value, bool):
        raise ConfigurationError(f"connector setting {key} must be a boolean")
    return value
