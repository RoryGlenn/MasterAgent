"""Build and enforce approval-bound live execution identities."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import urlsplit

from master_agent.config import IntegrationConfig
from master_agent.errors import ConfigurationError
from master_agent.models import (
    ChangePlan,
    ConnectorExecutionBinding,
    ExecutionContext,
    PluginExecutionBinding,
)
from master_agent.plugins import PluginDescriptor


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
    source = environ if environ is not None else os.environ
    connector_bindings: list[ConnectorExecutionBinding] = []
    for config in integrations.connectors.values():
        if not config.enabled:
            continue
        base_url, ca_bundle = config.resolve_execution_target(source)
        ca_path: str | None = None
        ca_digest: str | None = None
        if ca_bundle is not None:
            ca_path = str(ca_bundle)
            ca_digest = _hash_stable_regular_file(ca_bundle)
        connector_bindings.append(
            ConnectorExecutionBinding(
                system=config.system,
                deployment=str(config.deployment),
                config_identity_sha256=config.identity,
                resolved_base_url=base_url,
                resolved_origin=_origin(base_url, system=config.system),
                ca_bundle_path=ca_path,
                ca_bundle_sha256=ca_digest,
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
        connectors=tuple(connector_bindings),
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


def _hash_stable_regular_file(path: Path) -> str:
    try:
        path_metadata = path.lstat()
        if not stat.S_ISREG(path_metadata.st_mode):
            raise ConfigurationError("connector CA bundle must be a regular file")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            opened_metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or opened_metadata.st_dev != path_metadata.st_dev
                or opened_metadata.st_ino != path_metadata.st_ino
            ):
                raise ConfigurationError(
                    "connector CA bundle changed during identity verification"
                )
            total = 0
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                total += len(block)
                digest.update(block)
            final_metadata = os.fstat(handle.fileno())
        if (
            total != opened_metadata.st_size
            or final_metadata.st_size != opened_metadata.st_size
            or final_metadata.st_mtime_ns != opened_metadata.st_mtime_ns
        ):
            raise ConfigurationError(
                "connector CA bundle changed during identity verification"
            )
        return digest.hexdigest()
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "connector CA bundle could not be identified"
        ) from error
