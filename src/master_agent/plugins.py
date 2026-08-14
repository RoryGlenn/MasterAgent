"""Explicit, fail-closed connector plugin discovery.

Plugins are never loaded merely because they are installed. Operators must select
exact entry-point names, and every loaded object must satisfy the connector
contract before it can be registered.
"""

from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from master_agent.errors import ConfigurationError
from master_agent.registry import ConnectorRegistry

CONNECTOR_ENTRY_POINT_GROUP = "master_agent.connectors"


@dataclass(frozen=True, slots=True)
class PluginDescriptor:
    """Secret-free metadata for one installed plugin entry point."""

    name: str
    group: str
    value: str
    distribution: str | None = None
    distribution_version: str | None = None
    artifact_sha256: str | None = None
    identity_sha256: str = ""

    def __post_init__(self) -> None:
        payload = {
            "name": self.name,
            "group": self.group,
            "value": self.value,
            "distribution": self.distribution,
            "distribution_version": self.distribution_version,
            "artifact_sha256": self.artifact_sha256,
        }
        identity = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        object.__setattr__(self, "identity_sha256", identity)

    def to_dict(self) -> dict[str, str | None]:
        """Serialize plugin metadata without loading plugin code."""

        return {
            "name": self.name,
            "group": self.group,
            "value": self.value,
            "distribution": self.distribution,
            "distribution_version": self.distribution_version,
            "artifact_sha256": self.artifact_sha256,
            "identity_sha256": self.identity_sha256,
        }


@dataclass(frozen=True, slots=True)
class LoadedPlugin:
    """Metadata for one explicitly loaded connector plugin."""

    descriptor: PluginDescriptor
    systems: tuple[str, ...]
    capabilities: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the loaded plugin summary."""

        return {
            **self.descriptor.to_dict(),
            "systems": list(self.systems),
            "capabilities": list(self.capabilities),
        }


def discover_connector_plugins(
    *,
    entries: Iterable[Any] | None = None,
) -> tuple[PluginDescriptor, ...]:
    """List installed connector entry points without importing plugin modules.

    Parameters
    ----------
    entries
        Optional entry-point iterable used by deterministic tests. When omitted,
        installed entry points in ``master_agent.connectors`` are inspected.

    Returns
    -------
    tuple[PluginDescriptor, ...]
        Stable metadata ordered by entry-point name and value.
    """

    selected = tuple(entries) if entries is not None else _installed_entries()
    descriptors = tuple(
        sorted(
            (_descriptor(item) for item in selected),
            key=lambda item: (item.name, item.value),
        )
    )
    names = [item.name for item in descriptors]
    if len(names) != len(set(names)):
        raise ConfigurationError("connector plugin entry-point names must be unique")
    return descriptors


def load_connector_plugins(
    registry: ConnectorRegistry,
    *,
    enabled_names: Sequence[str],
    entries: Iterable[Any] | None = None,
) -> tuple[LoadedPlugin, ...]:
    """Load only explicitly named connector plugins into a registry.

    Parameters
    ----------
    registry
        Target registry. Existing duplicate capability checks remain active.
    enabled_names
        Exact entry-point names reviewed and enabled by the operator.
    entries
        Optional deterministic entry-point iterable used by tests.

    Returns
    -------
    tuple[LoadedPlugin, ...]
        Metadata for successfully loaded plugins.
    """

    requested = tuple(
        dict.fromkeys(name.strip() for name in enabled_names if name.strip())
    )
    if not requested:
        return ()
    selected = tuple(entries) if entries is not None else _installed_entries()
    descriptors = discover_connector_plugins(entries=selected)
    by_name = {str(item.name): item for item in selected}
    descriptor_by_name = {item.name: item for item in descriptors}
    missing = sorted(set(requested) - set(by_name))
    if missing:
        raise ConfigurationError(
            "enabled connector plugins are not installed: " + ", ".join(missing)
        )

    loaded: list[LoadedPlugin] = []
    for name in requested:
        entry = by_name[name]
        descriptor = descriptor_by_name[name]
        if entries is None and (
            not descriptor.distribution
            or not descriptor.distribution_version
            or not descriptor.artifact_sha256
        ):
            raise ConfigurationError(
                f"connector plugin {name} lacks a verifiable distribution artifact"
            )
        factory = entry.load()
        observed = _descriptor(entry)
        if observed.identity_sha256 != descriptor.identity_sha256:
            raise ConfigurationError(
                f"connector plugin {name} changed while it was being loaded"
            )
        produced = factory() if callable(factory) else factory
        connectors = _normalize_connectors(produced, plugin_name=name)
        for connector in connectors:
            _validate_connector(connector, plugin_name=name)
            registry.register(connector)
        loaded.append(
            LoadedPlugin(
                descriptor=descriptor,
                systems=tuple(sorted({str(item.system) for item in connectors})),
                capabilities=tuple(
                    sorted(
                        {
                            str(capability)
                            for item in connectors
                            for capability in item.capabilities
                        }
                    )
                ),
            )
        )
    return tuple(loaded)


def _installed_entries() -> tuple[Any, ...]:
    points = metadata.entry_points()
    if hasattr(points, "select"):
        return tuple(points.select(group=CONNECTOR_ENTRY_POINT_GROUP))
    return tuple(points.get(CONNECTOR_ENTRY_POINT_GROUP, ()))  # type: ignore[attr-defined]


def _descriptor(entry: Any) -> PluginDescriptor:
    group = str(getattr(entry, "group", CONNECTOR_ENTRY_POINT_GROUP))
    if group != CONNECTOR_ENTRY_POINT_GROUP:
        raise ConfigurationError(f"unexpected connector plugin group: {group}")
    distribution = getattr(entry, "dist", None)
    distribution_name = getattr(distribution, "name", None)
    distribution_version = getattr(distribution, "version", None)
    return PluginDescriptor(
        name=str(entry.name),
        group=group,
        value=str(entry.value),
        distribution=str(distribution_name) if distribution_name else None,
        distribution_version=(
            str(distribution_version) if distribution_version else None
        ),
        artifact_sha256=_distribution_artifact_sha256(distribution),
    )


def _distribution_artifact_sha256(distribution: Any) -> str | None:
    """Hash the currently installed files owned by a plugin distribution."""

    if distribution is None:
        return None
    files = getattr(distribution, "files", None)
    if not files:
        return None
    manifest: list[dict[str, object]] = []
    try:
        for relative in sorted(files, key=str):
            path = Path(distribution.locate_file(relative))
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ConfigurationError(
                    "connector plugin distribution contains a non-regular artifact"
                )
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            manifest.append(
                {
                    "path": str(relative),
                    "size": metadata.st_size,
                    "sha256": digest.hexdigest(),
                }
            )
    except (OSError, TypeError) as error:
        raise ConfigurationError(
            "connector plugin distribution artifacts could not be verified"
        ) from error
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_connectors(value: Any, *, plugin_name: str) -> tuple[Any, ...]:
    if _looks_like_connector(value):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        items = tuple(value)
        if items and all(_looks_like_connector(item) for item in items):
            return items
    raise ConfigurationError(
        f"connector plugin {plugin_name} did not return a connector or connector iterable"
    )


def _validate_connector(connector: Any, *, plugin_name: str) -> None:
    if not _looks_like_connector(connector):
        raise ConfigurationError(
            f"connector plugin {plugin_name} returned an invalid connector object"
        )
    system = str(connector.system).strip()
    capabilities = connector.capabilities
    if not system:
        raise ConfigurationError(f"connector plugin {plugin_name} has an empty system")
    if not isinstance(capabilities, frozenset) or not capabilities:
        raise ConfigurationError(
            f"connector plugin {plugin_name} capabilities must be a non-empty frozenset"
        )
    if not all(isinstance(item, str) and "." in item for item in capabilities):
        raise ConfigurationError(
            f"connector plugin {plugin_name} has invalid capability names"
        )


def _looks_like_connector(value: Any) -> bool:
    return bool(
        value is not None
        and hasattr(value, "system")
        and hasattr(value, "capabilities")
        and callable(getattr(value, "execute", None))
        and callable(getattr(value, "read", None))
        and callable(getattr(value, "verify", None))
    )
