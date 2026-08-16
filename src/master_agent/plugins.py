"""Explicit, fail-closed connector plugin discovery and loading.

Installation does not grant execution authority. Operators can create and
review an exact plugin lock and bind selected entries into a plan. The CLI does
not execute plugin code until an isolated worker can seal the plugin's complete
dependency closure; the loader below remains an internal implementation
scaffold and test surface.
"""

from __future__ import annotations

import atexit
import hashlib
import importlib
import json
import os
import stat
import sys
import sysconfig
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import machinery, metadata
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any

from master_agent.config_sources import ConfigSource
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError
from master_agent.registry import ConnectorRegistry

CONNECTOR_ENTRY_POINT_GROUP = "master_agent.connectors"
PLUGIN_LOCK_SCHEMA = "master-agent/plugins@1"
_MAX_DISTRIBUTION_FILES = 4_096
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_DISTRIBUTION_BYTES = 128 * 1024 * 1024
_MAX_ARTIFACT_DEPTH = 64
_MAX_ARTIFACT_PATH_CHARACTERS = 4_096
_READ_BLOCK_BYTES = 1024 * 1024


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

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PluginDescriptor:
        """Parse and authenticate one descriptor from an operator lock."""

        supplied_identity = str(data.get("identity_sha256", ""))
        descriptor = cls(
            name=str(data["name"]),
            group=str(data["group"]),
            value=str(data["value"]),
            distribution=(
                str(data["distribution"])
                if data.get("distribution") is not None
                else None
            ),
            distribution_version=(
                str(data["distribution_version"])
                if data.get("distribution_version") is not None
                else None
            ),
            artifact_sha256=(
                str(data["artifact_sha256"])
                if data.get("artifact_sha256") is not None
                else None
            ),
        )
        if supplied_identity != descriptor.identity_sha256:
            raise ConfigurationError("connector plugin lock has an invalid identity")
        return descriptor


@dataclass(frozen=True, slots=True)
class PluginLock:
    """Operator-reviewed identities for allowed connector plugin artifacts."""

    plugins: tuple[PluginDescriptor, ...]
    schema: str = PLUGIN_LOCK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PLUGIN_LOCK_SCHEMA:
            raise ConfigurationError("unsupported connector plugin lock schema")
        plugins = tuple(sorted(self.plugins, key=lambda item: item.name))
        if len({item.name for item in plugins}) != len(plugins):
            raise ConfigurationError("connector plugin lock names must be unique")
        for item in plugins:
            if item.group != CONNECTOR_ENTRY_POINT_GROUP:
                raise ConfigurationError(
                    f"unexpected connector plugin group in lock: {item.group}"
                )
            if not (
                item.name.strip()
                and item.value.strip()
                and item.distribution
                and item.distribution.strip()
                and item.distribution_version
                and item.distribution_version.strip()
                and item.artifact_sha256
                and _is_sha256(item.artifact_sha256)
            ):
                raise ConfigurationError(
                    "connector plugin lock requires exact name, distribution, "
                    "version, entry point, and artifact digest"
                )
        object.__setattr__(self, "plugins", plugins)

    def to_dict(self) -> dict[str, object]:
        """Serialize the trusted plugin inventory."""

        return {
            "schema": self.schema,
            "plugins": [item.to_dict() for item in self.plugins],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PluginLock:
        """Parse a strict plugin lock object."""

        raw_plugins = data.get("plugins")
        if not isinstance(raw_plugins, list) or not all(
            isinstance(item, Mapping) for item in raw_plugins
        ):
            raise ConfigurationError("connector plugin lock plugins must be a list")
        return cls(
            schema=str(data.get("schema", "")),
            plugins=tuple(PluginDescriptor.from_dict(item) for item in raw_plugins),
        )

    @classmethod
    def from_json(cls, source: ConfigSource) -> PluginLock:
        """Read a plugin lock without importing any plugin modules."""

        try:
            with source.open("rb") as handle:
                raw = json.loads(handle.read().decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ConfigurationError(
                "connector plugin lock could not be read"
            ) from error
        if not isinstance(raw, Mapping):
            raise ConfigurationError("connector plugin lock must be a JSON object")
        return cls.from_dict(raw)


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


@dataclass(slots=True)
class _PluginSnapshot:
    temporary_directory: tempfile.TemporaryDirectory[str]
    root: Path


_ACTIVE_PLUGIN_SNAPSHOTS: dict[tuple[str, str, str], _PluginSnapshot] = {}


def discover_connector_plugins(
    *,
    entries: Iterable[Any] | None = None,
) -> tuple[PluginDescriptor, ...]:
    """List installed connector entry points without importing plugin modules."""

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


def resolve_locked_plugin_descriptors(
    *,
    enabled_names: Sequence[str],
    trusted_lock: PluginLock,
    entries: Iterable[Any] | None = None,
) -> tuple[PluginDescriptor, ...]:
    """Verify selected installed entries against an exact operator lock."""

    requested = _requested_names(enabled_names)
    if not requested:
        return ()
    selected = tuple(entries) if entries is not None else _installed_entries()
    installed = {
        item.name: item for item in discover_connector_plugins(entries=selected)
    }
    locked = {item.name: item for item in trusted_lock.plugins}
    missing_installed = sorted(set(requested) - set(installed))
    if missing_installed:
        raise ConfigurationError(
            "enabled connector plugins are not installed: "
            + ", ".join(missing_installed)
        )
    missing_lock = sorted(set(requested) - set(locked))
    if missing_lock:
        raise ConfigurationError(
            "enabled connector plugins are absent from the trusted lock: "
            + ", ".join(missing_lock)
        )
    for name in requested:
        if installed[name].identity_sha256 != locked[name].identity_sha256:
            raise ConfigurationError(
                f"installed connector plugin {name} does not match the trusted lock"
            )
    return tuple(installed[name] for name in requested)


def load_connector_plugins(
    registry: ConnectorRegistry,
    *,
    enabled_names: Sequence[str],
    trusted_lock: PluginLock | None = None,
    entries: Iterable[Any] | None = None,
) -> tuple[LoadedPlugin, ...]:
    """Exercise the internal artifact-snapshot plugin loader.

    This loader is not wired to CLI execution because an in-process import
    cannot seal transitive or already-cached dependencies. ``entries`` is a
    deterministic test seam for the future isolated-worker implementation.
    """

    requested = _requested_names(enabled_names)
    if not requested:
        return ()
    selected = tuple(entries) if entries is not None else _installed_entries()
    by_name = {str(item.name): item for item in selected}

    if trusted_lock is None:
        if entries is None:
            raise ConfigurationError(
                "live connector plugins require an explicit trusted plugin lock"
            )
        descriptors = discover_connector_plugins(entries=selected)
        descriptor_by_name = {item.name: item for item in descriptors}
        missing = sorted(set(requested) - set(by_name))
        if missing:
            raise ConfigurationError(
                "enabled connector plugins are not installed: " + ", ".join(missing)
            )
    else:
        descriptors = resolve_locked_plugin_descriptors(
            enabled_names=requested,
            trusted_lock=trusted_lock,
            entries=selected,
        )
        descriptor_by_name = {item.name: item for item in descriptors}

    loaded: list[LoadedPlugin] = []
    for name in requested:
        entry = by_name[name]
        descriptor = descriptor_by_name[name]
        snapshot: _PluginSnapshot | None = None
        snapshot_key: tuple[str, str, str] | None = None
        snapshot_is_new = False
        try:
            if trusted_lock is None:
                factory = entry.load()
                observed = _descriptor(entry)
                if observed.identity_sha256 != descriptor.identity_sha256:
                    raise ConfigurationError(
                        f"connector plugin {name} changed while it was being loaded"
                    )
                produced = factory() if callable(factory) else factory
            else:
                produced, snapshot, snapshot_key, snapshot_is_new = (
                    _load_from_verified_snapshot(entry, descriptor)
                )
            connectors = _normalize_connectors(produced, plugin_name=name)
            for connector in connectors:
                _validate_connector(connector, plugin_name=name)
                registry.register(connector)
        except Exception:
            if snapshot_is_new and snapshot is not None:
                _purge_snapshot_modules(snapshot.root)
                snapshot.temporary_directory.cleanup()
            raise
        if snapshot_is_new and snapshot is not None and snapshot_key is not None:
            _ACTIVE_PLUGIN_SNAPSHOTS[snapshot_key] = snapshot
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
    artifacts = _validated_distribution_artifacts(distribution)
    if not artifacts:
        return None
    return _hash_distribution(
        distribution,
        snapshot_root=None,
        artifacts=artifacts,
    )


def _hash_distribution(
    distribution: Any,
    *,
    snapshot_root: Path | None,
    artifacts: tuple[tuple[str, Path], ...] | None = None,
) -> str:
    manifest: list[dict[str, object]] = []
    selected = artifacts or _validated_distribution_artifacts(distribution)
    if not selected:
        raise ConfigurationError("connector plugin distribution has no artifacts")
    try:
        root_path = _distribution_root(distribution)
        aggregate = 0
        with PinnedDirectory.open(root_path, require_private=False) as root:
            owner = root.identity.owner
            if owner not in {os.geteuid(), 0} or root.identity.mode & stat.S_IWOTH:
                raise ConfigurationError(
                    "connector plugin distribution root is not owner-controlled"
                )
            for relative_text, relative in selected:
                destination: Path | None = None
                if snapshot_root is not None:
                    destination = snapshot_root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                digest, total = _hash_distribution_artifact(
                    root,
                    relative,
                    expected_owner=owner,
                    remaining_bytes=_MAX_DISTRIBUTION_BYTES - aggregate,
                    destination=destination,
                )
                aggregate += total
                manifest.append(
                    {
                        "path": relative_text,
                        "size": total,
                        "sha256": digest,
                    }
                )
    except ConfigurationError:
        raise
    except (OSError, TypeError, ValueError) as error:
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


def _validated_distribution_artifacts(
    distribution: Any,
) -> tuple[tuple[str, Path], ...]:
    """Validate the complete untrusted inventory before any path lookup or open."""

    try:
        files = getattr(distribution, "files", None)
        if files is None:
            return ()
        raw_artifacts = tuple(islice(iter(files), _MAX_DISTRIBUTION_FILES + 1))
    except Exception as error:
        raise ConfigurationError(
            "connector plugin distribution inventory is invalid"
        ) from error
    if len(raw_artifacts) > _MAX_DISTRIBUTION_FILES:
        raise ConfigurationError(
            "connector plugin distribution exceeds the 4096-file limit"
        )
    artifacts: list[tuple[str, Path]] = []
    for raw in raw_artifacts:
        try:
            relative_text = str(raw)
        except Exception as error:
            raise ConfigurationError(
                "connector plugin distribution inventory is invalid"
            ) from error
        relative = _strict_distribution_relative(relative_text)
        artifacts.append((relative_text, relative))
    artifacts.sort(key=lambda item: item[0])
    if len({item[0] for item in artifacts}) != len(artifacts):
        raise ConfigurationError(
            "connector plugin distribution artifact paths must be unique"
        )
    return tuple(artifacts)


def _strict_distribution_relative(value: str) -> Path:
    if (
        not value
        or len(value) > _MAX_ARTIFACT_PATH_CHARACTERS
        or value in {".", ".."}
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ConfigurationError(
            "connector plugin distribution contains an unsafe artifact path"
        )
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or len(pure.parts) > _MAX_ARTIFACT_DEPTH
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != value
        or (len(pure.parts[0]) == 2 and pure.parts[0][1] == ":")
    ):
        raise ConfigurationError(
            "connector plugin distribution contains an unsafe artifact path"
        )
    return Path(*pure.parts)


def _distribution_root(distribution: Any) -> Path:
    try:
        selected = Path(distribution.locate_file(PurePosixPath()))
    except Exception as error:
        raise ConfigurationError(
            "connector plugin distribution root could not be located"
        ) from error
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    return selected


def _hash_distribution_artifact(
    root: PinnedDirectory,
    relative: Path,
    *,
    expected_owner: int,
    remaining_bytes: int,
    destination: Path | None,
) -> tuple[str, int]:
    """Hash one descriptor-relative regular file beneath a pinned root."""

    directory_fds: list[int] = []
    directory_edges: list[
        tuple[int, str, tuple[int, int, int, int, int, int, int, int]]
    ] = []
    file_fd = -1
    destination_handle = None
    try:
        current_fd = root.fileno()
        for part in relative.parts[:-1]:
            child_fd = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current_fd,
            )
            directory_fds.append(child_fd)
            child_metadata = os.fstat(child_fd)
            _validate_distribution_directory(
                child_metadata,
                expected_owner=expected_owner,
            )
            child_identity = _artifact_identity(child_metadata)
            if (
                _artifact_identity(
                    os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                )
                != child_identity
            ):
                raise ConfigurationError(
                    "connector plugin artifact parent changed during verification"
                )
            directory_edges.append((current_fd, part, child_identity))
            current_fd = child_fd

        file_fd = os.open(
            relative.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=current_fd,
        )
        opened = os.fstat(file_fd)
        _validate_distribution_file(opened, expected_owner=expected_owner)
        if opened.st_size > _MAX_ARTIFACT_BYTES:
            raise ConfigurationError(
                "connector plugin artifact exceeds the 32 MiB limit"
            )
        if opened.st_size > remaining_bytes:
            raise ConfigurationError(
                "connector plugin distribution exceeds the 128 MiB limit"
            )
        opened_identity = _artifact_identity(opened)
        if (
            _artifact_identity(
                os.stat(relative.name, dir_fd=current_fd, follow_symlinks=False)
            )
            != opened_identity
        ):
            raise ConfigurationError(
                "connector plugin artifact changed during verification"
            )

        if destination is not None:
            destination_handle = destination.open("xb")
        digest = hashlib.sha256()
        total = 0
        remaining = opened.st_size
        while remaining:
            block = os.read(file_fd, min(_READ_BLOCK_BYTES, remaining))
            if not block:
                raise ConfigurationError(
                    "connector plugin artifact changed during verification"
                )
            total += len(block)
            remaining -= len(block)
            digest.update(block)
            if destination_handle is not None:
                destination_handle.write(block)
        if os.read(file_fd, 1):
            raise ConfigurationError(
                "connector plugin artifact changed during verification"
            )
        final = os.fstat(file_fd)
        if _artifact_identity(final) != opened_identity:
            raise ConfigurationError(
                "connector plugin artifact changed during verification"
            )
        if (
            _artifact_identity(
                os.stat(relative.name, dir_fd=current_fd, follow_symlinks=False)
            )
            != opened_identity
        ):
            raise ConfigurationError(
                "connector plugin artifact changed during verification"
            )
        for parent_fd, part, expected in reversed(directory_edges):
            if (
                _artifact_identity(
                    os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                )
                != expected
            ):
                raise ConfigurationError(
                    "connector plugin artifact parent changed during verification"
                )
        root.validate()
        return digest.hexdigest(), total
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "connector plugin distribution contains an unsafe artifact"
        ) from error
    finally:
        if destination_handle is not None:
            destination_handle.close()
        if file_fd >= 0:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


def _validate_distribution_directory(
    value: os.stat_result,
    *,
    expected_owner: int,
) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != expected_owner
        or stat.S_IMODE(value.st_mode) & stat.S_IWOTH
    ):
        raise ConfigurationError(
            "connector plugin artifact parent is not an owner-controlled directory"
        )


def _validate_distribution_file(
    value: os.stat_result,
    *,
    expected_owner: int,
) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != expected_owner
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) & stat.S_IWOTH
    ):
        raise ConfigurationError(
            "connector plugin distribution contains an unsafe regular artifact"
        )


def _artifact_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _load_from_verified_snapshot(
    entry: Any,
    descriptor: PluginDescriptor,
) -> tuple[
    Any,
    _PluginSnapshot,
    tuple[str, str, str],
    bool,
]:
    distribution = getattr(entry, "dist", None)
    if not (
        distribution is not None
        and descriptor.distribution
        and descriptor.distribution_version
        and descriptor.artifact_sha256
    ):
        raise ConfigurationError(
            f"connector plugin {descriptor.name} lacks a verifiable distribution artifact"
        )
    key = (
        descriptor.distribution,
        descriptor.distribution_version,
        descriptor.artifact_sha256,
    )
    snapshot = _ACTIVE_PLUGIN_SNAPSHOTS.get(key)
    is_new = snapshot is None
    if snapshot is None:
        temporary_directory = tempfile.TemporaryDirectory(prefix="master-agent-plugin-")
        # Keep loaded plugin modules available for the lifetime of the process,
        # but explicitly clean their private snapshot before weakref's fallback
        # finalizer emits a ResourceWarning during interpreter shutdown.
        atexit.register(temporary_directory.cleanup)
        snapshot = _PluginSnapshot(
            temporary_directory=temporary_directory,
            root=Path(temporary_directory.name).resolve(),
        )
        try:
            observed_digest = _hash_distribution(
                distribution,
                snapshot_root=snapshot.root,
            )
        except Exception:
            snapshot.temporary_directory.cleanup()
            raise
        if observed_digest != descriptor.artifact_sha256:
            snapshot.temporary_directory.cleanup()
            raise ConfigurationError(
                f"connector plugin {descriptor.name} changed during snapshot creation"
            )

    try:
        module_name = _entry_module(entry)
        if not _snapshot_contains_module(snapshot.root, module_name):
            raise ConfigurationError(
                f"connector plugin {descriptor.name} entry module is not owned by its distribution"
            )
        _reject_cached_module_outside_snapshot(module_name, snapshot.root)
        with _sanitized_import_path(snapshot.root):
            factory = entry.load()
            loaded_module = sys.modules.get(module_name)
            if loaded_module is None or not _module_from_snapshot(
                loaded_module, snapshot.root
            ):
                raise ConfigurationError(
                    f"connector plugin {descriptor.name} loaded from an untrusted origin"
                )
            produced = factory() if callable(factory) else factory
    except ConfigurationError:
        if is_new:
            _purge_snapshot_modules(snapshot.root)
            snapshot.temporary_directory.cleanup()
        raise
    except Exception as error:
        if is_new:
            _purge_snapshot_modules(snapshot.root)
            snapshot.temporary_directory.cleanup()
        raise ConfigurationError(
            f"connector plugin {descriptor.name} could not be loaded from its trusted snapshot"
        ) from error
    return produced, snapshot, key, is_new


def _entry_module(entry: Any) -> str:
    try:
        module_name = str(entry.module)
    except (AttributeError, ValueError):
        module_name = str(entry.value).partition(":")[0].strip()
    if not module_name or not all(
        part.isidentifier() for part in module_name.split(".")
    ):
        raise ConfigurationError("connector plugin entry point has an invalid module")
    return module_name


def _snapshot_contains_module(root: Path, module_name: str) -> bool:
    module_path = Path(*module_name.split("."))
    module_files = [(root / module_path).with_suffix(".py")]
    module_files.extend(
        Path(f"{root / module_path}{suffix}") for suffix in machinery.EXTENSION_SUFFIXES
    )
    return (
        any(path.is_file() for path in module_files)
        or (root / module_path / "__init__.py").is_file()
    )


def _reject_cached_module_outside_snapshot(module_name: str, root: Path) -> None:
    parts = module_name.split(".")
    for index in range(1, len(parts) + 1):
        cached = sys.modules.get(".".join(parts[:index]))
        if cached is not None and not _module_from_snapshot(cached, root):
            raise ConfigurationError(
                "connector plugin module name is already loaded from an untrusted origin"
            )


def _module_from_snapshot(module: Any, root: Path) -> bool:
    origin = getattr(getattr(module, "__spec__", None), "origin", None)
    if isinstance(origin, str) and origin not in {"built-in", "frozen"}:
        try:
            return Path(origin).resolve(strict=True).is_relative_to(root)
        except OSError:
            return False
    search_locations = getattr(
        getattr(module, "__spec__", None), "submodule_search_locations", None
    )
    if search_locations:
        try:
            return all(
                Path(item).resolve(strict=True).is_relative_to(root)
                for item in search_locations
            )
        except OSError:
            return False
    return False


@contextmanager
def _sanitized_import_path(snapshot_root: Path) -> Iterator[None]:
    original = list(sys.path)
    trusted_roots = _trusted_import_roots()
    active_roots = [item.root for item in _ACTIVE_PLUGIN_SNAPSHOTS.values()]
    allowed: list[str] = [str(snapshot_root), *(str(item) for item in active_roots)]
    for item in original:
        if not item:
            continue
        try:
            resolved = Path(item).resolve(strict=True)
        except OSError:
            continue
        if any(
            resolved == root or resolved.is_relative_to(root) for root in trusted_roots
        ):
            rendered = str(resolved)
            if rendered not in allowed:
                allowed.append(rendered)
    sys.path[:] = allowed
    importlib.invalidate_caches()
    try:
        yield
    finally:
        sys.path[:] = original
        importlib.invalidate_caches()


def _trusted_import_roots() -> tuple[Path, ...]:
    candidates = {
        Path(value)
        for key, value in sysconfig.get_paths().items()
        if key in {"stdlib", "platstdlib", "purelib", "platlib"} and value
    }
    candidates.add(Path(__file__).resolve().parents[1])
    roots: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


def _purge_snapshot_modules(root: Path) -> None:
    for name, module in tuple(sys.modules.items()):
        if module is not None and _module_from_snapshot(module, root):
            sys.modules.pop(name, None)


def _requested_names(enabled_names: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name.strip() for name in enabled_names if name.strip()))


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


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
