"""Resolve explicit, project-local, and packaged configuration sources."""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import TypeAlias

from master_agent.errors import ConfigurationError

ConfigSource: TypeAlias = Path | Traversable

_DEFAULT_CONFIG_FILES = frozenset(
    {
        "integrations.toml",
        "policy.toml",
        "sources_of_truth.toml",
        "weekly-status.toml",
        "communication-context.toml",
        "identities.toml",
        "retention.toml",
        "capabilities.toml",
        "governance.toml",
        "oauth.toml",
        "draft-package.toml",
        "recurring.toml",
    }
)


def resolve_config_source(
    explicit: Path | None,
    filename: str,
) -> ConfigSource:
    """Resolve a configuration source without copying secrets or files.

    Resolution order is an explicit command-line path, a ``config`` directory
    in the current working directory, then the package's safe fallback
    configuration. Explicit paths are returned unchanged so the domain loader
    can report the precise missing-file error.

    Parameters
    ----------
    explicit
        Explicit user-provided path, or ``None`` to use normal resolution.
    filename
        Approved default configuration filename.

    Returns
    -------
    ConfigSource
        A filesystem path or importlib resource supporting binary reads.

    Raises
    ------
    ConfigurationError
        If ``filename`` is not an approved packaged configuration resource or
        the packaged fallback is unavailable.
    """

    if explicit is not None:
        return explicit
    if filename not in _DEFAULT_CONFIG_FILES:
        raise ConfigurationError(f"unsupported default configuration: {filename}")

    project_local = Path("config") / filename
    if project_local.is_file():
        return project_local

    packaged = files("master_agent.defaults").joinpath(filename)
    if not packaged.is_file():
        raise ConfigurationError(
            f"packaged default configuration is unavailable: {filename}"
        )
    return packaged
