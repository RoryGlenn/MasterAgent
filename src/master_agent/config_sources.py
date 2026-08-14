"""Resolve explicit trusted or packaged configuration sources.

Target repositories are untrusted inputs.  In particular, merely changing the
current working directory must never change policy, connector destinations, or
credential references used by the runtime.
"""

from __future__ import annotations

import os
import stat
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from master_agent.errors import ConfigurationError

type ConfigSource = Path | Traversable

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

    Resolution order is an explicit, permission-checked command-line path and
    then the package's safe fallback configuration.  The current working
    directory is deliberately never consulted.

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
        return _trusted_explicit_file(explicit)
    if filename not in _DEFAULT_CONFIG_FILES:
        raise ConfigurationError(f"unsupported default configuration: {filename}")

    packaged = files("master_agent.defaults").joinpath(filename)
    if not packaged.is_file():
        raise ConfigurationError(
            f"packaged default configuration is unavailable: {filename}"
        )
    return packaged


def _trusted_explicit_file(path: Path) -> Path:
    """Return an explicit configuration file after local trust checks.

    Symlinks and group/other-writable files are rejected because both permit a
    less-trusted repository or local account to replace security policy between
    operator review and use.  On POSIX, the invoking account must own the file.
    """

    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    try:
        metadata = selected.lstat()
    except FileNotFoundError:
        # Preserve the precise caller-supplied location for the domain loader's
        # existing missing-file diagnostic.
        return selected
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError(
            "explicit configuration must be a regular non-symlink file"
        )
    if os.name == "posix":
        if metadata.st_uid != os.geteuid():
            raise ConfigurationError(
                "explicit configuration must be owned by the current user"
            )
        if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigurationError(
                "explicit configuration must not be group- or other-writable"
            )
    return selected
