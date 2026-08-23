"""Current-user package paths that never depend on the working directory."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from master_agent.errors import ConfigurationError

_PRODUCT_DIRECTORY = "MasterAgent"


def current_user_product_root(
    *,
    home: Path | None = None,
    platform_name: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return the native private data root for the current user.

    Parameters
    ----------
    home
        Explicit home directory for POSIX use or Windows fallback.
    platform_name
        Explicit ``os.name`` value for tests. Defaults to the running platform.
    environ
        Explicit environment mapping for tests. On Windows, ``LOCALAPPDATA``
        is preferred and the conventional home-relative path is the fallback.

    Returns
    -------
    pathlib.Path
        Absolute product root independent of the current working directory.
    """

    selected_platform = os.name if platform_name is None else platform_name
    selected_home = (home or Path.home()).expanduser()
    if selected_platform == "nt":
        source = os.environ if environ is None else environ
        local_app_data = source.get("LOCALAPPDATA", "").strip()
        base = (
            Path(local_app_data) if local_app_data else selected_home / "AppData/Local"
        )
        return _validated_root(base / _PRODUCT_DIRECTORY)
    if selected_platform == "posix":
        return _validated_root(selected_home / ".master-agent" / _PRODUCT_DIRECTORY)
    raise ConfigurationError(
        f"unsupported current-user path platform: {selected_platform}"
    )


def _validated_root(path: Path) -> Path:
    """Return one absolute non-root path without consulting the working directory."""

    if "\x00" in os.fspath(path) or not path.is_absolute():
        raise ConfigurationError("current-user product path is invalid")
    selected = Path(os.path.abspath(os.fspath(path)))
    if selected == Path(selected.anchor):
        raise ConfigurationError("current-user product path is invalid")
    return selected


__all__ = ["current_user_product_root"]
