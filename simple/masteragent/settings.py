"""Remember connection details and project preferences without storing tokens."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROVIDERS = ("jira", "bitbucket", "confluence")
CONTEXT_TEMPLATE = """# My work context

Edit this file to remember project conventions, preferred output formats, and
decisions that should carry across tasks. Do not put passwords or tokens here.

## Preferences

- Keep updates concise and link to the results.
- Ask only when a missing decision changes the outcome.

## Projects and conventions

Add your coding conventions and definitions of done here.
"""


def home_path(value: str | None = None) -> Path:
    """Resolve the user-selected local data directory.

    Parameters
    ----------
    value : str, optional
        Explicit directory; otherwise MASTERAGENT_HOME or ~/.masteragent.

    Returns
    -------
    pathlib.Path
        Absolute data directory.
    """
    return Path(value or os.environ.get("MASTERAGENT_HOME", "~/.masteragent")).expanduser().resolve()


def initialize(home: Path) -> None:
    """Create local state and editable context, preserving existing files."""
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    context = home / "context.md"
    try:
        with context.open("x", encoding="utf-8") as stream:
            stream.write(CONTEXT_TEMPLATE)
        context.chmod(0o600)
    except FileExistsError:
        pass


def load_config(home: Path) -> dict[str, Any]:
    """Load configured providers and projects without resolving credentials."""
    path = home / "config.json"
    if not path.exists():
        return {"projects": {}}
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read {path}; restore a valid JSON object.") from exc
    if not isinstance(config, dict) or not isinstance(config.get("projects", {}), dict):
        raise ValueError("config.json must contain an object with a projects object.")  # noqa: TRY004 - Invalid parsed JSON value, not a caller argument type.
    return config


def save_config(home: Path, config: dict[str, Any]) -> None:
    """Atomically save non-secret connection and project settings."""
    initialize(home)
    descriptor, temporary = tempfile.mkstemp(prefix="config-", suffix=".tmp", dir=home)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, home / "config.json")
    finally:
        Path(temporary).unlink(missing_ok=True)


def configure_provider(
    config: dict[str, Any], name: str, url: str, *, deployment: str | None = None,
    token_env: str | None = None, username_env: str | None = None,
    ca_bundle: str | None = None,
) -> None:
    """Remember a provider URL and credential environment variable names."""
    if name not in PROVIDERS:
        raise ValueError(f"Unknown provider: {name}")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use an HTTPS provider URL without embedded credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError("Use the provider base URL without a query or fragment.")
    mode = deployment or ("cloud" if parsed.hostname.endswith(".atlassian.net") or parsed.hostname == "bitbucket.org" else "server")
    if mode not in ("cloud", "server"):
        raise ValueError("Deployment must be cloud or server.")
    section: dict[str, Any] = dict(config.get(name, {}))
    section.update(url=url.rstrip("/"), deployment=mode)
    section["token_env"] = token_env or section.get("token_env", f"MASTERAGENT_{name.upper()}_TOKEN")
    if username_env:
        section["username_env"] = username_env
    elif mode == "cloud":
        section.setdefault("username_env", f"MASTERAGENT_{name.upper()}_USERNAME")
    else:
        section.pop("username_env", None)
    for field in ("token_env", "username_env"):
        if field in section and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", section[field]):
            raise ValueError(f"{field} must be an environment variable name, not a credential value.")
    if ca_bundle:
        section["ca_bundle"] = str(Path(ca_bundle).expanduser().resolve())
    config[name] = section


def configure_project(
    config: dict[str, Any], key: str, *, repository: str | None = None,
    bitbucket_repository: str | None = None, pages: list[str] | None = None,
    checks: list[list[str]] | None = None,
) -> None:
    """Save a project mapping and explicit command argument lists."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
        raise ValueError("Project key must contain letters, digits, or underscores.")
    project = dict(config.setdefault("projects", {}).get(key.upper(), {}))
    if repository is not None:
        project["repository"] = str(Path(repository).expanduser().resolve())
    if bitbucket_repository is not None:
        if not re.fullmatch(r"[A-Za-z0-9_.~-]+/[A-Za-z0-9_.~-]+", bitbucket_repository):
            raise ValueError("Bitbucket repository must be workspace/repo or PROJECT/repo.")
        project["bitbucket_repository"] = bitbucket_repository
    if pages is not None:
        project["confluence_pages"] = list(dict.fromkeys(pages))
    if checks is not None:
        if any(not command or any(not isinstance(arg, str) or not arg for arg in command) for command in checks):
            raise ValueError("Each check must be a nonempty JSON array of command arguments.")
        project["checks"] = checks
    config["projects"][key.upper()] = project


def readiness(config: dict[str, Any]) -> dict[str, Any]:
    """Describe local connection setup without contacting any provider."""
    providers = {}
    for name in PROVIDERS:
        section = config.get(name)
        if not section:
            providers[name] = {"status": "not_configured"}
            continue
        missing = [section[field] for field in ("token_env", "username_env") if section.get(field) and not os.environ.get(section[field])]
        providers[name] = {"status": "missing_credentials" if missing else "configured", "missing_environment": missing, "url": section["url"]}
    return {"providers": providers, "projects": sorted(config.get("projects", {})), "network_checked": False}
