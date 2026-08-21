#!/usr/bin/env python3
"""Prepare and verify the repository-local MasterAgent runtime."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

_MINIMUM_PYTHON = (3, 12)
_MARKER_NAME = ".master-agent-bootstrap-v1"
_READINESS_CONFIGURATION_GAP = 2


class BootstrapError(RuntimeError):
    """A safe, actionable first-run setup failure."""


def _record_metadata_digest(marker: Path, digest: str) -> None:
    """Record a successfully prepared local runtime without changing its scope."""

    try:
        marker.write_text(f"{digest}\n", encoding="utf-8")
    except OSError as error:
        raise BootstrapError(f"could not record local setup state: {error}") from error


def _metadata_digest(root: Path) -> str:
    """Return the dependency and entry-point metadata digest."""

    digest = hashlib.sha256()
    for relative in (Path("pyproject.toml"), Path("setup.py")):
        path = root / relative
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise BootstrapError(f"cannot read {path}: {error}") from error
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _run(command: list[str], *, root: Path, private_install: bool = False) -> int:
    """Run one visible, argument-separated setup command."""

    previous_umask = os.umask(0o077) if private_install else None
    try:
        result = subprocess.run(command, cwd=root, check=False)
    except OSError as error:
        raise BootstrapError(f"could not run {command[0]}: {error}") from error
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
    return result.returncode


def bootstrap(
    root: Path,
    *,
    python_executable: str,
    python_version: tuple[int, int],
) -> int:
    """Create the local environment when needed and run offline readiness."""

    if python_version < _MINIMUM_PYTHON:
        observed = ".".join(str(item) for item in python_version)
        raise BootstrapError(
            f"Python 3.12 or newer is required; python3 is version {observed}"
        )

    root = root.resolve()
    environment = root / ".venv"
    environment_python = environment / "bin/python"
    command = environment / "bin/master-agent"
    marker = environment / _MARKER_NAME

    if environment.is_symlink():
        raise BootstrapError(".venv is a symbolic link and will not be used")
    if environment.exists() and not environment.is_dir():
        raise BootstrapError(".venv exists but is not a directory")

    if not environment.exists():
        print("Creating the repository-local .venv...", flush=True)
        if _run(
            [python_executable, "-m", "venv", str(environment)],
            root=root,
            private_install=True,
        ):
            raise BootstrapError(
                "python3 could not create .venv; the Python venv module may be missing"
            )

    if not environment_python.is_file():
        raise BootstrapError(
            ".venv exists but .venv/bin/python is missing; it was left unchanged"
        )

    try:
        observed_digest = marker.read_text(encoding="utf-8").strip()
    except OSError:
        observed_digest = ""

    # Only environments previously prepared by bootstrap are refreshed from
    # project metadata. A usable pre-existing environment is sufficient for
    # offline readiness but grants no credential, provider, or effect authority.
    tracked_runtime = bool(observed_digest)
    command_present = command.is_file()
    expected_digest = (
        _metadata_digest(root) if tracked_runtime or not command_present else ""
    )
    install_required = not command_present or (
        tracked_runtime and observed_digest != expected_digest
    )
    if install_required:
        print(
            "Installing the lightweight MasterAgent core into .venv...",
            flush=True,
        )
        if _run(
            [
                str(environment_python),
                "-m",
                "pip",
                "install",
                "-e",
                str(root),
            ],
            root=root,
            private_install=True,
        ):
            raise BootstrapError(
                "the repository-local pip install failed; review the installer error above"
            )
        if not command.is_file():
            raise BootstrapError(
                "installation finished without creating .venv/bin/master-agent"
            )
        _record_metadata_digest(marker, expected_digest)
    elif tracked_runtime:
        print(
            "The repository-local MasterAgent runtime is already prepared.",
            flush=True,
        )
    else:
        print(
            "Reusing the existing repository-local MasterAgent runtime.",
            flush=True,
        )

    print("Running the offline readiness check...", flush=True)
    readiness_status = _run([str(command), "readiness"], root=root)
    if readiness_status == _READINESS_CONFIGURATION_GAP:
        print("setup_status: local-runtime-ready; readiness-check-blocked", flush=True)
        return 0
    if readiness_status:
        raise BootstrapError(
            "the installed local runtime could not complete the offline readiness check"
        )
    print("setup_status: ready", flush=True)
    return 0


def main() -> int:
    """Run first-use setup from the checked-out repository."""

    root = Path(__file__).resolve().parents[1]
    print("MasterAgent first-run setup", flush=True)
    print(
        "This may install Python packages locally; it will not access workplace systems.",
        flush=True,
    )
    try:
        return bootstrap(
            root,
            python_executable=sys.executable,
            python_version=(sys.version_info.major, sys.version_info.minor),
        )
    except BootstrapError as error:
        print("setup_status: blocked", flush=True)
        print(f"reason: {error}", flush=True)
        print(
            "Nothing was connected, enabled, or installed outside this repository.",
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
