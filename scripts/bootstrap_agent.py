#!/usr/bin/env python3
"""Prepare and verify the repository-local MasterAgent runtime."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

_MINIMUM_PYTHON = (3, 12)
_MARKER_NAME = ".master-agent-bootstrap-v1"


class BootstrapError(RuntimeError):
    """A safe, actionable first-run setup failure."""


def _record_metadata_digest(marker: Path, digest: str) -> None:
    """Atomically record a prepared runtime without following marker links."""

    descriptor = -1
    staged: Path | None = None
    try:
        descriptor, staged_name = tempfile.mkstemp(
            dir=marker.parent,
            prefix=f".{_MARKER_NAME}.",
        )
        staged = Path(staged_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(f"{digest}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, marker)
        staged = None
    except OSError as error:
        raise BootstrapError(f"could not record local setup state: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if staged is not None:
            try:
                staged.unlink()
            except OSError:
                pass


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


def _installation_digest(root: Path, source: Path) -> str:
    """Bind a managed environment marker to project metadata and install source."""

    digest = hashlib.sha256()
    metadata_root = source if source.is_dir() else root
    digest.update(_metadata_digest(metadata_root).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(source).encode("utf-8"))
    if source.is_file():
        try:
            with source.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        except OSError as error:
            raise BootstrapError(
                f"cannot read local package source: {error}"
            ) from error
    return digest.hexdigest()


def _run(
    command: list[str],
    *,
    root: Path,
    private_install: bool = False,
    posix_permissions: bool | None = None,
) -> int:
    """Run one visible, argument-separated setup command."""

    use_posix_permissions = (
        os.name == "posix" if posix_permissions is None else posix_permissions
    )
    previous_umask = (
        os.umask(0o077) if private_install and use_posix_permissions else None
    )
    try:
        result = subprocess.run(command, cwd=root, check=False)
    except OSError as error:
        raise BootstrapError(f"could not run {command[0]}: {error}") from error
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
    return result.returncode


def _environment_commands(
    environment: Path, *, platform_name: str
) -> tuple[Path, Path]:
    """Return the interpreter and console launcher for one virtual environment."""

    if platform_name == "nt":
        scripts = environment / "Scripts"
        return scripts / "python.exe", scripts / "master-agent.exe"
    binary = environment / "bin"
    return binary / "python", binary / "master-agent"


def _marker_digest(marker: Path) -> str:
    """Read one bounded, ordinary, single-link bootstrap marker."""

    try:
        entry = marker.lstat()
        if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
            return ""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(marker, flags)
    except OSError:
        return ""
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > 65
        ):
            return ""
        payload = os.read(descriptor, 66)
    except OSError:
        return ""
    finally:
        os.close(descriptor)
    if len(payload) > 65:
        return ""
    try:
        value = payload.decode("ascii").strip()
    except UnicodeDecodeError:
        return ""
    try:
        int(value, 16)
    except ValueError:
        return ""
    return value if len(value) == 64 else ""


def _select_environment(
    root: Path,
    *,
    digest: str,
    platform_name: str,
) -> tuple[Path, Path, Path, bool]:
    """Select a fresh or bootstrap-managed environment without trusting collisions."""

    primary = root / ".venv"
    candidates = (primary,) + tuple(
        root / f".venv-master-agent-{digest[:12]}{suffix}"
        for suffix in ("", "-2", "-3", "-4")
    )
    for index, environment in enumerate(candidates):
        interpreter, command = _environment_commands(
            environment,
            platform_name=platform_name,
        )
        marker = environment / _MARKER_NAME
        if environment.is_symlink() or (
            environment.exists() and not environment.is_dir()
        ):
            continue
        if not environment.exists():
            return environment, interpreter, command, index != 0
        observed = _marker_digest(marker)
        if observed and interpreter.is_file():
            return environment, interpreter, command, index != 0
    raise BootstrapError(
        "no safe local environment path is available; existing environments were left unchanged"
    )


def _resolve_install_source(root: Path, source: Path | None) -> Path:
    """Resolve one explicit local source tree, wheel, or source archive."""

    selected = root if source is None else source.expanduser()
    if not selected.is_absolute():
        selected = root / selected
    selected = selected.resolve()
    if not selected.exists():
        raise BootstrapError(f"local package source does not exist: {selected}")
    if selected.is_file() and not selected.name.endswith(
        (".whl", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")
    ):
        raise BootstrapError("local package source must be a wheel or source archive")
    return selected


def _resolve_find_links(root: Path, values: tuple[Path, ...]) -> tuple[Path, ...]:
    """Resolve local offline package directories without accepting index credentials."""

    resolved: list[Path] = []
    for value in values:
        selected = value.expanduser()
        if not selected.is_absolute():
            selected = root / selected
        selected = selected.resolve()
        if not selected.is_dir():
            raise BootstrapError(
                f"offline package directory does not exist: {selected}"
            )
        resolved.append(selected)
    return tuple(resolved)


def bootstrap(
    root: Path,
    *,
    python_executable: str,
    python_version: tuple[int, int],
    platform_name: str | None = None,
    install_source: Path | None = None,
    no_index: bool = False,
    find_links: tuple[Path, ...] = (),
) -> int:
    """Create the local environment when needed and run offline readiness."""

    if python_version < _MINIMUM_PYTHON:
        observed = ".".join(str(item) for item in python_version)
        raise BootstrapError(
            f"Python 3.12 or newer is required; the selected interpreter is version {observed}"
        )

    root = root.resolve()
    selected_platform = os.name if platform_name is None else platform_name
    if selected_platform not in {"nt", "posix"}:
        raise BootstrapError(f"unsupported local platform: {selected_platform}")
    source = _resolve_install_source(root, install_source)
    expected_digest = _installation_digest(root, source)
    offline_directories = _resolve_find_links(root, find_links)
    environment, environment_python, command, side_by_side = _select_environment(
        root,
        digest=expected_digest,
        platform_name=selected_platform,
    )
    marker = environment / _MARKER_NAME

    if not environment.exists():
        display = environment.relative_to(root)
        reason = " side-by-side" if side_by_side else ""
        print(f"Creating the repository-local{reason} {display}...", flush=True)
        if _run(
            [python_executable, "-m", "venv", str(environment)],
            root=root,
            private_install=True,
            posix_permissions=selected_platform == "posix",
        ):
            raise BootstrapError(
                "the selected interpreter could not create the local environment; "
                "the Python venv module may be missing"
            )

    if not environment_python.is_file():
        raise BootstrapError(
            f"{environment.relative_to(root)} exists but its interpreter is missing; "
            "it was left unchanged"
        )

    observed_digest = _marker_digest(marker)
    tracked_runtime = bool(observed_digest)
    command_present = command.is_file()
    install_required = not command_present or (
        tracked_runtime and observed_digest != expected_digest
    )
    if install_required:
        display = environment.relative_to(root)
        print(
            f"Installing the lightweight MasterAgent core into {display}...",
            flush=True,
        )
        install_command = [str(environment_python), "-m", "pip", "install"]
        if no_index:
            install_command.append("--no-index")
        for directory in offline_directories:
            install_command.extend(("--find-links", str(directory)))
        if source.is_dir():
            install_command.append("-e")
        install_command.append(str(source))
        if _run(
            install_command,
            root=root,
            private_install=True,
            posix_permissions=selected_platform == "posix",
        ):
            raise BootstrapError(
                "the repository-local pip install failed; review the installer error above"
            )
        if not command.is_file():
            raise BootstrapError(
                "installation finished without creating the MasterAgent console launcher"
            )
        _record_metadata_digest(marker, expected_digest)
    elif tracked_runtime:
        print(
            "The repository-local MasterAgent runtime is already prepared.",
            flush=True,
        )
    else:
        raise BootstrapError("an unverified local environment will not be reused")

    print("Running the offline readiness check...", flush=True)
    readiness_status = _run(
        [str(command), "doctor", "--require-level", "install"],
        root=root,
    )
    if readiness_status:
        raise BootstrapError(
            "the installed local runtime could not complete the offline readiness check"
        )
    print(f"command: {command.relative_to(root)}", flush=True)
    print("setup_status: ready", flush=True)
    return 0


def main() -> int:
    """Run first-use setup from the checked-out repository."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--install-source",
        type=Path,
        help="local source tree, wheel, or source archive to install",
    )
    parser.add_argument(
        "--no-index",
        action="store_true",
        help="disable package-index access during installation",
    )
    parser.add_argument(
        "--find-links",
        action="append",
        default=[],
        type=Path,
        metavar="DIRECTORY",
        help="local package directory for offline dependency resolution",
    )
    args = parser.parse_args()
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
            install_source=args.install_source,
            no_index=args.no_index,
            find_links=tuple(args.find_links),
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
