#!/usr/bin/env python3
"""Prepare and verify the repository-local MasterAgent runtime."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from typing import Any

_MINIMUM_PYTHON = (3, 12)
_MARKER_NAME = ".master-agent-bootstrap-v1"
_MARKER_SCHEMA = "master-agent/bootstrap-attestation@2"
_MAX_MARKER_BYTES = 64 * 1024
_MAX_SOURCE_FILES = 10_000
_MAX_SOURCE_BYTES = 128 * 1024 * 1024
_DEPENDENCY_POLICY_PATHS = (
    Path("pyproject.toml"),
    Path("requirements-runtime.lock"),
    Path("requirements.txt"),
    Path("supply-chain/runtime-dependencies.toml"),
)


class BootstrapError(RuntimeError):
    """A safe, actionable first-run setup failure."""


def _stable_file_identity(value: os.stat_result) -> tuple[int, ...]:
    if os.name == "nt":
        return (
            value.st_dev,
            value.st_ino,
            stat.S_IFMT(value.st_mode),
            value.st_size,
            value.st_mtime_ns,
        )
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_stable_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    description: str,
) -> bytes:
    """Read one bounded regular file without following or losing its identity."""

    descriptor = -1
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise BootstrapError(f"{description} is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _stable_file_identity(before) != _stable_file_identity(opened):
            raise BootstrapError(f"{description} changed while it was opened")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise BootstrapError(f"{description} exceeds its size limit")
        after_open = os.fstat(descriptor)
        after_path = path.lstat()
        if not (
            _stable_file_identity(opened)
            == _stable_file_identity(after_open)
            == _stable_file_identity(after_path)
        ):
            raise BootstrapError(f"{description} changed while it was read")
        return b"".join(chunks)
    except OSError as error:
        raise BootstrapError(f"{description} could not be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class EnvironmentAttestation:
    """Expected identity for one bootstrap-managed environment."""

    installation_sha256: str
    dependency_policy_sha256: str
    project_version: str
    runtime_probe_sha256: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": _MARKER_SCHEMA,
                "installation_sha256": self.installation_sha256,
                "dependency_policy_sha256": self.dependency_policy_sha256,
                "project_version": self.project_version,
                "runtime_probe_sha256": self.runtime_probe_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _record_environment_attestation(
    marker: Path,
    attestation: EnvironmentAttestation,
) -> None:
    """Atomically record a bounded versioned environment attestation."""

    payload = attestation.to_json() + "\n"
    if len(payload.encode("utf-8")) > _MAX_MARKER_BYTES:
        raise BootstrapError("local setup attestation is unexpectedly large")
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
            handle.write(payload)
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
            payload = _read_stable_regular_file(
                path,
                maximum_bytes=4 * 1024 * 1024,
                description=f"project metadata {relative}",
            )
        except BootstrapError as error:
            raise BootstrapError(f"cannot read {path}: {error}") from error
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _dependency_policy_digest(root: Path) -> str:
    """Return the exact declared dependency-policy digest."""

    digest = hashlib.sha256()
    found = False
    for relative in _DEPENDENCY_POLICY_PATHS:
        path = root / relative
        if not path.is_file():
            continue
        found = True
        try:
            payload = _read_stable_regular_file(
                path,
                maximum_bytes=16 * 1024 * 1024,
                description=f"dependency policy {relative}",
            )
        except BootstrapError as error:
            raise BootstrapError(
                f"cannot read dependency policy: {relative}"
            ) from error
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    if not found:
        raise BootstrapError("project dependency policy is unavailable")
    return digest.hexdigest()


def _project_version(source: Path, root: Path) -> str:
    """Read the bounded declared MasterAgent version from project metadata."""

    metadata_root = source if source.is_dir() else root
    try:
        payload = _read_stable_regular_file(
            metadata_root / "pyproject.toml",
            maximum_bytes=4 * 1024 * 1024,
            description="project version metadata",
        )
        document = tomllib.loads(payload.decode("utf-8"))
        value = document["project"]["version"]
    except (
        BootstrapError,
        KeyError,
        TypeError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise BootstrapError("project version metadata is unavailable") from error
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BootstrapError("project version metadata is invalid")
    return value


def _source_build_digest(source: Path) -> str:
    """Hash one bounded local source tree or exact install artifact."""

    digest = hashlib.sha256()
    candidates: tuple[Path, ...]
    if source.is_file():
        candidates = (source,)
        base = source.parent
    else:
        selected: list[Path] = []
        for root_name in ("src", "config"):
            tree = source / root_name
            if tree.is_symlink():
                raise BootstrapError("local package source contains a symbolic link")
            if not tree.exists():
                continue
            files, _entries = _bounded_regular_tree(
                tree,
                maximum_entries=_MAX_SOURCE_FILES * 2,
                description="local package source",
            )
            selected.extend(
                path
                for path in files
                if "__pycache__" not in path.parts
                and not any(part.endswith(".egg-info") for part in path.parts)
                and path.suffix not in {".pyc", ".pyo"}
            )
        candidates = tuple(
            sorted(selected, key=lambda path: path.relative_to(source).as_posix())
        )
        base = source
    if len(candidates) > _MAX_SOURCE_FILES:
        raise BootstrapError("local package source contains too many files")
    total = 0
    for path in candidates:
        try:
            payload = _read_stable_regular_file(
                path,
                maximum_bytes=_MAX_SOURCE_BYTES - total,
                description="local package source",
            )
        except BootstrapError as error:
            raise BootstrapError("local package source could not be hashed") from error
        total += len(payload)
        if total > _MAX_SOURCE_BYTES:
            raise BootstrapError("local package source exceeds the build digest limit")
        relative = path.relative_to(base).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _bounded_regular_tree(
    root: Path,
    *,
    maximum_entries: int,
    description: str,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Enumerate a local tree without following links or growing unbounded."""

    try:
        root_entry = root.lstat()
    except OSError as error:
        raise BootstrapError(f"{description} could not be enumerated") from error
    if not stat.S_ISDIR(root_entry.st_mode):
        raise BootstrapError(f"{description} contains a symbolic or non-directory root")
    pending = [root]
    files: list[Path] = []
    entries: list[Path] = []
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = tuple(iterator)
        except OSError as error:
            raise BootstrapError(f"{description} could not be enumerated") from error
        for child in children:
            path = Path(child.path)
            entries.append(path)
            if len(entries) > maximum_entries:
                raise BootstrapError(f"{description} contains too many entries")
            try:
                if child.is_symlink():
                    raise BootstrapError(f"{description} contains a symbolic link")
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif child.is_file(follow_symlinks=False):
                    files.append(path)
                else:
                    raise BootstrapError(f"{description} contains a special file")
            except OSError as error:
                raise BootstrapError(
                    f"{description} could not be enumerated"
                ) from error
    return tuple(files), tuple(entries)


def _installation_digest(root: Path, source: Path) -> str:
    """Bind a managed environment marker to project metadata and install source."""

    digest = hashlib.sha256()
    metadata_root = source if source.is_dir() else root
    digest.update(_metadata_digest(metadata_root).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(source).encode("utf-8"))
    digest.update(b"\0")
    digest.update(_source_build_digest(source).encode("ascii"))
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
            or opened.st_size > _MAX_MARKER_BYTES
        ):
            return ""
        payload = os.read(descriptor, _MAX_MARKER_BYTES + 1)
    except OSError:
        return ""
    finally:
        os.close(descriptor)
    if len(payload) > _MAX_MARKER_BYTES:
        return ""
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        return ""
    if value.startswith("{"):
        attestation = _parse_environment_attestation(value)
        return attestation.installation_sha256 if attestation is not None else ""
    try:
        int(value, 16)
    except ValueError:
        return ""
    return value if len(value) == 64 else ""


def _parse_environment_attestation(value: str) -> EnvironmentAttestation | None:
    try:
        raw = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict) or set(raw) != {
        "schema",
        "installation_sha256",
        "dependency_policy_sha256",
        "project_version",
        "runtime_probe_sha256",
    }:
        return None
    if raw["schema"] != _MARKER_SCHEMA:
        return None
    digests = (
        raw["installation_sha256"],
        raw["dependency_policy_sha256"],
        raw["runtime_probe_sha256"],
    )
    if any(
        not isinstance(item, str)
        or len(item) != 64
        or any(character not in "0123456789abcdef" for character in item)
        for item in digests
    ):
        return None
    project_version = raw["project_version"]
    if (
        not isinstance(project_version, str)
        or not project_version
        or len(project_version) > 128
    ):
        return None
    return EnvironmentAttestation(
        installation_sha256=digests[0],
        dependency_policy_sha256=digests[1],
        project_version=project_version,
        runtime_probe_sha256=digests[2],
    )


def _environment_attestation(marker: Path) -> EnvironmentAttestation | None:
    """Read one exact versioned attestation without trusting legacy markers."""

    try:
        entry = marker.lstat()
        if (
            not stat.S_ISREG(entry.st_mode)
            or entry.st_nlink != 1
            or entry.st_size > _MAX_MARKER_BYTES
        ):
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(marker, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
            return None
        payload = os.read(descriptor, _MAX_MARKER_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    if len(payload) > _MAX_MARKER_BYTES:
        return None
    try:
        return _parse_environment_attestation(payload.decode("utf-8").strip())
    except UnicodeDecodeError:
        return None


def _runtime_probe(
    environment_python: Path,
    *,
    environment: Path,
    expected_version: str,
    expected_runtime_digest: str | None = None,
    repository_root: Path | None = None,
) -> str:
    """Verify bytes before execution, then confirm the isolated interpreter identity."""

    python_version = _configured_python_version(environment)
    runtime_digest = _installed_environment_digest(
        environment,
        environment_python=environment_python,
        python_version=python_version,
        expected_version=expected_version,
        repository_root=repository_root,
    )
    if (
        expected_runtime_digest is not None
        and runtime_digest != expected_runtime_digest
    ):
        raise BootstrapError(
            "managed environment contents do not match their attestation"
        )

    probe = (
        "import json,pathlib,sys\n"
        "print(json.dumps({'executable':str(pathlib.Path(sys.executable).resolve()),"
        "'python':[sys.version_info.major,sys.version_info.minor]},"
        "sort_keys=True,separators=(',',':')))\n"
    )
    try:
        result = subprocess.run(
            [str(environment_python), "-I", "-S", "-c", probe],
            cwd=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BootstrapError("managed environment identity probe failed") from error
    if result.returncode or len(result.stdout) > 16 * 1024:
        raise BootstrapError("managed environment identity probe failed")
    try:
        observed: Any = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BootstrapError(
            "managed environment identity probe was malformed"
        ) from error
    if not isinstance(observed, dict) or set(observed) != {"executable", "python"}:
        raise BootstrapError("managed environment identity probe was malformed")
    expected_executable = str(environment_python.resolve())
    if (
        observed["executable"] != expected_executable
        or not isinstance(observed["python"], list)
        or len(observed["python"]) != 2
        or not all(isinstance(item, int) for item in observed["python"])
        or tuple(observed["python"]) != python_version
        or python_version < _MINIMUM_PYTHON
    ):
        raise BootstrapError("managed environment identity does not match its path")
    return runtime_digest


def _configured_python_version(environment: Path) -> tuple[int, int]:
    """Read the interpreter major/minor identity without executing it."""

    payload = _read_stable_regular_file(
        environment / "pyvenv.cfg",
        maximum_bytes=16 * 1024,
        description="managed environment configuration",
    )
    return _python_version_from_configuration(payload)


def _python_version_from_configuration(payload: bytes) -> tuple[int, int]:
    """Parse one bounded ``pyvenv.cfg`` snapshot."""

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BootstrapError("managed environment configuration is invalid") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip().casefold()] = value.strip()
    declared = values.get("version_info", values.get("version", ""))
    components = declared.split(".")
    try:
        version = (int(components[0]), int(components[1]))
    except (IndexError, ValueError) as error:
        raise BootstrapError("managed environment Python version is invalid") from error
    if version < _MINIMUM_PYTHON:
        raise BootstrapError("managed environment Python version is unsupported")
    return version


def _installed_environment_digest(
    environment: Path,
    *,
    environment_python: Path,
    python_version: tuple[int, int],
    expected_version: str,
    repository_root: Path | None = None,
) -> str:
    """Hash a bounded environment without importing code from that environment."""

    try:
        environment_before = environment.lstat()
        python_before = environment_python.lstat()
    except OSError as error:
        raise BootstrapError("managed environment identity is unavailable") from error
    configuration = environment / "pyvenv.cfg"
    config_payload = _read_stable_regular_file(
        configuration,
        maximum_bytes=16 * 1024,
        description="managed environment configuration",
    )
    normalized_config = config_payload.decode("utf-8", errors="replace").casefold()
    if "include-system-site-packages = false" not in normalized_config:
        raise BootstrapError("managed environment must exclude system site packages")
    if _python_version_from_configuration(config_payload) != python_version:
        raise BootstrapError(
            "managed environment Python version changed during validation"
        )

    windows_layout = environment_python.parent.name.casefold() == "scripts"
    site_packages = (
        environment / "Lib" / "site-packages"
        if windows_layout
        else environment
        / "lib"
        / f"python{python_version[0]}.{python_version[1]}"
        / "site-packages"
    )
    command = environment_python.parent / (
        "master-agent.exe" if windows_layout else "master-agent"
    )
    try:
        site_entry = site_packages.lstat()
    except OSError as error:
        raise BootstrapError(
            "managed environment site packages are unavailable"
        ) from error
    if not stat.S_ISDIR(site_entry.st_mode) or site_packages.is_symlink():
        raise BootstrapError("managed environment site packages are invalid")

    files, entries = _bounded_regular_tree(
        site_packages,
        maximum_entries=_MAX_SOURCE_FILES * 2,
        description="managed environment",
    )
    files = tuple(
        sorted(files, key=lambda item: item.relative_to(environment).as_posix())
    )
    resolved_interpreter = environment_python.resolve()
    for required in (resolved_interpreter, command):
        if not required.is_file() or required.is_symlink():
            raise BootstrapError("managed environment executable identity is invalid")
    if os.name == "posix":
        _validate_posix_environment_permissions(
            environment,
            environment_python=environment_python,
            resolved_interpreter=resolved_interpreter,
            command=command,
            site_packages=site_packages,
            site_entries=entries,
        )
    elif os.name == "nt":
        if repository_root is None:
            raise BootstrapError(
                "repository identity is required for Windows environment validation"
            )
        _validate_windows_environment_permissions(
            environment,
            repository_root=repository_root,
            files=(configuration, environment_python, command, *files),
            directories=(site_packages, *(set(entries) - set(files))),
        )

    selected_files = tuple(
        (entry.relative_to(environment).as_posix(), entry) for entry in files
    ) + (
        ("interpreter-target", resolved_interpreter),
        (command.relative_to(environment).as_posix(), command),
    )
    payloads: dict[str, bytes] = {"pyvenv.cfg": config_payload}
    total = len(config_payload)
    for relative, path in selected_files:
        try:
            payload = _read_stable_regular_file(
                path,
                maximum_bytes=_MAX_SOURCE_BYTES - total,
                description="managed environment contents",
            )
        except BootstrapError as error:
            raise BootstrapError(
                "managed environment contents could not be hashed"
            ) from error
        total += len(payload)
        if total > _MAX_SOURCE_BYTES:
            raise BootstrapError("managed environment exceeds the identity limit")
        payloads[relative] = payload

    identities: list[tuple[str, str]] = []
    for relative, payload in payloads.items():
        path = Path(relative)
        if path.name != "METADATA" or not path.parent.name.endswith(".dist-info"):
            continue
        try:
            metadata = BytesParser(policy=compat32).parsebytes(
                payload, headersonly=True
            )
            name = metadata["Name"]
            version = metadata["Version"]
        except (TypeError, ValueError) as error:
            raise BootstrapError(
                "managed environment distribution metadata is invalid"
            ) from error
        if not name or not version or "\n" in name or "\n" in version:
            raise BootstrapError("managed environment distribution metadata is invalid")
        identities.append((name, version))
    identities.sort(key=lambda item: (item[0].casefold(), item[1]))
    if len(identities) > 512:
        raise BootstrapError("managed environment has too many distributions")
    master_versions = [
        version
        for name, version in identities
        if name.casefold().replace("_", "-") == "master-agent"
    ]
    if master_versions != [expected_version]:
        raise BootstrapError("managed environment MasterAgent version does not match")

    digest = hashlib.sha256()
    for name, version in identities:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(version.encode("utf-8"))
        digest.update(b"\0")
    for relative, payload in sorted(payloads.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    try:
        if (
            _stable_file_identity(environment_before)
            != _stable_file_identity(environment.lstat())
            or _stable_file_identity(python_before)
            != _stable_file_identity(environment_python.lstat())
            or config_payload
            != _read_stable_regular_file(
                configuration,
                maximum_bytes=16 * 1024,
                description="managed environment configuration",
            )
        ):
            raise BootstrapError("managed environment changed during validation")
    except OSError as error:
        raise BootstrapError("managed environment changed during validation") from error
    return digest.hexdigest()


def _validate_posix_environment_permissions(
    environment: Path,
    *,
    environment_python: Path,
    resolved_interpreter: Path,
    command: Path,
    site_packages: Path,
    site_entries: tuple[Path, ...],
) -> None:
    """Require user-private environment paths and non-shared executable bytes."""

    try:
        environment_entry = environment.stat()
    except OSError as error:
        raise BootstrapError(
            "managed environment permissions are unavailable"
        ) from error
    if environment_entry.st_uid != os.geteuid():
        raise BootstrapError("managed environment is not owned by the current user")
    paths = {
        environment,
        environment_python.parent,
        command,
        environment / "pyvenv.cfg",
        site_packages,
        *site_entries,
    }
    current = site_entries[0].parent if site_entries else command.parent
    while current != environment and current.is_relative_to(environment):
        paths.add(current)
        current = current.parent
    for path in paths:
        try:
            path_entry = path.stat()
            mode = stat.S_IMODE(path_entry.st_mode)
        except OSError as error:
            raise BootstrapError(
                "managed environment permissions are unavailable"
            ) from error
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise BootstrapError(
                "managed environment grants write access to an untrusted principal"
            )
        if _path_has_extended_posix_acl(
            path,
            directory=stat.S_ISDIR(path_entry.st_mode),
        ):
            raise BootstrapError(
                "managed environment grants ACL access outside its trust profile"
            )
    try:
        interpreter_entry = resolved_interpreter.stat()
    except OSError as error:
        raise BootstrapError(
            "managed interpreter permissions are unavailable"
        ) from error
    if interpreter_entry.st_uid not in {0, os.geteuid()}:
        raise BootstrapError("managed interpreter owner is not trusted")
    if interpreter_entry.st_uid == os.geteuid() and stat.S_IMODE(
        interpreter_entry.st_mode
    ) & (stat.S_IWGRP | stat.S_IWOTH):
        raise BootstrapError(
            "managed interpreter grants write access to an untrusted principal"
        )
    if _path_has_extended_posix_acl(resolved_interpreter, directory=False):
        raise BootstrapError(
            "managed interpreter grants ACL access outside its trust profile"
        )


def _path_has_extended_posix_acl(path: Path, *, directory: bool) -> bool:
    """Open one path without link traversal and check for named ACL entries."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BootstrapError("managed environment ACL could not be verified") from error
    try:
        return _descriptor_has_extended_posix_acl(descriptor)
    finally:
        os.close(descriptor)


def _descriptor_has_extended_posix_acl(descriptor: int) -> bool:
    """Detect a POSIX ACL that grants more authority than mode bits describe."""

    if sys.platform == "darwin":
        try:
            library = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
        except (AttributeError, OSError) as error:
            raise BootstrapError(
                "managed environment ACL could not be verified"
            ) from error
        library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        library.acl_get_fd_np.restype = ctypes.c_void_p
        library.acl_get_entry.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        library.acl_get_entry.restype = ctypes.c_int
        library.acl_free.argtypes = [ctypes.c_void_p]
        acl = library.acl_get_fd_np(descriptor, 0x100)  # ACL_TYPE_EXTENDED
        if not acl:
            if ctypes.get_errno() in {errno.ENOENT, errno.EOPNOTSUPP}:
                return False
            raise BootstrapError("managed environment ACL could not be verified")
        try:
            entry = ctypes.c_void_p()
            result = library.acl_get_entry(acl, 0, ctypes.byref(entry))
            if result == 0:
                return True
            if ctypes.get_errno() == errno.EINVAL:
                return False
            raise BootstrapError("managed environment ACL could not be verified")
        finally:
            library.acl_free(acl)
    if sys.platform.startswith("linux"):
        library_name = ctypes.util.find_library("acl")
        if library_name is None:
            raise BootstrapError("managed environment ACL could not be verified")
        try:
            library = ctypes.CDLL(library_name, use_errno=True)
        except (AttributeError, OSError) as error:
            raise BootstrapError(
                "managed environment ACL could not be verified"
            ) from error
        library.acl_get_fd.argtypes = [ctypes.c_int]
        library.acl_get_fd.restype = ctypes.c_void_p
        library.acl_equiv_mode.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint),
        ]
        library.acl_equiv_mode.restype = ctypes.c_int
        library.acl_free.argtypes = [ctypes.c_void_p]
        acl = library.acl_get_fd(descriptor)
        if not acl:
            if ctypes.get_errno() == errno.EOPNOTSUPP:
                return False
            raise BootstrapError("managed environment ACL could not be verified")
        try:
            mode = ctypes.c_uint()
            result = library.acl_equiv_mode(acl, ctypes.byref(mode))
            if result in {0, 1}:
                return bool(result == 1)
            raise BootstrapError("managed environment ACL could not be verified")
        finally:
            library.acl_free(acl)
    raise BootstrapError("managed environment ACL could not be verified")


def _validate_windows_environment_permissions(
    environment: Path,
    *,
    repository_root: Path,
    files: tuple[Path, ...],
    directories: tuple[Path, ...],
) -> None:
    """Require retained-handle DACL validation for every executable-runtime object."""

    source_directory = repository_root / "src"
    inserted = str(source_directory)
    sys.path.insert(0, inserted)
    try:
        from master_agent.errors import ConfigurationError
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )
    except ImportError as error:
        if sys.path and sys.path[0] == inserted:
            del sys.path[0]
        raise BootstrapError(
            "managed Windows environment write authority could not be verified"
        ) from error
    try:
        backend = WindowsSecureFilesystemBackend()
        with backend.pin_directory(environment, require_private=True):
            pass
        for path in sorted(set(directories)):
            with backend.pin_directory(path, require_private=True):
                pass
        for path in sorted(set(files)):
            with backend.pin_file(path, require_private=True):
                pass
    except (ConfigurationError, OSError, TypeError, ValueError) as error:
        raise BootstrapError(
            "managed Windows environment write authority could not be verified"
        ) from error
    finally:
        if sys.path and sys.path[0] == inserted:
            del sys.path[0]


def _select_environment(
    root: Path,
    *,
    digest: str,
    dependency_policy_digest: str,
    project_version: str,
    platform_name: str,
) -> tuple[Path, Path, Path, bool, bool]:
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
            return environment, interpreter, command, index != 0, False
        attestation = _environment_attestation(marker)
        if (
            attestation is None
            or attestation.installation_sha256 != digest
            or attestation.dependency_policy_sha256 != dependency_policy_digest
            or attestation.project_version != project_version
            or not interpreter.is_file()
            or not command.is_file()
            or command.is_symlink()
        ):
            continue
        try:
            _runtime_probe(
                interpreter,
                environment=environment,
                expected_version=project_version,
                expected_runtime_digest=attestation.runtime_probe_sha256,
                repository_root=root,
            )
        except BootstrapError:
            continue
        return environment, interpreter, command, index != 0, True
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
    dependency_policy_digest = _dependency_policy_digest(
        source if source.is_dir() else root
    )
    project_version = _project_version(source, root)
    offline_directories = _resolve_find_links(root, find_links)
    environment, environment_python, command, side_by_side, reused = (
        _select_environment(
            root,
            digest=expected_digest,
            dependency_policy_digest=dependency_policy_digest,
            project_version=project_version,
            platform_name=selected_platform,
        )
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

    if not reused:
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
        runtime_probe_digest = _runtime_probe(
            environment_python,
            environment=environment,
            expected_version=project_version,
            repository_root=root,
        )
        _record_environment_attestation(
            marker,
            EnvironmentAttestation(
                installation_sha256=expected_digest,
                dependency_policy_sha256=dependency_policy_digest,
                project_version=project_version,
                runtime_probe_sha256=runtime_probe_digest,
            ),
        )
    else:
        print(
            "The repository-local MasterAgent runtime is already prepared.",
            flush=True,
        )

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
