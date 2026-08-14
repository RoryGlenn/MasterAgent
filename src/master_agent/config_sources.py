"""Resolve explicit trusted or packaged configuration sources.

Target repositories are untrusted inputs.  In particular, merely changing the
current working directory must never change policy, connector destinations, or
credential references used by the runtime.
"""

from __future__ import annotations

import io
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import IO, BinaryIO, Literal, overload

from master_agent.errors import ConfigurationError

_MAX_CONFIG_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ConfigSnapshot:
    """Immutable bytes captured from one trusted configuration source.

    Returning a snapshot instead of a reopenable path or package resource closes
    the check/use race between source validation, approval hashing, and the
    individual TOML loaders.
    """

    display_path: Path
    payload: bytes

    @overload
    def open(self, mode: Literal["rb"]) -> BinaryIO: ...

    @overload
    def open(self, mode: str = "rb") -> BinaryIO: ...

    def open(self, mode: str = "rb") -> BinaryIO:
        """Return a fresh binary stream over the captured bytes."""

        if mode != "rb":
            raise ValueError("configuration snapshots support only binary reads")
        return io.BytesIO(self.payload)

    def __str__(self) -> str:
        return str(self.display_path)


type ConfigSource = Path | Traversable | ConfigSnapshot

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
) -> ConfigSnapshot:
    """Resolve a configuration source into one bounded immutable snapshot.

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
    ConfigSnapshot
        A bounded snapshot whose bytes remain identical across every parser and
        approval-hash read.

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
    try:
        with packaged.open("rb") as handle:
            payload = _read_stream_bounded(
                handle,
                _MAX_CONFIG_BYTES,
                object_name="packaged default configuration",
            )
    except OSError as error:
        raise ConfigurationError(
            f"packaged default configuration could not be read: {filename}"
        ) from error
    return ConfigSnapshot(display_path=Path(str(packaged)), payload=payload)


def _trusted_explicit_file(path: Path) -> ConfigSnapshot:
    """Snapshot an explicit configuration file after local trust checks.

    The parent and file are opened by descriptor, their identities are checked
    before use, and the resulting bytes are detached from the filesystem path.
    Symlinks and group/other-writable objects are rejected. On POSIX, the
    invoking account must own both objects.
    """

    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    try:
        parent = selected.parent.resolve(strict=True)
        parent_before = parent.lstat()
    except FileNotFoundError as error:
        raise ConfigurationError(
            f"explicit configuration not found: {selected}"
        ) from error

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(parent, directory_flags)
    except OSError as error:
        raise ConfigurationError(
            "explicit configuration parent could not be opened safely"
        ) from error

    file_fd: int | None = None
    try:
        parent_open = os.fstat(directory_fd)
        _validate_trusted_metadata(
            parent_open,
            expected=parent_before,
            object_name="explicit configuration parent",
            expected_type=stat.S_ISDIR,
        )
        try:
            file_before = os.stat(
                selected.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(file_before.st_mode) or not stat.S_ISREG(
                file_before.st_mode
            ):
                raise ConfigurationError(
                    "explicit configuration must be a regular non-symlink file"
                )
            file_fd = os.open(
                selected.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"explicit configuration not found: {selected}"
            ) from error
        except OSError as error:
            raise ConfigurationError(
                "explicit configuration could not be opened safely"
            ) from error

        file_open = os.fstat(file_fd)
        _validate_trusted_metadata(
            file_open,
            expected=file_before,
            object_name="explicit configuration",
            expected_type=stat.S_ISREG,
        )
        if file_open.st_size > _MAX_CONFIG_BYTES:
            raise ConfigurationError("explicit configuration exceeds the 4 MiB limit")
        payload = _read_bounded(file_fd, _MAX_CONFIG_BYTES)
        return ConfigSnapshot(display_path=selected, payload=payload)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _validate_trusted_metadata(
    observed: os.stat_result,
    *,
    expected: os.stat_result,
    object_name: str,
    expected_type: Callable[[int], bool],
) -> None:
    """Validate type, stable identity, ownership, and write permissions."""

    if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
        raise ConfigurationError(f"{object_name} changed while it was being opened")
    if not expected_type(observed.st_mode):
        raise ConfigurationError(f"{object_name} must be a regular non-symlink object")
    if os.name == "posix":
        if observed.st_uid != os.geteuid():
            raise ConfigurationError(f"{object_name} must be owned by the current user")
        if stat.S_IMODE(observed.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigurationError(
                f"{object_name} must not be group- or other-writable"
            )


def _read_bounded(descriptor: int, limit: int) -> bytes:
    """Read at most ``limit`` bytes from an already validated descriptor."""

    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise ConfigurationError("explicit configuration exceeds the 4 MiB limit")
    return payload


def _read_stream_bounded(
    stream: IO[bytes],
    limit: int,
    *,
    object_name: str,
) -> bytes:
    """Read one binary stream without allowing an unbounded package resource."""

    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise ConfigurationError(f"{object_name} exceeds the 4 MiB limit")
    return payload
