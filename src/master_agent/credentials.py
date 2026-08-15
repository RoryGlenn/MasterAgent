"""Restricted local JSON credential-store loading for development runtimes."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError

_MAX_STORE_BYTES = 1024 * 1024
_MAX_CREDENTIALS = 64
_MAX_VALUE_BYTES = 64 * 1024
_SCHEMA = "master-agent/credential-store@1"


def canonical_credential_store_path(path: Path) -> Path:
    """Return the canonical absolute path used in an execution binding."""

    selected = path.expanduser()
    if not selected.is_absolute():
        raise ConfigurationError("--credentials-file must be an absolute path")
    return selected.resolve(strict=False)


@dataclass(frozen=True, slots=True)
class CredentialStoreSnapshot:
    """An immutable, secret-redacted snapshot of one restricted JSON store."""

    path: Path
    _credentials: Mapping[str, str] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "_credentials", MappingProxyType(dict(self._credentials))
        )

    @classmethod
    def load(
        cls, path: Path, *, allowed_names: Sequence[str]
    ) -> CredentialStoreSnapshot:
        canonical, payload = _read_restricted_file(path)
        return cls(canonical, _parse_credentials(payload, allowed_names=allowed_names))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._credentials))

    def overlay(self, environ: Mapping[str, str]) -> dict[str, str]:
        collisions = sorted(name for name in self._credentials if environ.get(name, ""))
        if collisions:
            raise ConfigurationError(
                "credential variables must have exactly one source; unset the ambient "
                "value before using --credentials-file: " + ", ".join(collisions)
            )
        merged = dict(environ)
        merged.update(self._credentials)
        return merged


def _read_restricted_file(path: Path) -> tuple[Path, bytes]:
    selected = path.expanduser()
    canonical = canonical_credential_store_path(path)
    try:
        parent = PinnedDirectory.open(selected.parent)
    except ConfigurationError as error:
        raise ConfigurationError(
            "credential store parent must be a private current-user directory"
        ) from error
    descriptor: int | None = None
    try:
        if os.name == "posix" and parent.identity.mode & 0o077:
            raise ConfigurationError("credential store parent permissions must be 0700")
        before = os.stat(selected.name, dir_fd=parent.fileno(), follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ConfigurationError(
                "credential store must be a regular non-symlink file"
            )
        descriptor = os.open(
            selected.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent.fileno(),
        )
        observed = os.fstat(descriptor)
        if (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino):
            raise ConfigurationError("credential store changed while opening")
        if os.name == "posix":
            if observed.st_uid != os.geteuid():
                raise ConfigurationError(
                    "credential store must be owned by the current user"
                )
            if stat.S_IMODE(observed.st_mode) != 0o600:
                raise ConfigurationError("credential store permissions must be 0600")
        payload = _read_bounded(descriptor)
        parent.validate()
        if canonical != parent.path / selected.name:
            raise ConfigurationError("credential store path changed while opening")
        return canonical, payload
    except FileNotFoundError as error:
        raise ConfigurationError("credential store does not exist") from error
    except OSError as error:
        raise ConfigurationError(
            "credential store could not be opened safely"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        parent.close()


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_STORE_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > _MAX_STORE_BYTES:
        raise ConfigurationError("credential store exceeds the 1 MiB limit")
    return payload


def _parse_credentials(
    payload: bytes, *, allowed_names: Sequence[str]
) -> dict[str, str]:
    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_without_duplicates)
    except UnicodeDecodeError as error:
        raise ConfigurationError("credential store is not valid UTF-8") from error
    except json.JSONDecodeError as error:
        raise ConfigurationError("credential store is not valid JSON") from error
    if not isinstance(raw, Mapping):
        raise ConfigurationError("credential store must be a JSON object")
    if set(raw) - {"schema", "credentials"}:
        raise ConfigurationError("credential store contains unknown top-level fields")
    if raw.get("schema") != _SCHEMA:
        raise ConfigurationError("credential store schema is unsupported")
    values = raw.get("credentials")
    if not isinstance(values, Mapping) or not values:
        raise ConfigurationError(
            "credential store credentials must be a non-empty object"
        )
    if len(values) > _MAX_CREDENTIALS:
        raise ConfigurationError("credential store contains too many credentials")
    allowed = frozenset(allowed_names)
    result: dict[str, str] = {}
    for name, value in values.items():
        if not isinstance(name, str) or name not in allowed:
            raise ConfigurationError(
                "credential store contains a name not declared by integrations"
            )
        if not isinstance(value, str) or not value:
            raise ConfigurationError(
                f"credential store value must be a non-empty string: {name}"
            )
        if "\x00" in value:
            raise ConfigurationError(
                f"credential store value contains a prohibited NUL: {name}"
            )
        if len(value.encode()) > _MAX_VALUE_BYTES:
            raise ConfigurationError(
                f"credential store value exceeds the 64 KiB limit: {name}"
            )
        result[name] = value
    return result


def _without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("credential store contains a duplicate JSON key")
        result[key] = value
    return result
