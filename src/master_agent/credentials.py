"""Restricted local JSON credential-store loading for development runtimes."""

from __future__ import annotations

import json
import os
import re
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
        raw = _decode_document(payload)
        return cls(
            canonical,
            _parse_direct_or_canonical_credentials(
                raw,
                allowed_names=allowed_names,
            ),
        )

    @classmethod
    def load_github_compatible(
        cls,
        path: Path,
        *,
        credential_name: str = "MASTER_AGENT_GITHUB_TOKEN",
    ) -> CredentialStoreSnapshot:
        """Load the canonical store or an unambiguous GitHub token wrapper.

        Compatibility accepts ``{"github": "<token>"}`` or the named form
        ``{"github": {"token": "<token>"}}``. It is adapted in memory only so
        onboarding never needs to rewrite a credential. All normal path,
        ownership, permission, size, duplicate-key, and value checks apply.
        """

        return cls.load_provider_compatible(
            path,
            allowed_names=(credential_name,),
            aliases={"github": {"token": credential_name}},
        )

    @classmethod
    def load_provider_compatible(
        cls,
        path: Path,
        *,
        allowed_names: Sequence[str],
        aliases: Mapping[str, Mapping[str, str]],
        explicit_mappings: Mapping[str, str] | None = None,
    ) -> CredentialStoreSnapshot:
        """Load canonical, provider-keyed, or unambiguous friendly credentials.

        A provider value may be a token string or an object whose keys are
        explicitly mapped by ``aliases``. Flat friendly names are inferred only
        from their keys and only when one destination is possible. Adaptation is
        in memory only. Unknown fields, duplicate destinations, and ambiguous
        names fail closed without rendering credential material.
        """

        canonical, payload = _read_restricted_file(path)
        raw = _decode_document(payload)
        if (
            "schema" in raw
            or "credentials" in raw
            or _uses_direct_names(raw, allowed_names)
        ):
            credentials = _parse_direct_or_canonical_credentials(
                raw,
                allowed_names=allowed_names,
            )
        else:
            credentials = _parse_provider_credentials(
                raw,
                allowed_names=allowed_names,
                aliases=aliases,
                explicit_mappings=explicit_mappings or {},
            )
        return cls(canonical, credentials)

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


def _parse_direct_or_canonical_credentials(
    raw: Mapping[str, Any], *, allowed_names: Sequence[str]
) -> dict[str, str]:
    """Accept the versioned schema or exact integration environment names."""

    if "schema" in raw or "credentials" in raw:
        return _parse_credentials_document(raw, allowed_names=allowed_names)
    if not raw:
        raise ConfigurationError("credential store must not be empty")
    return _validate_credentials(raw, allowed_names=allowed_names)


def _uses_direct_names(raw: Mapping[str, Any], allowed_names: Sequence[str]) -> bool:
    """Identify an unambiguous direct-name store without fuzzy matching."""

    allowed = frozenset(allowed_names)
    return bool(raw) and all(isinstance(name, str) and name in allowed for name in raw)


def _decode_document(payload: bytes) -> Mapping[str, Any]:
    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_without_duplicates)
    except UnicodeDecodeError as error:
        raise ConfigurationError("credential store is not valid UTF-8") from error
    except json.JSONDecodeError as error:
        raise ConfigurationError("credential store is not valid JSON") from error
    if not isinstance(raw, Mapping):
        raise ConfigurationError("credential store must be a JSON object")
    return raw


def _parse_credentials_document(
    raw: Mapping[str, Any], *, allowed_names: Sequence[str]
) -> dict[str, str]:
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
    return _validate_credentials(values, allowed_names=allowed_names)


def _validate_credentials(
    values: Mapping[Any, Any], *, allowed_names: Sequence[str]
) -> dict[str, str]:
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


def _parse_provider_credentials(
    raw: Mapping[str, Any],
    *,
    allowed_names: Sequence[str],
    aliases: Mapping[str, Mapping[str, str]],
    explicit_mappings: Mapping[str, str],
) -> dict[str, str]:
    if not raw:
        raise ConfigurationError("provider credential store must not be empty")
    if len(raw) > _MAX_CREDENTIALS:
        raise ConfigurationError(
            "provider credential store contains too many providers"
        )
    if all(isinstance(value, str) for value in raw.values()):
        return _parse_flat_provider_credentials(
            raw,
            allowed_names=allowed_names,
            aliases=aliases,
            explicit_mappings=explicit_mappings,
        )

    if explicit_mappings:
        raise ConfigurationError(
            "--credential-map applies only to flat key/value credential files"
        )

    values: dict[str, Any] = {}
    for provider, provider_value in raw.items():
        fields = aliases.get(provider)
        if fields is None or not fields:
            raise ConfigurationError(
                "credential store contains an unselected or unknown provider"
            )
        if isinstance(provider_value, str):
            destination = fields.get("token")
            if destination is None:
                raise ConfigurationError(
                    f"provider credential requires named fields: {provider}"
                )
            provider_fields: Mapping[str, Any] = {"token": provider_value}
        elif isinstance(provider_value, Mapping):
            provider_fields = provider_value
        else:
            raise ConfigurationError(
                f"provider credential must be a string or object: {provider}"
            )
        if not provider_fields:
            raise ConfigurationError(
                f"provider credential fields must not be empty: {provider}"
            )
        unknown = sorted(str(key) for key in set(provider_fields) - set(fields))
        if unknown:
            raise ConfigurationError(
                f"provider credential contains unknown fields: {provider}"
            )
        for provider_field, value in provider_fields.items():
            destination = fields[str(provider_field)]
            if destination in values:
                raise ConfigurationError(
                    "provider credential fields map to the same destination"
                )
            values[destination] = value
            if len(values) > _MAX_CREDENTIALS:
                raise ConfigurationError(
                    "provider credential store contains too many credentials"
                )
    return _validate_credentials(values, allowed_names=allowed_names)


_FIELD_HINTS: Mapping[str, tuple[tuple[str, ...], ...]] = {
    "token": (
        ("token",),
        ("api", "key"),
        ("access", "key"),
        ("pat",),
        ("secret",),
    ),
    "username": (("username",), ("user",), ("email",), ("login",)),
    "token_file": (("token", "file"),),
    "token_expires_at": (("token", "expires", "at"), ("expiry",)),
    "tenant_id": (("tenant", "id"),),
    "client_id": (("client", "id"),),
    "client_secret": (("client", "secret"),),
}


def _parse_flat_provider_credentials(
    raw: Mapping[str, Any],
    *,
    allowed_names: Sequence[str],
    aliases: Mapping[str, Mapping[str, str]],
    explicit_mappings: Mapping[str, str],
) -> dict[str, str]:
    """Infer unambiguous provider/field names without inspecting values."""

    unknown_mappings = sorted(set(explicit_mappings) - set(raw))
    if unknown_mappings:
        raise ConfigurationError(
            "credential mapping names are absent from the file: "
            + ", ".join(unknown_mappings)
        )
    allowed = frozenset(allowed_names)
    invalid_destinations = sorted(set(explicit_mappings.values()) - allowed)
    if invalid_destinations:
        raise ConfigurationError(
            "credential mappings target names not declared by integrations: "
            + ", ".join(invalid_destinations)
        )

    provider_fields = _unique_provider_fields(aliases)
    values: dict[str, Any] = {}
    for source, value in raw.items():
        if not isinstance(source, str):
            raise ConfigurationError("credential key names must be strings")
        if (
            not source
            or "=" in source
            or len(source.encode("utf-8")) > 256
            or not source.isprintable()
        ):
            raise ConfigurationError(
                "friendly credential keys must be printable, at most 256 bytes, "
                "and must not contain '='"
            )
        destination = explicit_mappings.get(source)
        if destination is None:
            candidates = _credential_candidates(source, aliases, provider_fields)
            if len(candidates) != 1:
                possibilities = sorted(candidates or allowed)
                detail = ", ".join(possibilities)
                raise ConfigurationError(
                    f"credential key {source!r} is ambiguous; ask which declared "
                    f"credential it represents, then retry with --credential-map "
                    f"{source}=NAME (choices: {detail})"
                )
            destination = next(iter(candidates))
        if destination in values:
            raise ConfigurationError(
                "credential keys map to the same declared credential: " + destination
            )
        values[destination] = value
    return _validate_credentials(values, allowed_names=allowed_names)


def _unique_provider_fields(
    aliases: Mapping[str, Mapping[str, str]],
) -> tuple[Mapping[str, str], ...]:
    unique: dict[tuple[tuple[str, str], ...], Mapping[str, str]] = {}
    for fields in aliases.values():
        identity = tuple(sorted(fields.items()))
        if identity:
            unique[identity] = fields
    return tuple(unique.values())


def _credential_candidates(
    source: str,
    aliases: Mapping[str, Mapping[str, str]],
    provider_fields: tuple[Mapping[str, str], ...],
) -> set[str]:
    words = _name_words(source)
    compact = "".join(words)
    field_scores = {
        field: max(
            (len(hint) for hint in hints if _hint_matches(words, compact, hint)),
            default=0,
        )
        for field, hints in _FIELD_HINTS.items()
    }
    highest_score = max(field_scores.values(), default=0)
    matched_fields = {
        field for field, score in field_scores.items() if score == highest_score > 0
    }
    matched_providers = {
        tuple(sorted(fields.items())): fields
        for provider, fields in aliases.items()
        if _provider_matches(provider, words, compact)
    }
    provider_was_explicit = bool(matched_providers)
    candidate_providers = tuple(matched_providers.values())
    if not candidate_providers and matched_fields and len(provider_fields) == 1:
        candidate_providers = provider_fields

    candidates: set[str] = set()
    for fields in candidate_providers:
        available_fields = matched_fields & set(fields)
        if not available_fields and provider_was_explicit and "token" in fields:
            available_fields = {"token"}
        candidates.update(fields[field] for field in available_fields)
    return candidates


def _name_words(value: str) -> tuple[str, ...]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return tuple(word for word in re.split(r"[^a-z0-9]+", expanded.casefold()) if word)


def _provider_matches(provider: str, words: tuple[str, ...], compact: str) -> bool:
    provider_words = _name_words(provider)
    provider_compact = "".join(provider_words)
    return bool(provider_compact) and (
        provider_compact in compact or all(word in words for word in provider_words)
    )


def _hint_matches(words: tuple[str, ...], compact: str, hint: tuple[str, ...]) -> bool:
    return all(word in words for word in hint) or "".join(hint) in compact


def _without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("credential store contains a duplicate JSON key")
        result[key] = value
    return result
