"""Load explicit, independently scoped capability-capsule authorities."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping, Sequence

from master_agent.capsules import (
    CapsuleAuthority,
    CapsuleRole,
    CapsuleTrustStore,
)
from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.governance import EnvironmentKind

_AUTHORITY_KEYS = frozenset(
    {"subject", "roles", "environments", "secret_env", "enabled"}
)


def load_capsule_authorities(
    source: ConfigSource,
    *,
    environ: Mapping[str, str] | None = None,
    required_roles: Sequence[CapsuleRole] | None = None,
) -> tuple[dict[CapsuleRole, CapsuleAuthority], CapsuleTrustStore]:
    """Load a role-complete signer set from explicit environment-backed keys.

    Each enabled authority owns exactly one role, and every required role must
    have a different key and subject. Secret material is resolved only from
    environment variables and never serialized into a capsule artifact.
    """

    with source.open("rb") as handle:
        raw = tomllib.load(handle)
    if set(raw) != {"authorities"}:
        raise ConfigurationError(
            "capsule authority configuration must contain only [authorities]"
        )
    table = raw.get("authorities")
    if not isinstance(table, Mapping) or not table:
        raise ConfigurationError("[authorities] must contain capsule authority entries")
    selected_roles = frozenset(required_roles or tuple(CapsuleRole))
    if not selected_roles:
        raise ConfigurationError("at least one capsule authority role is required")
    environment = environ if environ is not None else os.environ
    by_role: dict[CapsuleRole, CapsuleAuthority] = {}
    secret_names: dict[CapsuleRole, str] = {}
    for raw_key_id, item in table.items():
        key_id = str(raw_key_id)
        if not isinstance(item, Mapping):
            raise ConfigurationError(f"capsule authority {key_id} must be a TOML table")
        unknown = sorted(set(item) - _AUTHORITY_KEYS)
        if unknown:
            raise ConfigurationError(
                f"capsule authority {key_id} has unsupported fields: "
                + ", ".join(unknown)
            )
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigurationError(
                f"capsule authority {key_id} enabled must be a boolean"
            )
        if not enabled:
            continue
        roles = _string_list(item, "roles", key_id=key_id)
        if len(roles) != 1:
            raise ConfigurationError(
                f"capsule authority {key_id} must own exactly one role"
            )
        try:
            role = CapsuleRole(roles[0])
        except ValueError as error:
            raise ConfigurationError(
                f"capsule authority {key_id} role is unsupported"
            ) from error
        if role not in selected_roles:
            continue
        if role in by_role:
            raise ConfigurationError(
                f"capsule authority role {role} has more than one signer"
            )
        subject = _required_string(item, "subject", key_id=key_id)
        raw_environments = _string_list(item, "environments", key_id=key_id)
        try:
            environments = frozenset(
                str(EnvironmentKind(value)) for value in raw_environments
            )
        except ValueError as error:
            raise ConfigurationError(
                f"capsule authority {key_id} environment is unsupported"
            ) from error
        secret_name = _required_string(item, "secret_env", key_id=key_id)
        secret = environment.get(secret_name, "").encode("utf-8")
        if not secret:
            raise ConfigurationError(
                f"capsule authority secret is unavailable: {secret_name}"
            )
        secret_names[role] = secret_name
        by_role[role] = CapsuleAuthority(
            key_id=key_id,
            subject=subject,
            roles=frozenset({role}),
            environments=environments,
            secret=secret,
        )
    missing = sorted(str(role) for role in selected_roles - set(by_role))
    if missing:
        raise ConfigurationError(
            "capsule authority roles are unavailable: " + ", ".join(missing)
        )
    authorities = tuple(by_role[role] for role in sorted(by_role, key=str))
    if len({item.key_id for item in authorities}) != len(authorities):
        raise ConfigurationError("capsule authority keys must be distinct by role")
    if len({item.subject.casefold() for item in authorities}) != len(authorities):
        raise ConfigurationError("capsule authority subjects must be distinct by role")
    if len(set(secret_names.values())) != len(authorities):
        raise ConfigurationError(
            "capsule authority secret references must be distinct by role"
        )
    if len({item.secret for item in authorities}) != len(authorities):
        raise ConfigurationError(
            "capsule authority secret values must be distinct by role"
        )
    trust = CapsuleTrustStore({item.key_id: item for item in authorities})
    return by_role, trust


def _required_string(
    item: Mapping[str, object],
    name: str,
    *,
    key_id: str,
) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ConfigurationError(
            f"capsule authority {key_id} {name} must be a non-empty string"
        )
    return value


def _string_list(
    item: Mapping[str, object],
    name: str,
    *,
    key_id: str,
) -> tuple[str, ...]:
    value = item.get(name)
    if (
        not isinstance(value, list)
        or not value
        or not all(
            isinstance(entry, str) and entry and entry == entry.strip()
            for entry in value
        )
        or len(value) != len(set(value))
    ):
        raise ConfigurationError(
            f"capsule authority {key_id} {name} must be a unique string list"
        )
    return tuple(value)
