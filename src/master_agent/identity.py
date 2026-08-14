"""Cross-system employee identity registry."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class PersonIdentity:
    """One person and their known identifiers across enterprise systems."""

    key: str
    display_name: str
    aliases: tuple[str, ...]
    identifiers: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ConfigurationError("identity key must not be empty")
        if not self.display_name.strip():
            raise ConfigurationError(f"identity {self.key} requires display_name")
        object.__setattr__(
            self,
            "identifiers",
            MappingProxyType(
                {
                    str(system): str(value).strip()
                    for system, value in self.identifiers.items()
                    if str(value).strip()
                }
            ),
        )

    def identifier(self, system: str) -> str | None:
        """Return the person's identifier for one system."""

        return self.identifiers.get(system)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the identity without secrets."""

        return {
            "key": self.key,
            "display_name": self.display_name,
            "aliases": list(self.aliases),
            "identifiers": dict(self.identifiers),
        }


@dataclass(frozen=True, slots=True)
class IdentityRegistry:
    """Resolve human references into system-specific identifiers."""

    people: Mapping[str, PersonIdentity]

    def __post_init__(self) -> None:
        object.__setattr__(self, "people", MappingProxyType(dict(self.people)))

    @classmethod
    def from_toml(cls, path: ConfigSource) -> IdentityRegistry:
        """Load a registry from ``[people.<key>]`` TOML tables."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"identity configuration not found: {path}"
            ) from error
        raw_people = raw.get("people", {})
        if not isinstance(raw_people, Mapping):
            raise ConfigurationError("[people] must be a TOML table")

        people: dict[str, PersonIdentity] = {}
        for key, value in raw_people.items():
            if not isinstance(value, Mapping):
                raise ConfigurationError(f"identity must be a table: {key}")
            display_name = str(value.get("display_name", "")).strip()
            aliases_value = value.get("aliases", [])
            aliases: tuple[str, ...]
            if isinstance(aliases_value, str):
                aliases = (aliases_value.strip(),) if aliases_value.strip() else ()
            elif isinstance(aliases_value, list):
                aliases = tuple(
                    str(item).strip() for item in aliases_value if str(item).strip()
                )
            else:
                raise ConfigurationError(f"identity aliases must be a list: {key}")

            identifiers: dict[str, str] = {}
            nested = value.get("identifiers")
            if isinstance(nested, Mapping):
                identifiers.update(
                    {str(name): str(item) for name, item in nested.items()}
                )
            for field_name, field_value in value.items():
                if field_name in {"display_name", "aliases", "identifiers"}:
                    continue
                if field_name == "email":
                    identifiers["email"] = str(field_value)
                elif field_name.endswith("_user_id"):
                    identifiers[field_name.removesuffix("_user_id")] = str(field_value)
                elif field_name.endswith("_account_id"):
                    identifiers[field_name.removesuffix("_account_id")] = str(
                        field_value
                    )

            people[str(key)] = PersonIdentity(
                key=str(key),
                display_name=display_name,
                aliases=aliases,
                identifiers=identifiers,
            )
        return cls(people=people)

    def resolve(self, query: str) -> PersonIdentity:
        """Resolve an exact alias, name, email, or system ID.

        Raises
        ------
        ConfigurationError
            If the query is missing, unknown, or ambiguous.
        """

        normalized = _normalize(query)
        if not normalized:
            raise ConfigurationError("identity query must not be empty")
        matches = [
            person
            for person in self.people.values()
            if normalized in _search_terms(person)
        ]
        if not matches:
            raise ConfigurationError(f"identity not found: {query}")
        if len(matches) > 1:
            keys = ", ".join(sorted(person.key for person in matches))
            raise ConfigurationError(f"identity query is ambiguous: {query} ({keys})")
        return matches[0]

    def resolve_identifier(self, query: str, system: str) -> str:
        """Resolve a person and return their identifier for ``system``."""

        person = self.resolve(query)
        value = person.identifier(system)
        if value is None:
            raise ConfigurationError(
                f"identity {person.key} has no configured {system} identifier"
            )
        return value

    def correlate_microsoft_user(
        self,
        user: Mapping[str, Any],
    ) -> PersonIdentity | None:
        """Correlate a normalized Graph user with a configured person."""

        candidates = {
            _normalize(str(user.get(key, "")))
            for key in ("id", "mail", "user_principal_name", "display_name")
        }
        candidates.discard("")
        matches = [
            person
            for person in self.people.values()
            if candidates & _search_terms(person)
        ]
        return matches[0] if len(matches) == 1 else None


def _search_terms(person: PersonIdentity) -> set[str]:
    terms = {
        _normalize(person.key),
        _normalize(person.display_name),
        *(_normalize(alias) for alias in person.aliases),
        *(_normalize(value) for value in person.identifiers.values()),
    }
    terms.discard("")
    return terms


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())
