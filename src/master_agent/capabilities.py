"""Capability catalog and action-contract validation."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
import tomllib
from typing import Any, Mapping

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import AgentAction, RiskLevel


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    """Static contract for one executable capability.

    Parameters
    ----------
    name
        Stable dotted capability name.
    enabled
        Whether the capability may be considered by policy.
    authentication
        Human-readable authentication requirement.
    risk
        Required action risk classification.
    reversible
        Whether the connector is expected to emit compensation metadata.
    required_scopes
        Provider scopes or roles expected for live execution.
    description
        Brief operator-facing description.
    """

    name: str
    enabled: bool
    authentication: str
    risk: RiskLevel
    reversible: bool = False
    requires_expected_version: bool = False
    required_scopes: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if "." not in self.name:
            raise ConfigurationError(
                f"capability name must be a dotted domain name: {self.name}"
            )
        if not self.authentication.strip():
            raise ConfigurationError(
                f"capability authentication must not be empty: {self.name}"
            )


@dataclass(frozen=True, slots=True)
class CapabilityCatalog:
    """Immutable capability definitions loaded from TOML."""

    definitions: Mapping[str, CapabilityDefinition]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "definitions",
            MappingProxyType(dict(self.definitions)),
        )

    @classmethod
    def from_toml(cls, path: ConfigSource) -> "CapabilityCatalog":
        """Load a capability catalog.

        Parameters
        ----------
        path
            TOML configuration source.

        Returns
        -------
        CapabilityCatalog
            Parsed immutable catalog.
        """

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"capability configuration not found: {path}"
            ) from error
        table = raw.get("capabilities", {})
        if not isinstance(table, Mapping):
            raise ConfigurationError("[capabilities] must be a TOML table")

        parsed: dict[str, CapabilityDefinition] = {}
        for name, value in table.items():
            if not isinstance(value, Mapping):
                raise ConfigurationError(
                    f"capability definition must be a table: {name}"
                )
            try:
                risk = RiskLevel(str(value["risk"]))
            except (KeyError, ValueError) as error:
                raise ConfigurationError(
                    f"capability {name} has an invalid or missing risk"
                ) from error
            scopes = value.get("required_scopes", [])
            if not isinstance(scopes, list) or not all(
                isinstance(item, str) and item.strip() for item in scopes
            ):
                raise ConfigurationError(
                    f"capability {name} required_scopes must be a list of strings"
                )
            definition = CapabilityDefinition(
                name=str(name),
                enabled=_strict_bool(value.get("enabled", False), f"capability {name} enabled"),
                authentication=str(value.get("authentication", "unspecified")),
                risk=risk,
                reversible=_strict_bool(value.get("reversible", False), f"capability {name} reversible"),
                requires_expected_version=_strict_bool(
                    value.get("requires_expected_version", False),
                    f"capability {name} requires_expected_version",
                ),
                required_scopes=tuple(str(item) for item in scopes),
                description=str(value.get("description", "")),
            )
            parsed[definition.name] = definition
        return cls(parsed)

    def definition(self, capability: str) -> CapabilityDefinition:
        """Return one known definition or raise a domain error."""

        try:
            return self.definitions[capability]
        except KeyError as error:
            raise ValidationError(
                f"capability is not registered in the catalog: {capability}"
            ) from error

    def validate_action(self, action: AgentAction) -> tuple[bool, str]:
        """Validate an action against catalog enablement and risk."""

        try:
            definition = self.definition(action.capability)
        except ValidationError as error:
            return False, str(error)
        if not definition.enabled:
            return False, f"capability is disabled by catalog: {action.capability}"
        if definition.risk is not action.risk:
            return (
                False,
                f"capability risk mismatch for {action.capability}: "
                f"catalog={definition.risk}, action={action.risk}",
            )
        if (
            definition.requires_expected_version
            and not action.target.expected_version
        ):
            return (
                False,
                f"capability requires an approved expected_version: "
                f"{action.capability}",
            )
        return True, "capability is enabled and risk-classified"

    def enabled_names(self) -> tuple[str, ...]:
        """Return enabled capability names in deterministic order."""

        return tuple(
            sorted(name for name, item in self.definitions.items() if item.enabled)
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the catalog without credential material."""

        return {
            "capabilities": {
                name: {
                    "enabled": item.enabled,
                    "authentication": item.authentication,
                    "risk": str(item.risk),
                    "reversible": item.reversible,
                    "requires_expected_version": item.requires_expected_version,
                    "required_scopes": list(item.required_scopes),
                    "description": item.description,
                }
                for name, item in sorted(self.definitions.items())
            }
        }


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value
