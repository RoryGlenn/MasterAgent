"""Capability catalog and action-contract validation."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from master_agent.config_sources import ConfigSource
from master_agent.connectors.base import CompensatingConnector, Connector
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    AgentAction,
    ConnectorExecutionBinding,
    RiskLevel,
)
from master_agent.resource_limits import (
    MAX_ACTION_PARAMETER_BYTES,
    MAX_LOCAL_ARTIFACT_BYTES,
    measure_json_resources,
)

_AUTHENTICATION_MODES: dict[str, frozenset[str]] = {
    "anonymous_or_configured_connector": frozenset(
        {"none", "basic", "bearer", "oauth_delegated", "oauth_application"}
    ),
    "configured_connector": frozenset(
        {"basic", "bearer", "oauth_delegated", "oauth_application"}
    ),
    "delegated": frozenset({"oauth_delegated"}),
    "delegated_or_application": frozenset({"oauth_delegated", "oauth_application"}),
    "delegated_or_explicit_user": frozenset({"oauth_delegated", "oauth_application"}),
    "local": frozenset({"local"}),
    "local_git": frozenset({"local_git"}),
    "microsoft_graph": frozenset({"oauth_delegated", "oauth_application"}),
    "microsoft_graph_mail": frozenset({"oauth_delegated", "oauth_application"}),
    "microsoft_graph_teams": frozenset({"oauth_delegated", "oauth_application"}),
    "service_or_delegated": frozenset(
        {"basic", "bearer", "oauth_delegated", "oauth_application"}
    ),
}
_PARAMETER_TYPES = frozenset(
    {
        "array",
        "boolean",
        "integer",
        "number",
        "object",
        "string",
        "string_list",
        "string_or_string_list",
    }
)
_PROVIDER_PRECONDITIONS = frozenset({"none", "if_match", "version"})


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
        Executable authentication-class requirement.
    risk
        Required action risk classification.
    reversible
        Whether the connector is expected to emit compensation metadata.
    requires_expected_version
        Whether a modifying action must bind the reviewed provider version.
    provider_precondition
        Provider-side conditional mechanism: ``version`` or ``if_match``.
    required_scopes
        Provider scopes or roles expected for live execution.
    target_system, target_resource_types
        Exact target identity contract.
    parameter_schema
        Closed top-level parameter names and primitive type descriptors.
    max_input_bytes, max_output_bytes
        Required per-action input and generated-artifact byte ceilings for
        local-generation capabilities; prohibited for live capabilities.
    uses_external_model
        Whether organization external-model data policy must be consulted.
    description
        Brief operator-facing description.
    """

    name: str
    enabled: bool
    authentication: str
    risk: RiskLevel
    reversible: bool = False
    requires_expected_version: bool = False
    provider_precondition: str = "none"
    required_scopes: tuple[str, ...] = ()
    target_system: str = ""
    target_resource_types: tuple[str, ...] = ()
    parameter_schema: Mapping[str, str] = field(default_factory=dict)
    max_input_bytes: int | None = None
    max_output_bytes: int | None = None
    uses_external_model: bool = False
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
        if self.authentication not in _AUTHENTICATION_MODES:
            raise ConfigurationError(
                f"capability {self.name} has unsupported authentication contract: "
                f"{self.authentication}"
            )
        if self.provider_precondition not in _PROVIDER_PRECONDITIONS:
            raise ConfigurationError(
                f"capability {self.name} has unsupported provider_precondition: "
                f"{self.provider_precondition}"
            )
        target_system = self.target_system.strip() or self.name.split(".", 1)[0]
        if not target_system:
            raise ConfigurationError(
                f"capability target system must not be empty: {self.name}"
            )
        resource_types = tuple(sorted(set(self.target_resource_types)))
        if any(not item.strip() for item in resource_types):
            raise ConfigurationError(
                f"capability {self.name} target resource types must not be empty"
            )
        schema = dict(self.parameter_schema)
        for parameter, descriptor in schema.items():
            if not parameter.strip():
                raise ConfigurationError(
                    f"capability {self.name} parameter name must not be empty"
                )
            base_type = descriptor.removesuffix("?")
            if base_type not in _PARAMETER_TYPES:
                raise ConfigurationError(
                    f"capability {self.name} has unsupported parameter type: "
                    f"{parameter}={descriptor}"
                )
        if self.enabled and self.risk is not RiskLevel.READ_ONLY:
            if not resource_types:
                raise ConfigurationError(
                    f"enabled side-effect capability {self.name} requires "
                    "target_resource_types"
                )
            if not schema:
                raise ConfigurationError(
                    f"enabled side-effect capability {self.name} requires a "
                    "parameter_schema"
                )
        if (
            self.enabled
            and self.requires_expected_version
            and self.provider_precondition == "none"
        ):
            raise ConfigurationError(
                f"enabled modifying capability {self.name} requires a "
                "provider_precondition"
            )
        if self.risk is RiskLevel.LOCAL_GENERATION:
            if not _is_positive_int(self.max_input_bytes) or not _is_positive_int(
                self.max_output_bytes
            ):
                raise ConfigurationError(
                    f"local-generation capability {self.name} requires positive "
                    "max_input_bytes and max_output_bytes quotas"
                )
            assert self.max_input_bytes is not None
            assert self.max_output_bytes is not None
            if self.max_input_bytes > MAX_ACTION_PARAMETER_BYTES:
                raise ConfigurationError(
                    f"capability {self.name} max_input_bytes exceeds the model ceiling"
                )
            if self.max_output_bytes > MAX_LOCAL_ARTIFACT_BYTES:
                raise ConfigurationError(
                    f"capability {self.name} max_output_bytes exceeds the artifact ceiling"
                )
        elif self.max_input_bytes is not None or self.max_output_bytes is not None:
            raise ConfigurationError(
                f"non-local capability {self.name} must not declare artifact quotas"
            )
        object.__setattr__(self, "target_system", target_system)
        object.__setattr__(self, "target_resource_types", resource_types)
        object.__setattr__(self, "parameter_schema", MappingProxyType(schema))


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
    def from_toml(cls, path: ConfigSource) -> CapabilityCatalog:
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
            resource_types = value.get("target_resource_types", [])
            if not isinstance(resource_types, list) or not all(
                isinstance(item, str) and item.strip() for item in resource_types
            ):
                raise ConfigurationError(
                    f"capability {name} target_resource_types must be a list of strings"
                )
            parameter_schema = value.get("parameter_schema", {})
            if not isinstance(parameter_schema, Mapping) or not all(
                isinstance(key, str)
                and key.strip()
                and isinstance(item, str)
                and item.strip()
                for key, item in parameter_schema.items()
            ):
                raise ConfigurationError(
                    f"capability {name} parameter_schema must be a string table"
                )
            definition = CapabilityDefinition(
                name=str(name),
                enabled=_strict_bool(
                    value.get("enabled", False), f"capability {name} enabled"
                ),
                authentication=str(value.get("authentication", "unspecified")),
                risk=risk,
                reversible=_strict_bool(
                    value.get("reversible", False), f"capability {name} reversible"
                ),
                requires_expected_version=_strict_bool(
                    value.get("requires_expected_version", False),
                    f"capability {name} requires_expected_version",
                ),
                provider_precondition=str(value.get("provider_precondition", "none")),
                required_scopes=tuple(str(item) for item in scopes),
                target_system=str(value.get("target_system", "")),
                target_resource_types=tuple(str(item) for item in resource_types),
                parameter_schema={
                    str(key): str(item) for key, item in parameter_schema.items()
                },
                max_input_bytes=_optional_positive_int(
                    value.get("max_input_bytes"),
                    f"capability {name} max_input_bytes",
                ),
                max_output_bytes=_optional_positive_int(
                    value.get("max_output_bytes"),
                    f"capability {name} max_output_bytes",
                ),
                uses_external_model=_strict_bool(
                    value.get("uses_external_model", False),
                    f"capability {name} uses_external_model",
                ),
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
        """Validate an action against the executable catalog contract."""

        try:
            definition = self.definition(action.capability)
        except ValidationError as error:
            return False, str(error)
        if not definition.enabled:
            return False, f"capability is disabled by catalog: {action.capability}"
        if definition.risk is not action.risk:
            return (
                False,
                (
                    f"capability risk mismatch for {action.capability}: "
                    f"catalog={definition.risk}, action={action.risk}"
                ),
            )
        if definition.target_system != action.target.system:
            return (
                False,
                (
                    f"capability target system mismatch for {action.capability}: "
                    f"catalog={definition.target_system}, "
                    f"action={action.target.system}"
                ),
            )
        if (
            definition.target_resource_types
            and action.target.resource_type not in definition.target_resource_types
        ):
            return (
                False,
                (
                    f"capability target resource type mismatch for "
                    f"{action.capability}: action={action.target.resource_type}"
                ),
            )
        parameter_error = _validate_parameters(
            action.parameters,
            definition.parameter_schema,
        )
        if parameter_error is not None:
            return False, f"capability parameter schema mismatch: {parameter_error}"
        if definition.risk is RiskLevel.LOCAL_GENERATION:
            if definition.max_input_bytes is None:  # pragma: no cover - load invariant.
                return False, "local-generation input quota is missing"
            try:
                measure_json_resources(
                    action.parameters,
                    context=f"{action.capability} input",
                    max_bytes=definition.max_input_bytes,
                )
            except ValidationError as error:
                return False, f"capability input quota exceeded: {error}"
        if definition.requires_expected_version and not action.target.expected_version:
            return (
                False,
                (
                    "capability requires an approved expected_version: "
                    f"{action.capability}"
                ),
            )
        return True, "capability is enabled and risk-classified"

    def validate_execution(
        self,
        action: AgentAction,
        connector: Connector,
        binding: ConnectorExecutionBinding | None,
        *,
        connector_mode: str,
    ) -> tuple[bool, str]:
        """Validate the effective live authentication and connector contract."""

        definition = self.definition(action.capability)
        if connector_mode == "mock":
            return True, "mock connector has no external authority"

        allowed_modes = _AUTHENTICATION_MODES[definition.authentication]
        local_mode = (
            "local_git" if definition.authentication == "local_git" else "local"
        )
        observed_mode = (
            binding.authentication_mode if binding is not None else local_mode
        )
        runtime_config = getattr(connector, "_config", None)
        if binding is not None:
            runtime_auth = getattr(getattr(runtime_config, "auth", None), "mode", None)
            if runtime_auth is None or str(runtime_auth) != binding.authentication_mode:
                return (
                    False,
                    f"resolved connector authentication drifted for {action.capability}",
                )
            if (
                getattr(runtime_config, "config_identity", None)
                != binding.config_identity_sha256
            ):
                return (
                    False,
                    f"resolved connector configuration drifted for {action.capability}",
                )
        if observed_mode not in allowed_modes:
            return (
                False,
                (
                    f"effective authentication mode {observed_mode} is not allowed "
                    f"for {action.capability}"
                ),
            )
        if observed_mode not in {"none", "local", "local_git"} and (
            binding is None or binding.credential_identity is None
        ):
            return (
                False,
                f"effective credential identity is not bound for {action.capability}",
            )
        if definition.required_scopes:
            observed_scopes = (
                frozenset(binding.credential_scopes)
                if binding is not None
                else frozenset()
            )
            missing = sorted(set(definition.required_scopes) - observed_scopes)
            if missing:
                return (
                    False,
                    (
                        f"effective credential scopes are missing for "
                        f"{action.capability}: {', '.join(missing)}"
                    ),
                )
        if definition.reversible and not isinstance(connector, CompensatingConnector):
            return (
                False,
                f"connector does not implement verified compensation: {action.capability}",
            )
        return True, "effective connector authority satisfies the capability contract"

    def enabled_names(self) -> tuple[str, ...]:
        """Return enabled capability names in deterministic order."""

        return tuple(
            sorted(name for name, item in self.definitions.items() if item.enabled)
        )

    def local_generation_output_limits(self) -> dict[str, int]:
        """Return declared per-action output ceilings for local generators."""

        return {
            name: item.max_output_bytes
            for name, item in self.definitions.items()
            if item.risk is RiskLevel.LOCAL_GENERATION
            and item.max_output_bytes is not None
        }

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
                    "provider_precondition": item.provider_precondition,
                    "required_scopes": list(item.required_scopes),
                    "target_system": item.target_system,
                    "target_resource_types": list(item.target_resource_types),
                    "parameter_schema": dict(item.parameter_schema),
                    "max_input_bytes": item.max_input_bytes,
                    "max_output_bytes": item.max_output_bytes,
                    "uses_external_model": item.uses_external_model,
                    "description": item.description,
                }
                for name, item in sorted(self.definitions.items())
            }
        }


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value


def _optional_positive_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if not _is_positive_int(value):
        raise ConfigurationError(f"{name} must be a positive integer")
    return int(value)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_parameters(
    parameters: Mapping[str, Any],
    schema: Mapping[str, str],
) -> str | None:
    """Return a deterministic top-level schema error, if any."""

    if not schema:
        return None
    unknown = sorted(set(parameters) - set(schema))
    if unknown:
        return f"unexpected parameters: {', '.join(unknown)}"
    for name, descriptor in schema.items():
        optional = descriptor.endswith("?")
        if name not in parameters:
            if optional:
                continue
            return f"required parameter is missing: {name}"
        value = parameters[name]
        if optional and value is None:
            continue
        expected = descriptor.removesuffix("?")
        if not _parameter_matches(value, expected):
            return f"parameter {name} must be {expected}"
    return None


def _parameter_matches(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list | tuple)
    if expected == "string_list":
        return isinstance(value, list | tuple) and all(
            isinstance(item, str) for item in value
        )
    if expected == "string_or_string_list":
        return isinstance(value, str) or (
            isinstance(value, list | tuple)
            and all(isinstance(item, str) for item in value)
        )
    return False  # pragma: no cover - definition loading rejects unknown types.
