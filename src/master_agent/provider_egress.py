"""Provider-data policy at the model-context return boundary.

Connector implementations do not need to call a model for their returned data
to enter an agent or model context.  This module therefore binds and enforces
organization egress policy independently of the capability catalog's legacy
``uses_external_model`` declaration.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from master_agent.capabilities import (
    READ_RESULT_CROSSCUT_FIELDS,
    READ_RESULT_OMITTED_FIELDS,
    CapabilityDefinition,
    is_reserved_read_result_field_name,
    normalize_read_result_field_name,
)
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.evidence import content_digest, redact_secrets
from master_agent.models import (
    AgentAction,
    ConnectorExecutionBinding,
    DataClassification,
    ExecutionResult,
)
from master_agent.resource_limits import (
    MAX_JSON_COLLECTION_ITEMS,
    MAX_RUN_ARTIFACT_BYTES,
    measure_json_resources,
    validate_bounded_string,
)
from master_agent.security import scan_untrusted_value

_MAX_RULE_ITEMS = 128
_MAX_RULE_TEXT = 256
_SENSITIVE_FINDING_KEYS = frozenset({"excerpt", "path"})
_SENSITIVE_PROVIDER_KEYS = frozenset(
    {
        "authorization",
        "authorization_header",
        "access_token",
        "refresh_token",
        "id_token",
        "api_token",
        "api_key",
        "token",
        "secret",
        "client_secret",
        "password",
        "credential",
        "credentials",
        "cookie",
        "set_cookie",
        "private_key",
    }
)
_SENSITIVE_PROVIDER_KEY_IDENTITIES = frozenset(
    key.replace("_", "") for key in _SENSITIVE_PROVIDER_KEYS
)
_SENSITIVE_PROVIDER_SUFFIX_IDENTITIES = (
    "token",
    "secret",
    "password",
    "credential",
    "cookie",
    "apikey",
    "privatekey",
)
_MODEL_CONTEXT_KEYS = frozenset(
    {
        "destination",
        "model_tenancy",
        "source_data_environment",
        "dlp_adapter",
        "development_default_classification",
        "rules",
    }
)
_MODEL_CONTEXT_REQUIRED_KEYS = _MODEL_CONTEXT_KEYS - frozenset(
    {"development_default_classification"}
)
_MODEL_CONTEXT_RULE_KEYS = frozenset(
    {
        "name",
        "providers",
        "capabilities",
        "data_classifications",
        "destinations",
        "model_tenancies",
        "routes",
        "handling",
        "audit_required",
        "dlp_required",
        "redacted_fields",
        "allowed_fields",
        "max_items",
        "max_output_bytes",
    }
)
_CROSSCUT_RESULT_FIELDS = READ_RESULT_CROSSCUT_FIELDS
_OMITTED_RESULT_FIELDS = READ_RESULT_OMITTED_FIELDS
_READ_RESULT_RESOURCE_TYPES = frozenset({"object", "object_list", "value"})
_FIELD_ALIASES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "issuetype": frozenset({"issue_type"}),
        "project": frozenset({"project_key"}),
        "resolutiondate": frozenset({"resolved_at"}),
        "updated": frozenset({"updated_at"}),
        "status": frozenset({"status", "status_category", "blocked"}),
    }
)


class ProviderDataRoute(StrEnum):
    """Runtime route which will return provider data."""

    EPHEMERAL = "ephemeral"
    AUDITED = "audited"


class ProviderDataHandling(StrEnum):
    """Handling required before verified provider data may be returned."""

    ALLOW = "allow"
    REDACT = "redact"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class ModelContextRule:
    """One typed organization rule for provider-data egress."""

    name: str
    providers: tuple[str, ...]
    capabilities: tuple[str, ...]
    data_classifications: frozenset[DataClassification]
    destinations: frozenset[str]
    model_tenancies: frozenset[str]
    routes: frozenset[ProviderDataRoute]
    handling: ProviderDataHandling
    audit_required: bool
    dlp_required: bool
    redacted_fields: frozenset[str]
    allowed_fields: frozenset[str]
    max_items: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _validate_text(self.name, "model-context rule name")
        for label, values in (
            ("providers", self.providers),
            ("capabilities", self.capabilities),
            ("destinations", tuple(self.destinations)),
            ("model_tenancies", tuple(self.model_tenancies)),
        ):
            if not values:
                raise ConfigurationError(
                    f"model-context rule {self.name} requires {label}"
                )
            if len(values) > _MAX_RULE_ITEMS:
                raise ConfigurationError(
                    f"model-context rule {self.name} has too many {label}"
                )
            for value in values:
                _validate_text(value, f"model-context rule {self.name} {label}")
        if not self.data_classifications:
            raise ConfigurationError(
                f"model-context rule {self.name} requires data classifications"
            )
        if not self.routes:
            raise ConfigurationError(f"model-context rule {self.name} requires routes")
        if self.audit_required and ProviderDataRoute.EPHEMERAL in self.routes:
            raise ConfigurationError(
                f"model-context rule {self.name} cannot require audit on an "
                "ephemeral route"
            )
        if self.handling is ProviderDataHandling.REDACT and not (
            self.redacted_fields or self.dlp_required
        ):
            raise ConfigurationError(
                f"model-context rule {self.name} redaction requires fields or DLP"
            )
        if (
            not isinstance(self.max_output_bytes, int)
            or isinstance(self.max_output_bytes, bool)
            or self.max_output_bytes <= 0
            or self.max_output_bytes > MAX_RUN_ARTIFACT_BYTES
        ):
            raise ConfigurationError(
                f"model-context rule {self.name} max_output_bytes must be between "
                f"1 and {MAX_RUN_ARTIFACT_BYTES}"
            )
        for field_name in self.redacted_fields:
            _validate_text(
                field_name,
                f"model-context rule {self.name} redacted field",
            )
        if not self.allowed_fields:
            raise ConfigurationError(
                f"model-context rule {self.name} requires allowed_fields"
            )
        if len(self.allowed_fields) > _MAX_RULE_ITEMS:
            raise ConfigurationError(
                f"model-context rule {self.name} has too many allowed_fields"
            )
        for field_name in self.allowed_fields:
            _validate_text(
                field_name,
                f"model-context rule {self.name} allowed field",
            )
        if "*" in self.allowed_fields and len(self.allowed_fields) != 1:
            raise ConfigurationError(
                f"model-context rule {self.name} wildcard allowed_fields must stand alone"
            )
        high_sensitivity = {
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
        }
        if self.handling is not ProviderDataHandling.DENY and (
            self.data_classifications & high_sensitivity
        ):
            if self.routes != frozenset({ProviderDataRoute.AUDITED}):
                raise ConfigurationError(
                    f"model-context rule {self.name} must keep high-sensitivity "
                    "data on the audited route"
                )
            if not self.audit_required:
                raise ConfigurationError(
                    f"model-context rule {self.name} must require audit for "
                    "high-sensitivity data"
                )
        if (
            self.handling is not ProviderDataHandling.DENY
            and self.data_classifications & high_sensitivity
            and "*" in self.allowed_fields
        ):
            raise ConfigurationError(
                f"model-context rule {self.name} must explicitly bound "
                "high-sensitivity fields"
            )
        if (
            not isinstance(self.max_items, int)
            or isinstance(self.max_items, bool)
            or self.max_items <= 0
            or self.max_items > MAX_JSON_COLLECTION_ITEMS
        ):
            raise ConfigurationError(
                f"model-context rule {self.name} max_items must be between 1 and "
                f"{MAX_JSON_COLLECTION_ITEMS}"
            )

    @property
    def specificity(self) -> tuple[int, int, int, int]:
        """Return deterministic precedence for overlapping provider rules."""

        patterns = (*self.providers, *self.capabilities)
        exact = sum(
            pattern not in {"*", "?"} and "*" not in pattern and "?" not in pattern
            for pattern in patterns
        )
        literal = sum(
            len(pattern.replace("*", "").replace("?", "")) for pattern in patterns
        )
        destination_exact = int("*" not in self.destinations) + int(
            "*" not in self.model_tenancies
        )
        return (exact, literal, destination_exact, -len(patterns))

    def matches(
        self,
        *,
        provider: str,
        capability: str,
        data_classification: DataClassification,
        destination: str,
        model_tenancy: str,
        route: ProviderDataRoute,
    ) -> bool:
        """Return whether this rule covers the complete requested boundary."""

        return (
            any(fnmatchcase(provider, pattern) for pattern in self.providers)
            and any(fnmatchcase(capability, pattern) for pattern in self.capabilities)
            and data_classification in self.data_classifications
            and (destination in self.destinations or "*" in self.destinations)
            and (model_tenancy in self.model_tenancies or "*" in self.model_tenancies)
            and route in self.routes
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize only typed, content-free organization policy facts."""

        return {
            "name": self.name,
            "providers": list(self.providers),
            "capabilities": list(self.capabilities),
            "data_classifications": sorted(map(str, self.data_classifications)),
            "destinations": sorted(self.destinations),
            "model_tenancies": sorted(self.model_tenancies),
            "routes": sorted(map(str, self.routes)),
            "handling": str(self.handling),
            "audit_required": self.audit_required,
            "dlp_required": self.dlp_required,
            "redacted_fields": sorted(self.redacted_fields),
            "allowed_fields": sorted(self.allowed_fields),
            "max_items": self.max_items,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class ProviderDataPolicyDecision:
    """Pre-content provider-data policy outcome."""

    permitted: bool
    reason: str
    rule: ModelContextRule | None = None


@dataclass(frozen=True, slots=True)
class ProviderDataEgressPolicy:
    """Typed active destination, tenancy, and provider-data rule set."""

    destination: str
    model_tenancy: str
    source_data_environment: str
    dlp_adapter: str
    development_default_classification: DataClassification | None
    rules: tuple[ModelContextRule, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("destination", self.destination),
            ("model_tenancy", self.model_tenancy),
            ("source_data_environment", self.source_data_environment),
            ("dlp_adapter", self.dlp_adapter),
        ):
            _validate_text(value, f"model-context {name}")
        if self.source_data_environment not in {"nonproduction", "production"}:
            raise ConfigurationError(
                "model-context source_data_environment must be nonproduction or "
                "production"
            )
        if not self.rules:
            raise ConfigurationError("model-context rules are required")
        names = [rule.name for rule in self.rules]
        if len(set(names)) != len(names):
            raise ConfigurationError("model-context rule names must be unique")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ProviderDataEgressPolicy:
        """Parse a strict ``[model_context]`` TOML table."""

        _validate_mapping_keys(
            value,
            allowed=_MODEL_CONTEXT_KEYS,
            required=_MODEL_CONTEXT_REQUIRED_KEYS,
            name="model-context policy",
        )
        raw_rules = value.get("rules")
        if not isinstance(raw_rules, list):
            raise ConfigurationError("[[model_context.rules]] must be an array")
        rules: list[ModelContextRule] = []
        for index, raw_rule in enumerate(raw_rules, start=1):
            if not isinstance(raw_rule, Mapping):
                raise ConfigurationError(f"model-context rule {index} must be a table")
            _validate_mapping_keys(
                raw_rule,
                allowed=_MODEL_CONTEXT_RULE_KEYS,
                required=_MODEL_CONTEXT_RULE_KEYS,
                name=f"model-context rule {index}",
            )
            name = _required_string(
                raw_rule.get("name"),
                f"model-context rule {index} name",
            )
            try:
                classifications = frozenset(
                    DataClassification(item)
                    for item in _string_list(
                        raw_rule.get("data_classifications"),
                        f"model-context rule {index} data_classifications",
                    )
                )
                routes = frozenset(
                    ProviderDataRoute(item)
                    for item in _string_list(
                        raw_rule.get("routes"),
                        f"model-context rule {index} routes",
                    )
                )
                handling = ProviderDataHandling(
                    _required_string(
                        raw_rule["handling"],
                        f"model-context rule {index} handling",
                    )
                )
            except (KeyError, ValueError) as error:
                raise ConfigurationError(
                    f"model-context rule {index} contains an invalid enum value"
                ) from error
            max_output_bytes = raw_rule.get("max_output_bytes")
            if not isinstance(max_output_bytes, int) or isinstance(
                max_output_bytes, bool
            ):
                raise ConfigurationError(
                    f"model-context rule {index} max_output_bytes must be an integer"
                )
            rules.append(
                ModelContextRule(
                    name=name,
                    providers=tuple(
                        _string_list(
                            raw_rule.get("providers"),
                            f"model-context rule {index} providers",
                        )
                    ),
                    capabilities=tuple(
                        _string_list(
                            raw_rule.get("capabilities"),
                            f"model-context rule {index} capabilities",
                        )
                    ),
                    data_classifications=classifications,
                    destinations=frozenset(
                        _string_list(
                            raw_rule.get("destinations"),
                            f"model-context rule {index} destinations",
                        )
                    ),
                    model_tenancies=frozenset(
                        _string_list(
                            raw_rule.get("model_tenancies"),
                            f"model-context rule {index} model_tenancies",
                        )
                    ),
                    routes=routes,
                    handling=handling,
                    audit_required=_strict_bool(
                        raw_rule.get("audit_required"),
                        f"model-context rule {index} audit_required",
                    ),
                    dlp_required=_strict_bool(
                        raw_rule.get("dlp_required"),
                        f"model-context rule {index} dlp_required",
                    ),
                    redacted_fields=frozenset(
                        _string_list(
                            raw_rule.get("redacted_fields"),
                            f"model-context rule {index} redacted_fields",
                        )
                    ),
                    allowed_fields=frozenset(
                        _string_list(
                            raw_rule.get("allowed_fields"),
                            f"model-context rule {index} allowed_fields",
                        )
                    ),
                    max_items=_strict_positive_int(
                        raw_rule.get("max_items"),
                        f"model-context rule {index} max_items",
                    ),
                    max_output_bytes=max_output_bytes,
                )
            )
        default_raw = value.get("development_default_classification")
        try:
            default_classification = (
                DataClassification(
                    _required_string(
                        default_raw,
                        "model-context development_default_classification",
                    )
                )
                if default_raw is not None
                else None
            )
        except ValueError as error:
            raise ConfigurationError(
                "model-context development_default_classification is invalid"
            ) from error
        return cls(
            destination=_required_string(
                value.get("destination"), "model-context destination"
            ),
            model_tenancy=_required_string(
                value.get("model_tenancy"), "model-context model_tenancy"
            ),
            source_data_environment=_required_string(
                value.get("source_data_environment"),
                "model-context source_data_environment",
            ),
            dlp_adapter=_required_string(
                value.get("dlp_adapter"), "model-context dlp_adapter"
            ),
            development_default_classification=default_classification,
            rules=tuple(rules),
        )

    @property
    def fingerprint(self) -> str:
        """Return a stable digest of the effective model-context policy."""

        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Serialize the effective model-context policy."""

        return {
            "destination": self.destination,
            "model_tenancy": self.model_tenancy,
            "source_data_environment": self.source_data_environment,
            "dlp_adapter": self.dlp_adapter,
            "development_default_classification": (
                str(self.development_default_classification)
                if self.development_default_classification is not None
                else None
            ),
            "rules": [rule.to_dict() for rule in self.rules],
        }

    def resolve_probe_classification(
        self,
        selected: DataClassification | None,
        *,
        environment: str,
    ) -> DataClassification:
        """Resolve trusted probe classification without a silent company default."""

        if selected is not None:
            return selected
        if environment != "development":
            raise ConfigurationError(
                "provider probe data classification is required outside development"
            )
        if self.source_data_environment != "nonproduction":
            raise ConfigurationError(
                "development provider probes require explicitly nonproduction data"
            )
        if self.development_default_classification is None:
            raise ConfigurationError(
                "development provider probe classification is not configured"
            )
        return self.development_default_classification

    def evaluate(
        self,
        *,
        provider: str,
        capability: str,
        data_classification: DataClassification,
        route: ProviderDataRoute,
        audit_available: bool,
    ) -> ProviderDataPolicyDecision:
        """Evaluate the active destination and tenancy before provider access."""

        matching = [
            rule
            for rule in self.rules
            if rule.matches(
                provider=provider,
                capability=capability,
                data_classification=data_classification,
                destination=self.destination,
                model_tenancy=self.model_tenancy,
                route=route,
            )
        ]
        if not matching:
            return ProviderDataPolicyDecision(
                False,
                "no model-context rule approves "
                f"{data_classification} data from {provider} for "
                f"{self.destination}/{self.model_tenancy} on {route}",
            )
        best_specificity = max(rule.specificity for rule in matching)
        selected = [rule for rule in matching if rule.specificity == best_specificity]
        if len(selected) != 1:
            return ProviderDataPolicyDecision(
                False,
                "model-context policy has ambiguous equally specific rules",
            )
        rule = selected[0]
        if rule.handling is ProviderDataHandling.DENY:
            return ProviderDataPolicyDecision(
                False,
                f"model-context rule {rule.name} denies provider data",
                rule,
            )
        if rule.audit_required and not audit_available:
            return ProviderDataPolicyDecision(
                False,
                f"model-context rule {rule.name} requires an implemented audit route",
                rule,
            )
        if rule.dlp_required and implemented_dlp_adapter(self.dlp_adapter) is None:
            return ProviderDataPolicyDecision(
                False,
                f"model-context rule {rule.name} requires an implemented DLP adapter",
                rule,
            )
        return ProviderDataPolicyDecision(
            True,
            f"model-context rule {rule.name} approves provider-data egress",
            rule,
        )


@dataclass(frozen=True, slots=True)
class ProviderDataEgressBinding:
    """Immutable content-free provider-to-context authorization."""

    provider: str
    capability: str
    action_fingerprint: str
    policy_fingerprint: str
    rule_name: str
    data_classification: DataClassification
    destination: str
    model_tenancy: str
    source_data_environment: str
    route: ProviderDataRoute
    handling: ProviderDataHandling
    audit_required: bool
    dlp_adapter: str
    connector_configuration_sha256: str
    provider_origin_sha256: str
    provider_account_sha256: str
    requested_fields: tuple[str, ...]
    field_contract: str
    output_schema: str
    output_resources: tuple[tuple[str, str], ...]
    output_metadata_fields: tuple[str, ...]
    request_parameter_names: tuple[str, ...]
    request_parameters_sha256: str
    requested_item_limit: int | None
    max_output_bytes: int
    redacted_fields: frozenset[str]
    policy_allowed_fields: frozenset[str]
    schema: str = "master-agent/provider-data-egress@1"

    def __post_init__(self) -> None:
        for name, value in (
            ("provider", self.provider),
            ("capability", self.capability),
            ("rule_name", self.rule_name),
            ("destination", self.destination),
            ("model_tenancy", self.model_tenancy),
            ("source_data_environment", self.source_data_environment),
            ("dlp_adapter", self.dlp_adapter),
            ("field_contract", self.field_contract),
            ("output_schema", self.output_schema),
        ):
            _validate_text(value, f"provider-data egress {name}")
        if self.source_data_environment not in {"nonproduction", "production"}:
            raise ValidationError(
                "provider-data egress source_data_environment is unsupported"
            )
        for name, value in (
            ("action_fingerprint", self.action_fingerprint),
            ("policy_fingerprint", self.policy_fingerprint),
            (
                "connector_configuration_sha256",
                self.connector_configuration_sha256,
            ),
            ("provider_origin_sha256", self.provider_origin_sha256),
            ("provider_account_sha256", self.provider_account_sha256),
            ("request_parameters_sha256", self.request_parameters_sha256),
        ):
            _validate_sha256(value, name)
        if self.schema != "master-agent/provider-data-egress@1":
            raise ValidationError("unsupported provider-data egress schema")
        if not isinstance(self.audit_required, bool):
            raise ValidationError("provider-data egress audit_required must be boolean")
        if (
            not isinstance(self.max_output_bytes, int)
            or isinstance(self.max_output_bytes, bool)
            or self.max_output_bytes <= 0
            or self.max_output_bytes > MAX_RUN_ARTIFACT_BYTES
        ):
            raise ValidationError(
                "provider-data egress max_output_bytes is outside the supported range"
            )
        if self.requested_item_limit is not None and (
            not isinstance(self.requested_item_limit, int)
            or isinstance(self.requested_item_limit, bool)
            or self.requested_item_limit <= 0
        ):
            raise ValidationError(
                "provider-data egress requested_item_limit must be positive"
            )
        for label, values in (
            ("requested_fields", self.requested_fields),
            (
                "output_resource_fields",
                tuple(name for name, _descriptor in self.output_resources),
            ),
            ("output_metadata_fields", self.output_metadata_fields),
            ("request_parameter_names", self.request_parameter_names),
            ("redacted_fields", tuple(self.redacted_fields)),
            ("policy_allowed_fields", tuple(self.policy_allowed_fields)),
        ):
            if len(values) > _MAX_RULE_ITEMS:
                raise ValidationError(f"provider-data egress has too many {label}")
            for value in values:
                _validate_binding_text(value, f"provider-data egress {label}")
        if len(self.output_resources) > _MAX_RULE_ITEMS:
            raise ValidationError("provider-data egress has too many output resources")
        resource_names: set[str] = set()
        for resource_name, descriptor in self.output_resources:
            _validate_binding_text(
                resource_name,
                "provider-data egress output resource",
            )
            if resource_name in resource_names:
                raise ValidationError(
                    "provider-data egress output resources must be unique"
                )
            resource_names.add(resource_name)
            if descriptor not in _READ_RESULT_RESOURCE_TYPES:
                raise ValidationError(
                    "provider-data egress output resource type is unsupported"
                )
        if resource_names & set(self.output_metadata_fields):
            raise ValidationError(
                "provider-data egress output resource and metadata fields overlap"
            )
        if any(
            is_reserved_read_result_field_name(name)
            for name in resource_names | set(self.output_metadata_fields)
        ):
            raise ValidationError(
                "provider-data egress output fields use reserved names"
            )

    @property
    def fingerprint(self) -> str:
        """Return a stable digest of the complete authorization boundary."""

        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Serialize the binding without provider content or account identity."""

        return {
            "schema": self.schema,
            "provider": self.provider,
            "capability": self.capability,
            "action_fingerprint": self.action_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "rule_name": self.rule_name,
            "data_classification": str(self.data_classification),
            "destination": self.destination,
            "model_tenancy": self.model_tenancy,
            "source_data_environment": self.source_data_environment,
            "route": str(self.route),
            "handling": str(self.handling),
            "audit_required": self.audit_required,
            "dlp_adapter": self.dlp_adapter,
            "connector_configuration_sha256": self.connector_configuration_sha256,
            "provider_origin_sha256": self.provider_origin_sha256,
            "provider_account_sha256": self.provider_account_sha256,
            "requested_fields": list(self.requested_fields),
            "field_contract": self.field_contract,
            "output_schema": self.output_schema,
            "output_resources": dict(self.output_resources),
            "output_metadata_fields": list(self.output_metadata_fields),
            "request_parameter_names": list(self.request_parameter_names),
            "request_parameters_sha256": self.request_parameters_sha256,
            "requested_item_limit": self.requested_item_limit,
            "max_output_bytes": self.max_output_bytes,
            "redacted_fields": sorted(self.redacted_fields),
            "policy_allowed_fields": sorted(self.policy_allowed_fields),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> ProviderDataEgressBinding:
        """Parse persisted content-free egress metadata."""

        requested_fields = _string_sequence(
            value.get("requested_fields"),
            "provider-data egress requested_fields",
        )
        parameter_names = _string_sequence(
            value.get("request_parameter_names"),
            "provider-data egress request_parameter_names",
        )
        redacted_fields = _string_sequence(
            value.get("redacted_fields"),
            "provider-data egress redacted_fields",
        )
        policy_allowed_fields = _string_sequence(
            value.get("policy_allowed_fields"),
            "provider-data egress policy_allowed_fields",
        )
        output_resources_value = value.get("output_resources")
        if not isinstance(output_resources_value, Mapping) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in output_resources_value.items()
        ):
            raise ValidationError(
                "provider-data egress output_resources must be a string object"
            )
        output_metadata_fields = _string_sequence(
            value.get("output_metadata_fields"),
            "provider-data egress output_metadata_fields",
        )
        item_limit = value.get("requested_item_limit")
        if item_limit is not None and (
            not isinstance(item_limit, int)
            or isinstance(item_limit, bool)
            or item_limit <= 0
        ):
            raise ValidationError(
                "provider-data egress requested_item_limit must be positive"
            )
        max_output_bytes = value.get("max_output_bytes")
        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool):
            raise ValidationError(
                "provider-data egress max_output_bytes must be an integer"
            )
        return cls(
            schema=str(value.get("schema", "")),
            provider=str(value["provider"]),
            capability=str(value["capability"]),
            action_fingerprint=str(value["action_fingerprint"]),
            policy_fingerprint=str(value["policy_fingerprint"]),
            rule_name=str(value["rule_name"]),
            data_classification=DataClassification(str(value["data_classification"])),
            destination=str(value["destination"]),
            model_tenancy=str(value["model_tenancy"]),
            source_data_environment=str(value["source_data_environment"]),
            route=ProviderDataRoute(str(value["route"])),
            handling=ProviderDataHandling(str(value["handling"])),
            audit_required=_strict_bool(
                value.get("audit_required"),
                "provider-data egress audit_required",
            ),
            dlp_adapter=str(value["dlp_adapter"]),
            connector_configuration_sha256=str(value["connector_configuration_sha256"]),
            provider_origin_sha256=str(value["provider_origin_sha256"]),
            provider_account_sha256=str(value["provider_account_sha256"]),
            requested_fields=requested_fields,
            field_contract=str(value["field_contract"]),
            output_schema=str(value["output_schema"]),
            output_resources=tuple(
                sorted(
                    (str(key), str(item))
                    for key, item in output_resources_value.items()
                )
            ),
            output_metadata_fields=output_metadata_fields,
            request_parameter_names=parameter_names,
            request_parameters_sha256=str(value["request_parameters_sha256"]),
            requested_item_limit=item_limit,
            max_output_bytes=max_output_bytes,
            redacted_fields=frozenset(redacted_fields),
            policy_allowed_fields=frozenset(policy_allowed_fields),
        )


def bind_provider_data_egress(
    *,
    policy: ProviderDataEgressPolicy,
    action: AgentAction,
    definition: CapabilityDefinition,
    connector_binding: ConnectorExecutionBinding | None,
    route: ProviderDataRoute,
    audit_available: bool,
    connector_mode: str = "live",
) -> ProviderDataEgressBinding:
    """Authorize and bind one provider read before its content request."""

    (
        rule,
        requested_fields,
        field_contract,
        item_limit,
        output_schema,
        output_resources,
        output_metadata_fields,
    ) = _provider_data_shape_preflight(
        policy=policy,
        action=action,
        definition=definition,
        route=route,
        audit_available=audit_available,
    )
    config_digest, origin_digest, account_digest = _connector_digests(
        provider=action.target.system,
        binding=connector_binding,
        connector_mode=connector_mode,
    )
    return ProviderDataEgressBinding(
        provider=action.target.system,
        capability=action.capability,
        action_fingerprint=action.effect_fingerprint,
        policy_fingerprint=policy.fingerprint,
        rule_name=rule.name,
        data_classification=action.data_classification,
        destination=policy.destination,
        model_tenancy=policy.model_tenancy,
        source_data_environment=policy.source_data_environment,
        route=route,
        handling=rule.handling,
        audit_required=rule.audit_required,
        dlp_adapter=policy.dlp_adapter,
        connector_configuration_sha256=config_digest,
        provider_origin_sha256=origin_digest,
        provider_account_sha256=account_digest,
        requested_fields=requested_fields,
        field_contract=field_contract,
        output_schema=output_schema,
        output_resources=output_resources,
        output_metadata_fields=output_metadata_fields,
        request_parameter_names=tuple(sorted(action.parameters)),
        request_parameters_sha256=_digest(_jsonable(action.parameters)),
        requested_item_limit=item_limit,
        max_output_bytes=rule.max_output_bytes,
        redacted_fields=rule.redacted_fields,
        policy_allowed_fields=rule.allowed_fields,
    )


def preflight_provider_data_egress(
    *,
    policy: ProviderDataEgressPolicy,
    action: AgentAction,
    definition: CapabilityDefinition,
    route: ProviderDataRoute,
    audit_available: bool,
) -> None:
    """Authorize policy, fields, and item limits without provider access."""

    _provider_data_shape_preflight(
        policy=policy,
        action=action,
        definition=definition,
        route=route,
        audit_available=audit_available,
    )


def _provider_data_shape_preflight(
    *,
    policy: ProviderDataEgressPolicy,
    action: AgentAction,
    definition: CapabilityDefinition,
    route: ProviderDataRoute,
    audit_available: bool,
) -> tuple[
    ModelContextRule,
    tuple[str, ...],
    str,
    int,
    str,
    tuple[tuple[str, str], ...],
    tuple[str, ...],
]:
    decision = policy.evaluate(
        provider=action.target.system,
        capability=action.capability,
        data_classification=action.data_classification,
        route=route,
        audit_available=audit_available,
    )
    if not decision.permitted or decision.rule is None:
        raise ConfigurationError(decision.reason)
    (
        requested_fields,
        field_contract,
        output_schema,
        output_resources,
        output_metadata_fields,
    ) = _requested_field_binding(action, definition)
    allowed_fields = decision.rule.allowed_fields
    normalized_allowed = {field.casefold() for field in allowed_fields}
    if requested_fields:
        disallowed = sorted(
            field
            for field in requested_fields
            if "*" not in allowed_fields and field.casefold() not in normalized_allowed
        )
        if disallowed:
            raise ConfigurationError(
                f"model-context rule {decision.rule.name} does not allow requested "
                f"fields: {', '.join(disallowed)}"
            )
    elif "*" not in allowed_fields:
        raise ConfigurationError(
            f"model-context rule {decision.rule.name} requires an explicit field "
            "projection"
        )
    requested_limit = action.parameters.get("limit")
    if requested_limit is not None and (
        not isinstance(requested_limit, int)
        or isinstance(requested_limit, bool)
        or requested_limit <= 0
    ):
        raise ConfigurationError("provider-data item limit must be a positive integer")
    if isinstance(requested_limit, int) and requested_limit > decision.rule.max_items:
        raise ConfigurationError(
            f"model-context rule {decision.rule.name} limits provider results to "
            f"{decision.rule.max_items} items"
        )
    if any(
        descriptor == "object_list" for _name, descriptor in output_resources
    ) and not isinstance(requested_limit, int):
        raise ConfigurationError(
            "provider-data collection reads require an explicit item limit"
        )
    item_limit = (
        requested_limit if isinstance(requested_limit, int) else decision.rule.max_items
    )
    return (
        decision.rule,
        requested_fields,
        field_contract,
        item_limit,
        output_schema,
        output_resources,
        output_metadata_fields,
    )


def sanitize_provider_mapping(
    value: Mapping[str, Any],
    binding: ProviderDataEgressBinding,
) -> dict[str, Any]:
    """Return a bounded private copy safe for the approved context boundary."""

    copied = deepcopy(dict(value))
    redacted = redact_secrets(copied)
    redacted = _redact_provider_secret_variants(redacted)
    normalized_fields = frozenset(
        _field_identity(field) for field in binding.redacted_fields
    )
    redacted = _redact_configured_fields(redacted, normalized_fields)
    redacted = _minimize_prompt_injection_findings(redacted)
    redacted = _minimize_references(
        redacted,
        minimize_path=binding.handling is ProviderDataHandling.REDACT,
    )
    if not isinstance(redacted, Mapping):  # pragma: no cover - mapping invariant.
        raise ValidationError("provider-data egress result must be an object")
    normalized = _apply_output_contract(redacted, binding)
    _enforce_item_limit(
        normalized,
        binding.requested_item_limit,
        binding.output_resources,
    )
    measure_json_resources(
        normalized,
        context="provider-data egress result",
        max_bytes=binding.max_output_bytes,
    )
    rendered = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(rendered) > binding.max_output_bytes:
        raise ValidationError(
            "provider-data egress result exceeds the serialized byte limit"
        )
    return normalized


def sanitize_provider_result(
    result: ExecutionResult,
    binding: ProviderDataEgressBinding,
) -> ExecutionResult:
    """Minimize a verified read result to one returned provider payload copy."""

    if result.compensation is not None:
        raise ValidationError("provider read result must not contain compensation")
    if result.after is None:
        raise ValidationError("provider read result is missing its bound output")
    after = sanitize_provider_mapping(result.after, binding)
    return ExecutionResult(
        action_id=result.action_id,
        state=result.state,
        before=None,
        after=after,
        connector_reference=_safe_reference(
            result.connector_reference,
            minimize_path=binding.handling is ProviderDataHandling.REDACT,
        ),
        message="provider read completed and crossed the approved egress boundary",
        compensation=None,
    )


def verification_metadata(
    observed: Mapping[str, Any] | None,
    binding: ProviderDataEgressBinding,
) -> Mapping[str, Any] | None:
    """Summarize verification without returning a duplicate provider body."""

    if observed is None:
        return None
    sanitized = sanitize_provider_mapping(observed, binding)
    return MappingProxyType(
        {
            "content_sha256": content_digest(sanitized),
            "key_count": len(sanitized),
        }
    )


def minimize_probe_result(
    result: Mapping[str, Any],
    binding: ProviderDataEgressBinding,
) -> dict[str, Any]:
    """Reduce connector-specific probes to one fixed versioned output contract."""

    copied = deepcopy(dict(result))
    redacted = redact_secrets(copied)
    redacted = _redact_provider_secret_variants(redacted)
    normalized_fields = frozenset(
        _field_identity(field) for field in binding.redacted_fields
    )
    redacted = _redact_configured_fields(redacted, normalized_fields)
    redacted = _minimize_prompt_injection_findings(redacted)
    redacted = _minimize_references(
        redacted,
        minimize_path=binding.handling is ProviderDataHandling.REDACT,
    )
    if not isinstance(redacted, Mapping):  # pragma: no cover - mapping invariant.
        raise ValidationError("provider probe result must be an object")
    measure_json_resources(
        redacted,
        context="provider probe result",
        max_bytes=binding.max_output_bytes,
    )
    probe = {
        "schema": "master-agent/provider-probe@1",
        "reachable": bool(redacted.get("reachable", True)),
        "result_sha256": content_digest(redacted),
    }
    sanitized = sanitize_provider_mapping(probe, binding)
    return {
        "schema": str(sanitized["schema"]),
        "reachable": bool(sanitized["reachable"]),
        "result_sha256": str(sanitized["result_sha256"]),
    }


def provider_result_audit_summary(
    result: ExecutionResult,
    binding: ProviderDataEgressBinding,
) -> dict[str, Any]:
    """Return content-free result metadata for governed access logs."""

    after = result.after or {}
    return {
        "action_id": str(result.action_id),
        "state": str(result.state),
        "content_sha256": content_digest(after),
        "key_count": len(after),
        "egress_fingerprint": binding.fingerprint,
    }


def implemented_dlp_adapter(name: str) -> str | None:
    """Return an executable DLP adapter name, if one is wired into this runtime.

    The v1 runtime has no centralized DLP implementation. Organization labels
    remain visible in readiness metadata, but a DLP-required rule fails closed
    until its adapter has executable enforcement here.
    """

    del name
    return None


def _connector_digests(
    *,
    provider: str,
    binding: ConnectorExecutionBinding | None,
    connector_mode: str,
) -> tuple[str, str, str]:
    if binding is None:
        if connector_mode not in {"mock", "local"}:
            raise ConfigurationError(
                f"provider-data egress requires a connector binding for {provider}"
            )
        return (
            _digest({"provider": provider, "mode": connector_mode}),
            _digest({"provider": provider, "origin": connector_mode}),
            _digest({"provider": provider, "account": connector_mode}),
        )
    expected_system = (
        "microsoft"
        if provider in {"microsoft", "sharepoint", "outlook", "teams", "onenote"}
        else provider
    )
    if binding.system != expected_system:
        raise ConfigurationError(
            "provider-data egress connector binding does not match the provider"
        )
    if binding.authentication_mode == "none":
        account = "anonymous"
    elif binding.credential_identity is not None:
        account = binding.credential_identity
    else:
        raise ConfigurationError(
            "provider-data egress requires a bound provider account identity"
        )
    return (
        binding.config_identity_sha256,
        _digest(binding.resolved_origin),
        _digest(account),
    )


def _requested_field_binding(
    action: AgentAction,
    definition: CapabilityDefinition,
) -> tuple[
    tuple[str, ...],
    str,
    str,
    tuple[tuple[str, str], ...],
    tuple[str, ...],
]:
    raw_fields = action.parameters.get("fields")
    fields: tuple[str, ...] = ()
    if isinstance(raw_fields, str):
        fields = (raw_fields,)
    elif isinstance(raw_fields, Mapping):
        fields = tuple(sorted(str(key) for key in raw_fields))
    elif isinstance(raw_fields, (tuple, list)) and all(
        isinstance(item, str) for item in raw_fields
    ):
        fields = tuple(sorted(set(raw_fields)))
    elif raw_fields is not None:
        raise ConfigurationError(
            "provider-data requested fields must be a string, string list, or object"
        )
    for field_name in fields:
        _validate_text(field_name, "provider-data requested field")
    reserved_fields = sorted(
        field_name
        for field_name in fields
        if is_reserved_read_result_field_name(field_name)
    )
    if reserved_fields:
        raise ConfigurationError(
            "provider-data requested fields use reserved result names: "
            + ", ".join(reserved_fields)
        )
    output_schema = definition.read_result_schema
    output_resources = tuple(sorted(definition.read_result_resources.items()))
    output_metadata_fields = tuple(definition.read_result_metadata)
    if not output_schema or not output_resources:
        raise ConfigurationError(
            f"provider read capability {definition.name} requires a versioned "
            "read result contract"
        )
    contract_material = {
        "name": definition.name,
        "target_system": definition.target_system,
        "target_resource_types": list(definition.target_resource_types),
        "parameter_schema": dict(definition.parameter_schema),
        "output_schema": output_schema,
        "output_resources": dict(output_resources),
        "output_metadata_fields": list(output_metadata_fields),
        "omitted_result_fields": sorted(_OMITTED_RESULT_FIELDS),
        "crosscut_result_fields": sorted(_CROSSCUT_RESULT_FIELDS),
        "contract_version": 2,
    }
    contract = "explicit-fields@2" if fields else output_schema
    return (
        fields,
        f"{contract};sha256={_digest(contract_material)}",
        output_schema,
        output_resources,
        output_metadata_fields,
    )


def _redact_configured_fields(value: Any, fields: frozenset[str]) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "<redacted>"
                if _field_identity(str(key)) in fields
                else _redact_configured_fields(item, fields)
            )
            for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [_redact_configured_fields(item, fields) for item in value]
    return value


def _redact_provider_secret_variants(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            normalized = _normalize_field_name(key_text)
            identity = normalized.replace("_", "")
            sensitive = (
                identity in _SENSITIVE_PROVIDER_KEY_IDENTITIES
                or identity.startswith("authorization")
                or identity.endswith(_SENSITIVE_PROVIDER_SUFFIX_IDENTITIES)
            )
            redacted[key_text] = (
                "<redacted>" if sensitive else _redact_provider_secret_variants(item)
            )
        return redacted
    if isinstance(value, (tuple, list)):
        return [_redact_provider_secret_variants(item) for item in value]
    return value


def _enforce_item_limit(
    value: Mapping[str, Any],
    limit: int | None,
    output_resources: tuple[tuple[str, str], ...],
) -> None:
    if limit is None:
        return
    for count_key in ("count", "returned"):
        count = value.get(count_key)
        if isinstance(count, int) and not isinstance(count, bool) and count > limit:
            raise ValidationError(
                "provider-data egress result exceeds the requested item limit"
            )
    if any(
        descriptor == "object_list"
        and isinstance(value.get(key), list)
        and len(value[key]) > limit
        for key, descriptor in output_resources
    ):
        raise ValidationError(
            "provider-data egress result exceeds the requested item limit"
        )


def _apply_output_contract(
    value: Mapping[str, Any],
    binding: ProviderDataEgressBinding,
) -> dict[str, Any]:
    """Validate one versioned envelope and apply its exact resource projection."""

    observed_schema = value.get("schema")
    if observed_schema != binding.output_schema:
        raise ValidationError(
            "provider-data egress result does not match its bound output schema"
        )
    resource_contract = dict(binding.output_resources)
    known_fields = (
        {"schema"}
        | set(resource_contract)
        | set(binding.output_metadata_fields)
        | set(_CROSSCUT_RESULT_FIELDS)
        | set(_OMITTED_RESULT_FIELDS)
    )
    unknown = sorted(str(key) for key in value if str(key) not in known_fields)
    if unknown:
        raise ValidationError(
            "provider-data egress result has fields outside its bound output contract"
        )

    projected: dict[str, Any] = {"schema": binding.output_schema}
    for key in binding.output_metadata_fields:
        if key in value:
            projected[key] = _copy_output_metadata(
                key,
                value[key],
                limit=binding.requested_item_limit,
            )
    if not binding.requested_fields:
        citations = _sanitize_citations(
            value.get("citations"),
            limit=binding.requested_item_limit,
        )
        if citations:
            projected["citations"] = citations
            projected["citation_ids"] = [
                citation["citation_id"]
                for citation in citations
                if "citation_id" in citation
            ]

    allowed = _normalized_requested_fields(binding.requested_fields)
    for key, descriptor in binding.output_resources:
        if key not in value:
            raise ValidationError(
                "provider-data egress result is missing a bound resource field"
            )
        item = value[key]
        if descriptor == "object":
            if not isinstance(item, Mapping):
                raise ValidationError(
                    "provider-data egress object resource has an invalid shape"
                )
            projected[key] = (
                _project_resource_object(item, allowed)
                if binding.requested_fields
                else _omit_reserved_resource_fields(item)
            )
        elif descriptor == "object_list":
            if not isinstance(item, list) or not all(
                isinstance(entry, Mapping) for entry in item
            ):
                raise ValidationError(
                    "provider-data egress collection resource has an invalid shape"
                )
            projected[key] = [
                (
                    _project_resource_object(entry, allowed)
                    if binding.requested_fields
                    else _omit_reserved_resource_fields(entry)
                )
                for entry in item
            ]
        elif descriptor == "value":
            if not _is_json_scalar(item):
                raise ValidationError(
                    "provider-data egress value resource must be a JSON scalar"
                )
            if not binding.requested_fields or _normalize_field_name(key) in allowed:
                projected[key] = item
        else:  # pragma: no cover - binding validation protects this branch.
            raise ValidationError(
                "provider-data egress output resource type is unsupported"
            )
    measure_json_resources(
        projected,
        context="provider-data egress projected result",
        max_bytes=binding.max_output_bytes,
    )
    evidence_digest = content_digest(projected)
    findings = scan_untrusted_value(projected)
    projected["evidence"] = {"content_sha256": evidence_digest}
    projected["security"] = {
        "content_is_untrusted": True,
        "prompt_injection_findings": [
            {
                "category": finding.category,
                "severity": finding.severity,
                "path_sha256": _digest(finding.path),
                "excerpt_sha256": _digest(finding.excerpt),
                "excerpt_length": len(finding.excerpt),
            }
            for finding in findings
        ],
    }
    return projected


def _copy_output_metadata(key: str, value: Any, *, limit: int | None) -> Any:
    """Copy one strictly shaped, non-resource envelope field."""

    if key == "source_urls":
        if not isinstance(value, list) or not all(
            item is None or isinstance(item, str) for item in value
        ):
            raise ValidationError(
                "provider-data egress source_urls metadata must be strings"
            )
        source_urls = [item for item in value if isinstance(item, str)]
        if limit is not None and len(source_urls) > limit + 1:
            raise ValidationError(
                "provider-data egress source_urls exceed the requested item limit"
            )
        return source_urls
    if key == "retention":
        if not isinstance(value, Mapping):
            raise ValidationError(
                "provider-data egress retention metadata must be an object"
            )
        allowed = {
            "content_kind",
            "evidence_type",
            "persistence_requires_explicit_output",
        }
        if set(value) - allowed:
            raise ValidationError(
                "provider-data egress retention metadata has an invalid shape"
            )
        rendered: dict[str, Any] = {}
        for name, item in value.items():
            if name == "persistence_requires_explicit_output":
                if not isinstance(item, bool):
                    raise ValidationError(
                        "provider-data egress retention persistence flag must be boolean"
                    )
                rendered[str(name)] = item
            elif isinstance(item, str):
                rendered[str(name)] = item
            else:
                raise ValidationError(
                    "provider-data egress retention metadata must be strings"
                )
        return rendered
    if key == "repository":
        if not isinstance(value, Mapping):
            raise ValidationError(
                "provider-data egress repository context must be an object"
            )
        allowed = {"name", "owner", "slug"}
        if set(value) - allowed or not all(
            isinstance(item, str) for item in value.values()
        ):
            raise ValidationError(
                "provider-data egress repository context has an invalid shape"
            )
        return {str(name): str(item) for name, item in value.items()}
    if not _is_json_scalar(value):
        raise ValidationError(
            "provider-data egress envelope metadata must be a JSON scalar"
        )
    return value


def _sanitize_citations(value: Any, *, limit: int | None) -> list[dict[str, Any]]:
    """Return only the fixed, scalar citation schema for wildcard reads."""

    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise ValidationError("provider-data egress citations have an invalid shape")
    if limit is not None and len(value) > limit:
        raise ValidationError(
            "provider-data egress citations exceed the requested item limit"
        )
    allowed = {
        "citation_id",
        "marker",
        "parent_resource_id",
        "resource_id",
        "resource_type",
        "retrieved_at",
        "system",
        "title",
        "url",
        "version",
    }
    citations: list[dict[str, Any]] = []
    for citation in value:
        if set(citation) - allowed or not all(
            _is_json_scalar(item) for item in citation.values()
        ):
            raise ValidationError(
                "provider-data egress citation has fields outside its fixed schema"
            )
        citations.append({str(key): item for key, item in citation.items()})
    return citations


def _is_json_scalar(value: Any) -> bool:
    """Return whether a value is a finite JSON scalar."""

    return (
        value is None
        or isinstance(value, (str, bool, int))
        and not isinstance(value, float)
        or isinstance(value, float)
        and math.isfinite(value)
    )


def _project_resource_object(
    value: Mapping[str, Any],
    allowed: frozenset[str],
) -> dict[str, Any]:
    """Project one normalized resource record to explicitly requested fields."""

    projected = _omit_reserved_resource_fields(
        {
            str(key): deepcopy(item)
            for key, item in value.items()
            if _normalize_field_name(str(key)) in allowed
        }
    )
    if not isinstance(projected, dict):  # pragma: no cover - mapping invariant.
        raise ValidationError("provider-data resource projection is invalid")
    return projected


def _omit_reserved_resource_fields(value: Any) -> Any:
    """Remove envelope-only and globally omitted names from resource content."""

    if isinstance(value, Mapping):
        return {
            str(key): _omit_reserved_resource_fields(item)
            for key, item in value.items()
            if not is_reserved_read_result_field_name(str(key))
        }
    if isinstance(value, (tuple, list)):
        return [_omit_reserved_resource_fields(item) for item in value]
    return deepcopy(value)


def _normalized_requested_fields(fields: tuple[str, ...]) -> frozenset[str]:
    normalized: set[str] = set()
    for field in fields:
        key = _normalize_field_name(field)
        normalized.add(key)
        normalized.update(_FIELD_ALIASES.get(field.casefold(), ()))
    return frozenset(normalized)


def _normalize_field_name(value: str) -> str:
    return normalize_read_result_field_name(value)


def _field_identity(value: str) -> str:
    """Return a case, separator, camel, and acronym-insensitive field identity."""

    return _normalize_field_name(value).replace("_", "")


def _minimize_references(
    value: Any,
    *,
    key_name: str = "",
    minimize_path: bool,
) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _minimize_references(
                item,
                key_name=str(key),
                minimize_path=minimize_path,
            )
            for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [
            _minimize_references(
                item,
                key_name=key_name,
                minimize_path=minimize_path,
            )
            for item in value
        ]
    normalized_key = _normalize_field_name(key_name)
    key_identity = normalized_key.replace("_", "")
    if isinstance(value, str) and (
        key_identity
        in {
            "connectorreference",
            "href",
            "link",
            "reference",
            "sourceurl",
            "sourceurls",
            "url",
        }
        or normalized_key.endswith("_url")
        or len(key_identity) > 4
        and key_identity.endswith("url")
    ):
        return _safe_reference(value, minimize_path=minimize_path)
    return value


def _minimize_prompt_injection_findings(value: Any) -> Any:
    if isinstance(value, Mapping):
        minimized: dict[str, Any] = {}
        for key, item in value.items():
            if _field_identity(str(key)) == "promptinjectionfindings" and isinstance(
                item, (tuple, list)
            ):
                minimized[key] = [
                    _finding_metadata(finding)
                    for finding in item
                    if isinstance(finding, Mapping)
                ]
            else:
                minimized[str(key)] = _minimize_prompt_injection_findings(item)
        return minimized
    if isinstance(value, (tuple, list)):
        return [_minimize_prompt_injection_findings(item) for item in value]
    return value


def _finding_metadata(finding: Mapping[str, Any]) -> dict[str, Any]:
    metadata = {
        str(key): deepcopy(item)
        for key, item in finding.items()
        if _field_identity(str(key)) not in _SENSITIVE_FINDING_KEYS
    }
    path = next(
        (
            item
            for key, item in finding.items()
            if _field_identity(str(key)) == "path" and isinstance(item, str)
        ),
        None,
    )
    if isinstance(path, str):
        metadata["path_sha256"] = _digest(path)
    excerpt = next(
        (
            item
            for key, item in finding.items()
            if _field_identity(str(key)) == "excerpt" and isinstance(item, str)
        ),
        None,
    )
    if isinstance(excerpt, str):
        metadata["excerpt_sha256"] = _digest(excerpt)
        metadata["excerpt_length"] = len(excerpt)
    return metadata


def _safe_reference(value: str | None, *, minimize_path: bool = False) -> str | None:
    if value is None:
        return None
    validate_bounded_string(value, context="provider-data egress reference")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return f"reference:sha256:{_digest(value)}"
    if parsed.scheme not in {"http", "https"} or hostname is None:
        return f"reference:sha256:{_digest(value)}"
    hostname = hostname.lower().rstrip(".")
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        rendered_host = f"{rendered_host}:{port}"
    path = f"/_redacted/{_digest(parsed.path)}" if minimize_path else parsed.path
    return urlunsplit((parsed.scheme, rendered_host, path, "", ""))


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: Any) -> str:
    payload: bytes | None = None
    invalid_unicode = False
    try:
        payload = json.dumps(
            _jsonable(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except UnicodeEncodeError:
        invalid_unicode = True
    if invalid_unicode or payload is None:
        raise ValidationError("provider-data value contains invalid Unicode")
    return hashlib.sha256(payload).hexdigest()


def _validate_sha256(value: str, name: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValidationError(f"provider-data egress {name} is not a SHA-256 digest")


def _validate_text(value: str, name: str) -> None:
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} must be a string")
    if not value or value != value.strip() or len(value) > _MAX_RULE_TEXT:
        raise ConfigurationError(f"{name} must be a bounded normalized string")
    if any(not character.isprintable() for character in value):
        raise ConfigurationError(f"{name} must contain printable characters")


def _string_list(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{name} must be a list of strings")
    return tuple(value)


def _string_sequence(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"{name} must be a list of strings")
    return tuple(value)


def _strict_positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")
    return value


def _required_string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} must be a string")
    _validate_text(value, name)
    return value


def _validate_mapping_keys(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    name: str,
) -> None:
    keys = {str(key) for key in value}
    unknown = sorted(keys - allowed)
    if unknown:
        raise ConfigurationError(f"{name} has unknown keys: {', '.join(unknown)}")
    missing = sorted(required - keys)
    if missing:
        raise ConfigurationError(f"{name} is missing keys: {', '.join(missing)}")


def _validate_binding_text(value: Any, name: str) -> None:
    try:
        _validate_text(value, name)
    except ConfigurationError as error:
        raise ValidationError(str(error)) from error


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value


__all__ = (
    "ModelContextRule",
    "ProviderDataEgressBinding",
    "ProviderDataEgressPolicy",
    "ProviderDataHandling",
    "ProviderDataPolicyDecision",
    "ProviderDataRoute",
    "bind_provider_data_egress",
    "minimize_probe_result",
    "provider_result_audit_summary",
    "sanitize_provider_mapping",
    "sanitize_provider_result",
    "verification_metadata",
)
