"""Organization governance profile and capability coverage checks."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
from types import MappingProxyType
from typing import Any

from master_agent.capabilities import CapabilityCatalog
from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.models import AgentAction, DataClassification, RiskLevel


class EnvironmentKind(StrEnum):
    """Deployment environment classification."""

    DEVELOPMENT = "development"
    NON_PRODUCTION = "non_production"
    PRODUCTION = "production"


class ApprovalTier(StrEnum):
    """Organization approval tier."""

    AUTOMATIC = "automatic"
    SINGLE = "single"
    DUAL = "dual"
    PROHIBITED = "prohibited"


@dataclass(frozen=True, slots=True)
class GovernanceRule:
    """Governance rule applied to matching capability names."""

    pattern: str
    owner: str
    authentication: str
    data_classifications: frozenset[DataClassification]
    approval_tier: ApprovalTier
    environments: frozenset[EnvironmentKind]
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.pattern.strip():
            raise ConfigurationError("governance rule pattern must not be empty")
        if not self.owner.strip():
            raise ConfigurationError(
                f"governance owner must not be empty for {self.pattern}"
            )
        if not self.authentication.strip():
            raise ConfigurationError(
                f"governance authentication must not be empty for {self.pattern}"
            )
        if not self.data_classifications:
            raise ConfigurationError(
                f"governance data classifications are required for {self.pattern}"
            )
        if not self.environments:
            raise ConfigurationError(
                f"governance environments are required for {self.pattern}"
            )

    @property
    def specificity(self) -> tuple[int, int, int]:
        """Return deterministic precedence for overlapping patterns."""

        wildcards = self.pattern.count("*") + self.pattern.count("?")
        literal_length = len(self.pattern) - wildcards
        return (literal_length, -wildcards, len(self.pattern))


@dataclass(frozen=True, slots=True)
class GovernanceProfile:
    """Organization-level policy facts required before live execution."""

    organization: str
    environment: EnvironmentKind
    secret_manager: str
    audit_sink: str
    external_model_policy: str
    rules: tuple[GovernanceRule, ...]
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        for name, value in (
            ("organization", self.organization),
            ("secret_manager", self.secret_manager),
            ("audit_sink", self.audit_sink),
            ("external_model_policy", self.external_model_policy),
        ):
            if not value.strip():
                raise ConfigurationError(f"governance {name} must not be empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @classmethod
    def from_toml(cls, path: ConfigSource) -> GovernanceProfile:
        """Load an organization governance profile."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"governance configuration not found: {path}"
            ) from error
        organization = raw.get("organization", {})
        if not isinstance(organization, Mapping):
            raise ConfigurationError("[organization] must be a TOML table")
        raw_rules = raw.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ConfigurationError("[[rules]] must be a TOML array of tables")
        rules: list[GovernanceRule] = []
        for index, value in enumerate(raw_rules, start=1):
            if not isinstance(value, Mapping):
                raise ConfigurationError(f"governance rule {index} must be a table")
            try:
                classifications = frozenset(
                    DataClassification(str(item))
                    for item in value.get("data_classifications", [])
                )
                environments = frozenset(
                    EnvironmentKind(str(item)) for item in value.get("environments", [])
                )
                approval = ApprovalTier(str(value["approval_tier"]))
            except (KeyError, ValueError) as error:
                raise ConfigurationError(
                    f"governance rule {index} contains an invalid enum value"
                ) from error
            rules.append(
                GovernanceRule(
                    pattern=str(value.get("pattern", "")),
                    owner=str(value.get("owner", "")),
                    authentication=str(value.get("authentication", "")),
                    data_classifications=classifications,
                    approval_tier=approval,
                    environments=environments,
                    enabled=_strict_bool(
                        value.get("enabled", True), f"governance rule {index} enabled"
                    ),
                )
            )
        return cls(
            organization=str(organization.get("name", "")),
            environment=EnvironmentKind(
                str(organization.get("environment", "development"))
            ),
            secret_manager=str(organization.get("secret_manager", "")),
            audit_sink=str(organization.get("audit_sink", "")),
            external_model_policy=str(organization.get("external_model_policy", "")),
            rules=tuple(rules),
            metadata={
                key: value
                for key, value in organization.items()
                if key
                not in {
                    "name",
                    "environment",
                    "secret_manager",
                    "audit_sink",
                    "external_model_policy",
                }
            },
        )

    def rule_for(self, capability: str) -> GovernanceRule | None:
        """Resolve the most specific matching governance rule."""

        matches = [rule for rule in self.rules if fnmatch(capability, rule.pattern)]
        if not matches:
            return None
        return max(matches, key=lambda rule: rule.specificity)

    def validate_action(self, action: AgentAction) -> tuple[bool, str]:
        """Validate one action against organization governance."""

        rule = self.rule_for(action.capability)
        if rule is None:
            return False, f"no governance owner/rule covers {action.capability}"
        if not rule.enabled:
            return False, f"governance rule disables {action.capability}"
        if self.environment not in rule.environments:
            return (
                False,
                (
                    f"capability {action.capability} is not allowed in "
                    f"{self.environment}"
                ),
            )
        if action.data_classification not in rule.data_classifications:
            return (
                False,
                (
                    f"data classification {action.data_classification} is not allowed "
                    f"for {action.capability}"
                ),
            )
        if rule.approval_tier is ApprovalTier.PROHIBITED:
            return False, f"governance prohibits {action.capability}"
        if rule.approval_tier is ApprovalTier.AUTOMATIC and action.risk not in {
            RiskLevel.READ_ONLY,
            RiskLevel.LOCAL_GENERATION,
        }:
            return (
                False,
                (
                    f"write capability {action.capability} cannot use automatic "
                    "governance approval"
                ),
            )
        return True, f"governed by {rule.owner} ({rule.approval_tier})"

    def approval_tier_for(self, capability: str) -> ApprovalTier | None:
        """Return the effective approval tier for a capability."""

        rule = self.rule_for(capability)
        return rule.approval_tier if rule is not None else None

    def minimum_approvers(self, capability: str) -> int:
        """Return the number of distinct human approvers required.

        Parameters
        ----------
        capability
            Capability name to evaluate.

        Returns
        -------
        int
            Zero for automatic actions, one for single approval, and two for
            dual approval. Prohibited or uncovered capabilities raise a
            configuration error so callers fail closed.
        """

        rule = self.rule_for(capability)
        if rule is None:
            raise ConfigurationError(f"no governance owner/rule covers {capability}")
        if not rule.enabled or rule.approval_tier is ApprovalTier.PROHIBITED:
            raise ConfigurationError(f"governance prohibits {capability}")
        return {
            ApprovalTier.AUTOMATIC: 0,
            ApprovalTier.SINGLE: 1,
            ApprovalTier.DUAL: 2,
        }[rule.approval_tier]

    def coverage_report(self, catalog: CapabilityCatalog) -> dict[str, Any]:
        """Return capability coverage and configuration errors."""

        covered: list[dict[str, Any]] = []
        errors: list[str] = []
        for name in sorted(catalog.definitions):
            definition = catalog.definitions[name]
            rule = self.rule_for(name)
            if rule is None:
                errors.append(f"no governance rule covers {name}")
                continue
            if definition.enabled and not rule.enabled:
                errors.append(
                    f"enabled catalog capability is disabled by governance: {name}"
                )
            if (
                definition.authentication != rule.authentication
                and rule.authentication != "provider_specific"
            ):
                errors.append(
                    f"authentication mismatch for {name}: "
                    f"catalog={definition.authentication}, "
                    f"governance={rule.authentication}"
                )
            covered.append(
                {
                    "capability": name,
                    "catalog_enabled": definition.enabled,
                    "owner": rule.owner,
                    "approval_tier": str(rule.approval_tier),
                    "governance_enabled": rule.enabled,
                    "environment_allowed": self.environment in rule.environments,
                }
            )
        return {
            "organization": self.organization,
            "environment": str(self.environment),
            "secret_manager": self.secret_manager,
            "audit_sink": self.audit_sink,
            "external_model_policy": self.external_model_policy,
            "covered": covered,
            "errors": errors,
            "ready": not errors,
        }


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be a boolean")
    return value
