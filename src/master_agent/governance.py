"""Organization governance profile and capability coverage checks."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
from types import MappingProxyType
from typing import Any

from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    RiskLevel,
)
from master_agent.provider_egress import ProviderDataEgressPolicy


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
    model_context: ProviderDataEgressPolicy | None = None

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
        raw_model_context = raw.get("model_context")
        if raw_model_context is not None and not isinstance(raw_model_context, Mapping):
            raise ConfigurationError("[model_context] must be a TOML table")
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
            model_context=(
                ProviderDataEgressPolicy.from_mapping(raw_model_context)
                if isinstance(raw_model_context, Mapping)
                else None
            ),
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

    def validate_external_model(
        self,
        action: AgentAction,
        definition: CapabilityDefinition,
    ) -> tuple[bool, str]:
        """Enforce the organization's declared external-model data boundary."""

        if not definition.uses_external_model:
            return True, "capability does not use an external model"
        configured = self.metadata.get("external_model_approved_classifications", [])
        if not isinstance(configured, list) or not all(
            isinstance(item, str) for item in configured
        ):
            return False, "external-model approved classifications are invalid"
        allowed = frozenset(configured)
        if str(action.data_classification) not in allowed:
            return (
                False,
                (
                    f"external-model policy {self.external_model_policy} does not "
                    f"approve {action.data_classification} data for "
                    f"{action.capability}"
                ),
            )
        return True, "external-model policy explicitly permits this classification"

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

    def allows_direct_read_session(self, plan: ChangePlan) -> tuple[bool, str]:
        """Return whether this profile permits a stateless direct read session.

        A direct read session is deliberately narrower than normal applied
        execution: it is limited to one directly requested, read-only provider
        and owns no approval, runtime-path, artifact, or durable audit state.
        An organization must opt in through its governance profile rather than
        inheriting this route merely by using read-only capability rules.
        """

        configured = self.metadata.get("allow_ephemeral_direct_reads", False)
        if not isinstance(configured, bool):
            return False, "allow_ephemeral_direct_reads must be a boolean"
        if not configured:
            return False, "governance disables direct read sessions"
        if plan.execution_context is not None:
            return False, "direct read sessions must not use an execution context"
        if plan.workflow_id is not None or plan.workflow_fingerprint is not None:
            return False, "direct read sessions cannot execute a registered workflow"
        if plan.compensate_on_failure:
            return False, "direct read sessions cannot request compensation"
        systems = {action.target.system for action in plan.actions}
        if len(systems) != 1:
            return False, "direct read sessions require exactly one provider"
        for action in plan.actions:
            if action.risk is not RiskLevel.READ_ONLY:
                return False, "direct read sessions permit read-only actions only"
            if action.authority_source is not AuthoritySource.DIRECT_USER:
                return (
                    False,
                    "direct read sessions require direct-user authority",
                )
            if action.requires_approval:
                return (
                    False,
                    "direct read sessions cannot carry approval-required actions",
                )
        return True, "governance permits an ephemeral direct read session"

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
