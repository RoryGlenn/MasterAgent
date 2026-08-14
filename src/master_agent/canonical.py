"""Canonical-source and projection enforcement."""

from __future__ import annotations

import hashlib
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.models import AgentAction, ChangePlan, RiskLevel


@dataclass(frozen=True, slots=True)
class SourceRule:
    """Ownership rule for one logical field."""

    field: str
    canonical_uri: str
    projection_uris: frozenset[str]
    direction: str
    canonical_capabilities: frozenset[str]
    projection_capabilities: frozenset[str]


class SourceOfTruthRegistry:
    """Prevent projections from silently becoming competing truth."""

    def __init__(self, rules: tuple[SourceRule, ...]) -> None:
        self._rules = rules

    @classmethod
    def from_toml(cls, path: ConfigSource) -> SourceOfTruthRegistry:
        """Load exact-resource ownership rules from TOML."""

        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        rules: list[SourceRule] = []
        for item in raw.get("rules", []):
            direction = str(item["direction"])
            if direction != "outbound_only":
                raise ConfigurationError(
                    f"unsupported source-of-truth direction: {direction}"
                )
            canonical_capabilities = _string_set(
                item.get("canonical_capabilities"),
                "canonical_capabilities",
            )
            projection_capabilities = _string_set(
                item.get("projection_capabilities"),
                "projection_capabilities",
            )
            rules.append(
                SourceRule(
                    field=str(item["field"]),
                    canonical_uri=(
                        f"{item['canonical_system']}:{item['canonical_resource_id']}"
                    ),
                    projection_uris=frozenset(str(uri) for uri in item["projections"]),
                    direction=direction,
                    canonical_capabilities=canonical_capabilities,
                    projection_capabilities=projection_capabilities,
                )
            )
        return cls(tuple(rules))

    def validate(self, plan: ChangePlan, action: AgentAction) -> tuple[bool, str]:
        """Validate a planned write against canonical ownership.

        Local generation is allowed because it creates derived output without
        modifying a projection in an external system.
        """

        if action.risk in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}:
            return True, "read or local generation does not modify a projection"

        for rule in self._rules:
            if action.target.uri not in rule.projection_uris:
                continue
            if action.capability not in rule.projection_capabilities:
                return (
                    False,
                    f"{rule.field} projection capability is not approved by its source rule",
                )
            projection_digest = _source_binding(action, rule.field)
            if projection_digest is None:
                return (
                    False,
                    f"{rule.field} projection is missing a valid source binding",
                )
            canonical_writes = {
                candidate.action_id: _source_binding(candidate, rule.field)
                for candidate in plan.actions
                if candidate.target.uri == rule.canonical_uri
                and candidate.risk
                not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
                and candidate.capability in rule.canonical_capabilities
            }
            if not canonical_writes:
                return (
                    False,
                    (
                        f"{rule.field} is owned by {rule.canonical_uri}; update the "
                        "canonical source before its projection"
                    ),
                )
            ancestors = _dependency_ancestors(plan, action)
            bound_ancestors = {
                action_id
                for action_id, digest in canonical_writes.items()
                if digest == projection_digest
            }
            if bound_ancestors.isdisjoint(ancestors):
                return (
                    False,
                    (
                        f"{rule.field} projection must depend on a matching field-bound "
                        f"{rule.canonical_uri}; plan ordering alone is not authority"
                    ),
                )

        return True, "source-of-truth policy satisfied"


def _dependency_ancestors(
    plan: ChangePlan,
    action: AgentAction,
) -> frozenset[UUID]:
    """Return all direct and transitive dependency IDs for an action."""

    by_id = {candidate.action_id: candidate for candidate in plan.actions}
    ancestors: set[UUID] = set()
    pending = list(action.dependencies)
    while pending:
        dependency = pending.pop()
        if dependency in ancestors:
            continue
        ancestors.add(dependency)
        pending.extend(by_id[dependency].dependencies)
    return frozenset(ancestors)


def _string_set(value: object, name: str) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError(f"source-of-truth {name} must be a non-empty list")
    rendered = frozenset(str(item).strip() for item in value)
    if "" in rendered:
        raise ConfigurationError(f"source-of-truth {name} entries must not be empty")
    return rendered


def _source_binding(action: AgentAction, field: str) -> str | None:
    """Return a validated digest binding an action to one logical field."""

    raw = action.parameters.get("source_bindings")
    if not isinstance(raw, Mapping):
        return None
    digest = str(raw.get(field, "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None
    if "body" in action.parameters and action.target.uri.startswith("confluence:"):
        observed = hashlib.sha256(
            str(action.parameters["body"]).encode("utf-8")
        ).hexdigest()
        if observed != digest:
            return None
    return digest
