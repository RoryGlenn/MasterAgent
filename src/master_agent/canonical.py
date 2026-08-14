"""Canonical-source and projection enforcement."""

from __future__ import annotations

from dataclasses import dataclass
import tomllib
from uuid import UUID

from master_agent.config_sources import ConfigSource
from master_agent.models import AgentAction, ChangePlan, RiskLevel


@dataclass(frozen=True, slots=True)
class SourceRule:
    """Ownership rule for one logical field."""

    field: str
    canonical_uri: str
    projection_uris: frozenset[str]
    direction: str


class SourceOfTruthRegistry:
    """Prevent projections from silently becoming competing truth."""

    def __init__(self, rules: tuple[SourceRule, ...]) -> None:
        self._rules = rules

    @classmethod
    def from_toml(cls, path: ConfigSource) -> SourceOfTruthRegistry:
        """Load exact-resource ownership rules from TOML."""

        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        rules = tuple(
            SourceRule(
                field=str(item["field"]),
                canonical_uri=(
                    f"{item['canonical_system']}:{item['canonical_resource_id']}"
                ),
                projection_uris=frozenset(str(uri) for uri in item["projections"]),
                direction=str(item["direction"]),
            )
            for item in raw.get("rules", [])
        )
        return cls(rules)

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
            if rule.direction != "outbound_only":
                continue
            canonical_writes = {
                candidate.action_id
                for candidate in plan.actions
                if candidate.target.uri == rule.canonical_uri
                and candidate.risk
                not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
            }
            if not canonical_writes:
                return (
                    False,
                    f"{rule.field} is owned by {rule.canonical_uri}; update the "
                    "canonical source before its projection",
                )
            ancestors = _dependency_ancestors(plan, action)
            if canonical_writes.isdisjoint(ancestors):
                return (
                    False,
                    f"{rule.field} projection must depend on a write to "
                    f"{rule.canonical_uri}; plan ordering alone is not authority",
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
