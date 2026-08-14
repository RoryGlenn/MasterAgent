"""Canonical-source and projection enforcement."""

from __future__ import annotations

from dataclasses import dataclass
import tomllib

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
            canonical_write_exists = any(
                candidate.target.uri == rule.canonical_uri
                and candidate.risk not in {
                    RiskLevel.READ_ONLY,
                    RiskLevel.LOCAL_GENERATION,
                }
                for candidate in plan.actions
            )
            if not canonical_write_exists:
                return (
                    False,
                    f"{rule.field} is owned by {rule.canonical_uri}; update the "
                    "canonical source before its projection",
                )

        return True, "source-of-truth policy satisfied"
