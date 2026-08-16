"""Canonical-source and projection enforcement."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.models import AgentAction, ChangePlan, RiskLevel


@dataclass(frozen=True, slots=True)
class SourceRule:
    """Ownership rule for one logical field."""

    field: str
    canonical_resource: tuple[str, str, str]
    projection_resources: frozenset[tuple[str, str, str]]
    direction: str
    canonical_capabilities: frozenset[str]
    projection_capabilities: frozenset[str]
    canonical_extractors: tuple[tuple[str, tuple[str, ...]], ...]
    projection_extractors: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def canonical_identity(self) -> tuple[object, ...]:
        """Return the exact resource, field, and selectors that own the value."""

        return (
            *self.canonical_resource,
            self.field,
            self.canonical_extractors,
        )

    @property
    def canonical_uri(self) -> str:
        """Render the typed canonical resource for diagnostics."""

        return ":".join(self.canonical_resource)


_SUPPORTED_PARAMETER_SELECTORS: dict[str, frozenset[str]] = {
    "confluence.page.update": frozenset({"body"}),
    "jira.issue.update": frozenset({"fields.status", "fields.status.name"}),
    "jira.issue.transition": frozenset({"target_status"}),
    "outlook.email.draft": frozenset({"body"}),
    "teams.message.draft": frozenset({"body"}),
}
_SELECTOR_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[\])?")


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
            if not isinstance(item, Mapping):
                raise ConfigurationError("source-of-truth rule must be a table")
            field = str(item.get("field", "")).strip()
            if not field:
                raise ConfigurationError("source-of-truth field must not be empty")
            direction = str(item["direction"])
            if direction != "outbound_only":
                raise ConfigurationError(
                    f"unsupported source-of-truth direction: {direction}"
                )
            canonical_extractors = _extractor_bindings(
                item.get("canonical_extractors"),
                "canonical_extractors",
            )
            projection_extractors = _extractor_bindings(
                item.get("projection_extractors"),
                "projection_extractors",
            )
            canonical_capabilities = frozenset(
                capability for capability, _ in canonical_extractors
            )
            projection_capabilities = frozenset(
                capability for capability, _ in projection_extractors
            )
            rules.append(
                SourceRule(
                    field=field,
                    canonical_resource=_canonical_resource(item),
                    projection_resources=_projection_resources(item.get("projections")),
                    direction=direction,
                    canonical_capabilities=canonical_capabilities,
                    projection_capabilities=projection_capabilities,
                    canonical_extractors=canonical_extractors,
                    projection_extractors=projection_extractors,
                )
            )
        return cls(tuple(rules))

    def validate(self, plan: ChangePlan, action: AgentAction) -> tuple[bool, str]:
        """Validate a planned write against canonical ownership.

        Read-only actions cannot modify a projection. Local generation is still
        checked when its exact target is governed by a projection rule so that
        generated artifacts cannot claim an unrelated canonical source.
        """

        for rule in self._rules:
            if _resource_identity(action) not in rule.projection_resources:
                continue
            if action.capability not in rule.projection_capabilities:
                if action.risk is RiskLevel.READ_ONLY:
                    continue
                return (
                    False,
                    f"{rule.field} projection capability is not approved by its source rule",
                )
            projection_digests = _parameter_digests(
                action,
                _selectors_for(rule.projection_extractors, action.capability),
            )
            if len(projection_digests) != 1:
                return (
                    False,
                    (
                        f"{rule.field} projection must expose exactly one "
                        "verifiable governed value"
                    ),
                )
            canonical_writes = {
                candidate.action_id: (
                    rule.canonical_identity,
                    _parameter_digests(
                        candidate,
                        _selectors_for(
                            rule.canonical_extractors,
                            candidate.capability,
                        ),
                    ),
                )
                for candidate in plan.actions
                if _resource_identity(candidate) == rule.canonical_resource
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
            matching_ancestors = {
                action_id
                for action_id, (identity, digests) in canonical_writes.items()
                if identity == rule.canonical_identity and digests == projection_digests
            }
            if matching_ancestors.isdisjoint(ancestors):
                return (
                    False,
                    (
                        f"{rule.field} projection must depend on a matching field-value "
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


def _projection_resources(value: object) -> frozenset[tuple[str, str, str]]:
    """Parse exact typed projection resources and reject legacy URI strings."""

    if not isinstance(value, list) or not value:
        raise ConfigurationError(
            "source-of-truth projections must be a non-empty array of tables"
        )
    resources: set[tuple[str, str, str]] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise ConfigurationError(
                "source-of-truth projection must declare system, resource_type, "
                "and resource_id"
            )
        try:
            identity = tuple(
                str(item[name]).strip()
                for name in ("system", "resource_type", "resource_id")
            )
        except KeyError as error:
            raise ConfigurationError(
                "source-of-truth projection must declare system, resource_type, "
                "and resource_id"
            ) from error
        if len(identity) != 3 or any(not part for part in identity):
            raise ConfigurationError(
                "source-of-truth projection identity values must not be empty"
            )
        resource = (identity[0], identity[1], identity[2])
        if resource in resources:
            raise ConfigurationError(
                "source-of-truth projection identities must be unique"
            )
        resources.add(resource)
    return frozenset(resources)


def _canonical_resource(item: Mapping[str, object]) -> tuple[str, str, str]:
    """Parse the exact typed canonical identity."""

    try:
        identity = tuple(
            str(item[name]).strip()
            for name in (
                "canonical_system",
                "canonical_resource_type",
                "canonical_resource_id",
            )
        )
    except KeyError as error:
        raise ConfigurationError(
            "source-of-truth canonical resource must declare system, "
            "resource_type, and resource_id"
        ) from error
    if len(identity) != 3 or any(not part for part in identity):
        raise ConfigurationError(
            "source-of-truth canonical resource identity values must not be empty"
        )
    return identity[0], identity[1], identity[2]


def _resource_identity(action: AgentAction) -> tuple[str, str, str]:
    return (
        action.target.system,
        action.target.resource_type,
        action.target.resource_id,
    )


def _extractor_bindings(
    value: object,
    name: str,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Validate exact parameter selectors for every allowed capability."""

    if not isinstance(value, Mapping) or not value:
        raise ConfigurationError(f"source-of-truth {name} must be a non-empty table")
    bindings: list[tuple[str, tuple[str, ...]]] = []
    for raw_capability, raw_selectors in value.items():
        capability = str(raw_capability).strip()
        if not capability:
            raise ConfigurationError(
                f"source-of-truth {name} capability must not be empty"
            )
        if not isinstance(raw_selectors, list) or not raw_selectors:
            raise ConfigurationError(
                f"source-of-truth {name}.{capability} must be a non-empty list"
            )
        selectors = tuple(str(selector).strip() for selector in raw_selectors)
        if any(not selector for selector in selectors):
            raise ConfigurationError(
                f"source-of-truth {name}.{capability} selectors must not be empty"
            )
        supported = _SUPPORTED_PARAMETER_SELECTORS.get(capability)
        if supported is None:
            raise ConfigurationError(
                f"source-of-truth capability has no parameter verifier: {capability}"
            )
        for selector in selectors:
            if not _valid_selector(selector) or selector not in supported:
                raise ConfigurationError(
                    "source-of-truth capability has unsupported parameter selector: "
                    f"{capability}={selector}"
                )
        bindings.append((capability, selectors))
    return tuple(sorted(bindings))


def _valid_selector(selector: str) -> bool:
    return all(
        _SELECTOR_SEGMENT.fullmatch(segment) is not None
        for segment in selector.split(".")
    )


def _selectors_for(
    bindings: tuple[tuple[str, tuple[str, ...]], ...],
    capability: str,
) -> tuple[str, ...]:
    for bound_capability, selectors in bindings:
        if bound_capability == capability:
            return selectors
    raise ConfigurationError(
        f"source-of-truth capability is missing its parameter verifier: {capability}"
    )


def _parameter_digests(
    action: AgentAction,
    selectors: tuple[str, ...],
) -> frozenset[str]:
    """Derive field digests from frozen action values, never asserted hashes."""

    values: list[Any] = []
    selected = tuple(
        (selector, value)
        for selector in selectors
        for value in _select_values(action.parameters, selector)
    )
    for selector, value in selected:
        normalized = _normalize_value(action.capability, selector, value)
        if normalized is not None:
            values.append(normalized)
    return frozenset(_digest_value(value) for value in values)


def _select_values(parameters: Mapping[str, Any], selector: str) -> tuple[Any, ...]:
    current: tuple[Any, ...] = (parameters,)
    for segment in selector.split("."):
        expand = segment.endswith("[]")
        key = segment[:-2] if expand else segment
        selected: list[Any] = []
        for item in current:
            if not isinstance(item, Mapping) or key not in item:
                continue
            value = item[key]
            if expand:
                if isinstance(value, Sequence) and not isinstance(
                    value,
                    (str, bytes),
                ):
                    selected.extend(value)
            else:
                selected.append(value)
        current = tuple(selected)
        if not current:
            break
    return current


def _normalize_value(capability: str, selector: str, value: Any) -> Any | None:
    """Mirror the connector's representation of a governed scalar value."""

    if (
        capability == "jira.issue.update"
        and selector == "fields.status"
        and isinstance(value, Mapping)
    ):
        return None
    if not isinstance(value, str):
        return None
    rendered = value.strip()
    return rendered or None


def _digest_value(value: Any) -> str:
    payload = json.dumps(
        _json_value(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_json_value(item) for item in value]
    return value
