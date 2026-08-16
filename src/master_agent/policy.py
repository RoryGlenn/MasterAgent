"""Risk, approval, and authority policy evaluation."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatch
from types import MappingProxyType
from typing import Any
from uuid import UUID

from master_agent.approvals import ApprovalAuthenticator
from master_agent.config_sources import ConfigSource
from master_agent.errors import ValidationError
from master_agent.models import (
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    DataClassification,
    RiskLevel,
)
from master_agent.resource_limits import measure_json_resources


@dataclass(frozen=True, slots=True)
class ContextualPolicyConstraints:
    """Canonical, typed run constraints; never executable policy code."""

    authenticated_principals: frozenset[str] = frozenset()
    agent_identities: frozenset[str] = frozenset()
    tenant_ids: frozenset[str] = frozenset()
    provider_account_ids: frozenset[str] = frozenset()
    resource_allowlists: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    maximum_items_per_action: int = 1_024
    maximum_bytes_per_action: int = 4 * 1024 * 1024
    allowed_classifications: frozenset[DataClassification] = frozenset(
        DataClassification
    )
    not_before: datetime | None = None
    not_after: datetime | None = None

    def __post_init__(self) -> None:
        for name, values in (
            ("authenticated_principals", self.authenticated_principals),
            ("agent_identities", self.agent_identities),
            ("tenant_ids", self.tenant_ids),
            ("provider_account_ids", self.provider_account_ids),
        ):
            if any(not value or value != value.strip() for value in values):
                raise ValueError(f"contextual policy {name} is malformed")
        if not 1 <= self.maximum_items_per_action <= 65_536:
            raise ValueError("contextual policy item budget is outside safe limits")
        if not 1 <= self.maximum_bytes_per_action <= 8 * 1024 * 1024:
            raise ValueError("contextual policy byte budget is outside safe limits")
        if not self.allowed_classifications:
            raise ValueError("contextual policy classifications are empty")
        for name, value in (
            ("not_before", self.not_before),
            ("not_after", self.not_after),
        ):
            if value is not None and value.tzinfo is None:
                raise ValueError(f"contextual policy {name} requires a timezone")
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_after <= self.not_before
        ):
            raise ValueError("contextual policy time window is empty")
        allowlists = {
            pattern: tuple(prefixes)
            for pattern, prefixes in self.resource_allowlists.items()
        }
        if any(
            not pattern
            or not prefixes
            or any(not prefix or prefix != prefix.strip() for prefix in prefixes)
            for pattern, prefixes in allowlists.items()
        ):
            raise ValueError("contextual policy resource allowlists are malformed")
        object.__setattr__(self, "resource_allowlists", MappingProxyType(allowlists))

    def validate(
        self,
        plan: ChangePlan,
        action: AgentAction,
        *,
        now: datetime,
    ) -> tuple[bool, str]:
        """Enforce identity, target, budget, time, and classification facts."""

        if self.not_before is not None and now < self.not_before.astimezone(UTC):
            return False, "contextual policy time window has not started"
        if self.not_after is not None and now >= self.not_after.astimezone(UTC):
            return False, "contextual policy time window has ended"
        if action.data_classification not in self.allowed_classifications:
            return False, "contextual policy rejects the data classification"
        if _collection_items(action.parameters) > self.maximum_items_per_action:
            return False, "contextual policy item budget is exceeded"
        try:
            measure_json_resources(
                action.parameters,
                context="contextual policy action",
                max_bytes=self.maximum_bytes_per_action,
            )
        except ValidationError as error:
            return (
                False,
                f"contextual policy byte budget is exceeded: {type(error).__name__}",
            )
        matched_prefixes = tuple(
            prefix
            for pattern, prefixes in self.resource_allowlists.items()
            if fnmatch(action.capability, pattern)
            for prefix in prefixes
        )
        if self.resource_allowlists and (
            not matched_prefixes
            or not any(
                action.target.uri.startswith(prefix) for prefix in matched_prefixes
            )
        ):
            return False, "contextual policy rejects the target resource"
        identity_sets = (
            self.authenticated_principals,
            self.agent_identities,
            self.tenant_ids,
            self.provider_account_ids,
        )
        if any(identity_sets):
            context = plan.execution_context
            binding = next(
                (
                    item
                    for item in (context.capsules if context is not None else ())
                    if item.capability_id == action.capability
                ),
                None,
            )
            if binding is None:
                return False, "contextual identity policy requires a capsule binding"
            if binding.data_classification is not action.data_classification:
                return False, "capsule and action data classifications differ"
            observed = (
                binding.authenticated_principal,
                binding.agent_identity,
                binding.tenant_id,
                binding.provider_account_id,
            )
            if any(
                allowed and value not in allowed
                for allowed, value in zip(identity_sets, observed, strict=True)
            ):
                return False, "contextual principal, tenant, or account is not allowed"
        return True, "contextual typed policy constraints satisfied"


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Runtime policy configuration."""

    auto_permit_risks: frozenset[RiskLevel]
    require_approval_risks: frozenset[RiskLevel]
    prohibit_risks: frozenset[RiskLevel]
    prohibited_capabilities: tuple[str, ...]
    write_capability_patterns: tuple[str, ...]

    @classmethod
    def from_toml(cls, path: ConfigSource) -> PolicyConfig:
        """Load policy configuration from TOML.

        Parameters
        ----------
        path
            Policy TOML path.

        Returns
        -------
        PolicyConfig
            Parsed configuration.
        """

        with path.open("rb") as handle:
            raw = tomllib.load(handle)["policy"]
        return cls(
            auto_permit_risks=frozenset(
                RiskLevel(value) for value in raw["auto_permit_risks"]
            ),
            require_approval_risks=frozenset(
                RiskLevel(value) for value in raw["require_approval_risks"]
            ),
            prohibit_risks=frozenset(
                RiskLevel(value) for value in raw["prohibit_risks"]
            ),
            prohibited_capabilities=tuple(raw["prohibited_capabilities"]),
            write_capability_patterns=tuple(raw["write_capability_patterns"]),
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Policy result for one action."""

    permitted: bool
    approval_required: bool
    reason: str


class PolicyEngine:
    """Evaluate whether actions may reach connectors."""

    def __init__(
        self,
        config: PolicyConfig,
        *,
        approval_authenticator: ApprovalAuthenticator | None = None,
        contextual_constraints: ContextualPolicyConstraints | None = None,
    ) -> None:
        self._config = config
        self._approval_authenticator = approval_authenticator
        self._contextual_constraints = contextual_constraints

    def evaluate(
        self,
        plan: ChangePlan,
        action: AgentAction,
        approvals: Iterable[Approval] = (),
        now: datetime | None = None,
        minimum_distinct_approvers: int = 0,
    ) -> PolicyDecision:
        """Evaluate one action against risk, authority, and approvals.

        Parameters
        ----------
        plan
            Immutable plan containing the action.
        action
            Action to evaluate.
        approvals
            Candidate approvals.
        now
            Evaluation time. Defaults to current UTC time.

        Returns
        -------
        PolicyDecision
            Permit, approval, and explanation.
        """

        current_time = now or datetime.now(UTC)
        if minimum_distinct_approvers < 0:
            raise ValueError("minimum_distinct_approvers must not be negative")

        context = plan.execution_context
        capsule_binding = next(
            (
                item
                for item in (context.capsules if context is not None else ())
                if item.capability_id == action.capability
            ),
            None,
        )
        if capsule_binding is not None and (
            capsule_binding.risk is not action.risk
            or capsule_binding.data_classification is not action.data_classification
        ):
            return PolicyDecision(
                permitted=False,
                approval_required=False,
                reason="capsule risk or data classification differs from the action",
            )

        if self._contextual_constraints is not None:
            allowed, reason = self._contextual_constraints.validate(
                plan,
                action,
                now=current_time.astimezone(UTC),
            )
            if not allowed:
                return PolicyDecision(
                    permitted=False,
                    approval_required=False,
                    reason=reason,
                )

        if any(
            fnmatch(action.capability, pattern)
            for pattern in self._config.prohibited_capabilities
        ):
            return PolicyDecision(
                permitted=False,
                approval_required=False,
                reason=f"capability is prohibited: {action.capability}",
            )

        if action.risk in self._config.prohibit_risks:
            return PolicyDecision(
                permitted=False,
                approval_required=False,
                reason=f"risk tier is prohibited: {action.risk}",
            )

        if self._is_write(action) and action.authority_source in {
            AuthoritySource.RETRIEVED_INTERNAL_CONTENT,
            AuthoritySource.RETRIEVED_EXTERNAL_CONTENT,
        }:
            return PolicyDecision(
                permitted=False,
                approval_required=False,
                reason=(
                    "retrieved content is data and cannot authorize a write "
                    "or external action"
                ),
            )

        approval_required = (
            action.requires_approval
            or action.risk in self._config.require_approval_risks
            or minimum_distinct_approvers > 0
        )
        if approval_required:
            covered_by: dict[str, Approval] = {}
            if self._approval_authenticator is not None:
                for approval in approvals:
                    subject = self._approval_authenticator.authenticated_subject(
                        approval
                    )
                    if subject is None or not approval.covers(
                        plan=plan,
                        action=action,
                        now=current_time,
                    ):
                        continue
                    covered_by[subject.casefold()] = approval
            required = max(1, minimum_distinct_approvers)
            if len(covered_by) < required:
                return PolicyDecision(
                    permitted=False,
                    approval_required=True,
                    reason=(
                        f"{required} distinct approval(s) bound to this exact "
                        "plan and action are required"
                    ),
                )
            return PolicyDecision(
                permitted=True,
                approval_required=True,
                reason=(f"{len(covered_by)} valid immutable-plan approval(s) supplied"),
            )

        if action.risk in self._config.auto_permit_risks:
            return PolicyDecision(
                permitted=True,
                approval_required=False,
                reason=f"risk tier is auto-permitted: {action.risk}",
            )

        return PolicyDecision(
            permitted=False,
            approval_required=True,
            reason="risk tier has no explicit permit rule",
        )

    def authenticated_approvals(
        self,
        plan: ChangePlan,
        approvals: Iterable[Approval],
        *,
        now: datetime | None = None,
    ) -> tuple[tuple[Approval, str], ...]:
        """Return only authenticated, current approvals covering this exact plan."""

        if self._approval_authenticator is None:
            return ()
        current_time = (now or datetime.now(UTC)).astimezone(UTC)
        selected: dict[UUID, tuple[Approval, str]] = {}
        for approval in approvals:
            subject = self._approval_authenticator.authenticated_subject(approval)
            if subject is None or not any(
                approval.covers(plan=plan, action=action, now=current_time)
                for action in plan.actions
            ):
                continue
            selected[approval.approval_id] = (approval, subject)
        return tuple(selected[key] for key in sorted(selected, key=str))

    def _is_write(self, action: AgentAction) -> bool:
        return any(
            fnmatch(action.capability, pattern)
            for pattern in self._config.write_capability_patterns
        ) or action.risk not in {
            RiskLevel.READ_ONLY,
            RiskLevel.LOCAL_GENERATION,
        }


def _collection_items(value: Any) -> int:
    count = 0
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, Mapping):
            count += len(current)
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            count += len(current)
            pending.extend(current)
    return count
