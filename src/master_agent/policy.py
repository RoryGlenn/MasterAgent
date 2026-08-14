"""Risk, approval, and authority policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatch
import tomllib
from typing import Iterable

from master_agent.config_sources import ConfigSource
from master_agent.models import (
    AgentAction,
    Approval,
    AuthoritySource,
    ChangePlan,
    RiskLevel,
)


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

    def __init__(self, config: PolicyConfig) -> None:
        self._config = config

    def evaluate(
        self,
        plan: ChangePlan,
        action: AgentAction,
        approvals: Iterable[Approval] = (),
        now: datetime | None = None,
        minimum_distinct_approvers: int = 1,
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
        )
        if approval_required:
            covered_by = {
                approval.approved_by.casefold(): approval
                for approval in approvals
                if approval.covers(plan=plan, action=action, now=current_time)
            }
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
                reason=(
                    f"{len(covered_by)} valid immutable-plan approval(s) supplied"
                ),
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

    def _is_write(self, action: AgentAction) -> bool:
        return any(
            fnmatch(action.capability, pattern)
            for pattern in self._config.write_capability_patterns
        ) or action.risk not in {
            RiskLevel.READ_ONLY,
            RiskLevel.LOCAL_GENERATION,
        }
