"""Connector protocol for deterministic external operations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from master_agent.models import (
    AgentAction,
    ExecutionResult,
    ResourceRef,
    VerificationResult,
)


class Connector(Protocol):
    """Protocol implemented by every registered system connector."""

    @property
    def system(self) -> str:
        """Return the connector system identifier."""

    @property
    def capabilities(self) -> frozenset[str]:
        """Return the exact capability names implemented by the connector."""

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Execute one validated action."""

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Read current resource state for verification."""

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify actual state after execution."""


@runtime_checkable
class CompensatingConnector(Protocol):
    """Optional connector contract for verified rollback operations."""

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Reverse a previously verified reversible action."""

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        """Verify the rollback result independently."""
