"""In-memory connector used for safe local development and tests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping
from uuid import uuid4

from master_agent.errors import ConnectorError, VersionConflictError
from master_agent.models import (
    ActionState,
    AgentAction,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)


class MockConnector:
    """Deterministic in-memory implementation of a connector.

    Parameters
    ----------
    system
        Connector system identifier.
    initial_resources
        Initial resource state keyed by resource ID. Each state may include a
        string ``version`` field.
    """

    def __init__(
        self,
        system: str,
        initial_resources: Mapping[str, Mapping[str, Any]] | None = None,
        *,
        capabilities: frozenset[str] | set[str] | tuple[str, ...] | None = None,
    ) -> None:
        self._system = system
        self._capabilities = frozenset(capabilities or ())
        self._resources: dict[str, dict[str, Any]] = {
            key: deepcopy(dict(value))
            for key, value in (initial_resources or {}).items()
        }
        self._generated: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return the connector system identifier."""

        return self._system

    @property
    def capabilities(self) -> frozenset[str]:
        """Return explicitly routed capabilities, if configured."""

        return self._capabilities

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Execute a read, local generation, or simple mock write."""

        if action.target.system != self.system:
            raise ConnectorError(
                f"connector {self.system} cannot execute target system "
                f"{action.target.system}"
            )
        if self.capabilities and action.capability not in self.capabilities:
            raise ConnectorError(
                f"mock connector {self.system} does not support capability "
                f"{action.capability}"
            )

        if action.risk is RiskLevel.READ_ONLY:
            observed = self.read(action.target)
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before=observed,
                after=observed,
                connector_reference=action.target.uri,
                message="mock read completed",
            )

        if action.risk is RiskLevel.LOCAL_GENERATION:
            artifact_id = f"generated-{uuid4()}"
            generated = {
                "artifact_id": artifact_id,
                "capability": action.capability,
                "target": action.target.uri,
                "content": deepcopy(dict(action.parameters)),
                "version": "1",
            }
            self._generated[action.target.resource_id] = generated
            return ExecutionResult(
                action_id=action.action_id,
                state=ActionState.SUCCEEDED,
                before=None,
                after=deepcopy(generated),
                connector_reference=artifact_id,
                message="mock local artifact generated",
            )

        before = self.read(action.target)
        self._enforce_version(action, before)
        operation = action.capability.rsplit(".", maxsplit=1)[-1]

        if operation in {
            "create",
            "send",
            "publish",
            "upload",
            "push",
            "reply",
            "apply",
            "restore",
            "compensate",
        }:
            if before is not None and operation == "create":
                raise ConnectorError(f"resource already exists: {action.target.uri}")
            after = {
                **deepcopy(dict(action.parameters)),
                "version": "1" if before is None else self._next_version(before),
            }
            self._resources[action.target.resource_id] = after
        elif operation in {"update", "transition", "comment"}:
            if before is None:
                raise ConnectorError(f"resource not found: {action.target.uri}")
            after = {
                **before,
                **deepcopy(dict(action.parameters)),
                "version": self._next_version(before),
            }
            self._resources[action.target.resource_id] = after
        else:
            raise ConnectorError(
                f"mock connector does not implement capability: {action.capability}"
            )

        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=before,
            after=deepcopy(after),
            connector_reference=action.target.uri,
            message="mock write completed",
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Read a resource or generated artifact."""

        if resource.resource_id in self._generated:
            return deepcopy(self._generated[resource.resource_id])
        state = self._resources.get(resource.resource_id)
        return deepcopy(state) if state is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Re-read state and compare it with the execution result."""

        observed = self.read(action.target)
        verified = observed == result.after
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message="verified by mock re-read" if verified else "state mismatch",
        )

    def _enforce_version(
        self,
        action: AgentAction,
        current: Mapping[str, Any] | None,
    ) -> None:
        expected = action.target.expected_version
        if expected is None:
            return
        observed = str(current.get("version")) if current is not None else None
        if observed != expected:
            raise VersionConflictError(
                f"version conflict for {action.target.uri}: expected {expected}, "
                f"observed {observed}"
            )

    @staticmethod
    def _next_version(current: Mapping[str, Any]) -> str:
        try:
            return str(int(str(current.get("version", "0"))) + 1)
        except ValueError as error:
            raise ConnectorError("mock resource version must be numeric") from error
