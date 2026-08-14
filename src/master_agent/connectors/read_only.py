"""Shared enforcement for read-only live connectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping

from master_agent.citations import enrich_resource_citations
from master_agent.errors import ConnectorError
from master_agent.evidence import content_digest
from master_agent.models import (
    ActionState,
    AgentAction,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)
from master_agent.security import scan_untrusted_value


@dataclass(frozen=True, slots=True)
class RetrievedPayload:
    """Normalized result returned by a connector-specific fetch."""

    data: Mapping[str, Any]
    connector_reference: str
    citations: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)


class ReadOnlyConnector(ABC):
    """Base class that prohibits writes and verifies reads by re-fetching."""

    def __init__(self, *, system: str, capabilities: frozenset[str]) -> None:
        self._system = system
        self._capabilities = capabilities
        self._last_results: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        """Return the connector system identifier."""

        return self._system

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported read-only capabilities."""

        return self._capabilities

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Execute one whitelisted read-only action."""

        self._validate_action(action)
        after, reference = self._retrieve(action)
        self._last_results[action.target.resource_id] = deepcopy(after)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=after,
            after=after,
            connector_reference=reference,
            message="live read completed",
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return the most recently retrieved state for a resource."""

        value = self._last_results.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Re-fetch a resource and compare its normalized evidence digest."""

        self._validate_action(action)
        observed, _ = self._retrieve(action)
        expected_digest = _result_digest(result.after)
        observed_digest = _result_digest(observed)
        verified = expected_digest == observed_digest
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified by independent live re-read"
                if verified
                else "resource changed between retrieval and verification"
            ),
        )

    def _validate_action(self, action: AgentAction) -> None:
        if action.target.system != self.system:
            raise ConnectorError(
                f"connector {self.system} cannot execute target system "
                f"{action.target.system}"
            )
        if action.risk is not RiskLevel.READ_ONLY:
            raise ConnectorError(
                f"live connector {self.system} only permits read-only actions"
            )
        if action.capability not in self.capabilities:
            raise ConnectorError(
                f"connector {self.system} does not support capability "
                f"{action.capability}"
            )

    def _retrieve(self, action: AgentAction) -> tuple[dict[str, Any], str]:
        fetched = self._fetch(action)
        normalized = deepcopy(dict(fetched.data))
        if fetched.citations:
            normalized["citations"] = [
                deepcopy(dict(citation)) for citation in fetched.citations
            ]
        citations = enrich_resource_citations(
            normalized,
            action=action,
            connector_reference=fetched.connector_reference,
        )
        digest = content_digest(normalized)
        findings = scan_untrusted_value(normalized)
        retrieved_at = datetime.now(UTC).isoformat()
        normalized["evidence"] = {
            "content_digest": digest,
            "retrieved_at": retrieved_at,
            "connector_reference": fetched.connector_reference,
        }
        normalized["citations"] = [
            {**dict(citation), "retrieved_at": retrieved_at}
            for citation in citations
        ]
        normalized["security"] = {
            "content_is_untrusted": True,
            "prompt_injection_findings": [
                {
                    "path": finding.path,
                    "category": finding.category,
                    "severity": finding.severity,
                    "excerpt": finding.excerpt,
                }
                for finding in findings
            ],
        }
        return normalized, fetched.connector_reference

    @abstractmethod
    def _fetch(self, action: AgentAction) -> RetrievedPayload:
        """Fetch and normalize one capability-specific payload."""


def _result_digest(value: Mapping[str, Any] | None) -> str | None:
    if value is None:
        return None
    evidence = value.get("evidence")
    if isinstance(evidence, Mapping):
        digest = evidence.get("content_digest")
        if isinstance(digest, str):
            return digest
    stripped = {
        key: item
        for key, item in value.items()
        if key not in {"evidence", "security"}
    }
    return content_digest(stripped)
