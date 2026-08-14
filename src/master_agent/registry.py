"""Connector registration and capability-aware resolution."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from master_agent.connectors.base import Connector
from master_agent.errors import ConnectorError


class ConnectorRegistry:
    """Resolve registered connectors by system and capability.

    Several narrowly scoped connectors may share one system identifier, for
    example a live read-only Outlook connector and a local Outlook draft
    generator. Resolution is capability-specific and rejects ambiguity.
    """

    def __init__(self) -> None:
        self._connectors: dict[str, list[Connector]] = defaultdict(list)

    def register(self, connector: Connector) -> None:
        """Register one connector and reject ambiguous capability overlap."""

        existing = self._connectors[connector.system]
        incoming = _capabilities(connector)
        for candidate in existing:
            overlap = incoming & _capabilities(candidate)
            if overlap:
                rendered = ", ".join(sorted(overlap))
                raise ConnectorError(
                    f"connector capability already registered for system "
                    f"{connector.system}: {rendered}"
                )
            if not incoming and not _capabilities(candidate):
                raise ConnectorError(
                    f"connector already registered for system: {connector.system}"
                )
        existing.append(connector)

    def resolve(self, system: str, capability: str | None = None) -> Connector:
        """Return the connector for a system and optional capability."""

        candidates = tuple(self._connectors.get(system, ()))
        if not candidates:
            raise ConnectorError(f"no connector registered for system: {system}")
        if capability is None:
            if len(candidates) == 1:
                return candidates[0]
            raise ConnectorError(
                f"multiple connectors registered for system {system}; "
                "capability is required"
            )

        matches = tuple(
            connector
            for connector in candidates
            if capability in _capabilities(connector)
        )
        if len(matches) == 1:
            return matches[0]
        if not matches:
            wildcards = tuple(
                connector for connector in candidates if not _capabilities(connector)
            )
            if len(wildcards) == 1:
                return wildcards[0]
            raise ConnectorError(
                f"no connector registered for capability {capability} "
                f"on system {system}"
            )
        raise ConnectorError(
            f"multiple connectors registered for capability {capability} "
            f"on system {system}"
        )

    def systems(self) -> tuple[str, ...]:
        """Return registered system identifiers in sorted order."""

        return tuple(sorted(self._connectors))

    def connectors(self, system: str | None = None) -> tuple[Connector, ...]:
        """Return registered connectors for inspection and discovery."""

        if system is not None:
            return tuple(self._connectors.get(system, ()))
        return tuple(
            connector
            for name in sorted(self._connectors)
            for connector in self._connectors[name]
        )


def _capabilities(connector: Connector) -> frozenset[str]:
    value: Iterable[object] = getattr(connector, "capabilities", ())
    return frozenset(str(item) for item in value)
