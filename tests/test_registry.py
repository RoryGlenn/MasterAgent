"""Capability-aware connector registry tests."""

from __future__ import annotations

import unittest

from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConnectorError
from master_agent.registry import ConnectorRegistry


class ConnectorRegistryTests(unittest.TestCase):
    """Verify one system can expose non-overlapping live and local tools."""

    def test_disjoint_capabilities_route_to_distinct_connectors(self) -> None:
        registry = ConnectorRegistry()
        reader = MockConnector("outlook", capabilities={"outlook.message.read"})
        drafter = MockConnector("outlook", capabilities={"outlook.email.draft"})
        registry.register(reader)
        registry.register(drafter)

        self.assertIs(registry.resolve("outlook", "outlook.message.read"), reader)
        self.assertIs(registry.resolve("outlook", "outlook.email.draft"), drafter)

    def test_overlapping_capability_is_rejected(self) -> None:
        registry = ConnectorRegistry()
        registry.register(
            MockConnector("teams", capabilities={"teams.chat.message.read"})
        )

        with self.assertRaisesRegex(ConnectorError, "already registered"):
            registry.register(
                MockConnector("teams", capabilities={"teams.chat.message.read"})
            )

    def test_capability_is_required_when_system_has_multiple_connectors(self) -> None:
        registry = ConnectorRegistry()
        registry.register(MockConnector("teams", capabilities={"teams.chat.list"}))
        registry.register(MockConnector("teams", capabilities={"teams.message.draft"}))

        with self.assertRaisesRegex(ConnectorError, "capability is required"):
            registry.resolve("teams")


if __name__ == "__main__":
    unittest.main()
