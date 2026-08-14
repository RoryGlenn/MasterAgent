"""Capability-aware connector registry tests."""

from __future__ import annotations

import unittest

from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConnectorError
from master_agent.registry import ConnectorRegistry


class ConnectorRegistryTests(unittest.TestCase):
    """Verify narrowly scoped connectors can share one external system."""

    def test_disjoint_read_and_draft_connectors_can_share_system(self) -> None:
        registry = ConnectorRegistry()
        live = MockConnector("outlook", capabilities={"outlook.message.read"})
        local = MockConnector("outlook", capabilities={"outlook.email.draft"})

        registry.register(live)
        registry.register(local)

        self.assertIs(registry.resolve("outlook", "outlook.message.read"), live)
        self.assertIs(registry.resolve("outlook", "outlook.email.draft"), local)
        self.assertEqual(registry.systems(), ("outlook",))

    def test_overlapping_capabilities_are_rejected(self) -> None:
        registry = ConnectorRegistry()
        registry.register(MockConnector("teams", capabilities={"teams.chat.list"}))

        with self.assertRaisesRegex(ConnectorError, "already registered"):
            registry.register(MockConnector("teams", capabilities={"teams.chat.list"}))

    def test_wildcard_connector_is_fallback_for_unknown_capability(self) -> None:
        registry = ConnectorRegistry()
        wildcard = MockConnector("jira")
        specific = MockConnector("jira", capabilities={"jira.issue.search"})
        registry.register(wildcard)
        registry.register(specific)

        self.assertIs(registry.resolve("jira", "jira.issue.search"), specific)
        self.assertIs(registry.resolve("jira", "jira.issue.comment"), wildcard)


if __name__ == "__main__":
    unittest.main()
