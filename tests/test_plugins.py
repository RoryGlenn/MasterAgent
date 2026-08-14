"""Explicit connector-plugin discovery and loading tests."""

from __future__ import annotations

from dataclasses import dataclass
import unittest

from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConfigurationError
from master_agent.plugins import (
    CONNECTOR_ENTRY_POINT_GROUP,
    discover_connector_plugins,
    load_connector_plugins,
)
from master_agent.registry import ConnectorRegistry


@dataclass
class _FakeEntryPoint:
    name: str
    value: str
    factory: object
    group: str = CONNECTOR_ENTRY_POINT_GROUP
    dist: object | None = None
    load_count: int = 0

    def load(self) -> object:
        self.load_count += 1
        return self.factory


class PluginTests(unittest.TestCase):
    """Verify that installation never implies execution authority."""

    def test_discovery_does_not_import_plugin(self) -> None:
        entry = _FakeEntryPoint(
            name="servicenow",
            value="example:factory",
            factory=lambda: MockConnector(
                "servicenow",
                capabilities={"servicenow.ticket.read"},
            ),
        )
        result = discover_connector_plugins(entries=(entry,))
        self.assertEqual(result[0].name, "servicenow")
        self.assertEqual(entry.load_count, 0)

    def test_only_explicitly_enabled_plugin_is_loaded(self) -> None:
        selected = _FakeEntryPoint(
            name="servicenow",
            value="example:factory",
            factory=lambda: MockConnector(
                "servicenow",
                capabilities={"servicenow.ticket.read"},
            ),
        )
        ignored = _FakeEntryPoint(
            name="salesforce",
            value="example:other",
            factory=lambda: MockConnector(
                "salesforce",
                capabilities={"salesforce.case.read"},
            ),
        )
        registry = ConnectorRegistry()
        loaded = load_connector_plugins(
            registry,
            enabled_names=("servicenow",),
            entries=(selected, ignored),
        )
        self.assertEqual(selected.load_count, 1)
        self.assertEqual(ignored.load_count, 0)
        self.assertEqual(loaded[0].systems, ("servicenow",))
        self.assertIn("servicenow", registry.systems())

    def test_unknown_or_invalid_plugin_fails_closed(self) -> None:
        entry = _FakeEntryPoint(
            name="invalid",
            value="example:invalid",
            factory=lambda: object(),
        )
        with self.assertRaises(ConfigurationError):
            load_connector_plugins(
                ConnectorRegistry(),
                enabled_names=("missing",),
                entries=(entry,),
            )
        with self.assertRaises(ConfigurationError):
            load_connector_plugins(
                ConnectorRegistry(),
                enabled_names=("invalid",),
                entries=(entry,),
            )


if __name__ == "__main__":
    unittest.main()
