"""Explicit connector-plugin discovery and loading tests."""

from __future__ import annotations

import importlib.metadata as metadata
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConfigurationError
from master_agent.plugins import (
    CONNECTOR_ENTRY_POINT_GROUP,
    PluginLock,
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


@dataclass
class _FakeDistribution:
    name: str
    version: str
    root: Path
    files: tuple[Path, ...]

    def locate_file(self, relative: Path) -> Path:
        return self.root / relative


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

    def test_duplicate_names_are_rejected_before_either_plugin_is_imported(
        self,
    ) -> None:
        first = _FakeEntryPoint("duplicate", "safe:factory", lambda: object())
        second = _FakeEntryPoint("duplicate", "attacker:factory", lambda: object())

        with self.assertRaisesRegex(ConfigurationError, "unique"):
            load_connector_plugins(
                ConnectorRegistry(),
                enabled_names=("duplicate",),
                entries=(first, second),
            )

        self.assertEqual(first.load_count, 0)
        self.assertEqual(second.load_count, 0)

    def test_descriptor_binds_distribution_version_entry_point_and_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "plugin.py"
            artifact.write_text("VALUE = 1\n", encoding="utf-8")
            distribution = _FakeDistribution(
                name="master-agent-example",
                version="1.2.3",
                root=root,
                files=(Path("plugin.py"),),
            )
            entry = _FakeEntryPoint(
                name="example",
                value="plugin:factory",
                factory=lambda: object(),
                dist=distribution,
            )

            before = discover_connector_plugins(entries=(entry,))[0]
            artifact.write_text("VALUE = 2\n", encoding="utf-8")
            after = discover_connector_plugins(entries=(entry,))[0]

        self.assertEqual(before.distribution_version, "1.2.3")
        self.assertNotEqual(before.artifact_sha256, after.artifact_sha256)
        self.assertNotEqual(before.identity_sha256, after.identity_sha256)
        self.assertEqual(entry.load_count, 0)

    def test_locked_plugin_import_ignores_cwd_shadow_module(self) -> None:
        module_name = "master_agent_verified_shadow_plugin"
        sys.modules.pop(module_name, None)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution_root = root / "safe-site"
            attacker_root = root / "target-repository"
            distribution_root.mkdir()
            attacker_root.mkdir()
            safe_module = distribution_root / f"{module_name}.py"
            safe_module.write_text(
                "from master_agent.connectors.mock import MockConnector\n"
                "def build():\n"
                "    return MockConnector('safe', "
                "capabilities={'safe.ticket.read'})\n",
                encoding="utf-8",
            )
            (attacker_root / f"{module_name}.py").write_text(
                "from master_agent.connectors.mock import MockConnector\n"
                "def build():\n"
                "    return MockConnector('attacker', "
                "capabilities={'attacker.ticket.read'})\n",
                encoding="utf-8",
            )
            distribution = _FakeDistribution(
                name="master-agent-shadow-test",
                version="1.0.0",
                root=distribution_root,
                files=(Path(f"{module_name}.py"),),
            )
            entry = metadata.EntryPoint(
                name="shadow-test",
                value=f"{module_name}:build",
                group=CONNECTOR_ENTRY_POINT_GROUP,
            )._for(distribution)  # type: ignore[attr-defined]
            descriptor = discover_connector_plugins(entries=(entry,))[0]
            trusted_lock = PluginLock(plugins=(descriptor,))
            registry = ConnectorRegistry()
            previous_cwd = Path.cwd()
            previous_path = list(sys.path)
            try:
                os.chdir(attacker_root)
                sys.path.insert(0, str(attacker_root))
                loaded = load_connector_plugins(
                    registry,
                    enabled_names=("shadow-test",),
                    trusted_lock=trusted_lock,
                    entries=(entry,),
                )
            finally:
                os.chdir(previous_cwd)
                sys.path[:] = previous_path

            module_file = sys.modules[module_name].__file__
            self.assertIsNotNone(module_file)
            assert module_file is not None
            loaded_module_path = Path(module_file).resolve()
            self.assertEqual(loaded[0].systems, ("safe",))
            self.assertIn("safe", registry.systems())
            self.assertNotIn("attacker", registry.systems())
            self.assertFalse(loaded_module_path.is_relative_to(attacker_root))
        sys.modules.pop(module_name, None)

    def test_artifact_changed_after_lock_is_rejected_before_import(self) -> None:
        module_name = "master_agent_changed_locked_plugin"
        sys.modules.pop(module_name, None)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / f"{module_name}.py"
            module.write_text(
                "def build():\n    raise AssertionError('loaded')\n", encoding="utf-8"
            )
            distribution = _FakeDistribution(
                name="master-agent-changed-test",
                version="1.0.0",
                root=root,
                files=(Path(f"{module_name}.py"),),
            )
            entry = metadata.EntryPoint(
                name="changed-test",
                value=f"{module_name}:build",
                group=CONNECTOR_ENTRY_POINT_GROUP,
            )._for(distribution)  # type: ignore[attr-defined]
            trusted_lock = PluginLock(
                plugins=(discover_connector_plugins(entries=(entry,))[0],)
            )
            module.write_text(
                "raise AssertionError('module was imported')\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConfigurationError, "trusted lock"):
                load_connector_plugins(
                    ConnectorRegistry(),
                    enabled_names=("changed-test",),
                    trusted_lock=trusted_lock,
                    entries=(entry,),
                )

        self.assertNotIn(module_name, sys.modules)


if __name__ == "__main__":
    unittest.main()
