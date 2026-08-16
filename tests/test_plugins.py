"""Explicit connector-plugin discovery and loading tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from unittest.mock import patch

from master_agent import plugins
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
    files: tuple[object, ...]
    locate_calls: list[str] = field(default_factory=list)

    def locate_file(self, relative: object) -> Path:
        self.locate_calls.append(str(relative))
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

    def test_unsafe_inventory_paths_fail_before_any_lookup_or_read(self) -> None:
        unsafe_paths = (
            "",
            ".",
            "..",
            "/etc/passwd",
            "../secret.txt",
            "safe/../secret.txt",
            "safe\\secret.txt",
            "safe//secret.txt",
            "./secret.txt",
            "safe/./secret.txt",
            "C:/secret.txt",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for unsafe in unsafe_paths:
                with self.subTest(path=unsafe):
                    distribution = _FakeDistribution(
                        name="master-agent-unsafe-test",
                        version="1.0.0",
                        root=root,
                        files=(unsafe,),
                    )
                    entry = _FakeEntryPoint(
                        name="unsafe",
                        value="unsafe:build",
                        factory=lambda: object(),
                        dist=distribution,
                    )

                    with (
                        patch("master_agent.plugins.os.read", wraps=os.read) as read,
                        self.assertRaisesRegex(
                            ConfigurationError, "unsafe artifact path"
                        ),
                    ):
                        discover_connector_plugins(entries=(entry,))

                    self.assertEqual(distribution.locate_calls, [])
                    read.assert_not_called()

    def test_late_invalid_inventory_entry_prevents_all_artifact_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.py").write_text("SAFE = True\n", encoding="utf-8")
            distribution = _FakeDistribution(
                name="master-agent-invalid-tail-test",
                version="1.0.0",
                root=root,
                files=("safe.py", "../outside.txt"),
            )
            entry = _FakeEntryPoint(
                name="invalid-tail",
                value="safe:build",
                factory=lambda: object(),
                dist=distribution,
            )

            with (
                patch("master_agent.plugins.os.read", wraps=os.read) as read,
                self.assertRaisesRegex(ConfigurationError, "unsafe artifact path"),
            ):
                discover_connector_plugins(entries=(entry,))

            self.assertEqual(distribution.locate_calls, [])
            read.assert_not_called()

    def test_parent_symlink_and_hardlink_escape_are_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution_root = root / "distribution"
            outside = root / "outside"
            distribution_root.mkdir()
            outside.mkdir()
            secret = outside / "secret.txt"
            secret.write_text("outside-canary\n", encoding="utf-8")

            cases: tuple[tuple[str, tuple[object, ...]], ...] = (
                ("parent-symlink", ("escaped/secret.txt",)),
                ("hardlink", ("hardlink.txt",)),
            )
            (distribution_root / "escaped").symlink_to(
                outside, target_is_directory=True
            )
            os.link(secret, distribution_root / "hardlink.txt")

            for label, files in cases:
                with self.subTest(label=label):
                    distribution = _FakeDistribution(
                        name=f"master-agent-{label}-test",
                        version="1.0.0",
                        root=distribution_root,
                        files=files,
                    )
                    entry = _FakeEntryPoint(
                        name=label,
                        value="unsafe:build",
                        factory=lambda: object(),
                        dist=distribution,
                    )

                    with (
                        patch("master_agent.plugins.os.read", wraps=os.read) as read,
                        self.assertRaises(ConfigurationError),
                    ):
                        discover_connector_plugins(entries=(entry,))

                    read.assert_not_called()
                    self.assertEqual(
                        secret.read_text(encoding="utf-8"), "outside-canary\n"
                    )

    def test_world_writable_distribution_root_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "plugin.py"
            artifact.write_text("SAFE = True\n", encoding="utf-8")
            root.chmod(0o777)
            distribution = _FakeDistribution(
                name="master-agent-world-writable-test",
                version="1.0.0",
                root=root,
                files=("plugin.py",),
            )
            entry = _FakeEntryPoint(
                name="world-writable",
                value="plugin:build",
                factory=lambda: object(),
                dist=distribution,
            )

            with (
                patch("master_agent.plugins.os.read", wraps=os.read) as read,
                self.assertRaisesRegex(ConfigurationError, "owner-controlled"),
            ):
                discover_connector_plugins(entries=(entry,))

            read.assert_not_called()

    def test_distribution_file_count_and_byte_budgets_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.bin"
            second = root / "second.bin"
            first.write_bytes(b"abc")
            second.write_bytes(b"def")

            count_distribution = _FakeDistribution(
                name="master-agent-count-test",
                version="1.0.0",
                root=root,
                files=("first.bin", "second.bin"),
            )
            count_entry = _FakeEntryPoint(
                name="count",
                value="count:build",
                factory=lambda: object(),
                dist=count_distribution,
            )
            with (
                patch.object(plugins, "_MAX_DISTRIBUTION_FILES", 1),
                self.assertRaisesRegex(ConfigurationError, "file limit"),
            ):
                discover_connector_plugins(entries=(count_entry,))
            self.assertEqual(count_distribution.locate_calls, [])

            size_distribution = _FakeDistribution(
                name="master-agent-size-test",
                version="1.0.0",
                root=root,
                files=("first.bin",),
            )
            size_entry = _FakeEntryPoint(
                name="size",
                value="size:build",
                factory=lambda: object(),
                dist=size_distribution,
            )
            with (
                patch.object(plugins, "_MAX_ARTIFACT_BYTES", 2),
                self.assertRaisesRegex(ConfigurationError, "32 MiB limit"),
            ):
                discover_connector_plugins(entries=(size_entry,))

            aggregate_distribution = _FakeDistribution(
                name="master-agent-aggregate-test",
                version="1.0.0",
                root=root,
                files=("first.bin", "second.bin"),
            )
            aggregate_entry = _FakeEntryPoint(
                name="aggregate",
                value="aggregate:build",
                factory=lambda: object(),
                dist=aggregate_distribution,
            )
            with (
                patch.object(plugins, "_MAX_DISTRIBUTION_BYTES", 5),
                self.assertRaisesRegex(ConfigurationError, "128 MiB limit"),
            ):
                discover_connector_plugins(entries=(aggregate_entry,))

    def test_artifact_namespace_replacement_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "plugin.py"
            displaced = root / "plugin-old.py"
            artifact.write_bytes(b"SAFE")
            distribution = _FakeDistribution(
                name="master-agent-race-test",
                version="1.0.0",
                root=root,
                files=("plugin.py",),
            )
            entry = _FakeEntryPoint(
                name="race",
                value="plugin:build",
                factory=lambda: object(),
                dist=distribution,
            )
            real_read = os.read
            replaced = False

            def replace_after_read(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                value = real_read(descriptor, size)
                if value and not replaced:
                    artifact.rename(displaced)
                    artifact.write_bytes(b"EVIL")
                    replaced = True
                return value

            with (
                patch("master_agent.plugins.os.read", side_effect=replace_after_read),
                self.assertRaisesRegex(ConfigurationError, "changed"),
            ):
                discover_connector_plugins(entries=(entry,))

            self.assertTrue(replaced)

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
