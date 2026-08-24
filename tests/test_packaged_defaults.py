"""Packaged configuration integrity tests."""

from __future__ import annotations

import tomllib
import unittest
from importlib.resources import files
from pathlib import Path

from master_agent.config import ConnectorImplementation, IntegrationConfig

ROOT = Path(__file__).resolve().parents[1]
_DEFAULTS = (
    "integrations.toml",
    "policy.toml",
    "sources_of_truth.toml",
    "weekly-status.toml",
    "communication-context.toml",
    "identities.toml",
    "retention.toml",
    "capabilities.toml",
    "governance.toml",
    "oauth.toml",
    "draft-package.toml",
    "recurring.toml",
    "organization-profile.toml",
)


class PackagedDefaultTests(unittest.TestCase):
    """Prevent standalone wheel defaults from drifting from the scaffold."""

    def test_packaged_defaults_match_repository_configuration(self) -> None:
        package = files("master_agent.defaults")
        for filename in _DEFAULTS:
            with self.subTest(filename=filename):
                expected = (ROOT / "config" / filename).read_bytes()
                actual = package.joinpath(filename).read_bytes()
                self.assertEqual(actual, expected)

    def test_packaged_connectors_explicitly_select_native(self) -> None:
        source = ROOT / "config" / "integrations.toml"
        raw = tomllib.loads(source.read_text(encoding="utf-8"))
        integrations = IntegrationConfig.from_toml(source)

        self.assertGreater(len(integrations.connectors), 0)
        self.assertTrue(
            all(
                connector.get("implementation") == "native"
                for connector in raw["connectors"].values()
            )
        )
        self.assertTrue(
            all(
                connector.implementation is ConnectorImplementation.NATIVE
                for connector in integrations.connectors.values()
            )
        )


if __name__ == "__main__":
    unittest.main()
