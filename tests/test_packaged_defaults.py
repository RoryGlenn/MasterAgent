"""Packaged configuration integrity tests."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
import unittest


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


if __name__ == "__main__":
    unittest.main()
