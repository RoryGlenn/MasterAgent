"""Release metadata and safe-default validation tests."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_release import (
    _validate_demo_readiness,
    _validate_file_hygiene,
    validate_project,
)


class ReleaseMetadataTests(unittest.TestCase):
    """Keep the v1 source tree packageable and fail-closed."""

    def test_repository_passes_release_validation(self) -> None:
        """The checked-in source tree should pass offline release checks."""

        root = Path(__file__).resolve().parents[1]
        report = validate_project(root)
        self.assertEqual(report.errors, ())
        self.assertTrue(report.valid)

    def test_runtime_directory_is_rejected_even_when_contents_are_ignored(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / ".master-agent" / "tokens"
            runtime.mkdir(parents=True)
            (runtime / "microsoft.json").write_text(
                '{"access_token":"TOP-SECRET"}\n',
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_file_hygiene(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("runtime directory" in error for error in errors))

    def test_demo_readiness_count_must_match_capability_catalog(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            demo = root / "examples/v1-demo"
            config = root / "config"
            demo.mkdir(parents=True)
            config.mkdir()
            (demo / "readiness.json").write_text(
                '{"checks":[{"name":"governance_coverage",'
                '"covered_capabilities":71}]}\n',
                encoding="utf-8",
            )
            (config / "capabilities.toml").write_text(
                '[capabilities."one"]\nenabled=true\n',
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_demo_readiness(root, demo, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("does not match" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
