"""Release metadata and safe-default validation tests."""

from __future__ import annotations

from pathlib import Path
import unittest

from scripts.validate_release import validate_project


class ReleaseMetadataTests(unittest.TestCase):
    """Keep the v1 source tree packageable and fail-closed."""

    def test_repository_passes_release_validation(self) -> None:
        """The checked-in source tree should pass offline release checks."""

        root = Path(__file__).resolve().parents[1]
        report = validate_project(root)
        self.assertEqual(report.errors, ())
        self.assertTrue(report.valid)


if __name__ == "__main__":
    unittest.main()
