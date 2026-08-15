"""Regression tests for shared test-fixture constructors."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from tests.helpers import private_temporary_directory


class PrivateTemporaryDirectoryTests(unittest.TestCase):
    """Keep permission-sensitive fixtures independent of the shell umask."""

    def test_collaborative_umask_is_restricted_and_restored(self) -> None:
        previous_umask = os.umask(0o002)
        try:
            with private_temporary_directory() as directory:
                root = Path(directory)
                child = root / "runtime"
                child.mkdir()
                config = root / "config.toml"
                config.write_text("enabled = false\n", encoding="utf-8")

                self.assertEqual(child.stat().st_mode & 0o777, 0o700)
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)

            restored_umask = os.umask(previous_umask)
            self.assertEqual(restored_umask, 0o002)
        finally:
            os.umask(previous_umask)


if __name__ == "__main__":
    unittest.main()
