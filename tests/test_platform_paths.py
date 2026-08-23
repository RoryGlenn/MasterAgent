"""Tests for current-user platform-native package paths."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.errors import ConfigurationError
from master_agent.operating import default_organization_profile_path
from master_agent.platform_paths import current_user_product_root


class PlatformPathTests(unittest.TestCase):
    """Keep defaults native, absolute, and independent of the checkout."""

    def test_posix_product_root_preserves_existing_private_home_layout(self) -> None:
        with TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            self.assertEqual(
                current_user_product_root(
                    home=home,
                    platform_name="posix",
                    environ={},
                ),
                home / ".master-agent/MasterAgent",
            )

    def test_windows_product_root_uses_local_app_data(self) -> None:
        with TemporaryDirectory(prefix="Local App Data Ω ") as directory:
            local = Path(directory).resolve()
            self.assertEqual(
                current_user_product_root(
                    home=local / "ignored-home",
                    platform_name="nt",
                    environ={"LOCALAPPDATA": str(local)},
                ),
                local / "MasterAgent",
            )
            self.assertEqual(
                default_organization_profile_path(
                    home=local / "ignored-home",
                    platform_name="nt",
                    environ={"LOCALAPPDATA": str(local)},
                ),
                local / "MasterAgent/organization-profile.toml",
            )

    def test_windows_product_root_falls_back_without_using_cwd(self) -> None:
        with TemporaryDirectory() as directory:
            home = Path(directory).resolve() / "User Profile"
            original = Path.cwd()
            try:
                os.chdir(directory)
                selected = current_user_product_root(
                    home=home,
                    platform_name="nt",
                    environ={},
                )
            finally:
                os.chdir(original)
            self.assertEqual(selected, home / "AppData/Local/MasterAgent")

    def test_unknown_platform_fails_closed(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "unsupported"):
            current_user_product_root(platform_name="plan9")

    def test_windows_rejects_relative_local_app_data_without_using_cwd(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "path is invalid"):
            current_user_product_root(
                home=Path("relative-home"),
                platform_name="nt",
                environ={"LOCALAPPDATA": "relative-local-data"},
            )


if __name__ == "__main__":
    unittest.main()
