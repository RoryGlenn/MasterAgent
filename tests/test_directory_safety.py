"""Adversarial tests for descriptor-pinned runtime directories."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from master_agent import directory_safety
from master_agent.directory_safety import DirectoryIdentity, PinnedDirectory
from master_agent.errors import ConfigurationError

ROOT = Path(__file__).resolve().parents[1]


class PinnedDirectoryTests(unittest.TestCase):
    """Exercise identity, replacement, and descriptor-lifetime boundaries."""

    def test_windows_native_open_and_child_errors_are_bounded(self) -> None:
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        backend = Mock(spec=WindowsSecureFilesystemBackend)
        backend.pin_directory.side_effect = OSError("native open failure")
        with (
            patch.object(
                directory_safety,
                "get_secure_filesystem_backend",
                return_value=backend,
            ),
            self.assertRaisesRegex(
                ConfigurationError,
                "runtime directory could not be opened safely",
            ),
        ):
            directory_safety._WindowsPinnedDirectory.open_native(
                Path(r"C:\MasterAgent\state"),
                expected_identity=None,
                require_private=True,
            )

        native = Mock()
        duplicate = Mock()
        native.duplicate.return_value = duplicate
        duplicate.pin_child.side_effect = OSError("native child failure")
        pinned = directory_safety._WindowsPinnedDirectory(
            native,
            require_private=True,
        )
        with self.assertRaisesRegex(
            ConfigurationError,
            "runtime child directory could not be opened safely",
        ):
            pinned.pin_child("child")
        duplicate.close.assert_called_once_with()

    def test_identity_and_duplicate_remain_valid_after_original_closes(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory)
            current = path.stat()
            pinned = PinnedDirectory.open(path)

            self.assertEqual(pinned.path, path.resolve())
            self.assertEqual(pinned.identity, DirectoryIdentity.from_stat(current))
            self.assertEqual(
                pinned.identity.to_dict(),
                {
                    "device": current.st_dev,
                    "inode": current.st_ino,
                    "owner": current.st_uid,
                    "mode": stat.S_IMODE(current.st_mode),
                },
            )

            descriptor = pinned.duplicate_fd()
            duplicate = pinned.duplicate()
            try:
                self.assertTrue(pinned.identity.matches(os.fstat(descriptor)))
                pinned.close()

                self.assertTrue(pinned.closed)
                duplicate.validate()
                self.assertEqual(
                    duplicate.identity, DirectoryIdentity.from_stat(current)
                )
            finally:
                os.close(descriptor)
                duplicate.close()

    def test_duplicate_descriptor_chain_remains_owned_after_pin_closes(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory)
            pinned = PinnedDirectory.open(path)
            descriptors = pinned.duplicate_descriptor_chain()
            try:
                self.assertEqual(len(descriptors), len(pinned.path.parts))
                self.assertTrue(
                    all(stat.S_ISDIR(os.fstat(value).st_mode) for value in descriptors)
                )
                self.assertTrue(pinned.identity.matches(os.fstat(descriptors[-1])))

                pinned.close()

                self.assertTrue(
                    all(stat.S_ISDIR(os.fstat(value).st_mode) for value in descriptors)
                )
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
                pinned.close()

    def test_replacing_final_directory_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            displaced = root / "displaced"
            selected.mkdir(mode=0o700)
            pinned = PinnedDirectory.open(selected)
            try:
                selected.rename(displaced)
                selected.mkdir(mode=0o700)

                with self.assertRaisesRegex(ConfigurationError, "path was replaced"):
                    pinned.validate()
                with self.assertRaisesRegex(ConfigurationError, "path was replaced"):
                    pinned.duplicate_fd()
            finally:
                pinned.close()

    def test_replacing_ancestor_directory_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ancestor = root / "approved"
            leaf = ancestor / "leaf"
            displaced = root / "displaced"
            leaf.mkdir(parents=True, mode=0o700)
            pinned = PinnedDirectory.open(leaf)
            try:
                ancestor.rename(displaced)
                leaf.mkdir(parents=True, mode=0o700)

                with self.assertRaisesRegex(ConfigurationError, "path was replaced"):
                    pinned.validate()
                with self.assertRaisesRegex(ConfigurationError, "path was replaced"):
                    pinned.pin_child("child")
            finally:
                pinned.close()

    def test_symlink_child_is_rejected_without_following_it(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            alias = root / "alias"
            target.mkdir(mode=0o700)
            alias.symlink_to(target, target_is_directory=True)

            with (
                PinnedDirectory.open(root) as pinned,
                self.assertRaisesRegex(ConfigurationError, "no-follow directory"),
            ):
                pinned.pin_child("alias")

    def test_create_is_rejected_without_mutating_missing_components(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                PinnedDirectory.open(root) as pinned,
                self.assertRaisesRegex(ConfigurationError, "exist before approval"),
            ):
                pinned.pin_child("one/two", create=True, mode=0o700)

            self.assertEqual(list(root.iterdir()), [])

    def test_open_create_is_rejected_even_when_directory_exists(self) -> None:
        with (
            TemporaryDirectory() as directory,
            self.assertRaisesRegex(ConfigurationError, "exist before approval"),
        ):
            PinnedDirectory.open(Path(directory), create=True)

    def test_create_never_chmods_preexisting_unsafe_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o777)

            with (
                PinnedDirectory.open(root) as pinned,
                self.assertRaisesRegex(ConfigurationError, "exist before approval"),
            ):
                pinned.pin_child("unsafe", create=True, mode=0o700)

            self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o777)

    def test_read_only_pin_can_delegate_permissions_without_weakening_default(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            readable = root / "readable"
            readable.mkdir(mode=0o700)
            readable.chmod(0o775)

            with self.assertRaisesRegex(ConfigurationError, "group- or world-writable"):
                PinnedDirectory.open(readable)

            with PinnedDirectory.open(readable, require_private=False) as pinned:
                pinned.validate()
                self.assertEqual(pinned.identity.owner, os.geteuid())

    def test_expected_identity_mismatch_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            other = root / "other"
            other.mkdir(mode=0o700)
            wrong_identity = DirectoryIdentity.from_stat(other.stat())

            with self.assertRaisesRegex(ConfigurationError, "approved identity"):
                PinnedDirectory.open(root, expected_identity=wrong_identity)

    def test_child_paths_reject_traversal_and_absolute_names(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with PinnedDirectory.open(root) as pinned:
                invalid = (Path("."), Path("child/../escape"), root / "absolute")
                for child in invalid:
                    with (
                        self.subTest(child=child),
                        self.assertRaisesRegex(
                            ConfigurationError,
                            "normalized relative path",
                        ),
                    ):
                        pinned.pin_child(child)

    def test_child_path_depth_is_bounded_before_creation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            too_deep = Path(*("segment" for _ in range(65)))

            with (
                PinnedDirectory.open(root) as pinned,
                self.assertRaisesRegex(ConfigurationError, "path is too deep"),
            ):
                pinned.pin_child(too_deep)

            self.assertEqual(list(root.iterdir()), [])

    def test_close_is_idempotent_and_all_later_operations_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            pinned = PinnedDirectory.open(Path(directory))
            pinned.close()
            pinned.close()

            self.assertTrue(pinned.closed)
            for operation in (
                pinned.validate,
                pinned.fileno,
                pinned.duplicate_fd,
                pinned.duplicate_descriptor_chain,
                pinned.duplicate,
            ):
                with (
                    self.subTest(operation=operation.__name__),
                    self.assertRaisesRegex(ConfigurationError, "closed"),
                ):
                    operation()

    def test_duplicate_fd_stays_above_closed_standard_streams(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "approved"
            report = root / "descriptor.txt"
            approved.mkdir(mode=0o700)
            script = """
import os
import sys
from pathlib import Path
from master_agent.directory_safety import PinnedDirectory

for descriptor in range(3):
    try:
        os.close(descriptor)
    except OSError:
        pass
pinned = PinnedDirectory.open(Path(sys.argv[1]))
duplicate = pinned.duplicate_fd()
Path(sys.argv[2]).write_text(str(duplicate), encoding="ascii")
os.close(duplicate)
pinned.close()
"""
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ROOT / "src")
            completed = subprocess.run(
                [sys.executable, "-c", script, str(approved), str(report)],
                check=False,
                env=environment,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertGreaterEqual(int(report.read_text(encoding="ascii")), 3)


if __name__ == "__main__":
    unittest.main()
