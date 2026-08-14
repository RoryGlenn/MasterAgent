"""Adversarial tests for descriptor-pinned runtime directories."""

from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.directory_safety import DirectoryIdentity, PinnedDirectory
from master_agent.errors import ConfigurationError


class PinnedDirectoryTests(unittest.TestCase):
    """Exercise identity, replacement, and descriptor-lifetime boundaries."""

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
                    pinned.pin_child("child", create=True)
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

    def test_create_sets_requested_mode_on_every_new_component(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with PinnedDirectory.open(root) as pinned:
                created = pinned.pin_child("one/two", create=True, mode=0o700)
                created.close()

            self.assertEqual(stat.S_IMODE((root / "one").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "one" / "two").stat().st_mode), 0o700)

    def test_create_never_chmods_preexisting_unsafe_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o777)

            with (
                PinnedDirectory.open(root) as pinned,
                self.assertRaisesRegex(ConfigurationError, "group- or world-writable"),
            ):
                pinned.pin_child("unsafe", create=True, mode=0o700)

            self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o777)

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
                pinned.pin_child(too_deep, create=True)

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
                pinned.duplicate,
            ):
                with (
                    self.subTest(operation=operation.__name__),
                    self.assertRaisesRegex(ConfigurationError, "closed"),
                ):
                    operation()


if __name__ == "__main__":
    unittest.main()
