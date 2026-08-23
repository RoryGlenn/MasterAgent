"""Immutable packaged-configuration snapshot regressions."""

from __future__ import annotations

import hashlib
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from master_agent.config_sources import (
    ConfigSnapshot,
    ConfigSource,
    OrganizationManagedFileTrust,
    resolve_config_source,
)
from master_agent.errors import ConfigurationError
from master_agent.identity import IdentityRegistry
from master_agent.models import RiskLevel
from master_agent.policy import PolicyConfig
from master_agent.retention import PersistenceMode, RetentionConfig

ROOT = Path(__file__).resolve().parents[1]
_MAX_CONFIG_BYTES = 4 * 1024 * 1024


class PackagedConfigSnapshotTests(unittest.TestCase):
    """Prove packaged defaults cannot change between hashing and parsing."""

    def test_policy_replacement_after_gate_cannot_change_parsed_bytes(self) -> None:
        trusted = (ROOT / "config/policy.toml").read_bytes()
        attacker = trusted.replace(
            b'prohibit_risks = ["destructive"]',
            b"prohibit_risks = []",
        )
        self.assertNotEqual(trusted, attacker)

        with TemporaryDirectory() as directory:
            default_root = Path(directory)
            packaged = default_root / "policy.toml"
            packaged.write_bytes(trusted)
            source = _resolve_packaged(default_root, "policy.toml")
            approved_digest = _digest(source)

            packaged.write_bytes(attacker)
            parsed = PolicyConfig.from_toml(source)

        self.assertIsInstance(source, ConfigSnapshot)
        self.assertEqual(_digest(source), approved_digest)
        self.assertIn(RiskLevel.DESTRUCTIVE, parsed.prohibit_risks)

    def test_retention_replacement_after_gate_cannot_weaken_persistence(self) -> None:
        trusted = (
            b'[retention]\ndefault_ttl_hours = 1\ndefault_persistence = "prohibited"\n'
        )
        attacker = trusted.replace(b'"prohibited"', b'"explicit_content"')

        with TemporaryDirectory() as directory:
            default_root = Path(directory)
            packaged = default_root / "retention.toml"
            packaged.write_bytes(trusted)
            source = _resolve_packaged(default_root, "retention.toml")
            approved_digest = _digest(source)

            packaged.write_bytes(attacker)
            parsed = RetentionConfig.from_toml(source)

        self.assertEqual(_digest(source), approved_digest)
        self.assertEqual(parsed.default.persistence, PersistenceMode.PROHIBITED)

    def test_identity_aba_uses_the_same_bytes_for_hash_and_parse(self) -> None:
        trusted = (
            b"[people.reviewed]\n"
            b'display_name = "Reviewed User"\n'
            b'aliases = ["reviewed"]\n'
            b"[people.reviewed.identifiers]\n"
            b'microsoft = "reviewed-object-id"\n'
        )
        attacker = (
            b"[people.attacker]\n"
            b'display_name = "Attacker"\n'
            b'aliases = ["reviewed"]\n'
            b"[people.attacker.identifiers]\n"
            b'microsoft = "attacker-object-id"\n'
        )

        with TemporaryDirectory() as directory:
            default_root = Path(directory)
            packaged = default_root / "identities.toml"
            packaged.write_bytes(trusted)
            source = _resolve_packaged(default_root, "identities.toml")
            approved_digest = _digest(source)

            packaged.write_bytes(attacker)
            parsed = IdentityRegistry.from_toml(source)
            packaged.write_bytes(trusted)
            post_gate_digest = _digest(source)

        self.assertEqual(post_gate_digest, approved_digest)
        self.assertEqual(parsed.resolve("reviewed").key, "reviewed")
        self.assertNotIn("attacker", parsed.people)

    def test_packaged_snapshot_enforces_the_four_mibibyte_limit(self) -> None:
        with TemporaryDirectory() as directory:
            default_root = Path(directory)
            packaged = default_root / "policy.toml"
            packaged.write_bytes(b"x" * _MAX_CONFIG_BYTES)

            source = _resolve_packaged(default_root, "policy.toml")
            self.assertEqual(len(source.payload), _MAX_CONFIG_BYTES)
            self.assertEqual(source.display_path, packaged)

            packaged.write_bytes(b"x" * (_MAX_CONFIG_BYTES + 1))
            with self.assertRaisesRegex(
                ConfigurationError,
                "packaged default configuration exceeds the 4 MiB limit",
            ):
                _resolve_packaged(default_root, "policy.toml")

    def test_windows_missing_explicit_configuration_is_bounded(self) -> None:
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        backend = Mock(spec=WindowsSecureFilesystemBackend)
        backend.read_restricted_file.side_effect = FileNotFoundError("missing")
        windows_os = Mock()
        windows_os.name = "nt"
        selected = Path("/missing/policy.toml")

        with (
            patch("master_agent.config_sources.os", windows_os),
            patch(
                "master_agent.config_sources.get_secure_filesystem_backend",
                return_value=backend,
            ),
            patch("master_agent.config_sources.require_platform_contract"),
            self.assertRaisesRegex(
                ConfigurationError,
                "explicit configuration not found",
            ),
        ):
            resolve_config_source(selected, "policy.toml")

        backend.read_restricted_file.assert_called_once_with(
            selected,
            _MAX_CONFIG_BYTES,
            require_private=False,
        )

    @unittest.skipIf(os.name == "nt", "creating test symlinks is privilege-dependent")
    def test_explicit_configuration_rejects_symbolic_parent_traversal(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            actual = root / "actual"
            actual.mkdir()
            (actual / "policy.toml").write_text("[policy]\n", encoding="utf-8")
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)

            with self.assertRaisesRegex(ConfigurationError, "symbolic link"):
                resolve_config_source(alias / "policy.toml", "policy.toml")

    def test_user_private_configuration_rejects_extended_acl(self) -> None:
        with TemporaryDirectory() as directory:
            selected = Path(directory).resolve() / "policy.toml"
            selected.write_text("[policy]\n", encoding="utf-8")
            with (
                patch(
                    "master_agent.config_sources._has_extended_posix_acl",
                    side_effect=(False, True),
                ),
                self.assertRaisesRegex(ConfigurationError, "user-private policy"),
            ):
                resolve_config_source(selected, "policy.toml")

    def test_posix_organization_managed_configuration_is_digest_bound(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            selected = root / "policy.toml"
            payload = b'[policy]\nprohibit_risks = ["destructive"]\n'
            selected.write_bytes(payload)
            selected.chmod(0o644)
            owner = selected.stat().st_uid
            group = selected.stat().st_gid
            trust = OrganizationManagedFileTrust(
                sha256=hashlib.sha256(payload).hexdigest(),
                posix_uids=(owner,),
                posix_gids=(group,),
            )
            with (
                patch("master_agent.config_sources.os.geteuid", return_value=owner + 1),
                patch("master_agent.config_sources.os.getegid", return_value=group + 1),
                patch("master_agent.config_sources.os.getgroups", return_value=[]),
                patch("master_agent.config_sources.os.access", return_value=False),
            ):
                snapshot = resolve_config_source(
                    selected,
                    "policy.toml",
                    organization_trust=trust,
                )

                self.assertEqual(snapshot.payload, payload)
                self.assertEqual(snapshot.trust_class, "organization-managed")
                selected.chmod(0o664)
                group_writable = resolve_config_source(
                    selected,
                    "policy.toml",
                    organization_trust=trust,
                )
                self.assertEqual(group_writable.payload, payload)
                selected.write_bytes(payload + b"# changed\n")
                with self.assertRaisesRegex(
                    ConfigurationError, "digest does not match"
                ):
                    resolve_config_source(
                        selected,
                        "policy.toml",
                        organization_trust=trust,
                    )

    def test_posix_managed_configuration_rejects_effective_user_write(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            selected = root / "policy.toml"
            payload = b"[policy]\n"
            selected.write_bytes(payload)
            selected.chmod(0o660)
            owner = selected.stat().st_uid
            group = selected.stat().st_gid
            trust = OrganizationManagedFileTrust(
                sha256=hashlib.sha256(payload).hexdigest(),
                posix_uids=(owner,),
                posix_gids=(group,),
            )
            with (
                patch("master_agent.config_sources.os.geteuid", return_value=owner + 1),
                patch("master_agent.config_sources.os.getegid", return_value=group),
                patch("master_agent.config_sources.os.getgroups", return_value=[group]),
                patch("master_agent.config_sources.os.access", return_value=False),
                self.assertRaisesRegex(ConfigurationError, "effective user"),
            ):
                resolve_config_source(
                    selected,
                    "policy.toml",
                    organization_trust=trust,
                )

            untrusted_group = OrganizationManagedFileTrust(
                sha256=hashlib.sha256(payload).hexdigest(),
                posix_uids=(owner,),
            )
            with (
                patch("master_agent.config_sources.os.geteuid", return_value=owner + 1),
                patch("master_agent.config_sources.os.getegid", return_value=group + 1),
                patch("master_agent.config_sources.os.getgroups", return_value=[]),
                patch("master_agent.config_sources.os.access", return_value=False),
                self.assertRaisesRegex(ConfigurationError, "untrusted principal"),
            ):
                resolve_config_source(
                    selected,
                    "policy.toml",
                    organization_trust=untrusted_group,
                )

    def test_posix_managed_configuration_rejects_effective_acl_write(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            selected = root / "policy.toml"
            payload = b"[policy]\n"
            selected.write_bytes(payload)
            selected.chmod(0o644)
            owner = selected.stat().st_uid
            group = selected.stat().st_gid
            trust = OrganizationManagedFileTrust(
                sha256=hashlib.sha256(payload).hexdigest(),
                posix_uids=(owner,),
            )
            with (
                patch("master_agent.config_sources.os.geteuid", return_value=owner + 1),
                patch("master_agent.config_sources.os.getegid", return_value=group + 1),
                patch("master_agent.config_sources.os.getgroups", return_value=[]),
                patch(
                    "master_agent.config_sources.os.access",
                    side_effect=(False, True),
                ),
                self.assertRaisesRegex(ConfigurationError, "effective user"),
            ):
                resolve_config_source(
                    selected,
                    "policy.toml",
                    organization_trust=trust,
                )

    def test_posix_managed_configuration_rejects_named_acl_entries(self) -> None:
        with TemporaryDirectory() as directory:
            selected = Path(directory).resolve() / "policy.toml"
            payload = b"[policy]\n"
            selected.write_bytes(payload)
            selected.chmod(0o644)
            owner = selected.stat().st_uid
            group = selected.stat().st_gid
            trust = OrganizationManagedFileTrust(
                sha256=hashlib.sha256(payload).hexdigest(),
                posix_uids=(owner,),
            )
            with (
                patch("master_agent.config_sources.os.geteuid", return_value=owner + 1),
                patch("master_agent.config_sources.os.getegid", return_value=group + 1),
                patch("master_agent.config_sources.os.getgroups", return_value=[]),
                patch("master_agent.config_sources.os.access", return_value=False),
                patch(
                    "master_agent.config_sources._has_extended_posix_acl",
                    return_value=True,
                ),
                self.assertRaisesRegex(ConfigurationError, "extended ACL"),
            ):
                resolve_config_source(
                    selected,
                    "policy.toml",
                    organization_trust=trust,
                )

    def test_windows_managed_configuration_uses_non_user_writer_policy(self) -> None:
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        payload = b"[policy]\n"
        trust = OrganizationManagedFileTrust(
            sha256=hashlib.sha256(payload).hexdigest(),
            windows_sids=("S-1-5-21-1-2-3-4100",),
        )
        backend = Mock(spec=WindowsSecureFilesystemBackend)
        managed = Mock(spec=WindowsSecureFilesystemBackend)
        backend.for_organization_managed_configuration.return_value = managed
        selected = Path("/Company/policy.toml")
        managed.read_restricted_file.return_value = (selected, payload, Mock())
        windows_os = Mock()
        windows_os.name = "nt"
        with (
            patch("master_agent.config_sources.os", windows_os),
            patch(
                "master_agent.config_sources.get_secure_filesystem_backend",
                return_value=backend,
            ),
            patch("master_agent.config_sources.require_platform_contract"),
        ):
            snapshot = resolve_config_source(
                selected,
                "policy.toml",
                organization_trust=trust,
            )

        backend.for_organization_managed_configuration.assert_called_once_with(
            ("S-1-5-21-1-2-3-4100",)
        )
        managed.read_restricted_file.assert_called_once_with(
            selected,
            _MAX_CONFIG_BYTES,
            require_private=False,
        )
        self.assertEqual(snapshot.trust_reason, "content-and-writer-bound")

    def test_windows_managed_missing_configuration_redacts_selected_path(self) -> None:
        from master_agent.platform_runtime.windows.filesystem import (
            WindowsSecureFilesystemBackend,
        )

        trust = OrganizationManagedFileTrust(
            sha256="a" * 64,
            windows_sids=("S-1-5-21-1-2-3-4100",),
        )
        backend = Mock(spec=WindowsSecureFilesystemBackend)
        managed = Mock(spec=WindowsSecureFilesystemBackend)
        backend.for_organization_managed_configuration.return_value = managed
        managed.read_restricted_file.side_effect = FileNotFoundError("missing")
        selected = Path("/Company/secret-layout/policy.toml")
        windows_os = Mock()
        windows_os.name = "nt"
        with (
            patch("master_agent.config_sources.os", windows_os),
            patch(
                "master_agent.config_sources.get_secure_filesystem_backend",
                return_value=backend,
            ),
            patch("master_agent.config_sources.require_platform_contract"),
            self.assertRaises(ConfigurationError) as raised,
        ):
            resolve_config_source(
                selected,
                "policy.toml",
                organization_trust=trust,
            )

        self.assertIn("organization-managed configuration", str(raised.exception))
        self.assertNotIn("secret-layout", str(raised.exception))


def _resolve_packaged(root: Path, filename: str) -> ConfigSnapshot:
    with patch("master_agent.config_sources.files", return_value=root):
        return resolve_config_source(None, filename)


def _digest(source: ConfigSource) -> str:
    with source.open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


if __name__ == "__main__":
    unittest.main()
