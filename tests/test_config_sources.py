"""Immutable packaged-configuration snapshot regressions."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from master_agent.config_sources import (
    ConfigSnapshot,
    ConfigSource,
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


def _resolve_packaged(root: Path, filename: str) -> ConfigSnapshot:
    with patch("master_agent.config_sources.files", return_value=root):
        return resolve_config_source(None, filename)


def _digest(source: ConfigSource) -> str:
    with source.open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


if __name__ == "__main__":
    unittest.main()
