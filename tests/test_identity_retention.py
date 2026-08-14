"""Identity correlation and evidence-retention tests."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.connectors.identity import IdentityMapConnector
from master_agent.errors import ConfigurationError
from master_agent.identity import IdentityRegistry
from master_agent.retention import (
    RetentionConfig,
    purge_expired_evidence,
    write_retained_json,
)
from tests.helpers import read_action

ROOT = Path(__file__).resolve().parents[1]


class IdentityRegistryTests(unittest.TestCase):
    """Verify exact, unambiguous, cross-system identity resolution."""

    def test_resolves_alias_and_system_identifier(self) -> None:
        registry = IdentityRegistry.from_toml(ROOT / "config/identities.toml")

        person = registry.resolve("Rory")

        self.assertEqual(person.key, "rory")
        self.assertEqual(registry.resolve_identifier("rory", "microsoft"), "me")

    def test_connector_returns_resource_citation(self) -> None:
        registry = IdentityRegistry.from_toml(ROOT / "config/identities.toml")
        connector = IdentityMapConnector(registry)
        action = read_action(
            "identity.person.resolve",
            system="identity",
            resource_type="person",
            resource_id="rory",
            parameters={"query": "Rory"},
        )

        result = connector.execute(action)
        verification = connector.verify(action, result)

        self.assertTrue(verification.verified)
        self.assertEqual(result.after["person"]["display_name"], "Rory Glenn")
        self.assertTrue(result.after["person"]["citation_id"].startswith("CIT-"))

    def test_ambiguous_alias_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "identities.toml"
            path.write_text(
                """
[people.alex_one]
display_name = "Alex One"
aliases = ["Alex"]

[people.alex_two]
display_name = "Alex Two"
aliases = ["Alex"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            registry = IdentityRegistry.from_toml(path)

            with self.assertRaisesRegex(ConfigurationError, "ambiguous"):
                registry.resolve("Alex")


class RetentionTests(unittest.TestCase):
    """Verify explicit persistence, expiry, and path-confinement rules."""

    def test_explicit_evidence_writes_sidecar_and_can_be_purged(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config/retention.toml")
        created = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_json(
                root / "communication-context-evidence.json",
                {
                    "schema": "master-agent/test@1",
                    "content": "sensitive communication evidence",
                    "citations": [
                        {
                            "citation_id": "CIT-TEST",
                            "marker": "[CIT-TEST]",
                        }
                    ],
                },
                evidence_type="communication-context/package",
                config=config,
                include_content=True,
                now=created,
            )

            manifest = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertTrue(manifest["content_included"])
            self.assertEqual(manifest["citation_ids"], ["CIT-TEST"])
            self.assertEqual(manifest["evidence_path"], evidence.name)

            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=73),
                dry_run=True,
            )
            self.assertEqual(preview.expired_manifests, 1)
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

            with self.assertRaisesRegex(ConfigurationError, "pruning is disabled"):
                purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=73),
                    dry_run=False,
                )
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

    def test_metadata_only_rule_rejects_content_persistence(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config/retention.toml")
        with (
            TemporaryDirectory() as directory,
            self.assertRaisesRegex(ConfigurationError, "does not permit"),
        ):
            write_retained_json(
                Path(directory) / "identity.json",
                {"schema": "master-agent/identity@1", "identity": {"id": "u1"}},
                evidence_type="microsoft.identity.metadata",
                config=config,
                include_content=True,
            )

    def test_corrupt_sidecar_cannot_delete_outside_selected_root(self) -> None:
        now = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            outside = Path(directory) / "outside.txt"
            outside.write_text("must remain", encoding="utf-8")
            sidecar = root / "malicious.retention.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "evidence_path": "../outside.txt",
                        "expires_at": (now - timedelta(hours=1)).isoformat(),
                    }
                ),
                encoding="utf-8",
            )

            result = purge_expired_evidence(root, now=now, dry_run=True)

            self.assertTrue(result.errors)
            self.assertTrue(outside.exists())
            self.assertTrue(sidecar.exists())


if __name__ == "__main__":
    unittest.main()
