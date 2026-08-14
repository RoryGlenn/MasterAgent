"""Retention-policy and expiration cleanup tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from master_agent.errors import ConfigurationError
from master_agent.retention import (
    RetentionConfig,
    purge_expired_evidence,
    write_retained_json,
    write_retained_text,
)


ROOT = Path(__file__).resolve().parents[1]


class RetentionTests(unittest.TestCase):
    """Verify explicit persistence, sidecars, and bounded expiration deletion."""

    def test_metadata_only_write_excludes_communication_content(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            evidence, sidecar = write_retained_json(
                path,
                {
                    "schema": "example@1",
                    "system": "outlook",
                    "messages": [{"id": "m1", "body": "sensitive"}],
                    "citations": [{"citation_id": "CIT-ONE"}],
                },
                evidence_type="outlook.message.metadata",
                config=config,
                include_content=False,
                now=datetime(2026, 8, 13, tzinfo=UTC),
            )
            stored = json.loads(evidence.read_text(encoding="utf-8"))
            manifest = json.loads(sidecar.read_text(encoding="utf-8"))

        self.assertNotIn("messages", stored)
        self.assertEqual(stored["citations"][0]["citation_id"], "CIT-ONE")
        self.assertFalse(manifest["content_included"])
        self.assertEqual(manifest["evidence_path"], "evidence.json")

    def test_content_requires_explicit_content_rule(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigurationError, "does not permit"):
                write_retained_json(
                    Path(directory) / "evidence.json",
                    {"messages": [{"body": "sensitive"}]},
                    evidence_type="outlook.message.metadata",
                    config=config,
                    include_content=True,
                )

    def test_retained_text_receives_sidecar_and_expiration_cleanup(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "communication-context.md",
                "# Context\nSensitive summary.\n",
                evidence_type="communication-context/markdown",
                config=config,
                citation_ids=("CIT-ONE",),
                now=created,
            )
            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=73),
                dry_run=True,
            )
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertEqual(preview.expired_manifests, 1)
            self.assertEqual(len(preview.removed_files), 2)

            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=73),
                dry_run=False,
            )
            self.assertEqual(applied.errors, ())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_prohibited_evidence_cannot_be_persisted(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigurationError, "prohibits"):
                write_retained_json(
                    Path(directory) / "credential.json",
                    {"token": "secret"},
                    evidence_type="outlook.credential.token",
                    config=config,
                    include_content=False,
                )

    def test_cleanup_rejects_path_traversal_sidecar(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root.parent / "victim.txt"
            victim.write_text("do not delete", encoding="utf-8")
            sidecar = root / "malicious.retention.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "evidence_path": "../victim.txt",
                        "expires_at": "2020-01-01T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )

            result = purge_expired_evidence(
                root,
                now=datetime(2026, 8, 13, tzinfo=UTC),
                dry_run=False,
            )

            self.assertTrue(result.errors)
            self.assertTrue(victim.exists())
            victim.unlink()


if __name__ == "__main__":
    unittest.main()
