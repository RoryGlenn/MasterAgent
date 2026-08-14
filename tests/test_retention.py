"""Retention-policy and expiration cleanup tests."""

from __future__ import annotations

import json
import os
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent.errors import ConfigurationError
from master_agent.retention import (
    RetentionConfig,
    purge_expired_evidence,
    repair_orphaned_evidence,
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

    def test_metadata_only_recursively_removes_retrieved_content(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        secret = "TOP-SECRET-RETRIEVED-CONTENT"
        with TemporaryDirectory() as directory:
            evidence, _ = write_retained_json(
                Path(directory) / "evidence.json",
                {
                    "schema": "example@1",
                    "evidence": {
                        "content_digest": "abc123",
                        "connector_reference": secret,
                        "nested": {"body": secret},
                    },
                    "security": {
                        "content_is_untrusted": True,
                        "prompt_injection_findings": [
                            {
                                "path": "$.message.body",
                                "category": "instruction_override",
                                "severity": "high",
                                "excerpt": secret,
                            }
                        ],
                        "raw_content": secret,
                    },
                    "citations": [
                        {
                            "citation_id": "CIT-ONE",
                            "resource_id": "item-1",
                            "title": secret,
                            "url": f"https://example.test/?q={secret}",
                        }
                    ],
                },
                evidence_type="outlook.message.metadata",
                config=config,
                include_content=False,
            )
            stored_text = evidence.read_text(encoding="utf-8")
            stored = json.loads(stored_text)

        self.assertNotIn(secret, stored_text)
        self.assertEqual(stored["evidence"], {"content_digest": "abc123"})
        self.assertNotIn(
            "excerpt",
            stored["security"]["prompt_injection_findings"][0],
        )
        self.assertEqual(
            stored["citations"],
            [{"citation_id": "CIT-ONE", "resource_id": "item-1"}],
        )

    def test_prohibited_rule_overrides_broad_explicit_content_rule(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        decision = config.decide("run-result/foo.credential.token")

        self.assertEqual(decision.persistence.value, "prohibited")
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigurationError, "prohibits"):
                write_retained_json(
                    Path(directory) / "result.json",
                    {"token": "TOP-SECRET"},
                    evidence_type="run-result/foo.credential.token",
                    config=config,
                    include_content=False,
                )

    def test_shadowed_allow_rule_is_rejected_at_load_time(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "retention.toml"
            path.write_text(
                """
[retention]
default_ttl_hours = 24
default_persistence = "metadata_only"

[[rules]]
pattern = "evidence/*"
ttl_hours = 24
persistence = "metadata_only"

[[rules]]
pattern = "evidence/public/*"
ttl_hours = 24
persistence = "explicit_content"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConfigurationError, "shadowed"):
                RetentionConfig.from_toml(path)

    def test_symlink_destination_is_rejected_without_touching_victim(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.json"
            victim.write_text('{"safe":true}\n', encoding="utf-8")
            evidence = root / "evidence.json"
            evidence.symlink_to(victim)

            with self.assertRaisesRegex(ConfigurationError, "unsafe"):
                write_retained_json(
                    evidence,
                    {"schema": "example@1"},
                    evidence_type="outlook.message.metadata",
                    config=config,
                    include_content=False,
                )

            self.assertEqual(victim.read_text(encoding="utf-8"), '{"safe":true}\n')
            self.assertTrue(evidence.is_symlink())
            self.assertFalse((root / "evidence.json.retention.json").exists())

    def test_permission_failure_leaves_no_partial_evidence(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            with (
                patch(
                    "master_agent.retention.os.fchmod",
                    side_effect=PermissionError("simulated chmod failure"),
                ),
                self.assertRaisesRegex(ConfigurationError, "commit failed"),
            ):
                write_retained_json(
                    evidence,
                    {"schema": "example@1"},
                    evidence_type="outlook.message.metadata",
                    config=config,
                    include_content=False,
                )

            self.assertFalse(evidence.exists())
            self.assertFalse(evidence.with_suffix(".json.retention.json").exists())

    def test_partial_pair_commit_rolls_back_evidence(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            real_replace = os.replace
            calls = 0

            def fail_second_replace(source: object, destination: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated sidecar commit failure")
                real_replace(source, destination)

            with (
                patch(
                    "master_agent.retention.os.replace",
                    side_effect=fail_second_replace,
                ),
                self.assertRaisesRegex(ConfigurationError, "commit failed"),
            ):
                write_retained_json(
                    evidence,
                    {"schema": "example@1"},
                    evidence_type="outlook.message.metadata",
                    config=config,
                    include_content=False,
                )

            self.assertFalse(evidence.exists())
            self.assertFalse(evidence.with_suffix(".json.retention.json").exists())

    def test_orphaned_evidence_is_detected_and_quarantined(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            orphan = root / "orphan.json"
            orphan.write_text('{"secret":"TOP-SECRET"}\n', encoding="utf-8")

            preview = repair_orphaned_evidence(root, dry_run=True)
            applied = repair_orphaned_evidence(root, dry_run=False)

            self.assertEqual(preview.orphaned_files, (str(orphan),))
            self.assertFalse(orphan.exists())
            self.assertEqual(len(applied.quarantined_files), 1)
            quarantined = Path(applied.quarantined_files[0])
            self.assertTrue(quarantined.is_file())
            self.assertIn("TOP-SECRET", quarantined.read_text(encoding="utf-8"))

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
