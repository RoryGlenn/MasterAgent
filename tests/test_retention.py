"""Retention-policy and expiration cleanup tests."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent import retention
from master_agent.errors import ConfigurationError
from master_agent.evidence import content_digest
from master_agent.retention import (
    RetainedJSONReservation,
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
        citation_id = _citation_id("outlook", "message", "m1")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            evidence, sidecar = write_retained_json(
                path,
                {
                    "schema": "example@1",
                    "system": "outlook",
                    "messages": [{"id": "m1", "body": "sensitive"}],
                    "citations": [
                        {
                            "citation_id": "CIT-DEADBEEFCAFE",
                            "system": "outlook",
                            "resource_type": "message",
                            "resource_id": "m1",
                        }
                    ],
                },
                evidence_type="outlook.message.metadata",
                config=config,
                include_content=False,
                now=datetime(2026, 8, 13, tzinfo=UTC),
            )
            stored = json.loads(evidence.read_text(encoding="utf-8"))
            manifest = json.loads(sidecar.read_text(encoding="utf-8"))

        self.assertNotIn("messages", stored)
        self.assertEqual(stored["citations"][0]["citation_id"], citation_id)
        self.assertFalse(manifest["content_included"])
        self.assertEqual(manifest["evidence_path"], "evidence.json")

    def test_content_requires_explicit_content_rule(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with (
            TemporaryDirectory() as directory,
            self.assertRaisesRegex(ConfigurationError, "does not permit"),
        ):
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
        digest = "a" * 64
        citation_id = _citation_id("outlook", "message", "item-1")
        with TemporaryDirectory() as directory:
            evidence, _ = write_retained_json(
                Path(directory) / "evidence.json",
                {
                    "schema": "example@1",
                    "evidence": {
                        "content_digest": digest,
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
                            "citation_id": citation_id,
                            "system": "outlook",
                            "resource_type": "message",
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
        self.assertNotEqual(stored["evidence"]["content_digest"], digest)
        self.assertEqual(len(stored["evidence"]["content_digest"]), 64)
        self.assertNotIn(
            "excerpt",
            stored["security"]["prompt_injection_findings"][0],
        )
        self.assertEqual(
            stored["citations"],
            [
                {
                    "citation_id": citation_id,
                    "system_digest": hashlib.sha256(b"outlook").hexdigest(),
                    "resource_type_digest": hashlib.sha256(b"message").hexdigest(),
                    "resource_id_digest": hashlib.sha256(b"item-1").hexdigest(),
                }
            ],
        )

    def test_metadata_only_validates_digests_and_derives_opaque_ids(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        secret = "sk-proj-ABCDEF1234567890"
        claimed_citation_id = "CIT-DEADBEEFCAFE"
        claimed_digest = "deadbeef" * 8
        resource_id = "provider-resource-123"
        etag = 'W/"provider-version-42"'
        path = "$.messages[0].body"
        derived_citation_id = _citation_id(secret, secret, resource_id)
        payload = {
            "schema": secret,
            "system": secret,
            "deployment": secret,
            "citation_ids": [claimed_citation_id],
            "evidence": {
                "content_digest": claimed_digest,
                "etag": etag,
                "version": secret,
            },
            "citations": [
                {
                    "citation_id": claimed_citation_id,
                    "system": secret,
                    "resource_type": secret,
                    "resource_id": resource_id,
                    "content_digest": claimed_digest,
                }
            ],
            "security": {
                "content_is_untrusted": True,
                "prompt_injection_findings": [
                    {
                        "path": path,
                        "category": "instruction_override",
                        "severity": "high",
                        "excerpt": secret,
                    }
                ],
            },
        }
        with TemporaryDirectory() as directory:
            evidence, _ = write_retained_json(
                Path(directory) / "evidence.json",
                payload,
                evidence_type="outlook.message.metadata",
                config=config,
                include_content=False,
            )
            stored_text = evidence.read_text(encoding="utf-8")
            stored = json.loads(stored_text)

        self.assertNotIn(secret, stored_text)
        self.assertNotIn(claimed_citation_id, stored_text)
        self.assertNotIn(claimed_digest, stored_text)
        self.assertNotIn(etag, stored_text)
        self.assertEqual(stored["citation_ids"], [derived_citation_id])
        identifier_digest = hashlib.sha256(secret.encode()).hexdigest()
        self.assertEqual(stored["schema_digest"], identifier_digest)
        self.assertEqual(stored["system_digest"], identifier_digest)
        self.assertEqual(stored["deployment_digest"], identifier_digest)
        self.assertEqual(
            stored["evidence"]["content_digest"],
            content_digest(payload),
        )
        self.assertEqual(
            stored["evidence"]["etag_digest"],
            hashlib.sha256(etag.encode()).hexdigest(),
        )
        self.assertEqual(
            stored["evidence"]["version_digest"],
            hashlib.sha256(secret.encode()).hexdigest(),
        )
        self.assertEqual(
            stored["citations"][0],
            {
                "citation_id": derived_citation_id,
                "system_digest": identifier_digest,
                "resource_type_digest": identifier_digest,
                "resource_id_digest": hashlib.sha256(resource_id.encode()).hexdigest(),
            },
        )
        self.assertEqual(
            stored["security"]["prompt_injection_findings"][0],
            {
                "path_digest": hashlib.sha256(path.encode()).hexdigest(),
                "category": "instruction_override",
                "severity": "high",
            },
        )

    def test_prohibited_rule_overrides_broad_explicit_content_rule(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        decision = config.decide("run-result/foo.credential.token")

        self.assertEqual(decision.persistence.value, "prohibited")
        with (
            TemporaryDirectory() as directory,
            self.assertRaisesRegex(ConfigurationError, "prohibits"),
        ):
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

            with self.assertRaisesRegex(ConfigurationError, "already exists"):
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
            real_open = retention._open_new_restricted_file_at
            calls = 0

            def fail_second_create(
                parent_descriptor: int,
                name: str,
            ) -> tuple[int, tuple[int, int]]:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated sidecar commit failure")
                return real_open(parent_descriptor, name)

            with (
                patch.object(
                    retention,
                    "_open_new_restricted_file_at",
                    side_effect=fail_second_create,
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

    def test_pair_is_staged_privately_and_publishes_manifest_first(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            sidecar = root / "evidence.json.retention.json"
            real_publish = retention._publish_restricted_temp_file_at
            publication_order: list[str] = []

            def observe_publication(
                parent_descriptor: int,
                temporary_name: str,
                final_name: str,
                identity: tuple[int, int],
            ) -> None:
                temporary = root / temporary_name
                self.assertTrue(temporary.is_file())
                self.assertEqual(temporary.stat().st_mode & 0o777, 0o600)
                self.assertFalse(evidence.exists())
                if final_name == evidence.name:
                    self.assertTrue(sidecar.is_file())
                real_publish(
                    parent_descriptor,
                    temporary_name,
                    final_name,
                    identity,
                )
                publication_order.append(final_name)

            with patch.object(
                retention,
                "_publish_restricted_temp_file_at",
                side_effect=observe_publication,
            ):
                write_retained_json(
                    evidence,
                    {"schema": "example@1"},
                    evidence_type="outlook.message.metadata",
                    config=config,
                    include_content=False,
                )

            self.assertEqual(publication_order, [sidecar.name, evidence.name])
            self.assertFalse(any(path.name.endswith(".tmp") for path in root.iterdir()))

    def test_failure_after_manifest_publication_rolls_back_the_pair(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            sidecar = root / "evidence.json.retention.json"
            real_publish = retention._publish_restricted_temp_file_at

            def fail_evidence_publication(
                parent_descriptor: int,
                temporary_name: str,
                final_name: str,
                identity: tuple[int, int],
            ) -> None:
                if final_name == evidence.name:
                    self.assertTrue(sidecar.is_file())
                    raise OSError("simulated evidence publication failure")
                real_publish(
                    parent_descriptor,
                    temporary_name,
                    final_name,
                    identity,
                )

            with (
                patch.object(
                    retention,
                    "_publish_restricted_temp_file_at",
                    side_effect=fail_evidence_publication,
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
            self.assertFalse(sidecar.exists())
            self.assertFalse(any(path.name.endswith(".tmp") for path in root.iterdir()))

    def test_existing_pair_is_never_overwritten(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            evidence = Path(directory) / "result.txt"
            first_evidence, first_sidecar = write_retained_text(
                evidence,
                "first",
                evidence_type="run-result/test",
                config=config,
            )
            evidence_before = first_evidence.read_bytes()
            sidecar_before = first_sidecar.read_bytes()

            with self.assertRaisesRegex(ConfigurationError, "already exists"):
                write_retained_text(
                    evidence,
                    "second",
                    evidence_type="run-result/test",
                    config=config,
                )

            self.assertEqual(first_evidence.read_bytes(), evidence_before)
            self.assertEqual(first_sidecar.read_bytes(), sidecar_before)

    def test_result_reservation_rejects_stale_name_before_commit(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "result.json"
            evidence.write_bytes(b"peer-result")
            evidence.chmod(0o600)

            with self.assertRaisesRegex(ConfigurationError, "already exists"):
                RetainedJSONReservation(
                    evidence,
                    evidence_type="run-result/full",
                    config=config,
                    include_content=True,
                )

            self.assertEqual(evidence.read_bytes(), b"peer-result")
            self.assertFalse((root / "result.json.retention.json").exists())

    def test_result_reservation_exposes_no_partial_pair_to_repair_preview(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "result.json"
            with RetainedJSONReservation(
                evidence,
                evidence_type="run-result/full",
                config=config,
                include_content=True,
            ) as reservation:
                preview = repair_orphaned_evidence(root, dry_run=True)
                self.assertEqual(preview.orphaned_files, ())
                self.assertFalse(evidence.exists())
                self.assertFalse((root / "result.json.retention.json").exists())
                reservation.commit({"schema": "run-result@1"})

            repair = repair_orphaned_evidence(root, dry_run=True)
            self.assertEqual(repair.orphaned_files, ())
            self.assertTrue(evidence.is_file())
            self.assertTrue((root / "result.json.retention.json").is_file())

    def test_digest_mismatch_is_repaired_and_never_purged_as_valid(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "approved",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            evidence.write_text("tampered", encoding="utf-8")

            purge = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=True,
            )
            repair = repair_orphaned_evidence(root, dry_run=True)

            self.assertTrue(purge.errors)
            self.assertEqual(purge.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertEqual(
                set(repair.orphaned_files),
                {str(evidence), str(sidecar)},
            )

    def test_missing_parent_is_not_created_by_retention_write(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"

            with self.assertRaisesRegex(ConfigurationError, "does not exist"):
                write_retained_text(
                    missing / "result.txt",
                    "content",
                    evidence_type="run-result/test",
                    config=config,
                )

            self.assertFalse(missing.exists())

    def test_orphaned_evidence_is_detected_and_recoverably_quarantined(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir(mode=0o700)
            orphan = nested / "orphan.json"
            orphan.write_text('{"secret":"TOP-SECRET"}\n', encoding="utf-8")

            preview = repair_orphaned_evidence(root, dry_run=True)
            repair = repair_orphaned_evidence(root, dry_run=False)
            destination = root / ".retention-quarantine" / "nested" / "orphan.json"

            self.assertEqual(preview.orphaned_files, (str(orphan),))
            self.assertEqual(repair.errors, ())
            self.assertEqual(repair.quarantined_files, (str(destination),))
            self.assertFalse(orphan.exists())
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                '{"secret":"TOP-SECRET"}\n',
            )
            self.assertEqual(
                (root / ".retention-quarantine").stat().st_mode & 0o777,
                0o700,
            )

    def test_orphan_preview_does_not_create_a_transaction_lock(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            orphan = root / "orphan.json"
            orphan.write_text("orphan", encoding="utf-8")

            preview = repair_orphaned_evidence(root, dry_run=True)

            self.assertEqual(preview.orphaned_files, (str(orphan),))
            self.assertFalse((root / ".master-agent-retention.flock").exists())

    def test_quarantine_refuses_source_replacement_after_scan(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            orphan = root / "orphan.json"
            displaced = root / "displaced.json"
            orphan.write_text("original", encoding="utf-8")
            real_quarantine = retention._quarantine_owned_name_at
            raced = False

            def race_source(
                source_parent: int,
                destination_parent: int,
                name: str,
                expected_identity: tuple[int, int],
                expected_mode: int,
            ) -> None:
                nonlocal raced
                raced = True
                orphan.rename(displaced)
                orphan.write_text("replacement", encoding="utf-8")
                real_quarantine(
                    source_parent,
                    destination_parent,
                    name,
                    expected_identity,
                    expected_mode,
                )

            with patch.object(
                retention,
                "_quarantine_owned_name_at",
                side_effect=race_source,
            ):
                repair = repair_orphaned_evidence(root, dry_run=False)

            self.assertTrue(raced)
            self.assertTrue(repair.errors)
            self.assertEqual(orphan.read_text(encoding="utf-8"), "replacement")
            self.assertEqual(displaced.read_text(encoding="utf-8"), "original")
            self.assertFalse((root / ".retention-quarantine" / "orphan.json").exists())

    def test_quarantine_refuses_an_incomplete_bounded_scan(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "a.json"
            second = root / "b.json"
            first.write_text("first", encoding="utf-8")
            second.write_text("second", encoding="utf-8")

            repair = repair_orphaned_evidence(
                root,
                dry_run=False,
                max_files=1,
            )

            self.assertTrue(repair.errors)
            self.assertEqual(repair.quarantined_files, ())
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())

    def test_orphaned_symlink_is_quarantined_without_following_target(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "evidence"
            root.mkdir(mode=0o700)
            target = base / "target.txt"
            target.write_text("target", encoding="utf-8")
            link = root / "orphan-link"
            link.symlink_to(Path("..") / target.name)

            repair = repair_orphaned_evidence(root, dry_run=False)
            quarantined_link = root / ".retention-quarantine" / link.name

            self.assertEqual(repair.errors, ())
            self.assertFalse(link.exists())
            self.assertTrue(quarantined_link.is_symlink())
            self.assertEqual(
                quarantined_link.readlink(),
                Path("..") / target.name,
            )
            self.assertEqual(target.read_text(encoding="utf-8"), "target")

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

            with self.assertRaisesRegex(ConfigurationError, "pruning is disabled"):
                purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=73),
                    dry_run=False,
                )
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

    def test_prohibited_evidence_cannot_be_persisted(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with (
            TemporaryDirectory() as directory,
            self.assertRaisesRegex(ConfigurationError, "prohibits"),
        ):
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
                dry_run=True,
            )

            self.assertTrue(result.errors)
            self.assertTrue(victim.exists())
            victim.unlink()

    def test_destructive_maintenance_rejects_before_traversal(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(retention, "_purge_expired_evidence_locked") as purge,
                self.assertRaisesRegex(ConfigurationError, "pruning is disabled"),
            ):
                purge_expired_evidence(root, dry_run=False)
            purge.assert_not_called()

            expected = retention.RetentionRepairResult(
                scanned_files=0,
                orphaned_files=(),
                quarantined_files=(),
                errors=(),
                dry_run=False,
            )
            with patch.object(
                retention,
                "_repair_orphaned_evidence_locked",
                return_value=expected,
            ) as repair:
                self.assertIs(
                    repair_orphaned_evidence(root, dry_run=False),
                    expected,
                )
            repair.assert_called_once_with(root, dry_run=False, max_files=10_000)


def _citation_id(system: str, resource_type: str, resource_id: str) -> str:
    identity = f"{system}\0{resource_type}\0{resource_id}".encode()
    return "CIT-" + hashlib.sha256(identity).hexdigest()[:12].upper()


if __name__ == "__main__":
    unittest.main()
