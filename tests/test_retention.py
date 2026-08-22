"""Retention-policy and expiration cleanup tests."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent import retention
from master_agent.directory_safety import PinnedDirectory
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
            self.assertFalse(
                (Path(directory) / retention._RETENTION_FLOCK_NAME).exists()
            )

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
            applied_repair = repair_orphaned_evidence(root, dry_run=False)

            self.assertTrue(purge.errors)
            self.assertEqual(purge.removed_files, ())
            self.assertEqual(
                set(repair.orphaned_files),
                {str(evidence), str(sidecar)},
            )
            self.assertTrue(
                any(
                    "content digest mismatch" in error
                    for error in applied_repair.errors
                )
            )
            self.assertFalse(
                any("quarantine refused" in error for error in applied_repair.errors)
            )
            self.assertEqual(len(applied_repair.quarantined_files), 2)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            self.assertEqual(
                {Path(path).name for path in applied_repair.quarantined_files},
                {evidence.name, sidecar.name},
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

    def test_ancestor_repair_refuses_child_first_active_publication(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir(mode=0o700)
            evidence = child / "result.txt"
            sidecar = child / "result.txt.retention.json"
            sidecar_published = threading.Event()
            release_publication = threading.Event()
            real_publish = retention._publish_restricted_temp_file_at
            writer_errors: list[BaseException] = []

            def publish_then_pause(
                parent_descriptor: int,
                temporary_name: str,
                final_name: str,
                identity: tuple[int, int],
            ) -> None:
                real_publish(
                    parent_descriptor,
                    temporary_name,
                    final_name,
                    identity,
                )
                if final_name == sidecar.name:
                    sidecar_published.set()
                    if not release_publication.wait(timeout=5):
                        raise RuntimeError("test publication release timed out")

            def publish() -> None:
                try:
                    write_retained_text(
                        evidence,
                        "retained",
                        evidence_type="run-result/test",
                        config=config,
                    )
                except BaseException as error:  # noqa: BLE001
                    writer_errors.append(error)

            with patch.object(
                retention,
                "_publish_restricted_temp_file_at",
                side_effect=publish_then_pause,
            ):
                writer = threading.Thread(target=publish)
                writer.start()
                self.assertTrue(sidecar_published.wait(timeout=5))
                self.assertTrue(sidecar.is_file())
                self.assertFalse(evidence.exists())
                with self.assertRaisesRegex(
                    ConfigurationError,
                    "descendant retention maintenance is active",
                ):
                    repair_orphaned_evidence(root, dry_run=False)
                release_publication.set()
                writer.join(timeout=5)

            self.assertFalse(writer.is_alive())
            self.assertEqual(writer_errors, [])
            self.assertTrue(evidence.is_file())
            self.assertTrue(sidecar.is_file())
            preview = repair_orphaned_evidence(root, dry_run=True)
            self.assertEqual(preview.errors, ())
            self.assertEqual(preview.orphaned_files, ())

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

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "mkfifo"),
        "FIFO safety requires POSIX",
    )
    def test_repair_refuses_quarantine_when_scan_finds_a_fifo(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            orphan = root / "orphan.json"
            orphan.write_text("orphan", encoding="utf-8")
            fifo = root / "unsupported.fifo"
            os.mkfifo(fifo, mode=0o600)

            repair = repair_orphaned_evidence(root, dry_run=False)

            self.assertTrue(
                any(
                    "unsupported.fifo: unsupported retained file type" in error
                    for error in repair.errors
                )
            )
            self.assertTrue(
                any(
                    "descriptor scan was incomplete" in error for error in repair.errors
                )
            )
            self.assertEqual(repair.orphaned_files, (str(orphan),))
            self.assertEqual(repair.quarantined_files, ())
            self.assertTrue(orphan.exists())
            self.assertTrue(fifo.exists())
            self.assertFalse((root / retention._RETENTION_QUARANTINE_NAME).exists())

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

            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=73),
                dry_run=False,
            )
            repeated = purge_expired_evidence(
                root,
                now=created + timedelta(hours=73),
                dry_run=False,
            )

            self.assertEqual(applied.errors, ())
            self.assertEqual(applied.removed_files, preview.removed_files)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            self.assertEqual(repeated.expired_manifests, 0)
            self.assertEqual(repeated.removed_files, ())
            self.assertEqual(repeated.errors, ())

    def test_prune_ignores_unrelated_runtime_file_and_deletes_expired_pair(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            unrelated = root / "audit.sqlite3"
            unrelated.write_bytes(b"unrelated runtime state\n")
            unrelated.chmod(0o600)
            evidence, sidecar = write_retained_text(
                root / "expired.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(result.errors, ())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            self.assertEqual(
                unrelated.read_bytes(),
                b"unrelated runtime state\n",
            )

    def test_prune_round_trips_writer_serialization_independent_of_suffix(
        self,
    ) -> None:
        class ChangingString:
            def __init__(self) -> None:
                self.calls = 0

            def __str__(self) -> str:
                self.calls += 1
                return f"value-{self.calls}"

        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            text_evidence, text_sidecar = write_retained_text(
                root / "plain.json",
                "not JSON",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            json_evidence, json_sidecar = write_retained_json(
                root / "payload.txt",
                {"value": 1},
                evidence_type="run-result/test",
                config=config,
                include_content=True,
                now=created,
            )
            changing = ChangingString()
            changing_evidence, changing_sidecar = write_retained_json(
                root / "changing.data",
                {"value": changing},
                evidence_type="run-result/test",
                config=config,
                include_content=True,
                now=created,
            )

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(result.errors, ())
            self.assertEqual(
                set(result.removed_files),
                {
                    str(text_evidence),
                    str(text_sidecar),
                    str(json_evidence),
                    str(json_sidecar),
                    str(changing_evidence),
                    str(changing_sidecar),
                },
            )
            self.assertEqual(changing.calls, 1)
            self.assertFalse(text_evidence.exists())
            self.assertFalse(text_sidecar.exists())
            self.assertFalse(json_evidence.exists())
            self.assertFalse(json_sidecar.exists())
            self.assertFalse(changing_evidence.exists())
            self.assertFalse(changing_sidecar.exists())

    def test_retained_publication_enforces_prune_schema_and_size_bounds(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(retention, "_MAX_REPAIR_FILE_BYTES", 512):
                evidence, sidecar = write_retained_text(
                    root / "at-limit.txt",
                    "x" * 512,
                    evidence_type="run-result/test",
                    config=config,
                    now=created,
                )
                with self.assertRaisesRegex(ConfigurationError, "size limit"):
                    write_retained_text(
                        root / "too-large.txt",
                        "x" * 513,
                        evidence_type="run-result/test",
                        config=config,
                        now=created,
                    )
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertEqual(result.errors, ())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            self.assertFalse((root / "too-large.txt").exists())
            self.assertFalse((root / "too-large.txt.retention.json").exists())

            invalid_cases: tuple[tuple[str, tuple[str, ...]], ...] = (
                ("   ", ()),
                ("run-result/test", ("",)),
            )
            for index, (evidence_type, citation_ids) in enumerate(invalid_cases):
                with self.subTest(index=index), self.assertRaises(ConfigurationError):
                    write_retained_text(
                        root / f"invalid-{index}.txt",
                        "invalid",
                        evidence_type=evidence_type,
                        citation_ids=citation_ids,
                        config=config,
                        now=created,
                    )
            with self.assertRaises(ConfigurationError):
                write_retained_text(
                    root / "invalid-2.txt",
                    "invalid",
                    evidence_type="run-result/test",
                    citation_ids=(123,),  # type: ignore[arg-type]
                    config=config,
                    now=created,
                )
            self.assertFalse(
                any(path.name.startswith("invalid-") for path in root.iterdir())
            )

    def test_prune_normalizes_transaction_directories_under_restrictive_umask(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )

            previous_umask = os.umask(0o777)
            try:
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )
            finally:
                os.umask(previous_umask)

            self.assertEqual(result.errors, ())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)

    def test_apply_recovers_private_directories_left_before_chmod(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            stage.mkdir(mode=0o700)
            transaction = stage / "txn-before-chmod"
            transaction.mkdir(mode=0o700)
            transaction.chmod(0o000)
            stage.chmod(0o000)

            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=True,
            )

            self.assertTrue(preview.errors)
            self.assertEqual(preview.removed_files, ())
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o000)
            stage.chmod(0o700)
            self.assertEqual(stat.S_IMODE(transaction.stat().st_mode), 0o000)
            stage.chmod(0o000)

            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(applied.errors, ())
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
            self.assertFalse(transaction.exists())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_apply_recovers_root_lock_left_before_chmod(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            lock = root / retention._RETENTION_FLOCK_NAME
            lock.chmod(0o000)

            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=True,
            )

            self.assertTrue(preview.errors)
            self.assertEqual(preview.removed_files, ())
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o000)

            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(applied.errors, ())
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_apply_recovers_transaction_marker_left_before_chmod(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            stage.mkdir(mode=0o700)
            transaction = stage / "txn-marker-before-chmod"
            transaction.mkdir(mode=0o700)
            marker = transaction / retention._RETENTION_PRUNE_MARKER_NAME
            marker.write_text("{}\n", encoding="utf-8")
            marker.chmod(0o000)

            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=True,
            )

            self.assertTrue(preview.errors)
            self.assertEqual(preview.removed_files, ())
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o000)

            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(applied.errors, ())
            self.assertFalse(transaction.exists())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_retained_evidence_rejects_reserved_names_case_insensitively(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        reserved_names = (
            ".MASTER-AGENT-RETENTION.FLOCK",
            ".RETENTION-PRUNE",
            ".RETENTION-QUARANTINE",
            "result.RETENTION.JSON",
        )
        for name in reserved_names:
            with self.subTest(name=name), TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaisesRegex(ConfigurationError, "reserved"):
                    write_retained_text(
                        root / name,
                        "must not be written",
                        evidence_type="run-result/test",
                        config=config,
                    )
                self.assertEqual(tuple(root.iterdir()), ())

    def test_prune_preserves_future_evidence_and_uses_one_candidate_order(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            expired, expired_sidecar = write_retained_text(
                root / "a-expired.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            future, future_sidecar = write_retained_text(
                root / "b-future.txt",
                "future",
                evidence_type="run-result/test",
                config=config,
                now=created + timedelta(hours=12),
            )
            current = created + timedelta(hours=25)

            preview = purge_expired_evidence(root, now=current, dry_run=True)
            applied = purge_expired_evidence(root, now=current, dry_run=False)

            self.assertEqual(preview.errors, ())
            self.assertEqual(preview.removed_files, applied.removed_files)
            self.assertEqual(
                tuple(Path(value).name for value in applied.removed_files),
                (expired.name, expired_sidecar.name),
            )
            self.assertFalse(expired.exists())
            self.assertFalse(expired_sidecar.exists())
            self.assertTrue(future.exists())
            self.assertTrue(future_sidecar.exists())

    def test_prune_fails_closed_for_any_malformed_record(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "valid.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            malformed = root / "malformed.retention.json"
            malformed.write_text("{}\n", encoding="utf-8")
            malformed.chmod(0o600)

            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=True,
            )
            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertTrue(preview.errors)
            self.assertTrue(applied.errors)
            self.assertEqual(preview.removed_files, ())
            self.assertEqual(applied.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertTrue(malformed.exists())

    def test_prune_rejects_a_sidecar_used_as_another_pairs_evidence(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "payload",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            sidecar_value = json.loads(sidecar.read_text(encoding="utf-8"))
            outer_sidecar = root / f"{sidecar.name}.retention.json"
            outer_sidecar.write_text(
                json.dumps(
                    {
                        "evidence_path": sidecar.name,
                        "evidence_type": "run-result/test",
                        "created_at": created.isoformat(),
                        "expires_at": current.isoformat(),
                        "persistence": "explicit_content",
                        "content_included": True,
                        "content_digest": content_digest(sidecar_value),
                        "citation_ids": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            outer_sidecar.chmod(0o600)

            preview = purge_expired_evidence(root, now=current, dry_run=True)
            applied = purge_expired_evidence(root, now=current, dry_run=False)

            self.assertTrue(preview.errors)
            self.assertTrue(applied.errors)
            self.assertEqual(preview.removed_files, ())
            self.assertEqual(applied.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertTrue(outer_sidecar.exists())

    def test_prune_rejects_symlinks_without_following_them(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "evidence"
            root.mkdir(mode=0o700)
            evidence, sidecar = write_retained_text(
                root / "valid.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            victim = base / "victim.retention.json"
            victim.write_text("outside\n", encoding="utf-8")
            link = root / "linked.retention.json"
            link.symlink_to(victim)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertTrue(result.errors)
            self.assertEqual(result.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertEqual(victim.read_text(encoding="utf-8"), "outside\n")

    def test_prune_rejects_unsafe_permissions_and_hard_links(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "valid.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            extra_link = root / "linked.txt"
            os.link(evidence, extra_link)
            sidecar.chmod(0o640)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertTrue(result.errors)
            self.assertEqual(result.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertTrue(extra_link.exists())

    def test_prune_preflights_cross_device_pairs_before_any_deletion(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_sidecar = write_retained_text(
                root / "a.txt",
                "first",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            second, second_sidecar = write_retained_text(
                root / "b.txt",
                "second",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            with PinnedDirectory.open(root) as pinned:
                records, scan_errors = retention._scan_retained_files_at(
                    pinned.fileno(),
                    max_files=100,
                    strict_unsupported=False,
                )
            self.assertEqual(scan_errors, [])
            modeled_records = [
                retention._RetainedFileRecord(
                    relative_parts=record.relative_parts,
                    identity=(record.identity[0] + 1, record.identity[1]),
                    mode=record.mode,
                    size=record.size,
                )
                if record.relative_parts == (second_sidecar.name,)
                else record
                for record in records
            ]

            with patch.object(
                retention,
                "_scan_retained_files_at",
                return_value=(modeled_records, []),
            ):
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertTrue(result.errors)
            self.assertEqual(result.removed_files, ())
            self.assertTrue(first.exists())
            self.assertTrue(first_sidecar.exists())
            self.assertTrue(second.exists())
            self.assertTrue(second_sidecar.exists())

    def test_prune_refuses_an_incomplete_bounded_scan(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_sidecar = write_retained_text(
                root / "a.txt",
                "first",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            second, second_sidecar = write_retained_text(
                root / "b.txt",
                "second",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
                max_manifests=1,
            )

            self.assertTrue(result.errors)
            self.assertEqual(result.removed_files, ())
            for path in (first, first_sidecar, second, second_sidecar):
                self.assertTrue(path.exists())

    def test_prune_bounds_empty_directory_fanout_before_deletion(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            for index in range(10):
                (root / f"empty-{index:02d}").mkdir(mode=0o700)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
                max_manifests=2,
            )

            self.assertTrue(result.errors)
            self.assertTrue(any("entry limit" in value for value in result.errors))
            self.assertEqual(result.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

    def test_prune_recovers_empty_transaction_before_deleting_expired_pair(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            stage.mkdir(mode=0o700)
            empty_transaction = stage / "txn-empty"
            empty_transaction.mkdir(mode=0o700)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(result.errors, ())
            self.assertFalse(empty_transaction.exists())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_prune_rolls_back_malformed_marker_only_transaction_before_deletion(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            stage.mkdir(mode=0o700)
            transaction = stage / "txn-malformed"
            transaction.mkdir(mode=0o700)
            marker = transaction / retention._RETENTION_PRUNE_MARKER_NAME
            marker.write_text("{}\n", encoding="utf-8")
            marker.chmod(0o600)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(result.errors, ())
            self.assertFalse(transaction.exists())
            self.assertFalse(marker.exists())
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_prune_bounds_transaction_stage_before_deletion(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            stage.mkdir(mode=0o700)
            for name in ("txn-a", "txn-b"):
                (stage / name).mkdir(mode=0o700)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
                max_manifests=1,
            )

            self.assertTrue(result.errors)
            self.assertTrue(any("transaction" in value for value in result.errors))
            self.assertEqual(result.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())
            self.assertEqual(
                tuple(path.name for path in sorted(stage.iterdir())),
                ("txn-a", "txn-b"),
            )

    def test_prune_deletes_a_nested_pair_under_its_publication_lock(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir(mode=0o700)
            evidence, sidecar = write_retained_text(
                nested / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )

            preview = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=True,
            )
            applied = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertEqual(preview.errors, ())
            self.assertEqual(applied.errors, ())
            self.assertEqual(preview.removed_files, applied.removed_files)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            self.assertTrue((nested / retention._RETENTION_FLOCK_NAME).is_file())

    def test_prune_sanitizes_excessive_sidecar_nesting(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "valid.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            deeply_nested = root / "deep.retention.json"
            deeply_nested.write_text(
                '{"nested":' * 2_000 + "0" + "}" * 2_000 + "\n",
                encoding="utf-8",
            )
            deeply_nested.chmod(0o600)

            result = purge_expired_evidence(
                root,
                now=created + timedelta(hours=25),
                dry_run=False,
            )

            self.assertTrue(result.errors)
            self.assertEqual(result.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

    def test_prune_refuses_file_substitution_after_planning(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "original",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            displaced = root / "displaced.txt"
            real_link = retention._link_prune_stage_file_at
            raced = False

            def substitute_before_link(
                root_descriptor: int,
                record: retention._RetainedFileRecord,
                transaction_descriptor: int,
                stage_name: str,
            ) -> None:
                nonlocal raced
                if stage_name == retention._RETENTION_PRUNE_EVIDENCE_NAME:
                    raced = True
                    evidence.rename(displaced)
                    evidence.write_text("replacement", encoding="utf-8")
                    evidence.chmod(0o600)
                real_link(
                    root_descriptor,
                    record,
                    transaction_descriptor,
                    stage_name,
                )

            with patch.object(
                retention,
                "_link_prune_stage_file_at",
                side_effect=substitute_before_link,
            ):
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertTrue(raced)
            self.assertTrue(result.errors)
            self.assertEqual(result.removed_files, ())
            self.assertEqual(evidence.read_text(encoding="utf-8"), "replacement")
            self.assertEqual(displaced.read_text(encoding="utf-8"), "original")
            self.assertTrue(sidecar.exists())

    def test_prune_coordinates_with_the_retention_lock(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            with PinnedDirectory.open(root) as pinned:
                lock_descriptor, _ = retention._open_retention_lock(pinned.fileno())
                try:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    preview = purge_expired_evidence(
                        root,
                        now=created + timedelta(hours=25),
                        dry_run=True,
                    )
                    with self.assertRaisesRegex(
                        ConfigurationError,
                        "retention maintenance is active",
                    ):
                        purge_expired_evidence(
                            root,
                            now=created + timedelta(hours=25),
                            dry_run=False,
                        )
                finally:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                    os.close(lock_descriptor)

            self.assertTrue(preview.errors)
            self.assertEqual(preview.removed_files, ())
            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

    def test_hierarchy_lock_closes_descriptor_when_flock_errors(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir(mode=0o700)
            with PinnedDirectory.open(root) as pinned:
                descriptor, _ = retention._open_retention_lock(pinned.fileno())
                os.close(descriptor)

            attempted: list[int] = []

            def fail_lock(descriptor: int, _operation: int) -> None:
                attempted.append(descriptor)
                raise OSError("simulated flock failure")

            with (
                PinnedDirectory.open(child) as pinned,
                patch.object(retention.fcntl, "flock", side_effect=fail_lock),
                self.assertRaisesRegex(OSError, "simulated flock failure"),
            ):
                retention._acquire_retention_directory_hierarchy(pinned)

            self.assertEqual(len(attempted), 1)
            with self.assertRaises(OSError):
                os.fstat(attempted[0])

    def test_descendant_lock_closes_descriptor_when_flock_errors(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir(mode=0o700)
            with PinnedDirectory.open(child) as pinned:
                descriptor, _ = retention._open_retention_lock(pinned.fileno())
                os.close(descriptor)

            attempted: list[int] = []

            def fail_lock(descriptor: int, _operation: int) -> None:
                attempted.append(descriptor)
                raise OSError("simulated flock failure")

            with (
                PinnedDirectory.open(root) as pinned,
                patch.object(retention.fcntl, "flock", side_effect=fail_lock),
                self.assertRaisesRegex(OSError, "simulated flock failure"),
            ):
                retention._acquire_descendant_retention_locks_at(
                    pinned.fileno(),
                    {("child",)},
                    dry_run=True,
                )

            self.assertEqual(len(attempted), 1)
            with self.assertRaises(OSError):
                os.fstat(attempted[0])

    def test_nested_publication_after_rescan_is_refused_by_root_hierarchy(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            later = root / "later"
            later.mkdir(mode=0o700)
            evidence, sidecar = write_retained_text(
                root / "old.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            real_plan = retention._plan_retained_pairs_at
            publication_errors: list[ConfigurationError] = []

            def plan_then_publish(
                root_descriptor: int,
                records: list[retention._RetainedFileRecord],
                *,
                max_manifests: int,
            ) -> tuple[
                list[retention._RetainedEvidencePair],
                list[str],
                int,
            ]:
                plan = real_plan(
                    root_descriptor,
                    records,
                    max_manifests=max_manifests,
                )
                try:
                    write_retained_text(
                        later / "new.txt",
                        "concurrent",
                        evidence_type="run-result/test",
                        config=config,
                        now=created,
                    )
                except ConfigurationError as error:
                    publication_errors.append(error)
                return plan

            with patch.object(
                retention,
                "_plan_retained_pairs_at",
                side_effect=plan_then_publish,
            ):
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertEqual(result.errors, ())
            self.assertEqual(len(publication_errors), 1)
            self.assertIn("hierarchy", str(publication_errors[0]))
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            self.assertFalse((later / "new.txt").exists())
            self.assertFalse((later / "new.txt.retention.json").exists())

    def test_recovery_fsyncs_absent_sources_before_discarding_stage(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            root_identity = (root.stat().st_dev, root.stat().st_ino)
            real_fsync = retention.os.fsync
            commit_syncs = 0

            def interrupt_first_commit_sync(descriptor: int) -> None:
                nonlocal commit_syncs
                metadata = os.fstat(descriptor)
                if (
                    (metadata.st_dev, metadata.st_ino) == root_identity
                    and not evidence.exists()
                    and not sidecar.exists()
                ):
                    commit_syncs += 1
                    if commit_syncs == 1:
                        raise OSError("simulated source-parent fsync interruption")
                real_fsync(descriptor)

            with patch.object(
                retention.os,
                "fsync",
                side_effect=interrupt_first_commit_sync,
            ):
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertEqual(result.errors, ())
            self.assertGreaterEqual(commit_syncs, 2)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())
            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            self.assertEqual(tuple(stage.iterdir()), ())

    def test_failed_recovery_commit_sync_preserves_transaction(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            root_identity = (root.stat().st_dev, root.stat().st_ino)
            real_fsync = retention.os.fsync
            refused_syncs = 0

            def refuse_commit_sync(descriptor: int) -> None:
                nonlocal refused_syncs
                metadata = os.fstat(descriptor)
                if (
                    (metadata.st_dev, metadata.st_ino) == root_identity
                    and not evidence.exists()
                    and not sidecar.exists()
                ):
                    refused_syncs += 1
                    raise OSError("simulated persistent source-parent fsync failure")
                real_fsync(descriptor)

            with patch.object(
                retention.os,
                "fsync",
                side_effect=refuse_commit_sync,
            ):
                interrupted = purge_expired_evidence(
                    root,
                    now=current,
                    dry_run=False,
                )

            stage = root / retention._RETENTION_PRUNE_STAGE_NAME
            self.assertTrue(interrupted.errors)
            self.assertEqual(interrupted.removed_files, ())
            self.assertGreaterEqual(refused_syncs, 2)
            self.assertEqual(len(tuple(stage.iterdir())), 1)

            recovered = purge_expired_evidence(
                root,
                now=current,
                dry_run=False,
            )

            self.assertEqual(recovered.errors, ())
            self.assertEqual(
                set(recovered.removed_files),
                {str(evidence.resolve()), str(sidecar.resolve())},
            )
            self.assertEqual(tuple(stage.iterdir()), ())

    def test_ancestor_prune_reports_pending_nested_root_transaction(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir(mode=0o700)
            child_evidence, child_sidecar = write_retained_text(
                child / "child.txt",
                "child expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            root_evidence, root_sidecar = write_retained_text(
                root / "root.txt",
                "root expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            real_unlink = retention._unlink_relative_record_at
            interrupted = False

            def unlink_sidecar_then_interrupt(
                root_descriptor: int,
                record: retention._RetainedFileRecord,
                *,
                allowed_link_counts: frozenset[int],
            ) -> None:
                nonlocal interrupted
                real_unlink(
                    root_descriptor,
                    record,
                    allowed_link_counts=allowed_link_counts,
                )
                if not interrupted and record.name == child_sidecar.name:
                    interrupted = True
                    raise OSError("simulated child-root process loss")

            with (
                patch.object(
                    retention,
                    "_unlink_relative_record_at",
                    side_effect=unlink_sidecar_then_interrupt,
                ),
                patch.object(
                    retention,
                    "_recover_prune_transaction_at",
                    side_effect=OSError("simulated process loss"),
                ),
            ):
                child_result = purge_expired_evidence(
                    child,
                    now=current,
                    dry_run=False,
                )

            ancestor_result = purge_expired_evidence(
                root,
                now=current,
                dry_run=False,
            )

            self.assertTrue(interrupted)
            self.assertTrue(child_result.errors)
            self.assertTrue(
                any("exact root" in error for error in ancestor_result.errors)
            )
            self.assertEqual(ancestor_result.removed_files, ())
            self.assertTrue(child_evidence.exists())
            self.assertFalse(child_sidecar.exists())
            self.assertTrue(root_evidence.exists())
            self.assertTrue(root_sidecar.exists())

            child_recovered = purge_expired_evidence(
                child,
                now=current,
                dry_run=False,
            )
            ancestor_applied = purge_expired_evidence(
                root,
                now=current,
                dry_run=False,
            )

            self.assertEqual(child_recovered.errors, ())
            self.assertEqual(ancestor_applied.errors, ())
            self.assertFalse(child_evidence.exists())
            self.assertFalse(root_evidence.exists())
            self.assertFalse(root_sidecar.exists())

    def test_interrupted_pair_transaction_is_recovered_by_repeated_apply(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            current = created + timedelta(hours=25)

            with (
                patch.object(
                    retention,
                    "_unlink_relative_record_at",
                    side_effect=OSError("simulated interruption"),
                ),
                patch.object(
                    retention,
                    "_recover_prune_transaction_at",
                    side_effect=OSError("simulated process loss"),
                ),
            ):
                interrupted = purge_expired_evidence(
                    root,
                    now=current,
                    dry_run=False,
                )

            pending_preview = purge_expired_evidence(
                root,
                now=current,
                dry_run=True,
            )
            recovered = purge_expired_evidence(
                root,
                now=current,
                dry_run=False,
            )

            self.assertTrue(interrupted.errors)
            self.assertEqual(interrupted.removed_files, ())
            self.assertTrue(pending_preview.errors)
            self.assertEqual(pending_preview.removed_files, ())
            self.assertEqual(recovered.errors, ())
            self.assertEqual(len(recovered.removed_files), 2)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_interrupted_pair_at_maximum_directory_depth_is_recoverable(
        self,
    ) -> None:
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root
            for _ in range(retention._MAX_REPAIR_DEPTH):
                parent /= "d"
                parent.mkdir(mode=0o700)
            evidence = parent / "result.txt"
            sidecar = parent / "result.txt.retention.json"
            evidence.write_text("expired", encoding="utf-8")
            evidence.chmod(0o600)
            sidecar.write_text(
                json.dumps(
                    {
                        "evidence_path": evidence.name,
                        "evidence_type": "run-result/test",
                        "created_at": created.isoformat(),
                        "expires_at": current.isoformat(),
                        "persistence": "explicit_content",
                        "content_included": True,
                        "content_digest": content_digest("expired"),
                        "citation_ids": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar.chmod(0o600)

            with (
                patch.object(
                    retention,
                    "_unlink_relative_record_at",
                    side_effect=OSError("simulated interruption"),
                ),
                patch.object(
                    retention,
                    "_recover_prune_transaction_at",
                    side_effect=OSError("simulated process loss"),
                ),
            ):
                interrupted = purge_expired_evidence(
                    root,
                    now=current,
                    dry_run=False,
                )
            recovered = purge_expired_evidence(
                root,
                now=current,
                dry_run=False,
            )

            self.assertTrue(interrupted.errors)
            self.assertEqual(recovered.errors, ())
            self.assertEqual(
                set(recovered.removed_files), {str(evidence), str(sidecar)}
            )
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_marker_cleanup_failure_reports_a_completed_pair(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            real_unlink = retention._unlink_stage_record_at
            interrupted = False

            def fail_marker_once(
                transaction_descriptor: int,
                name: str,
                identity: tuple[int, int],
            ) -> None:
                nonlocal interrupted
                if name == retention._RETENTION_PRUNE_MARKER_NAME and not interrupted:
                    interrupted = True
                    raise OSError("simulated marker cleanup failure")
                real_unlink(transaction_descriptor, name, identity)

            with patch.object(
                retention,
                "_unlink_stage_record_at",
                side_effect=fail_marker_once,
            ):
                result = purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertTrue(interrupted)
            self.assertEqual(result.errors, ())
            self.assertEqual(set(result.removed_files), {str(evidence), str(sidecar)})
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_nested_interrupted_recovery_refuses_an_active_descendant_lock(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir(mode=0o700)
            evidence, sidecar = write_retained_text(
                nested / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            with (
                patch.object(
                    retention,
                    "_unlink_relative_record_at",
                    side_effect=OSError("simulated interruption"),
                ),
                patch.object(
                    retention,
                    "_recover_prune_transaction_at",
                    side_effect=OSError("simulated process loss"),
                ),
            ):
                interrupted = purge_expired_evidence(
                    root,
                    now=current,
                    dry_run=False,
                )

            self.assertTrue(interrupted.errors)
            with PinnedDirectory.open(nested) as pinned:
                lock_descriptor, _ = retention._open_retention_lock(pinned.fileno())
                try:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaisesRegex(
                        ConfigurationError,
                        "descendant retention maintenance is active",
                    ):
                        purge_expired_evidence(
                            root,
                            now=current,
                            dry_run=False,
                        )
                finally:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                    os.close(lock_descriptor)

            self.assertTrue(evidence.exists())
            self.assertTrue(sidecar.exists())

    def test_keyboard_interrupt_recovers_current_pair_and_leaves_next_pair(
        self,
    ) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_sidecar = write_retained_text(
                root / "a.txt",
                "first",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            second, second_sidecar = write_retained_text(
                root / "b.txt",
                "second",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            real_unlink = retention._unlink_relative_record_at
            interrupted = False

            def interrupt_once(
                root_descriptor: int,
                record: retention._RetainedFileRecord,
                *,
                allowed_link_counts: frozenset[int],
            ) -> None:
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt
                real_unlink(
                    root_descriptor,
                    record,
                    allowed_link_counts=allowed_link_counts,
                )

            with (
                patch.object(
                    retention,
                    "_unlink_relative_record_at",
                    side_effect=interrupt_once,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                purge_expired_evidence(root, now=current, dry_run=False)

            self.assertTrue(interrupted)
            self.assertFalse(first.exists())
            self.assertFalse(first_sidecar.exists())
            self.assertTrue(second.exists())
            self.assertTrue(second_sidecar.exists())

    def test_keyboard_interrupt_after_final_cleanup_is_not_swallowed(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, sidecar = write_retained_text(
                root / "result.txt",
                "expired",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            real_remove = retention._remove_private_transaction_directory_at
            interrupted = False

            def remove_then_interrupt(
                stage_descriptor: int,
                name: str,
                identity: tuple[int, int],
            ) -> None:
                nonlocal interrupted
                real_remove(stage_descriptor, name, identity)
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt

            with (
                patch.object(
                    retention,
                    "_remove_private_transaction_directory_at",
                    side_effect=remove_then_interrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                purge_expired_evidence(
                    root,
                    now=created + timedelta(hours=25),
                    dry_run=False,
                )

            self.assertTrue(interrupted)
            self.assertFalse(evidence.exists())
            self.assertFalse(sidecar.exists())

    def test_recovery_and_unrelated_insertion_race_refuses_new_deletion(self) -> None:
        config = RetentionConfig.from_toml(ROOT / "config" / "retention.toml")
        created = datetime(2026, 8, 13, tzinfo=UTC)
        current = created + timedelta(hours=25)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_sidecar = write_retained_text(
                root / "a.txt",
                "first",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            second, second_sidecar = write_retained_text(
                root / "b.txt",
                "second",
                evidence_type="run-result/test",
                config=config,
                now=created,
            )
            with (
                patch.object(
                    retention,
                    "_unlink_relative_record_at",
                    side_effect=OSError("simulated interruption"),
                ),
                patch.object(
                    retention,
                    "_recover_prune_transaction_at",
                    side_effect=OSError("simulated process loss"),
                ),
            ):
                interrupted = purge_expired_evidence(
                    root,
                    now=current,
                    dry_run=False,
                )
            self.assertTrue(interrupted.errors)

            injected = root / "unrelated.tmp"
            real_recover = retention._recover_prune_transactions_at

            def recover_and_insert(
                root_descriptor: int,
                display_root: Path,
                *,
                current: datetime,
                max_transactions: int,
            ) -> tuple[list[tuple[str, str]], list[str]]:
                recovered = real_recover(
                    root_descriptor,
                    display_root,
                    current=current,
                    max_transactions=max_transactions,
                )
                injected.write_text("inserted during recovery\n", encoding="utf-8")
                injected.chmod(0o600)
                return recovered

            with patch.object(
                retention,
                "_recover_prune_transactions_at",
                side_effect=recover_and_insert,
            ):
                result = purge_expired_evidence(
                    root,
                    now=current,
                    dry_run=False,
                )

            self.assertTrue(result.errors)
            self.assertFalse(first.exists())
            self.assertFalse(first_sidecar.exists())
            self.assertTrue(second.exists())
            self.assertTrue(second_sidecar.exists())
            self.assertEqual(
                injected.read_text(encoding="utf-8"),
                "inserted during recovery\n",
            )

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
                        "evidence_type": "run-result/test",
                        "created_at": "2019-01-01T00:00:00+00:00",
                        "expires_at": "2020-01-01T00:00:00+00:00",
                        "persistence": "explicit_content",
                        "content_included": True,
                        "content_digest": "0" * 64,
                        "citation_ids": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sidecar.chmod(0o600)

            result = purge_expired_evidence(
                root,
                now=datetime(2026, 8, 13, tzinfo=UTC),
                dry_run=True,
            )

            self.assertTrue(result.errors)
            self.assertTrue(victim.exists())
            victim.unlink()

    def test_destructive_maintenance_uses_the_descriptor_bound_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            expected_purge = retention.RetentionPurgeResult(
                scanned_manifests=0,
                expired_manifests=0,
                removed_files=(),
                errors=(),
                dry_run=False,
            )
            with patch.object(
                retention,
                "_purge_expired_evidence_locked",
                return_value=expected_purge,
            ) as purge:
                self.assertIs(
                    purge_expired_evidence(root, dry_run=False),
                    expected_purge,
                )
            purge.assert_called_once_with(
                root,
                now=None,
                dry_run=False,
                max_manifests=10_000,
            )

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

    def test_windows_prune_is_capability_gated_before_traversal(self) -> None:
        with (
            TemporaryDirectory() as directory,
            patch.object(retention.os, "name", "nt"),
            patch.object(retention, "_purge_expired_evidence_locked") as purge,
            self.assertRaisesRegex(ConfigurationError, "unavailable on Windows"),
        ):
            purge_expired_evidence(Path(directory), dry_run=False)

        purge.assert_not_called()


def _citation_id(system: str, resource_type: str, resource_id: str) -> str:
    identity = f"{system}\0{resource_type}\0{resource_id}".encode()
    return "CIT-" + hashlib.sha256(identity).hexdigest()[:12].upper()


if __name__ == "__main__":
    unittest.main()
