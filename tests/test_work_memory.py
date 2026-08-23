"""Persistent issue-to-merge work-memory tests."""

from __future__ import annotations

import json
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from master_agent.approval_handoff import validate_restricted_json_payload
from master_agent.cli import main
from master_agent.errors import ValidationError
from master_agent.sqlite_safety import PinnedSQLiteDatabase
from master_agent.work_memory import (
    WorkEventKind,
    WorkMemory,
    WorkMemoryError,
    WorkStage,
)
from tests.helpers import private_temporary_directory


class WorkMemoryTests(unittest.TestCase):
    """Exercise persistence, integrity, lifecycle, bounds, and CLI behavior."""

    def test_issue_to_merge_survives_process_restart(self) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            with WorkMemory(database) as memory:
                started = memory.start(
                    work_id="issue-161",
                    issue="https://github.com/RoryGlenn/MasterAgent/issues/161",
                    summary="Add bounded persistent work memory.",
                )
                self.assertEqual(started.stage, WorkStage.ISSUE)
                memory.record(
                    work_id="issue-161",
                    kind=WorkEventKind.DECISION,
                    stage=WorkStage.PLANNED,
                    summary="Use an append-only local SQLite journal.",
                )

            for stage in (
                WorkStage.IMPLEMENTING,
                WorkStage.REVIEWING,
                WorkStage.VERIFIED,
                WorkStage.MERGED,
            ):
                with WorkMemory(database) as memory:
                    snapshot = memory.record(
                        work_id="issue-161",
                        kind=WorkEventKind.CHECKPOINT,
                        stage=stage,
                        summary=f"Advanced work to {stage.value}.",
                    )
                    self.assertEqual(snapshot.stage, stage)

            snapshot = WorkMemory.show_existing(database, "issue-161")
            self.assertEqual(snapshot.stage, WorkStage.MERGED)
            self.assertEqual(len(snapshot.events), 6)
            self.assertTrue(snapshot.to_dict()["untrusted_metadata"])
            verification = WorkMemory.verify_existing(database)
            self.assertTrue(verification.valid, verification.message)
            self.assertEqual(verification.event_count, 6)
            self.assertEqual(verification.work_count, 1)

    def test_lifecycle_regression_skip_duplicate_and_post_merge_fail_closed(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            with WorkMemory(database) as memory:
                memory.start(work_id="issue-1", issue="#1", summary="Start work.")
                with self.assertRaisesRegex(WorkMemoryError, "already exists"):
                    memory.start(
                        work_id="issue-1",
                        issue="#1",
                        summary="Start twice.",
                    )
                with self.assertRaisesRegex(WorkMemoryError, "skip"):
                    memory.record(
                        work_id="issue-1",
                        kind=WorkEventKind.CHECKPOINT,
                        stage=WorkStage.IMPLEMENTING,
                        summary="Skip planning.",
                    )
                memory.record(
                    work_id="issue-1",
                    kind=WorkEventKind.CHECKPOINT,
                    stage=WorkStage.PLANNED,
                    summary="Plan the work.",
                )
                with self.assertRaisesRegex(WorkMemoryError, "regress"):
                    memory.record(
                        work_id="issue-1",
                        kind=WorkEventKind.CHECKPOINT,
                        stage=WorkStage.ISSUE,
                        summary="Move backwards.",
                    )
                for stage in (
                    WorkStage.IMPLEMENTING,
                    WorkStage.REVIEWING,
                    WorkStage.VERIFIED,
                    WorkStage.MERGED,
                ):
                    memory.record(
                        work_id="issue-1",
                        kind=WorkEventKind.CHECKPOINT,
                        stage=stage,
                        summary=f"Advance to {stage.value}.",
                    )
                with self.assertRaisesRegex(WorkMemoryError, "terminal"):
                    memory.record(
                        work_id="issue-1",
                        kind=WorkEventKind.DECISION,
                        summary="Append after merge.",
                    )
            self.assertEqual(
                WorkMemory.verify_existing(database).event_count,
                6,
            )

    def test_reference_events_and_sensitive_or_unbounded_input_are_rejected(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            with WorkMemory(database) as memory:
                memory.start(work_id="issue-2", issue="#2", summary="Start work.")
                with self.assertRaisesRegex(ValueError, "require --reference"):
                    memory.record(
                        work_id="issue-2",
                        kind=WorkEventKind.REFERENCE,
                        summary="Remember a pull request.",
                    )
                with self.assertRaisesRegex(ValueError, "sensitive"):
                    memory.record(
                        work_id="issue-2",
                        kind=WorkEventKind.DECISION,
                        summary="token=secret-value",
                    )
                for credential in (
                    "Authorization: Basic dXNlcjpwYXNz",
                    "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
                    "AWS_SECRET_ACCESS_KEY=example-secret-value",
                    "SharedAccessSignature=example-signature-value",
                    "xoxb-1234567890-secret",
                    "AIza1234567890abcdefghijklmnopqrstuvwxyz",
                    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature12345678",
                ):
                    with (
                        self.subTest(credential=credential),
                        self.assertRaisesRegex(
                            ValueError,
                            "sensitive",
                        ),
                    ):
                        memory.record(
                            work_id="issue-2",
                            kind=WorkEventKind.DECISION,
                            summary=credential,
                        )
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    memory.record(
                        work_id="issue-2",
                        kind=WorkEventKind.REFERENCE,
                        summary="Remember a review.",
                        reference="https://example.test/review?view=full",
                    )
                self.assertEqual(
                    memory.show("issue-2").journal_event_count,
                    1,
                )
                with self.assertRaisesRegex(ValueError, "work ID is invalid"):
                    memory.start(
                        work_id="AKIA1234567890ABCDEF",
                        issue="#credential",
                        summary="Do not retain a credential-shaped work ID.",
                    )
                self.assertEqual(
                    memory.show("issue-2").journal_event_count,
                    1,
                )
                with self.assertRaisesRegex(ValueError, "invalid or sensitive"):
                    memory.record(
                        work_id="issue-2",
                        kind=WorkEventKind.DECISION,
                        summary="x" * 2_049,
                    )

    def test_concurrent_writers_preserve_every_event(self) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            with WorkMemory(database) as memory:
                memory.start(work_id="issue-3", issue="#3", summary="Start work.")
                memory.record(
                    work_id="issue-3",
                    kind=WorkEventKind.CHECKPOINT,
                    stage=WorkStage.PLANNED,
                    summary="Plan work.",
                )

            def append(index: int) -> None:
                with WorkMemory(database) as memory:
                    memory.record(
                        work_id="issue-3",
                        kind=WorkEventKind.DECISION,
                        summary=f"Concurrent decision {index}.",
                    )

            with ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(append, range(12)))

            verification = WorkMemory.verify_existing(database)
            self.assertTrue(verification.valid, verification.message)
            self.assertEqual(verification.event_count, 14)
            snapshot = WorkMemory.show_existing(database, "issue-3")
            self.assertEqual(len(snapshot.events), 14)

    def test_hash_tampering_deletion_and_schema_drift_are_detected(self) -> None:
        for mutation, expected in (
            (
                "UPDATE work_events SET summary = 'edited' WHERE sequence = 1",
                "event hash mismatch",
            ),
            (
                "DELETE FROM work_events WHERE sequence = 1",
                "event sequence gap",
            ),
            (
                "UPDATE work_memory_state SET head_hash = " + "'" + ("0" * 64) + "'",
                "checkpoint head",
            ),
            (
                (
                    "UPDATE work_events SET timestamp = "
                    "replace(timestamp, 'T', ' ') WHERE sequence = 1"
                ),
                "malformed event row",
            ),
        ):
            with (
                self.subTest(mutation=mutation),
                private_temporary_directory() as directory,
            ):
                database = Path(directory) / "work-memory.sqlite3"
                with WorkMemory(database) as memory:
                    memory.start(
                        work_id="issue-4",
                        issue="#4",
                        summary="Start work.",
                    )
                    memory.record(
                        work_id="issue-4",
                        kind=WorkEventKind.DECISION,
                        summary="Choose the journal.",
                    )
                state = PinnedSQLiteDatabase(database)
                try:
                    with state.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        connection.execute(mutation)
                finally:
                    state.close()
                verification = WorkMemory.verify_existing(database)
                self.assertFalse(verification.valid)
                self.assertIn(expected, verification.message)
                with self.assertRaises(WorkMemoryError):
                    WorkMemory.show_existing(database, "issue-4")

        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            with WorkMemory(database) as memory:
                memory.start(work_id="issue-5", issue="#5", summary="Start work.")
            state = PinnedSQLiteDatabase(database)
            try:
                with state.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("CREATE TABLE unexpected (value TEXT)")
            finally:
                state.close()
            verification = WorkMemory.verify_existing(database)
            self.assertFalse(verification.valid)
            self.assertIn("schema tables", verification.message)

    def test_missing_verification_and_show_do_not_create_database(self) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "missing.sqlite3"
            verification = WorkMemory.verify_existing(database)
            self.assertFalse(verification.valid)
            self.assertFalse(database.exists())
            with self.assertRaises(WorkMemoryError):
                WorkMemory.show_existing(database, "issue-6")
            self.assertFalse(database.exists())

    @unittest.skipIf(os.name == "nt", "POSIX permission fixture")
    def test_unsafe_database_parent_is_rejected(self) -> None:
        with private_temporary_directory() as directory:
            unsafe = Path(directory) / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o777)
            try:
                with self.assertRaises(WorkMemoryError):
                    WorkMemory(unsafe / "work-memory.sqlite3")
            finally:
                unsafe.chmod(0o700)

    def test_cli_start_record_show_and_verify_emit_deterministic_json(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "work-memory.sqlite3"
            output = root / "show.json"
            for arguments in (
                [
                    "work-memory",
                    "start",
                    "--database",
                    str(database),
                    "--work-id",
                    "issue-161",
                    "--issue",
                    "#161",
                    "--summary",
                    "Add persistent work memory.",
                ],
                [
                    "work-memory",
                    "record",
                    "--database",
                    str(database),
                    "--work-id",
                    "issue-161",
                    "--kind",
                    "checkpoint",
                    "--stage",
                    "planned",
                    "--summary",
                    "Plan the implementation.",
                ],
                [
                    "work-memory",
                    "show",
                    "--database",
                    str(database),
                    "--work-id",
                    "issue-161",
                    "--output",
                    str(output),
                ],
            ):
                stdout = StringIO()
                stderr = StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(arguments)
                self.assertEqual(status, 0, stderr.getvalue())

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "master-agent/work-memory@1")
            self.assertEqual(payload["stage"], "planned")
            self.assertEqual(payload["event_count"], 2)

            stdout = StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "work-memory",
                        "verify",
                        "--database",
                        str(database),
                    ]
                )
            self.assertEqual(status, 0)
            verification = json.loads(stdout.getvalue())
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["event_count"], 2)

    def test_cli_rejects_action_incompatible_arguments_without_creating_state(
        self,
    ) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "work-memory",
                        "start",
                        "--database",
                        str(database),
                        "--work-id",
                        "issue-162",
                        "--issue",
                        "#162",
                        "--summary",
                        "Start work.",
                        "--stage",
                        "planned",
                    ]
                )
            self.assertEqual(status, 1)
            self.assertIn("incompatible arguments", stderr.getvalue())
            self.assertFalse(database.exists())

    def test_cli_refuses_occupied_output_before_mutating_journal(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "work-memory.sqlite3"
            output = root / "occupied.json"
            output.write_text("{}", encoding="utf-8")

            for arguments in (
                [
                    "work-memory",
                    "start",
                    "--database",
                    str(database),
                    "--work-id",
                    "issue-163",
                    "--issue",
                    "#163",
                    "--summary",
                    "Start work.",
                    "--output",
                    str(output),
                ],
                [
                    "work-memory",
                    "record",
                    "--database",
                    str(database),
                    "--work-id",
                    "issue-163",
                    "--kind",
                    "decision",
                    "--summary",
                    "Choose the journal.",
                    "--output",
                    str(output),
                ],
            ):
                if not database.exists():
                    stdout = StringIO()
                    stderr = StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        status = main(arguments)
                    self.assertEqual(status, 1)
                    self.assertIn("already exists", stderr.getvalue())
                    self.assertFalse(database.exists())
                    with WorkMemory(database) as memory:
                        memory.start(
                            work_id="issue-163",
                            issue="#163",
                            summary="Start work.",
                        )
                    continue

                before = WorkMemory.show_existing(database, "issue-163")
                stdout = StringIO()
                stderr = StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(arguments)
                self.assertEqual(status, 1)
                self.assertIn("already exists", stderr.getvalue())
                after = WorkMemory.show_existing(database, "issue-163")
                self.assertEqual(after.journal_event_count, before.journal_event_count)
                self.assertEqual(after.journal_head_hash, before.journal_head_hash)

    def test_cli_rolls_back_event_when_output_payload_is_oversized(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "work-memory.sqlite3"
            output = root / "snapshot.json"
            with self.assertRaisesRegex(ValidationError, "exceeds the 8 MiB limit"):
                validate_restricted_json_payload({"payload": "x" * (8 * 1024 * 1024)})
            with WorkMemory(database) as memory:
                memory.start(
                    work_id="issue-164",
                    issue="#164",
                    summary="Start work.",
                )
            before = WorkMemory.show_existing(database, "issue-164")

            stdout = StringIO()
            stderr = StringIO()
            with (
                patch(
                    "master_agent.cli.validate_restricted_json_payload",
                    side_effect=ValidationError(
                        "restricted artifact exceeds the 8 MiB limit"
                    ),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = main(
                    [
                        "work-memory",
                        "record",
                        "--database",
                        str(database),
                        "--work-id",
                        "issue-164",
                        "--kind",
                        "decision",
                        "--summary",
                        "Choose the journal.",
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("exceeds the 8 MiB limit", stderr.getvalue())
            self.assertFalse(output.exists())
            after = WorkMemory.show_existing(database, "issue-164")
            self.assertEqual(after.journal_event_count, before.journal_event_count)
            self.assertEqual(after.journal_head_hash, before.journal_head_hash)


if __name__ == "__main__":
    unittest.main()
