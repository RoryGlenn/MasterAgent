"""Persistent issue-to-merge work-memory tests."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from master_agent import work_memory
from master_agent.approval_handoff import (
    validate_restricted_json_payload,
    write_restricted_json,
)
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
                    "xapp-"
                    + "1-A1234567890-1234567890123-abcdefABCDEF1234567890abcdef",
                    "AIza1234567890abcdefghijklmnopqrstuvwxyz",
                    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature12345678",
                    "Cookie: sessionid=abc1234567890",
                    "Set-Cookie: auth=abc1234567890; Secure; HttpOnly",
                    "postgresql://alice:secret-password@db.example/app",
                    "https://alice:secret@example.com/path",
                    "machine api.example.com login alice password supersecret123",
                    "machine api.example.com password supersecret123 login alice",
                    "default login alice password supersecret123",
                    "mysql --user alice --password supersecret123",
                    (
                        "<server><username>alice</username><password>"
                        "supersecret123</password></server>"
                    ),
                    '{"access_token":"supersecret123456789"}',
                    '{"client_secret":"supersecret123456789"}',
                    '{"Authorization":"Bearer supersecret123456789"}',
                    '{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}',
                    '{"identitytoken":"supersecret123456789"}',
                    "client-key-data: REDACTED",
                    "Bearer abcDEF1234567890xyz",
                    "PGPASSWORD=supersecret123",
                    "MYSQL_PWD=supersecret123",
                    "REDISCLI_AUTH=supersecret123",
                    "PRIVATE_" + "KEY=encoded-private-key-material",
                    "SSH_PRIVATE_" + "KEY=encoded-private-key-material",
                    "-----BEGIN PGP PRIVATE " + "KEY BLOCK-----",
                    "AGE-SECRET-KEY-1" + "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
                    "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz0123456789",
                    "_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789",
                    "_auth=dXNlcjpwYXNz",
                    "//registry.npmjs.org/:_auth=dXNlcjpwYXNz",
                    "npm_abcdefghijklmnopqrstuvwxyz0123456789",
                    "glpat-abcdefghijklmnopqrst",
                    "hf_abcdefghijklmnopqrstuvwxyz012345",
                    "lin_api_abcdefghijklmnopqrstuvwxyz012345",
                    "sk-" + "abcdefghijklmnopqrstuvwxyz0123456789",
                    "hvs." + "CAESIJabcdefghijklmnopqrstuvwxyz012345",
                    "hvb." + "CAESIJabcdefghijklmnopqrstuvwxyz012345",
                    "hvr." + "CAESIJabcdefghijklmnopqrstuvwxyz012345",
                    "ya29." + "abcdefghijklmnopqrstuvwxyz012345",
                    "sntrys_" + "abcdefghijklmnopqrstuvwxyz012345",
                    "ops_" + "eyJabcdefghijklmnopqrstuvwxyz012345",
                    "dckr_pat_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "dapi" + "0123456789abcdef0123456789abcdef",
                    "pypi-abcdefghijklmnopqrstuvwxyz0123456789",
                    "rk_live_" + "1234567890abcdefghijklmnop",
                    "whsec_" + "1234567890abcdefghijklmnop",
                    (
                        "https://acct.blob.core.windows.net/c/b?"
                        "sv=2024-11-04&sig=abcDEF123%2Fxyz%3D&sp=r"
                    ),
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
                memory.record(
                    work_id="issue-2",
                    kind=WorkEventKind.DECISION,
                    summary="Use Basic authentication for the integration.",
                )
                memory.record(
                    work_id="issue-2",
                    kind=WorkEventKind.DECISION,
                    summary="Use Digest authentication for the integration.",
                )
                memory.record(
                    work_id="issue-2",
                    kind=WorkEventKind.DECISION,
                    summary="Use Bearer authentication for API requests.",
                )
                self.assertEqual(
                    work_memory._validate_work_id("sk-12345678"),
                    "sk-12345678",
                )
                self.assertEqual(
                    work_memory._validate_summary("Use sk-telemetry as the label."),
                    "Use sk-telemetry as the label.",
                )
                self.assertEqual(memory.show("issue-2").journal_event_count, 4)

    def test_maximum_journal_payload_fits_windows_state_boundary(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(work_memory._WORK_EVENTS_TABLE_SQL)
            connection.execute(work_memory._WORK_MEMORY_STATE_TABLE_SQL)
            maximum_row = (
                "0" * 36,
                "2026-08-23T00:00:00.000000+00:00",
                "w" * 128,
                WorkEventKind.REFERENCE.value,
                WorkStage.IMPLEMENTING.value,
                "s" * 2_048,
                "r" * 1_024,
                "a" * 64,
                "b" * 64,
            )
            connection.executemany(
                "INSERT INTO work_events ("
                "sequence, event_id, timestamp, work_id, kind, stage, summary, "
                "reference, previous_hash, event_hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (sequence, *maximum_row)
                    for sequence in range(1, work_memory._MAX_EVENTS + 1)
                ),
            )
            connection.execute(
                "INSERT INTO work_memory_state (id, event_count, head_hash) "
                "VALUES (1, ?, ?)",
                (work_memory._MAX_EVENTS, "b" * 64),
            )
            payload = connection.serialize()
        finally:
            connection.close()

        self.assertLessEqual(len(payload), 8 * 1024 * 1024)

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

    def test_concurrent_first_starts_share_the_created_journal(self) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            absence_barrier = threading.Barrier(2)

            def report_absent(_path: Path) -> bool:
                absence_barrier.wait(timeout=5)
                return False

            def start(index: int) -> None:
                with WorkMemory(database) as memory:
                    memory.start(
                        work_id=f"issue-first-{index}",
                        issue=f"#first-{index}",
                        summary=f"Concurrent first start {index}.",
                    )

            with (
                patch(
                    "master_agent.work_memory.path_entry_exists",
                    side_effect=report_absent,
                ),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                list(executor.map(start, range(2)))

            verification = WorkMemory.verify_existing(database)
            self.assertTrue(verification.valid, verification.message)
            self.assertEqual(verification.event_count, 2)
            self.assertEqual(verification.work_count, 2)

    def test_concurrent_start_waits_for_exposed_empty_generation(self) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            creator_reached_schema = threading.Event()
            release_creator = threading.Event()
            waiter_observed_empty = threading.Event()
            original_initialize = WorkMemory._initialize

            def controlled_initialize(
                memory: WorkMemory,
                *,
                create_schema: bool,
            ) -> None:
                if create_schema:
                    creator_reached_schema.set()
                    if not release_creator.wait(timeout=5):
                        raise AssertionError("concurrent creator was not released")
                try:
                    original_initialize(memory, create_schema=create_schema)
                except WorkMemoryError as error:
                    if str(error) == work_memory._UNINITIALIZED_JOURNAL_MESSAGE:
                        waiter_observed_empty.set()
                        release_creator.set()
                    raise

            def start(index: int) -> None:
                with WorkMemory(database) as memory:
                    memory.start(
                        work_id=f"issue-exposed-{index}",
                        issue=f"#exposed-{index}",
                        summary=f"Exposed generation start {index}.",
                    )

            with (
                patch.object(WorkMemory, "_initialize", new=controlled_initialize),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                creator = executor.submit(start, 0)
                self.assertTrue(creator_reached_schema.wait(timeout=5))
                waiter = executor.submit(start, 1)
                self.assertTrue(waiter_observed_empty.wait(timeout=5))
                creator.result(timeout=5)
                waiter.result(timeout=5)

            verification = WorkMemory.verify_existing(database)
            self.assertTrue(verification.valid, verification.message)
            self.assertEqual(verification.event_count, 2)
            self.assertEqual(verification.work_count, 2)

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

        with private_temporary_directory() as directory:
            database = Path(directory) / "work-memory.sqlite3"
            with WorkMemory(database) as memory:
                memory.start(work_id="issue-5b", issue="#5b", summary="Start work.")
            state = PinnedSQLiteDatabase(database)
            try:
                with state.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "ALTER TABLE work_memory_state RENAME TO work_memory_state_old"
                    )
                    connection.execute(
                        "CREATE TABLE work_memory_state ("
                        "id INTEGER PRIMARY KEY, "
                        "event_count INTEGER NOT NULL, "
                        "head_hash TEXT NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO work_memory_state "
                        "SELECT * FROM work_memory_state_old"
                    )
                    connection.execute("DROP TABLE work_memory_state_old")
            finally:
                state.close()
            verification = WorkMemory.verify_existing(database)
            self.assertFalse(verification.valid)
            self.assertIn("schema definitions", verification.message)

    def test_missing_verification_and_show_do_not_create_database(self) -> None:
        with private_temporary_directory() as directory:
            database = Path(directory) / "missing.sqlite3"
            verification = WorkMemory.verify_existing(database)
            self.assertFalse(verification.valid)
            self.assertFalse(database.exists())
            with self.assertRaises(WorkMemoryError):
                WorkMemory.show_existing(database, "issue-6")
            self.assertFalse(database.exists())

    def test_start_does_not_repurpose_existing_empty_pinned_database(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "existing.sqlite3"
            state = PinnedSQLiteDatabase(database)
            state.close()

            with self.assertRaisesRegex(WorkMemoryError, "initialized journal"):
                WorkMemory(database)

            self.assertTrue(database.exists())
            self.assertTrue((root / ".existing.sqlite3.master-agent.lock").exists())
            self.assertTrue((root / ".existing.sqlite3.master-agent.flock").exists())
            self.assertFalse(WorkMemory.verify_existing(database).valid)

    @unittest.skipIf(os.name == "nt", "POSIX bookkeeping fixture")
    def test_start_does_not_repair_missing_journal_bookkeeping(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "work-memory.sqlite3"
            ledger = root / ".work-memory.sqlite3.master-agent.lock"
            with WorkMemory(database) as memory:
                memory.start(
                    work_id="issue-bookkeeping",
                    issue="#bookkeeping",
                    summary="Start work.",
                )
            before = database.read_bytes()
            ledger.unlink()

            with self.assertRaises(WorkMemoryError):
                WorkMemory(database)

            self.assertEqual(database.read_bytes(), before)
            self.assertFalse(ledger.exists())

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

    def test_cli_reserves_output_before_journal_commit(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "work-memory.sqlite3"
            output = root / "snapshot.json"
            with WorkMemory(database) as memory:
                memory.start(
                    work_id="issue-164b",
                    issue="#164b",
                    summary="Start work.",
                )
            before = WorkMemory.show_existing(database, "issue-164b")

            def create_after_preflight(
                selected_output: Path | None,
                *,
                database: Path,
            ) -> None:
                del database
                assert selected_output is not None
                write_restricted_json(selected_output, {"racer": True})

            stdout = StringIO()
            stderr = StringIO()
            with (
                patch(
                    "master_agent.cli._preflight_work_memory_output",
                    side_effect=create_after_preflight,
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
                        "issue-164b",
                        "--kind",
                        "decision",
                        "--summary",
                        "Choose the journal.",
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("already exists", stderr.getvalue())
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {"racer": True},
            )
            after = WorkMemory.show_existing(database, "issue-164b")
            self.assertEqual(after.journal_event_count, before.journal_event_count)
            self.assertEqual(after.journal_head_hash, before.journal_head_hash)

    def test_cli_record_missing_database_does_not_create_state(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "missing.sqlite3"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "work-memory",
                        "record",
                        "--database",
                        str(database),
                        "--work-id",
                        "issue-164c",
                        "--kind",
                        "decision",
                        "--summary",
                        "Choose the journal.",
                    ]
                )
            self.assertEqual(status, 1)
            self.assertIn("could not be opened safely", stderr.getvalue())
            self.assertFalse(database.exists())
            self.assertFalse((root / ".missing.sqlite3.master-agent.lock").exists())
            self.assertFalse((root / ".missing.sqlite3.master-agent.flock").exists())

    def test_cli_invalid_start_fields_do_not_create_state(self) -> None:
        for work_id, summary, expected in (
            ("bad id", "Start work.", "work ID is invalid"),
            (
                "issue-166",
                (
                    "https://acct.blob.core.windows.net/c/b?"
                    "sv=2024-11-04&sig=abcDEF123%2Fxyz%3D&sp=r"
                ),
                "invalid or sensitive",
            ),
            (
                "issue-166-json",
                '{"access_token":"supersecret123456789"}',
                "invalid or sensitive",
            ),
        ):
            with (
                self.subTest(work_id=work_id, summary=summary),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                database = root / "missing.sqlite3"
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
                            work_id,
                            "--issue",
                            "#166",
                            "--summary",
                            summary,
                        ]
                    )
                self.assertEqual(status, 1)
                self.assertIn(expected, stderr.getvalue())
                self.assertFalse(database.exists())
                self.assertFalse((root / ".missing.sqlite3.master-agent.lock").exists())
                self.assertFalse(
                    (root / ".missing.sqlite3.master-agent.flock").exists()
                )

    def test_cli_verify_never_occupies_missing_journal_state(self) -> None:
        for output_name in (
            "missing.sqlite3",
            ".missing.sqlite3.master-agent.lock",
            ".missing.sqlite3.master-agent.flock",
        ):
            with (
                self.subTest(output_name=output_name),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                database = root / "missing.sqlite3"
                output = root / output_name
                stdout = StringIO()
                stderr = StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(
                        [
                            "work-memory",
                            "verify",
                            "--database",
                            str(database),
                            "--output",
                            str(output),
                        ]
                    )
                self.assertEqual(status, 1)
                self.assertIn("must not alias", stderr.getvalue())
                self.assertFalse(database.exists())
                self.assertFalse(output.exists())

    def test_cli_show_never_occupies_missing_journal_sidecar(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory)
            database = root / "work-memory.sqlite3"
            output = root / "work-memory.sqlite3-wal"
            with WorkMemory(database) as memory:
                memory.start(
                    work_id="issue-164d",
                    issue="#164d",
                    summary="Start work.",
                )
            self.assertFalse(output.exists())

            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "work-memory",
                        "show",
                        "--database",
                        str(database),
                        "--work-id",
                        "issue-164d",
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("must not alias", stderr.getvalue())
            self.assertFalse(output.exists())
            self.assertTrue(WorkMemory.verify_existing(database).valid)

    def test_cli_refuses_output_aliases_for_journal_state(self) -> None:
        for output_name in (
            "work-memory.sqlite3",
            ".work-memory.sqlite3.master-agent.lock",
            ".work-memory.sqlite3.master-agent.flock",
            "work-memory.sqlite3-wal",
            ".master-agent-00000000000000000000000000000000.ledger",
        ):
            with (
                self.subTest(output_name=output_name),
                private_temporary_directory() as directory,
            ):
                root = Path(directory)
                database = root / "work-memory.sqlite3"
                output = root / output_name
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
                            "issue-165",
                            "--issue",
                            "#165",
                            "--summary",
                            "Start work.",
                            "--output",
                            str(output),
                        ]
                    )
                self.assertEqual(status, 1)
                self.assertIn("must not alias", stderr.getvalue())
                self.assertFalse(database.exists())
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
