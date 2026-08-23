"""Bounded, tamper-evident local memory for issue-to-merge work."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Self
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from master_agent.errors import ConfigurationError
from master_agent.sqlite_safety import (
    PinnedSQLiteDatabase,
    readonly_snapshot_connection,
)

_SCHEMA_VERSION = 1
_GENESIS_HASH = "GENESIS"
_MAX_EVENTS = 4_096
_MAX_WORK_ID_BYTES = 128
_MAX_SUMMARY_BYTES = 2_048
_MAX_REFERENCE_BYTES = 1_024
_EVENT_COLUMNS = (
    "sequence",
    "event_id",
    "timestamp",
    "work_id",
    "kind",
    "stage",
    "summary",
    "reference",
    "previous_hash",
    "event_hash",
)
_STATE_COLUMNS = ("id", "event_count", "head_hash")
_EVENT_SCHEMA = (
    ("sequence", "INTEGER", 0, None, 1),
    ("event_id", "TEXT", 1, None, 0),
    ("timestamp", "TEXT", 1, None, 0),
    ("work_id", "TEXT", 1, None, 0),
    ("kind", "TEXT", 1, None, 0),
    ("stage", "TEXT", 1, None, 0),
    ("summary", "TEXT", 1, None, 0),
    ("reference", "TEXT", 0, None, 0),
    ("previous_hash", "TEXT", 1, None, 0),
    ("event_hash", "TEXT", 1, None, 0),
)
_STATE_SCHEMA = (
    ("id", "INTEGER", 0, None, 1),
    ("event_count", "INTEGER", 1, None, 0),
    ("head_hash", "TEXT", 1, None, 0),
)
_WORK_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/#-]*\Z")
_SENSITIVE_TEXT_PATTERN = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:proxy-)?authorization\s*:\s*\S+(?:\s+\S+)?|"
    r"\b(?:basic|digest|aws4-hmac-sha256)\s+[A-Za-z0-9+/=,_:-]{8,}|"
    r"\bbearer\s+\S+|"
    r"\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|auth[_-]?token|secret|token)\s*[:=]\s*\S+|"
    r"\b(?:aws_(?:access_key_id|secret_access_key|session_token)|"
    r"azure_client_secret|accountkey|sharedaccesssignature)\s*[:=]\s*\S+|"
    r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b|"
    r"\bAIza[A-Za-z0-9_-]{32,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b|"
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b(?:gh[pousr]_|github_pat_|sk-proj-|sk-|sk_(?:live|test)_)[A-Za-z0-9_-]{8,}"
    r")",
    re.IGNORECASE,
)


class WorkMemoryError(RuntimeError):
    """Persistent work memory is missing, unsafe, malformed, or inconsistent."""


class WorkStage(StrEnum):
    """Ordered issue-to-merge lifecycle stages."""

    ISSUE = "issue"
    PLANNED = "planned"
    IMPLEMENTING = "implementing"
    REVIEWING = "reviewing"
    VERIFIED = "verified"
    MERGED = "merged"


class WorkEventKind(StrEnum):
    """Allowed work-memory event kinds."""

    STARTED = "started"
    DECISION = "decision"
    CHECKPOINT = "checkpoint"
    REFERENCE = "reference"


_STAGE_ORDER = {stage: index for index, stage in enumerate(WorkStage)}


@dataclass(frozen=True, slots=True)
class WorkEvent:
    """One verified, bounded work-memory event."""

    sequence: int
    event_id: UUID
    timestamp: datetime
    work_id: str
    kind: WorkEventKind
    stage: WorkStage
    summary: str
    reference: str | None
    previous_hash: str
    event_hash: str

    def to_dict(self) -> dict[str, object]:
        """Return deterministic JSON-serializable event metadata."""

        return {
            "sequence": self.sequence,
            "event_id": str(self.event_id),
            "timestamp": self.timestamp.isoformat(),
            "work_id": self.work_id,
            "kind": self.kind.value,
            "stage": self.stage.value,
            "summary": self.summary,
            "reference": self.reference,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


@dataclass(frozen=True, slots=True)
class WorkSnapshot:
    """Current state derived from a verified work event history."""

    work_id: str
    issue_reference: str
    initial_summary: str
    stage: WorkStage
    events: tuple[WorkEvent, ...]
    journal_event_count: int
    journal_head_hash: str

    def to_dict(self) -> dict[str, object]:
        """Return bounded deterministic JSON-serializable state."""

        return {
            "schema": "master-agent/work-memory@1",
            "untrusted_metadata": True,
            "work_id": self.work_id,
            "issue_reference": self.issue_reference,
            "initial_summary": self.initial_summary,
            "stage": self.stage.value,
            "event_count": len(self.events),
            "journal_event_count": self.journal_event_count,
            "journal_head_hash": self.journal_head_hash,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(frozen=True, slots=True)
class WorkMemoryVerification:
    """Content-free verification result for an existing work journal."""

    valid: bool
    message: str
    event_count: int = 0
    work_count: int = 0
    head_hash: str = _GENESIS_HASH

    def to_dict(self) -> dict[str, object]:
        """Return deterministic JSON-serializable verification metadata."""

        return {
            "schema": "master-agent/work-memory-verification@1",
            "valid": self.valid,
            "message": self.message,
            "event_count": self.event_count,
            "work_count": self.work_count,
            "head_hash": self.head_hash,
        }


@dataclass(frozen=True, slots=True)
class _Replay:
    events: tuple[WorkEvent, ...]
    by_work: dict[str, tuple[WorkEvent, ...]]
    head_hash: str


class WorkMemory:
    """Append and inspect bounded work metadata in one private SQLite journal.

    Remembered fields are untrusted metadata. They never grant identity,
    capability, authority, or approval.
    """

    def __init__(self, database: Path) -> None:
        self._database_path = database
        try:
            self._database = PinnedSQLiteDatabase(database)
        except (ConfigurationError, OSError, RuntimeError, sqlite3.Error) as error:
            raise WorkMemoryError(
                "work-memory database could not be opened safely"
            ) from error
        try:
            self._initialize()
        except BaseException:
            self._database.close(remove_created=True)
            raise

    def close(self) -> None:
        """Release pinned database and transaction-lock resources."""

        self._database.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exception_type, exception, traceback
        self.close()

    def start(
        self,
        *,
        work_id: str,
        issue: str,
        summary: str,
        snapshot_validator: Callable[[WorkSnapshot], None] | None = None,
    ) -> WorkSnapshot:
        """Start one new work record at the issue stage."""

        selected_id = _validate_work_id(work_id)
        selected_issue = _validate_reference(issue, label="issue reference")
        selected_summary = _validate_summary(summary)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            replay = _replay(connection, allow_empty=True)
            if selected_id in replay.by_work:
                raise WorkMemoryError("work record already exists")
            self._append_event(
                connection,
                replay=replay,
                work_id=selected_id,
                kind=WorkEventKind.STARTED,
                stage=WorkStage.ISSUE,
                summary=selected_summary,
                reference=selected_issue,
            )
            updated = _replay(connection, allow_empty=False)
            snapshot = _snapshot(updated, selected_id)
            if snapshot_validator is not None:
                snapshot_validator(snapshot)
            return snapshot

    def record(
        self,
        *,
        work_id: str,
        kind: WorkEventKind,
        summary: str,
        stage: WorkStage | None = None,
        reference: str | None = None,
        snapshot_validator: Callable[[WorkSnapshot], None] | None = None,
    ) -> WorkSnapshot:
        """Append one decision, checkpoint, or reference to existing work."""

        selected_id = _validate_work_id(work_id)
        if kind is WorkEventKind.STARTED:
            raise ValueError("started events must use work-memory start")
        selected_summary = _validate_summary(summary)
        selected_reference = (
            _validate_reference(reference, label="reference")
            if reference is not None
            else None
        )
        if kind is WorkEventKind.REFERENCE and selected_reference is None:
            raise ValueError("reference events require --reference")
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            replay = _replay(connection, allow_empty=False)
            work_events = replay.by_work.get(selected_id)
            if work_events is None:
                raise WorkMemoryError("work record does not exist")
            current_stage = work_events[-1].stage
            if current_stage is WorkStage.MERGED:
                raise WorkMemoryError("merged work records are terminal")
            selected_stage = stage or current_stage
            current_rank = _STAGE_ORDER[current_stage]
            selected_rank = _STAGE_ORDER[selected_stage]
            if selected_rank < current_rank:
                raise WorkMemoryError("work stage cannot regress")
            if selected_rank > current_rank + 1:
                raise WorkMemoryError("work stage cannot skip lifecycle stages")
            self._append_event(
                connection,
                replay=replay,
                work_id=selected_id,
                kind=kind,
                stage=selected_stage,
                summary=selected_summary,
                reference=selected_reference,
            )
            updated = _replay(connection, allow_empty=False)
            snapshot = _snapshot(updated, selected_id)
            if snapshot_validator is not None:
                snapshot_validator(snapshot)
            return snapshot

    def show(self, work_id: str) -> WorkSnapshot:
        """Inspect one work record through a non-mutating verified snapshot."""

        return self.show_existing(self._database_path, work_id)

    @classmethod
    def show_existing(cls, database: Path, work_id: str) -> WorkSnapshot:
        """Inspect existing work without creating or modifying its database."""

        selected_id = _validate_work_id(work_id)
        try:
            with readonly_snapshot_connection(database) as connection:
                cls._validate_schema(connection)
                replay = _replay(connection, allow_empty=False)
                return _snapshot(replay, selected_id)
        except WorkMemoryError:
            raise
        except (ConfigurationError, OSError, RuntimeError, sqlite3.Error) as error:
            raise WorkMemoryError(
                "work-memory database could not be inspected safely"
            ) from error

    @classmethod
    def verify_existing(cls, database: Path) -> WorkMemoryVerification:
        """Verify an existing journal without creating or modifying it."""

        try:
            with readonly_snapshot_connection(database) as connection:
                cls._validate_schema(connection)
                replay = _replay(connection, allow_empty=False)
        except WorkMemoryError as error:
            return WorkMemoryVerification(valid=False, message=str(error))
        except (ConfigurationError, OSError, RuntimeError, sqlite3.Error):
            return WorkMemoryVerification(
                valid=False,
                message="work-memory database could not be verified safely",
            )
        return WorkMemoryVerification(
            valid=True,
            message=f"verified {len(replay.events)} work-memory events",
            event_count=len(replay.events),
            work_count=len(replay.by_work),
            head_hash=replay.head_hash,
        )

    def _initialize(self) -> None:
        try:
            with self._database.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                version = _schema_version(connection)
                tables = _user_tables(connection)
                if version == 0 and not tables:
                    connection.execute(
                        """
                        CREATE TABLE work_events (
                            sequence INTEGER PRIMARY KEY,
                            event_id TEXT NOT NULL,
                            timestamp TEXT NOT NULL,
                            work_id TEXT NOT NULL,
                            kind TEXT NOT NULL,
                            stage TEXT NOT NULL,
                            summary TEXT NOT NULL,
                            reference TEXT,
                            previous_hash TEXT NOT NULL,
                            event_hash TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE work_memory_state (
                            id INTEGER PRIMARY KEY CHECK (id = 1),
                            event_count INTEGER NOT NULL,
                            head_hash TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        "INSERT INTO work_memory_state (id, event_count, head_hash) "
                        "VALUES (1, 0, ?)",
                        (_GENESIS_HASH,),
                    )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                elif version != _SCHEMA_VERSION:
                    raise WorkMemoryError("work-memory schema version is incompatible")
                self._validate_schema(connection)
                _replay(connection, allow_empty=True)
        except WorkMemoryError:
            raise
        except (ConfigurationError, OSError, RuntimeError, sqlite3.Error) as error:
            raise WorkMemoryError(
                "work-memory schema initialization failed closed"
            ) from error

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        if _schema_version(connection) != _SCHEMA_VERSION:
            raise WorkMemoryError("work-memory schema version is incompatible")
        if _user_schema_objects(connection) != {
            ("table", "work_events"),
            ("table", "work_memory_state"),
        }:
            raise WorkMemoryError("work-memory schema tables are incompatible")
        event_schema = tuple(
            (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
            for row in connection.execute("PRAGMA table_info(work_events)")
        )
        state_schema = tuple(
            (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
            for row in connection.execute("PRAGMA table_info(work_memory_state)")
        )
        if event_schema != _EVENT_SCHEMA or state_schema != _STATE_SCHEMA:
            raise WorkMemoryError("work-memory schema columns are incompatible")

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        replay: _Replay,
        work_id: str,
        kind: WorkEventKind,
        stage: WorkStage,
        summary: str,
        reference: str | None,
    ) -> None:
        if len(replay.events) >= _MAX_EVENTS:
            raise WorkMemoryError("work-memory event limit is exhausted")
        sequence = len(replay.events) + 1
        event_id = uuid4()
        timestamp = datetime.now(UTC)
        previous_hash = replay.head_hash
        event_hash = _event_hash(
            sequence=sequence,
            event_id=event_id,
            timestamp=timestamp,
            work_id=work_id,
            kind=kind,
            stage=stage,
            summary=summary,
            reference=reference,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO work_events (
                sequence, event_id, timestamp, work_id, kind, stage, summary,
                reference, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                str(event_id),
                timestamp.isoformat(),
                work_id,
                kind.value,
                stage.value,
                summary,
                reference,
                previous_hash,
                event_hash,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE work_memory_state
            SET event_count = ?, head_hash = ?
            WHERE id = 1 AND event_count = ? AND head_hash = ?
            """,
            (sequence, event_hash, sequence - 1, previous_hash),
        )
        if cursor.rowcount != 1:
            raise WorkMemoryError("work-memory checkpoint changed concurrently")


def _schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], int):
        raise WorkMemoryError("work-memory schema version is malformed")
    return row[0]


def _user_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _user_schema_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    return {
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        )
    }


def _replay(connection: sqlite3.Connection, *, allow_empty: bool) -> _Replay:
    try:
        rows = connection.execute(
            """
            SELECT sequence, event_id, timestamp, work_id, kind, stage, summary,
                   reference, previous_hash, event_hash
            FROM work_events ORDER BY sequence
            LIMIT ?
            """,
            (_MAX_EVENTS + 1,),
        ).fetchall()
        state_rows = connection.execute(
            "SELECT id, event_count, head_hash FROM work_memory_state"
        ).fetchall()
    except sqlite3.Error as error:
        raise WorkMemoryError("work-memory rows could not be read") from error
    if len(rows) > _MAX_EVENTS:
        raise WorkMemoryError("work-memory event limit was exceeded")
    if len(state_rows) != 1 or state_rows[0][0] != 1:
        raise WorkMemoryError("work-memory checkpoint is malformed")
    checkpoint_count = state_rows[0][1]
    checkpoint_hash = state_rows[0][2]
    if (
        not isinstance(checkpoint_count, int)
        or isinstance(checkpoint_count, bool)
        or checkpoint_count < 0
        or not isinstance(checkpoint_hash, str)
    ):
        raise WorkMemoryError("work-memory checkpoint is malformed")
    if not rows and not allow_empty:
        raise WorkMemoryError("work-memory journal contains no events")

    events: list[WorkEvent] = []
    by_work_mutable: dict[str, list[WorkEvent]] = {}
    event_ids: set[UUID] = set()
    expected_previous = _GENESIS_HASH
    for expected_sequence, row in enumerate(rows, start=1):
        event = _decode_event(row, expected_sequence=expected_sequence)
        if event.event_id in event_ids:
            raise WorkMemoryError(f"duplicate event ID at sequence {expected_sequence}")
        event_ids.add(event.event_id)
        if event.previous_hash != expected_previous:
            raise WorkMemoryError(
                f"broken previous-hash link at sequence {expected_sequence}"
            )
        calculated = _event_hash(
            sequence=event.sequence,
            event_id=event.event_id,
            timestamp=event.timestamp,
            work_id=event.work_id,
            kind=event.kind,
            stage=event.stage,
            summary=event.summary,
            reference=event.reference,
            previous_hash=event.previous_hash,
        )
        if calculated != event.event_hash:
            raise WorkMemoryError(
                f"event hash mismatch at sequence {expected_sequence}"
            )
        work_events = by_work_mutable.setdefault(event.work_id, [])
        _validate_lifecycle_event(event, work_events)
        work_events.append(event)
        events.append(event)
        expected_previous = event.event_hash

    if checkpoint_count != len(events):
        raise WorkMemoryError("work-memory checkpoint count does not match history")
    if checkpoint_hash != expected_previous:
        raise WorkMemoryError("work-memory checkpoint head does not match history")
    return _Replay(
        events=tuple(events),
        by_work={key: tuple(value) for key, value in by_work_mutable.items()},
        head_hash=expected_previous,
    )


def _decode_event(row: tuple[object, ...], *, expected_sequence: int) -> WorkEvent:
    if len(row) != len(_EVENT_COLUMNS):
        raise WorkMemoryError(f"malformed event row at sequence {expected_sequence}")
    (
        sequence_raw,
        event_id_raw,
        timestamp_raw,
        work_id_raw,
        kind_raw,
        stage_raw,
        summary_raw,
        reference_raw,
        previous_hash_raw,
        event_hash_raw,
    ) = row
    if (
        not isinstance(sequence_raw, int)
        or isinstance(sequence_raw, bool)
        or sequence_raw != expected_sequence
    ):
        raise WorkMemoryError(f"event sequence gap at sequence {expected_sequence}")
    if (
        not isinstance(event_id_raw, str)
        or not isinstance(timestamp_raw, str)
        or not isinstance(work_id_raw, str)
        or not isinstance(kind_raw, str)
        or not isinstance(stage_raw, str)
        or not isinstance(summary_raw, str)
        or (reference_raw is not None and not isinstance(reference_raw, str))
    ):
        raise WorkMemoryError(f"malformed event row at sequence {expected_sequence}")
    try:
        event_id = UUID(event_id_raw)
        if str(event_id) != event_id_raw:
            raise ValueError
        timestamp = datetime.fromisoformat(timestamp_raw)
        if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(
            timestamp
        ):
            raise ValueError
        if timestamp.isoformat() != timestamp_raw:
            raise ValueError
        kind = WorkEventKind(kind_raw)
        stage = WorkStage(stage_raw)
        work_id = _validate_work_id(work_id_raw)
        summary = _validate_summary(summary_raw)
        reference = (
            _validate_reference(reference_raw, label="reference")
            if reference_raw is not None
            else None
        )
    except (TypeError, ValueError) as error:
        raise WorkMemoryError(
            f"malformed event row at sequence {expected_sequence}"
        ) from error
    if (
        not isinstance(previous_hash_raw, str)
        or not isinstance(event_hash_raw, str)
        or not _is_chain_hash(previous_hash_raw, allow_genesis=True)
        or not _is_chain_hash(event_hash_raw, allow_genesis=False)
    ):
        raise WorkMemoryError(f"malformed event hash at sequence {expected_sequence}")
    return WorkEvent(
        sequence=sequence_raw,
        event_id=event_id,
        timestamp=timestamp,
        work_id=work_id,
        kind=kind,
        stage=stage,
        summary=summary,
        reference=reference,
        previous_hash=previous_hash_raw,
        event_hash=event_hash_raw,
    )


def _validate_lifecycle_event(event: WorkEvent, existing: list[WorkEvent]) -> None:
    if not existing:
        if (
            event.kind is not WorkEventKind.STARTED
            or event.stage is not WorkStage.ISSUE
            or event.reference is None
        ):
            raise WorkMemoryError(
                f"work record does not start correctly at sequence {event.sequence}"
            )
        return
    if event.kind is WorkEventKind.STARTED:
        raise WorkMemoryError(f"duplicate work start at sequence {event.sequence}")
    if event.kind is WorkEventKind.REFERENCE and event.reference is None:
        raise WorkMemoryError(f"reference is missing at sequence {event.sequence}")
    previous_stage = existing[-1].stage
    if previous_stage is WorkStage.MERGED:
        raise WorkMemoryError(f"event follows merge at sequence {event.sequence}")
    difference = _STAGE_ORDER[event.stage] - _STAGE_ORDER[previous_stage]
    if difference < 0:
        raise WorkMemoryError(f"stage regresses at sequence {event.sequence}")
    if difference > 1:
        raise WorkMemoryError(f"stage skips at sequence {event.sequence}")


def _snapshot(replay: _Replay, work_id: str) -> WorkSnapshot:
    events = replay.by_work.get(work_id)
    if events is None:
        raise WorkMemoryError("work record does not exist")
    issue_reference = events[0].reference
    if issue_reference is None:
        raise WorkMemoryError("work record issue reference is missing")
    return WorkSnapshot(
        work_id=work_id,
        issue_reference=issue_reference,
        initial_summary=events[0].summary,
        stage=events[-1].stage,
        events=events,
        journal_event_count=len(replay.events),
        journal_head_hash=replay.head_hash,
    )


def _event_hash(
    *,
    sequence: int,
    event_id: UUID,
    timestamp: datetime,
    work_id: str,
    kind: WorkEventKind,
    stage: WorkStage,
    summary: str,
    reference: str | None,
    previous_hash: str,
) -> str:
    material = json.dumps(
        {
            "schema": "master-agent/work-memory-event@1",
            "sequence": sequence,
            "event_id": str(event_id),
            "timestamp": timestamp.isoformat(),
            "work_id": work_id,
            "kind": kind.value,
            "stage": stage.value,
            "summary": summary,
            "reference": reference,
            "previous_hash": previous_hash,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _validate_work_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > _MAX_WORK_ID_BYTES
        or _WORK_ID_PATTERN.fullmatch(value) is None
        or _SENSITIVE_TEXT_PATTERN.search(value) is not None
    ):
        raise ValueError("work ID is invalid")
    return value


def _validate_summary(value: str) -> str:
    return _validate_text(value, label="summary", max_bytes=_MAX_SUMMARY_BYTES)


def _validate_reference(value: str, *, label: str) -> str:
    selected = _validate_text(value, label=label, max_bytes=_MAX_REFERENCE_BYTES)
    parsed = urlsplit(selected)
    if "://" in selected and (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} URL is unsafe")
    return selected


def _validate_text(value: str, *, label: str, max_bytes: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > max_bytes
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
        )
        or _SENSITIVE_TEXT_PATTERN.search(value) is not None
    ):
        raise ValueError(f"work-memory {label} is invalid or sensitive")
    return value


def _is_chain_hash(value: str, *, allow_genesis: bool) -> bool:
    if allow_genesis and value == _GENESIS_HASH:
        return True
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
