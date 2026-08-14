"""Tamper-evident local audit storage and idempotency records."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from master_agent.errors import ConfigurationError, StructuredDataTypeError


class IdempotencyClaimState(StrEnum):
    """Result of atomically reserving one idempotency key."""

    CLAIMED = "claimed"
    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class IdempotencyClaim:
    """Atomic idempotency reservation outcome."""

    state: IdempotencyClaimState
    token: str | None = None
    result: Mapping[str, Any] | None = None


class AuditSinkKind(StrEnum):
    """Implemented durable-audit transport kinds."""

    LOCAL_SQLITE = "local_sqlite"


@dataclass(frozen=True, slots=True)
class AuditSinkDescriptor:
    """Runtime-backed audit sink properties used by readiness checks."""

    identifier: str
    kind: AuditSinkKind
    external: bool
    tamper_resistant: bool


_LOCAL_SQLITE_SINK = AuditSinkDescriptor(
    identifier="local-sqlite-for-development",
    kind=AuditSinkKind.LOCAL_SQLITE,
    external=False,
    tamper_resistant=False,
)


def implemented_audit_sink(identifier: str) -> AuditSinkDescriptor | None:
    """Resolve only audit sinks with an implementation in this runtime."""

    if identifier.strip().casefold() == _LOCAL_SQLITE_SINK.identifier:
        return _LOCAL_SQLITE_SINK
    return None


class AuditLog:
    """SQLite-backed audit chain for local development.

    Parameters
    ----------
    database
        SQLite database path.
    """

    def __init__(self, database: Path) -> None:
        database.parent.mkdir(parents=True, exist_ok=True)
        self._database = database
        created = _prepare_database_file(database)
        try:
            self._initialize()
        except Exception:
            if created:
                database.unlink(missing_ok=True)
            raise

    def record(
        self,
        *,
        run_id: UUID,
        plan_id: UUID,
        action_id: UUID | None,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> str:
        """Append one event and return its hash."""

        timestamp = datetime.now(UTC).isoformat()
        payload_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = connection.execute(
                "SELECT event_count, head_hash FROM audit_state WHERE id = 1"
            ).fetchone()
            if state is None:
                raise RuntimeError("audit checkpoint state is missing")
            event_count, previous_hash = int(state[0]), str(state[1])
            latest = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            latest_hash = str(latest[0]) if latest else "GENESIS"
            if latest_hash != previous_hash:
                raise RuntimeError("audit checkpoint does not match the event chain")
            material = "|".join(
                [
                    previous_hash,
                    timestamp,
                    str(run_id),
                    str(plan_id),
                    str(action_id or ""),
                    event_type,
                    payload_json,
                ]
            )
            event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
            connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, run_id, plan_id, action_id, event_type,
                    payload_json, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    str(run_id),
                    str(plan_id),
                    str(action_id) if action_id else None,
                    event_type,
                    payload_json,
                    previous_hash,
                    event_hash,
                ),
            )
            connection.execute(
                "UPDATE audit_state SET event_count = ?, head_hash = ? WHERE id = 1",
                (event_count + 1, event_hash),
            )
        return event_hash

    def save_completed(
        self,
        *,
        idempotency_key: str,
        plan_id: UUID,
        action_id: UUID,
        result: Mapping[str, Any],
        action_fingerprint: str = "legacy-unbound",
    ) -> None:
        """Persist a successful result for compatibility with old callers.

        New execution paths must call :meth:`claim_action` followed by
        :meth:`complete_action` so the side effect is reserved before it runs.
        """

        result_json = json.dumps(result, sort_keys=True, default=str)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO completed_actions (
                    idempotency_key, plan_id, action_id, action_fingerprint,
                    status, claim_token, result_json, claimed_at, completed_at
                ) VALUES (?, ?, ?, ?, 'completed', NULL, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    str(plan_id),
                    str(action_id),
                    action_fingerprint,
                    result_json,
                    datetime.now(UTC).isoformat(),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def claim_action(
        self,
        *,
        idempotency_key: str,
        action_fingerprint: str,
        plan_id: UUID,
        action_id: UUID,
    ) -> IdempotencyClaim:
        """Atomically reserve a key before any connector side effect occurs."""

        token = str(uuid4())
        claimed_at = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT action_fingerprint, status, claim_token, result_json
                FROM completed_actions WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO completed_actions (
                        idempotency_key, plan_id, action_id, action_fingerprint,
                        status, claim_token, result_json, claimed_at, completed_at
                    ) VALUES (?, ?, ?, ?, 'pending', ?, '{}', ?, ?)
                    """,
                    (
                        idempotency_key,
                        str(plan_id),
                        str(action_id),
                        action_fingerprint,
                        token,
                        claimed_at,
                        claimed_at,
                    ),
                )
                return IdempotencyClaim(
                    state=IdempotencyClaimState.CLAIMED,
                    token=token,
                )
            stored_fingerprint, status, _stored_token, result_json = row
            if stored_fingerprint != action_fingerprint:
                return IdempotencyClaim(state=IdempotencyClaimState.CONFLICT)
            if status == "completed":
                result = json.loads(str(result_json))
                return IdempotencyClaim(
                    state=IdempotencyClaimState.COMPLETED,
                    result=result,
                )
            return IdempotencyClaim(state=IdempotencyClaimState.IN_PROGRESS)

    def complete_action(
        self,
        *,
        idempotency_key: str,
        action_fingerprint: str,
        claim_token: str,
        result: Mapping[str, Any],
    ) -> None:
        """Complete exactly the reservation held by one execution attempt."""

        result_json = json.dumps(result, sort_keys=True, default=str)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE completed_actions
                SET status = 'completed', result_json = ?, completed_at = ?
                WHERE idempotency_key = ?
                  AND action_fingerprint = ?
                  AND status = 'pending'
                  AND claim_token = ?
                """,
                (
                    result_json,
                    datetime.now(UTC).isoformat(),
                    idempotency_key,
                    action_fingerprint,
                    claim_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("idempotency reservation was lost or replaced")

    def completed_result(
        self,
        idempotency_key: str,
        *,
        action_fingerprint: str | None = None,
    ) -> dict[str, Any] | None:
        """Return a prior successful result for an idempotency key."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT result_json, action_fingerprint, status
                FROM completed_actions WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
        if row is None or row[2] != "completed":
            return None
        if action_fingerprint is not None and row[1] != action_fingerprint:
            return None
        result = json.loads(str(row[0]))
        if not isinstance(result, dict):
            raise StructuredDataTypeError(
                "completed action result must be a JSON object"
            )
        return result

    def clear_completed(
        self,
        idempotency_key: str,
        *,
        action_fingerprint: str | None = None,
    ) -> None:
        """Remove an idempotency completion after verified compensation."""

        with self._connect() as connection:
            if action_fingerprint is None:
                connection.execute(
                    "DELETE FROM completed_actions WHERE idempotency_key = ?",
                    (idempotency_key,),
                )
            else:
                connection.execute(
                    """
                    DELETE FROM completed_actions
                    WHERE idempotency_key = ? AND action_fingerprint = ?
                    """,
                    (idempotency_key, action_fingerprint),
                )

    def verify_chain(self) -> tuple[bool, str]:
        """Verify a nonempty audit chain against its durable checkpoint."""

        with self._connect() as connection:
            return self._verify_connection(connection)

    @classmethod
    def verify_existing(cls, database: Path) -> tuple[bool, str]:
        """Verify an existing database without creating or modifying it."""

        if database.is_symlink():
            return False, "audit database must not be a symbolic link"
        if not database.exists():
            return False, f"audit database does not exist: {database}"
        if not database.is_file():
            return False, f"audit database is not a regular file: {database}"
        try:
            uri = database.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                return cls._verify_connection(connection)
        except sqlite3.Error as error:
            return False, f"audit database could not be verified: {error}"

    @staticmethod
    def _verify_connection(connection: sqlite3.Connection) -> tuple[bool, str]:
        """Verify event hashes, links, and the append checkpoint."""

        try:
            rows = connection.execute(
                """
                SELECT timestamp, run_id, plan_id, action_id, event_type,
                       payload_json, previous_hash, event_hash
                FROM audit_events ORDER BY id
                """
            ).fetchall()
            checkpoint = connection.execute(
                "SELECT event_count, head_hash FROM audit_state WHERE id = 1"
            ).fetchone()
        except sqlite3.Error as error:
            return False, f"audit database schema is invalid: {error}"
        if not rows:
            return False, "audit database contains no events"
        if checkpoint is None:
            return False, "audit checkpoint state is missing"

        expected_previous = "GENESIS"
        for index, row in enumerate(rows, start=1):
            (
                timestamp,
                run_id,
                plan_id,
                action_id,
                event_type,
                payload_json,
                previous_hash,
                event_hash,
            ) = row
            if previous_hash != expected_previous:
                return False, f"broken previous-hash link at event {index}"
            material = "|".join(
                [
                    str(previous_hash),
                    str(timestamp),
                    str(run_id),
                    str(plan_id),
                    str(action_id or ""),
                    str(event_type),
                    str(payload_json),
                ]
            )
            calculated = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if calculated != event_hash:
                return False, f"event hash mismatch at event {index}"
            expected_previous = str(event_hash)
        checkpoint_count, checkpoint_hash = int(checkpoint[0]), str(checkpoint[1])
        if checkpoint_count != len(rows):
            return (
                False,
                (
                    "audit checkpoint count does not match the event chain "
                    f"({checkpoint_count} != {len(rows)})"
                ),
            )
        if checkpoint_hash != expected_previous:
            return False, "audit checkpoint head does not match the event chain"
        return True, f"verified {len(rows)} audit events"

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    action_id TEXT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    event_count INTEGER NOT NULL,
                    head_hash TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS completed_actions (
                    idempotency_key TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action_fingerprint TEXT,
                    status TEXT NOT NULL DEFAULT 'completed',
                    claim_token TEXT,
                    result_json TEXT NOT NULL,
                    claimed_at TEXT,
                    completed_at TEXT NOT NULL
                )
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(completed_actions)"
                ).fetchall()
            }
            migrations = {
                "action_fingerprint": "TEXT",
                "status": "TEXT NOT NULL DEFAULT 'completed'",
                "claim_token": "TEXT",
                "claimed_at": "TEXT",
            }
            for name, definition in migrations.items():
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE completed_actions ADD COLUMN {name} {definition}"
                    )
            schema_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            state = connection.execute(
                "SELECT event_count, head_hash FROM audit_state WHERE id = 1"
            ).fetchone()
            if state is None and schema_version == 0:
                row = connection.execute(
                    "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM audit_events"
                ).fetchone()
                event_count = int(row[0])
                latest = connection.execute(
                    "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
                ).fetchone()
                head_hash = str(latest[0]) if latest else "GENESIS"
                connection.execute(
                    "INSERT INTO audit_state (id, event_count, head_hash) "
                    "VALUES (1, ?, ?)",
                    (event_count, head_hash),
                )
                connection.execute("PRAGMA user_version = 1")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open, commit, and close one SQLite transaction safely."""

        connection = sqlite3.connect(self._database, timeout=30.0)
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _prepare_database_file(path: Path) -> bool:
    """Create or open a regular audit database without following symlinks."""

    if path.parent.is_symlink():
        raise ConfigurationError("audit database parent must not be a symbolic link")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise ConfigurationError(
                "audit database must be a regular no-follow file"
            ) from error
    except OSError as error:
        raise ConfigurationError(
            "audit database could not be created safely"
        ) from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ConfigurationError("audit database must be a regular file")
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        if created:
            path.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    return created
