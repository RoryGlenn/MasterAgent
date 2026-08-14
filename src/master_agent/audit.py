"""Tamper-evident local audit storage and idempotency records."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import sqlite3
from collections.abc import Iterator
from typing import Any, Mapping
from uuid import UUID, uuid4


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
        self._initialize()

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
            previous = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = str(previous[0]) if previous else "GENESIS"
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
        return json.loads(str(row[0]))

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
        """Verify every audit event hash and link."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT timestamp, run_id, plan_id, action_id, event_type,
                       payload_json, previous_hash, event_hash
                FROM audit_events ORDER BY id
                """
            ).fetchall()

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
        return True, f"verified {len(rows)} audit events"

    def _initialize(self) -> None:
        with self._connect() as connection:
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
