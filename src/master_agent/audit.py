"""Tamper-evident local audit storage and idempotency records."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from collections.abc import Iterator
from typing import Any, Mapping
from uuid import UUID


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
    ) -> None:
        """Persist a successful idempotent result."""

        result_json = json.dumps(result, sort_keys=True, default=str)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO completed_actions (
                    idempotency_key, plan_id, action_id, result_json, completed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    str(plan_id),
                    str(action_id),
                    result_json,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def completed_result(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return a prior successful result for an idempotency key."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM completed_actions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return json.loads(str(row[0])) if row else None

    def clear_completed(self, idempotency_key: str) -> None:
        """Remove an idempotency completion after verified compensation."""

        with self._connect() as connection:
            connection.execute(
                "DELETE FROM completed_actions WHERE idempotency_key = ?",
                (idempotency_key,),
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
                    result_json TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open, commit, and close one SQLite transaction safely."""

        connection = sqlite3.connect(self._database)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
