"""Registered, narrow recurring-workflow scheduler for Phase 6."""

from __future__ import annotations

import json
import os
import sqlite3
import tomllib
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import Event, RLock, Thread
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.platform_runtime import require_persistent_state_platform
from master_agent.sqlite_safety import PinnedSQLiteDatabase, path_entry_exists


class WorkflowKind(StrEnum):
    """Built-in recurring workflows. Arbitrary kinds are rejected."""

    WEEKLY_STATUS_PACKAGE = "weekly_status_package"
    COMMUNICATION_CONTEXT_PACKAGE = "communication_context_package"
    WEEKLY_OPERATING_REVIEW = "weekly_operating_review"


class DeliveryMode(StrEnum):
    """Permitted recurring output modes."""

    LOCAL_ONLY = "local_only"
    DRAFT_ONLY = "draft_only"


class DstFoldPolicy(StrEnum):
    """Explicit handling for a weekly time repeated by a DST transition."""

    REJECT = "reject"
    FIRST = "first"
    SECOND = "second"


class CatchUpPolicy(StrEnum):
    """Bounded recurring catch-up behavior."""

    LATEST_ONLY = "latest_only"


class ClaimStatus(StrEnum):
    """Durable lifecycle of one scheduled occurrence claim."""

    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    RECOVERABLE = "recoverable"


class OccurrenceStatus(StrEnum):
    """Exact-bound occurrence lifecycle."""

    BOUND = "bound"
    RUNNING = "running"
    APPROVAL_BLOCKED = "approval_blocked"
    SUCCEEDED = "succeeded"
    FAILED_PRE_EFFECT = "failed_pre_effect"
    RECOVERABLE = "recoverable"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    INDETERMINATE = "indeterminate"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class WeeklySchedule:
    """Fixed weekly schedule in an IANA timezone."""

    weekday: int
    hour: int
    minute: int
    timezone: str
    max_lateness_minutes: int = 1440
    fold_policy: DstFoldPolicy = DstFoldPolicy.REJECT

    def __post_init__(self) -> None:
        if not 0 <= self.weekday <= 6:
            raise ConfigurationError("weekday must be 0 (Monday) through 6 (Sunday)")
        if not 0 <= self.hour <= 23:
            raise ConfigurationError("hour must be 0 through 23")
        if not 0 <= self.minute <= 59:
            raise ConfigurationError("minute must be 0 through 59")
        if self.max_lateness_minutes < 0:
            raise ConfigurationError("max_lateness_minutes must not be negative")
        if not isinstance(self.fold_policy, DstFoldPolicy):
            raise ConfigurationError("DST fold policy is invalid")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ConfigurationError(
                f"unknown IANA timezone: {self.timezone}"
            ) from error

    def scheduled_at_or_before(self, now: datetime) -> datetime:
        """Return the most recent scheduled instant at or before ``now``."""

        zone = ZoneInfo(self.timezone)
        local = now.astimezone(zone)
        days_back = (local.weekday() - self.weekday) % 7
        candidate_date = (local - timedelta(days=days_back)).date()
        candidate = datetime(
            candidate_date.year,
            candidate_date.month,
            candidate_date.day,
            self.hour,
            self.minute,
            tzinfo=UTC,
        ).replace(tzinfo=None)
        selected = self._resolve_local(candidate, zone)
        if selected > now.astimezone(UTC):
            candidate -= timedelta(days=7)
            selected = self._resolve_local(candidate, zone)
        return selected

    def resolve_occurrence(self, local: datetime) -> datetime:
        """Resolve one explicit local wall time under the bound DST policy."""

        if local.tzinfo is not None:
            raise ConfigurationError("recurring occurrence must be a local wall time")
        return self._resolve_local(local, ZoneInfo(self.timezone))

    def _resolve_local(self, local: datetime, zone: ZoneInfo) -> datetime:
        candidates: list[tuple[int, datetime]] = []
        for fold in (0, 1):
            candidate = local.replace(tzinfo=zone, fold=fold)
            instant = candidate.astimezone(UTC)
            round_trip = instant.astimezone(zone)
            if round_trip.replace(tzinfo=None) == local and round_trip.fold == fold:
                candidates.append((fold, instant))
        unique = tuple(dict.fromkeys(instant for _fold, instant in candidates))
        if not unique:
            raise ConfigurationError("recurring local time does not exist in its zone")
        if len(unique) == 1:
            return unique[0]
        if self.fold_policy is DstFoldPolicy.REJECT:
            raise ConfigurationError(
                "recurring local time is ambiguous and requires a fold policy"
            )
        selected_fold = 0 if self.fold_policy is DstFoldPolicy.FIRST else 1
        for fold, instant in candidates:
            if fold == selected_fold:
                return instant
        raise ConfigurationError("recurring DST fold policy could not be satisfied")


@dataclass(frozen=True, slots=True)
class RegisteredWorkflow:
    """One fixed-scope recurring workflow registration."""

    name: str
    enabled: bool
    kind: WorkflowKind
    schedule: WeeklySchedule
    delivery_mode: DeliveryMode
    output_dir: Path
    integration_config: Path
    workflow_config: Path
    identity_config: Path | None
    retention_config: Path | None
    allowed_capabilities: tuple[str, ...]
    allowed_recipients: tuple[str, ...]
    canonical_sources: tuple[str, ...]
    generation: int = 1
    revoked: bool = False
    catch_up_policy: CatchUpPolicy = CatchUpPolicy.LATEST_ONLY
    approval_resume_minutes: int = 1440


@dataclass(frozen=True, slots=True)
class RecurringConfig:
    """Registered recurring workflows and scheduler storage."""

    state_database: Path
    lock_dir: Path
    workflows: Mapping[str, RegisteredWorkflow]
    occurrence_root: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "workflows", MappingProxyType(dict(self.workflows)))

    @classmethod
    def from_toml(cls, path: ConfigSource) -> RecurringConfig:
        """Load only known recurring workflow kinds from TOML."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"recurring configuration not found: {path}"
            ) from error
        # Resolve once against the trusted configuration source. Apply-time CWD
        # must never change a recurring security boundary.
        base = Path(str(path)).expanduser().resolve(strict=False).parent
        scheduler = _table(raw, "scheduler")
        state_database = _resolve(base, _required(scheduler, "state_database"))
        lock_dir = _resolve(base, _required(scheduler, "lock_dir"))
        occurrence_root_value = str(scheduler.get("occurrence_root", "")).strip()
        occurrence_root = (
            _resolve(base, occurrence_root_value) if occurrence_root_value else None
        )
        raw_workflows = _table(raw, "workflows")
        workflows: dict[str, RegisteredWorkflow] = {}
        for name, raw_value in raw_workflows.items():
            value = _mapping(raw_value, f"workflow {name}")
            try:
                kind = WorkflowKind(str(value.get("kind", "")))
                delivery_mode = DeliveryMode(
                    str(value.get("delivery_mode", "local_only"))
                )
            except ValueError as error:
                raise ConfigurationError(
                    f"unsupported recurring workflow: {name}"
                ) from error
            allowed_capabilities = _string_list(value, "allowed_capabilities")
            if not allowed_capabilities:
                raise ConfigurationError(
                    f"recurring workflow {name} requires allowed_capabilities"
                )
            canonical_sources = _string_list(value, "canonical_sources")
            if not canonical_sources:
                raise ConfigurationError(
                    f"recurring workflow {name} requires canonical_sources"
                )
            workflows[str(name)] = RegisteredWorkflow(
                name=str(name),
                enabled=_strict_bool(value, "enabled", default=False),
                kind=kind,
                schedule=WeeklySchedule(
                    weekday=_int(value, "weekday", 0),
                    hour=_int(value, "hour", 0),
                    minute=_int(value, "minute", 0),
                    timezone=_required(value, "timezone"),
                    max_lateness_minutes=_int(
                        value,
                        "max_lateness_minutes",
                        1440,
                    ),
                    fold_policy=_enum(
                        value,
                        "dst_fold",
                        DstFoldPolicy,
                        DstFoldPolicy.REJECT,
                    ),
                ),
                delivery_mode=delivery_mode,
                output_dir=_resolve(base, _required(value, "output_dir")),
                integration_config=_resolve(
                    base,
                    _required(value, "integration_config"),
                ),
                workflow_config=_resolve(
                    base,
                    _required(value, "workflow_config"),
                ),
                identity_config=(
                    _resolve(base, str(value["identity_config"]))
                    if value.get("identity_config")
                    else None
                ),
                retention_config=(
                    _resolve(base, str(value["retention_config"]))
                    if value.get("retention_config")
                    else None
                ),
                allowed_capabilities=allowed_capabilities,
                allowed_recipients=_string_list(value, "allowed_recipients"),
                canonical_sources=canonical_sources,
                generation=_positive_int(value, "generation", 1),
                revoked=_strict_bool(value, "revoked", default=False),
                catch_up_policy=_enum(
                    value,
                    "catch_up_policy",
                    CatchUpPolicy,
                    CatchUpPolicy.LATEST_ONLY,
                ),
                approval_resume_minutes=_positive_int(
                    value,
                    "approval_resume_minutes",
                    1440,
                ),
            )
        return cls(
            state_database=state_database,
            lock_dir=lock_dir,
            workflows=workflows,
            occurrence_root=occurrence_root,
        )


@dataclass(frozen=True, slots=True)
class WorkflowDueStatus:
    """Due calculation for a registered workflow."""

    name: str
    enabled: bool
    due: bool
    scheduled_at: datetime
    last_success_at: datetime | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the status."""

        return {
            "name": self.name,
            "enabled": self.enabled,
            "due": self.due,
            "scheduled_at": self.scheduled_at.isoformat(),
            "last_success_at": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RecurringRunResult:
    """Recorded result returned by a recurring workflow callback."""

    successful: bool
    summary: Mapping[str, Any]


class RecurringStateStore:
    """SQLite scheduler state with atomic scheduled-occurrence claims."""

    def __init__(
        self,
        path: Path,
        *,
        lease_duration: timedelta = timedelta(minutes=5),
    ) -> None:
        require_persistent_state_platform()
        if lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be positive")
        self._path = Path(os.path.abspath(os.fspath(path)))
        self._lease_duration = lease_duration
        self._initialization_lock = RLock()
        self._database: PinnedSQLiteDatabase | None = None
        self._initialized = False
        if path_entry_exists(self._path):
            self._ensure_initialized()

    def close(self) -> None:
        """Close the persistent scheduler-state database connection."""

        with self._initialization_lock:
            if self._database is not None:
                self._database.close()

    def last_success(self, name: str) -> datetime | None:
        """Return the most recent successful completion time."""

        if self._database is None and not path_entry_exists(self._path):
            return None
        self._ensure_initialized()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT finished_at FROM recurring_runs "
                "WHERE workflow_name = ? AND successful = 1 "
                "ORDER BY id DESC LIMIT 1",
                (name,),
            ).fetchone()
        return datetime.fromisoformat(str(row[0])) if row else None

    def occurrence_status(self, name: str, scheduled_at: datetime) -> str | None:
        """Return the durable state of one scheduled occurrence."""

        if self._database is None and not path_entry_exists(self._path):
            return None
        self._ensure_initialized()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM recurring_runs "
                "WHERE workflow_name = ? AND scheduled_at = ?",
                (name, scheduled_at.isoformat()),
            ).fetchone()
        return str(row[0]) if row else None

    def register_occurrence_artifact(
        self,
        *,
        workflow_name: str,
        scheduled_at: datetime,
        artifact_fingerprint: str,
        artifact_sha256: str,
        registration_digest: str,
        execution_key: str,
        resume_deadline: datetime,
    ) -> None:
        """Atomically authenticate one locally published occurrence artifact."""

        self._ensure_initialized()
        values = (
            workflow_name,
            scheduled_at.astimezone(UTC).isoformat(),
            artifact_fingerprint,
            artifact_sha256,
            registration_digest,
            execution_key,
            str(OccurrenceStatus.BOUND),
            resume_deadline.astimezone(UTC).isoformat(),
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT artifact_fingerprint, artifact_sha256,
                       registration_digest, execution_key, resume_deadline
                FROM recurring_occurrences
                WHERE workflow_name = ? AND scheduled_at = ?
                """,
                values[:2],
            ).fetchone()
            if existing is not None:
                if tuple(str(item) for item in existing) == values[2:6] + values[7:]:
                    return
                raise ConfigurationError(
                    "a different recurring artifact is already registered for "
                    "this occurrence"
                )
            connection.execute(
                """
                INSERT INTO recurring_occurrences (
                    workflow_name, scheduled_at, artifact_fingerprint,
                    artifact_sha256, registration_digest, execution_key,
                    status, claim_generation, claim_token, lease_expires_at,
                    approval_request_fingerprint, resume_deadline, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?, NULL)
                """,
                values,
            )

    def authenticate_occurrence_artifact(
        self,
        *,
        workflow_name: str,
        scheduled_at: datetime,
        artifact_fingerprint: str,
        artifact_sha256: str,
        registration_digest: str,
        execution_key: str,
    ) -> OccurrenceStatus:
        """Verify one artifact against separately trusted local state."""

        self._ensure_initialized()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT artifact_fingerprint, artifact_sha256,
                       registration_digest, execution_key, status
                FROM recurring_occurrences
                WHERE workflow_name = ? AND scheduled_at = ?
                """,
                (workflow_name, scheduled_at.astimezone(UTC).isoformat()),
            ).fetchone()
        if row is None:
            raise ConfigurationError(
                "recurring artifact is not registered in trusted local state"
            )
        expected = (
            artifact_fingerprint,
            artifact_sha256,
            registration_digest,
            execution_key,
        )
        if tuple(str(item) for item in row[:4]) != expected:
            raise ConfigurationError("recurring artifact authentication changed")
        try:
            return OccurrenceStatus(str(row[4]))
        except ValueError as error:
            raise ConfigurationError("recurring occurrence state is invalid") from error

    def reserve_occurrence(
        self,
        *,
        artifact_fingerprint: str,
        started_at: datetime,
    ) -> tuple[int, UUID]:
        """Reserve one bound occurrence and return its generation and token."""

        self._ensure_initialized()
        token = uuid4()
        current = started_at.astimezone(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences
                SET status = ?, claim_generation = claim_generation + 1,
                    claim_token = ?, lease_expires_at = ?, finished_at = NULL
                WHERE artifact_fingerprint = ? AND status IN (?, ?)
                  AND resume_deadline >= ?
                """,
                (
                    str(OccurrenceStatus.RUNNING),
                    str(token),
                    (current + self._lease_duration).isoformat(),
                    artifact_fingerprint,
                    str(OccurrenceStatus.BOUND),
                    str(OccurrenceStatus.RECOVERABLE),
                    current.isoformat(),
                ),
            )
            if cursor.rowcount != 1:
                raise ConfigurationError(
                    "recurring occurrence is not eligible for reservation"
                )
            row = connection.execute(
                "SELECT claim_generation FROM recurring_occurrences "
                "WHERE artifact_fingerprint = ?",
                (artifact_fingerprint,),
            ).fetchone()
        if row is None:  # pragma: no cover - transaction invariant.
            raise RuntimeError("reserved recurring occurrence disappeared")
        return int(row[0]), token

    def mark_occurrence_recoverable(
        self,
        *,
        artifact_fingerprint: str,
    ) -> None:
        """Apply an explicit reviewed transition for a pre-effect retry."""

        self._ensure_initialized()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences
                SET status = ?, approval_request_fingerprint = NULL
                WHERE artifact_fingerprint = ? AND status = ?
                """,
                (
                    str(OccurrenceStatus.RECOVERABLE),
                    artifact_fingerprint,
                    str(OccurrenceStatus.FAILED_PRE_EFFECT),
                ),
            )
        if cursor.rowcount != 1:
            raise ConfigurationError(
                "only a certified failed-pre-effect occurrence can be recovered"
            )

    def reconcile_expired_occurrence(
        self,
        *,
        artifact_fingerprint: str,
        status: OccurrenceStatus,
        now: datetime | None = None,
    ) -> None:
        """Transition one expired running lease after exact-record review."""

        if status not in {
            OccurrenceStatus.RECOVERABLE,
            OccurrenceStatus.INDETERMINATE,
        }:
            raise ValueError("unsupported recurring reconciliation state")
        self._ensure_initialized()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences
                SET status = ?, claim_token = NULL, lease_expires_at = NULL,
                    finished_at = ?
                WHERE artifact_fingerprint = ? AND status = ?
                  AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?
                """,
                (
                    str(status),
                    current.isoformat(),
                    artifact_fingerprint,
                    str(OccurrenceStatus.RUNNING),
                    current.isoformat(),
                ),
            )
        if cursor.rowcount != 1:
            raise ConfigurationError(
                "recurring occurrence has no expired running claim to reconcile"
            )

    def cancel_occurrence(self, *, artifact_fingerprint: str) -> OccurrenceStatus:
        """Cancel pending work or conservatively fence an active attempt."""

        self._ensure_initialized()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status FROM recurring_occurrences "
                "WHERE artifact_fingerprint = ?",
                (artifact_fingerprint,),
            ).fetchone()
            if row is None:
                raise ConfigurationError("recurring occurrence is not registered")
            current = OccurrenceStatus(str(row[0]))
            if current in {
                OccurrenceStatus.SUCCEEDED,
                OccurrenceStatus.INDETERMINATE,
                OccurrenceStatus.REVOKED,
                OccurrenceStatus.CANCELLED,
            }:
                raise ConfigurationError(
                    "completed or uncertain recurring occurrence cannot be cancelled"
                )
            selected = (
                OccurrenceStatus.INDETERMINATE
                if current is OccurrenceStatus.RUNNING
                else OccurrenceStatus.CANCELLED
            )
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences
                SET status = ?, claim_token = NULL, lease_expires_at = NULL,
                    finished_at = ?
                WHERE artifact_fingerprint = ? AND status = ?
                """,
                (
                    str(selected),
                    datetime.now(UTC).isoformat(),
                    artifact_fingerprint,
                    str(current),
                ),
            )
            if cursor.rowcount != 1:  # pragma: no cover - write-lock invariant.
                raise ConfigurationError("recurring occurrence changed during cancel")
        return selected

    def validate_occurrence_fence(
        self,
        *,
        artifact_fingerprint: str,
        claim_generation: int,
        claim_token: UUID,
        now: datetime | None = None,
    ) -> None:
        """Fail unless the caller still owns the exact unexpired fence."""

        self._ensure_initialized()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT status, claim_generation, claim_token, lease_expires_at
                FROM recurring_occurrences WHERE artifact_fingerprint = ?
                """,
                (artifact_fingerprint,),
            ).fetchone()
        if (
            row is None
            or str(row[0]) != str(OccurrenceStatus.RUNNING)
            or int(row[1]) != claim_generation
            or str(row[2]) != str(claim_token)
            or row[3] is None
            or datetime.fromisoformat(str(row[3])) <= current
        ):
            raise ConfigurationError("recurring occurrence claim fence was lost")

    def renew_occurrence_fence(
        self,
        *,
        artifact_fingerprint: str,
        claim_generation: int,
        claim_token: UUID,
        now: datetime | None = None,
    ) -> bool:
        """Renew only the exact current occurrence fence."""

        self._ensure_initialized()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences SET lease_expires_at = ?
                WHERE artifact_fingerprint = ? AND status = ?
                  AND claim_generation = ? AND claim_token = ?
                """,
                (
                    (current + self._lease_duration).isoformat(),
                    artifact_fingerprint,
                    str(OccurrenceStatus.RUNNING),
                    claim_generation,
                    str(claim_token),
                ),
            )
        return cursor.rowcount == 1

    def block_occurrence_for_approval(
        self,
        *,
        artifact_fingerprint: str,
        claim_generation: int,
        claim_token: UUID,
        request_fingerprint: str,
    ) -> None:
        """Release the lease into one durable exact approval-blocked state."""

        self._transition_running_occurrence(
            artifact_fingerprint=artifact_fingerprint,
            claim_generation=claim_generation,
            claim_token=claim_token,
            status=OccurrenceStatus.APPROVAL_BLOCKED,
            request_fingerprint=request_fingerprint,
        )

    def resume_approval_blocked_occurrence(
        self,
        *,
        artifact_fingerprint: str,
        prior_generation: int,
        request_fingerprint: str,
        started_at: datetime,
    ) -> tuple[int, UUID]:
        """Atomically reclaim the same occurrence for one exact approval resume."""

        self._ensure_initialized()
        token = uuid4()
        current = started_at.astimezone(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences
                SET status = ?, claim_generation = claim_generation + 1,
                    claim_token = ?, lease_expires_at = ?, finished_at = NULL
                WHERE artifact_fingerprint = ? AND status = ?
                  AND claim_generation = ?
                  AND approval_request_fingerprint = ?
                  AND resume_deadline >= ?
                """,
                (
                    str(OccurrenceStatus.RUNNING),
                    str(token),
                    (current + self._lease_duration).isoformat(),
                    artifact_fingerprint,
                    str(OccurrenceStatus.APPROVAL_BLOCKED),
                    prior_generation,
                    request_fingerprint,
                    current.isoformat(),
                ),
            )
            if cursor.rowcount != 1:
                raise ConfigurationError(
                    "recurring approval resume is stale, expired, or changed"
                )
        return prior_generation + 1, token

    def finalize_occurrence(
        self,
        *,
        artifact_fingerprint: str,
        claim_generation: int,
        claim_token: UUID,
        status: OccurrenceStatus,
        finished_at: datetime | None = None,
    ) -> None:
        """Finalize one currently fenced occurrence."""

        if status not in {
            OccurrenceStatus.SUCCEEDED,
            OccurrenceStatus.FAILED_PRE_EFFECT,
            OccurrenceStatus.INDETERMINATE,
            OccurrenceStatus.REVOKED,
        }:
            raise ValueError("unsupported recurring occurrence terminal state")
        self._transition_running_occurrence(
            artifact_fingerprint=artifact_fingerprint,
            claim_generation=claim_generation,
            claim_token=claim_token,
            status=status,
            finished_at=finished_at or datetime.now(UTC),
        )

    def _transition_running_occurrence(
        self,
        *,
        artifact_fingerprint: str,
        claim_generation: int,
        claim_token: UUID,
        status: OccurrenceStatus,
        request_fingerprint: str | None = None,
        finished_at: datetime | None = None,
    ) -> None:
        self._ensure_initialized()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_occurrences
                SET status = ?, claim_token = NULL, lease_expires_at = NULL,
                    approval_request_fingerprint = ?, finished_at = ?
                WHERE artifact_fingerprint = ? AND status = ?
                  AND claim_generation = ? AND claim_token = ?
                """,
                (
                    str(status),
                    request_fingerprint,
                    finished_at.astimezone(UTC).isoformat()
                    if finished_at is not None
                    else None,
                    artifact_fingerprint,
                    str(OccurrenceStatus.RUNNING),
                    claim_generation,
                    str(claim_token),
                ),
            )
        if cursor.rowcount != 1:
            raise ConfigurationError("recurring occurrence claim fence was lost")

    def claim(
        self,
        *,
        name: str,
        scheduled_at: datetime,
        started_at: datetime,
    ) -> UUID | None:
        """Atomically claim an occurrence and return its attempt owner token."""

        self._ensure_initialized()
        claim_token = uuid4()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            lease_expires_at = started_at + self._lease_duration
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO recurring_runs (
                    workflow_name, scheduled_at, started_at, finished_at,
                    successful, summary_json, status, lease_expires_at,
                    attempt_count, recovery_reason, claim_token
                ) VALUES (?, ?, ?, ?, 0, '{}', ?, ?, 1, NULL, ?)
                """,
                (
                    name,
                    scheduled_at.isoformat(),
                    started_at.isoformat(),
                    started_at.isoformat(),
                    str(ClaimStatus.RUNNING),
                    lease_expires_at.isoformat(),
                    str(claim_token),
                ),
            )
            if cursor.rowcount != 1:
                cursor = connection.execute(
                    """
                    UPDATE recurring_runs
                    SET started_at = ?, finished_at = ?, successful = 0,
                        summary_json = '{}', status = ?, lease_expires_at = ?,
                        attempt_count = attempt_count + 1,
                        recovery_reason = NULL, claim_token = ?
                    WHERE workflow_name = ? AND scheduled_at = ?
                      AND status = ?
                    """,
                    (
                        started_at.isoformat(),
                        started_at.isoformat(),
                        str(ClaimStatus.RUNNING),
                        lease_expires_at.isoformat(),
                        str(claim_token),
                        name,
                        scheduled_at.isoformat(),
                        str(ClaimStatus.RECOVERABLE),
                    ),
                )
            return claim_token if cursor.rowcount == 1 else None

    def renew(
        self,
        *,
        name: str,
        scheduled_at: datetime,
        claim_token: UUID,
        now: datetime | None = None,
    ) -> bool:
        """Renew a running claim lease while its callback is active."""

        self._ensure_initialized()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_runs SET lease_expires_at = ?
                WHERE workflow_name = ? AND scheduled_at = ? AND status = ?
                  AND claim_token = ?
                """,
                (
                    (current + self._lease_duration).isoformat(),
                    name,
                    scheduled_at.isoformat(),
                    str(ClaimStatus.RUNNING),
                    str(claim_token),
                ),
            )
        return cursor.rowcount == 1

    def expire_claims(self, *, now: datetime | None = None) -> int:
        """Mark elapsed running leases expired without automatically retrying."""

        if self._database is None and not path_entry_exists(self._path):
            return 0
        self._ensure_initialized()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_runs
                SET status = ?, recovery_reason = 'lease_expired',
                    claim_token = NULL
                WHERE status = ? AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (
                    str(ClaimStatus.EXPIRED),
                    str(ClaimStatus.RUNNING),
                    current.isoformat(),
                ),
            )
        return cursor.rowcount

    def mark_recoverable(self, *, name: str, scheduled_at: datetime) -> bool:
        """Explicitly permit a reviewed expired occurrence to be reclaimed."""

        if self._database is None and not path_entry_exists(self._path):
            return False
        self._ensure_initialized()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_runs
                SET status = ?, recovery_reason = 'operator_reviewed'
                WHERE workflow_name = ? AND scheduled_at = ? AND status = ?
                """,
                (
                    str(ClaimStatus.RECOVERABLE),
                    name,
                    scheduled_at.isoformat(),
                    str(ClaimStatus.EXPIRED),
                ),
            )
        return cursor.rowcount == 1

    def complete(
        self,
        *,
        name: str,
        scheduled_at: datetime,
        claim_token: UUID,
        finished_at: datetime,
        result: RecurringRunResult,
    ) -> None:
        """Complete a previously claimed occurrence exactly once."""

        self._ensure_initialized()
        payload = json.dumps(
            result.summary,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE recurring_runs
                SET finished_at = ?, successful = ?, summary_json = ?, status = ?
                    , lease_expires_at = NULL, claim_token = NULL
                WHERE workflow_name = ? AND scheduled_at = ? AND status = 'running'
                  AND claim_token = ?
                """,
                (
                    finished_at.isoformat(),
                    int(result.successful),
                    payload,
                    (
                        str(ClaimStatus.SUCCEEDED)
                        if result.successful
                        else str(ClaimStatus.FAILED)
                    ),
                    name,
                    scheduled_at.isoformat(),
                    str(claim_token),
                ),
            )
            if cursor.rowcount != 1:
                raise ConfigurationError(
                    f"recurring occurrence is not actively claimed: "
                    f"{name} at {scheduled_at.isoformat()}"
                )

    def fail(
        self,
        *,
        name: str,
        scheduled_at: datetime,
        claim_token: UUID,
        finished_at: datetime,
        error: BaseException,
    ) -> None:
        """Mark a claimed occurrence failed without persisting error content."""

        self.complete(
            name=name,
            scheduled_at=scheduled_at,
            claim_token=claim_token,
            finished_at=finished_at,
            result=RecurringRunResult(
                successful=False,
                summary={
                    "workflow": name,
                    "failed": True,
                    "error_type": type(error).__name__,
                },
            ),
        )

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recurring_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_name TEXT NOT NULL,
                    scheduled_at TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    successful INTEGER NOT NULL,
                    summary_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'succeeded',
                    lease_expires_at TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 1,
                    recovery_reason TEXT,
                    claim_token TEXT
                )
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(recurring_runs)")
            }
            if "status" not in columns:
                connection.execute(
                    "ALTER TABLE recurring_runs "
                    "ADD COLUMN status TEXT NOT NULL DEFAULT 'succeeded'"
                )
            if "lease_expires_at" not in columns:
                connection.execute(
                    "ALTER TABLE recurring_runs ADD COLUMN lease_expires_at TEXT"
                )
            if "attempt_count" not in columns:
                connection.execute(
                    "ALTER TABLE recurring_runs "
                    "ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 1"
                )
            if "recovery_reason" not in columns:
                connection.execute(
                    "ALTER TABLE recurring_runs ADD COLUMN recovery_reason TEXT"
                )
            if "claim_token" not in columns:
                connection.execute(
                    "ALTER TABLE recurring_runs ADD COLUMN claim_token TEXT"
                )
            try:
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "recurring_occurrence_once "
                    "ON recurring_runs (workflow_name, scheduled_at)"
                )
            except sqlite3.IntegrityError as error:
                raise ConfigurationError(
                    "recurring state contains duplicate scheduled occurrences; "
                    "review and repair it before upgrading"
                ) from error
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recurring_occurrences (
                    workflow_name TEXT NOT NULL,
                    scheduled_at TEXT NOT NULL,
                    artifact_fingerprint TEXT NOT NULL UNIQUE,
                    artifact_sha256 TEXT NOT NULL,
                    registration_digest TEXT NOT NULL,
                    execution_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    claim_generation INTEGER NOT NULL DEFAULT 0,
                    claim_token TEXT,
                    lease_expires_at TEXT,
                    approval_request_fingerprint TEXT,
                    resume_deadline TEXT NOT NULL,
                    finished_at TEXT,
                    PRIMARY KEY (workflow_name, scheduled_at)
                )
                """
            )

    def _ensure_initialized(self) -> None:
        """Create scheduler state only when state is read or written."""

        with self._initialization_lock:
            if self._initialized:
                return
            database = PinnedSQLiteDatabase(self._path)
            self._database = database
            try:
                self._initialize()
            except Exception:
                self._database = None
                database.close(remove_created=True)
                raise
            self._initialized = True

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield only the persistent identity-pinned database connection."""

        if self._database is None:
            raise RuntimeError("recurring state database is not initialized")
        with self._database.connect() as connection:
            yield connection


class RecurringRunner:
    """Execute only enabled, registered, due workflows under a file lock."""

    def __init__(self, config: RecurringConfig) -> None:
        self._config = config
        self._store = RecurringStateStore(config.state_database)

    def due_status(
        self,
        workflow: RegisteredWorkflow,
        *,
        now: datetime | None = None,
    ) -> WorkflowDueStatus:
        """Calculate whether a workflow is currently due."""

        current = (now or datetime.now(UTC)).astimezone(UTC)
        self._store.expire_claims(now=current)
        scheduled = workflow.schedule.scheduled_at_or_before(current)
        last = self._store.last_success(workflow.name)
        occurrence_status = self._store.occurrence_status(workflow.name, scheduled)
        lateness = current - scheduled
        if not workflow.enabled:
            due = False
            reason = "workflow is disabled"
        elif lateness > timedelta(minutes=workflow.schedule.max_lateness_minutes):
            due = False
            reason = "latest schedule is outside the configured lateness window"
        elif occurrence_status is not None:
            due = False
            reason = (
                f"latest scheduled occurrence is already claimed ({occurrence_status})"
            )
        else:
            due = True
            reason = "registered workflow is due"
        return WorkflowDueStatus(
            name=workflow.name,
            enabled=workflow.enabled,
            due=due,
            scheduled_at=scheduled,
            last_success_at=last,
            reason=reason,
        )

    def run(
        self,
        name: str,
        callback: Callable[[RegisteredWorkflow], RecurringRunResult],
        *,
        now: datetime | None = None,
        force: bool = False,
    ) -> RecurringRunResult:
        """Run one registered workflow and record durable scheduler state."""

        try:
            workflow = self._config.workflows[name]
        except KeyError as error:
            raise ConfigurationError(
                f"recurring workflow is not registered: {name}"
            ) from error
        status = self.due_status(workflow, now=now)
        if not workflow.enabled:
            raise ConfigurationError(f"recurring workflow is disabled: {name}")
        if not force and not status.due:
            return RecurringRunResult(
                successful=True,
                summary={"skipped": True, "reason": status.reason},
            )
        started = (now or datetime.now(UTC)).astimezone(UTC)
        claim_token = self._store.claim(
            name=name,
            scheduled_at=status.scheduled_at,
            started_at=started,
        )
        if claim_token is None:
            return RecurringRunResult(
                successful=True,
                summary={
                    "skipped": True,
                    "reason": "latest scheduled occurrence is already claimed",
                },
            )
        try:
            stop_heartbeat = Event()
            heartbeat_errors: list[Exception] = []

            def heartbeat() -> None:
                interval = max(
                    self._store._lease_duration.total_seconds() / 3,
                    0.1,
                )
                while not stop_heartbeat.wait(interval):
                    try:
                        renewed = self._store.renew(
                            name=name,
                            scheduled_at=status.scheduled_at,
                            claim_token=claim_token,
                        )
                        if not renewed:
                            raise ConfigurationError(
                                "recurring occurrence lease was lost"
                            )
                    except (OSError, sqlite3.Error, ConfigurationError) as error:
                        heartbeat_errors.append(error)
                        return

            heartbeat_thread = Thread(target=heartbeat, daemon=True)
            heartbeat_thread.start()
            try:
                with self._lock(name):
                    result = callback(workflow)
            finally:
                stop_heartbeat.set()
                heartbeat_thread.join()
            if heartbeat_errors:
                raise ConfigurationError(
                    "recurring occurrence lease could not be renewed"
                ) from heartbeat_errors[0]
        except BaseException as error:
            self._store.fail(
                name=name,
                scheduled_at=status.scheduled_at,
                claim_token=claim_token,
                finished_at=datetime.now(UTC),
                error=error,
            )
            raise
        self._store.complete(
            name=name,
            scheduled_at=status.scheduled_at,
            claim_token=claim_token,
            finished_at=datetime.now(UTC),
            result=result,
        )
        return result

    @contextmanager
    def _lock(self, name: str) -> Iterator[None]:
        self._config.lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self._config.lock_dir / f"{_safe_name(name)}.lock"
        try:
            descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as error:
            raise ConfigurationError(
                f"recurring workflow is already running: {name}"
            ) from error
        try:
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.close(descriptor)
            yield
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


def validate_plan_scope(
    capabilities: tuple[str, ...],
    workflow: RegisteredWorkflow,
) -> None:
    """Reject a generated plan that exceeds its registered capability set."""

    allowed = set(workflow.allowed_capabilities)
    unexpected = sorted(set(capabilities) - allowed)
    if unexpected:
        raise ConfigurationError(
            "registered workflow generated unapproved capabilities: "
            + ", ".join(unexpected)
        )


def validate_recipients(
    recipients: tuple[str, ...],
    workflow: RegisteredWorkflow,
) -> None:
    """Reject recipients outside the immutable registration allowlist."""

    allowed = {item.casefold() for item in workflow.allowed_recipients}
    unexpected = sorted(item for item in recipients if item.casefold() not in allowed)
    if unexpected:
        raise ConfigurationError(
            "registered workflow selected unapproved recipients: "
            + ", ".join(unexpected)
        )


def _table(raw: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return _mapping(raw.get(key, {}), f"[{key}]")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{name} must be a TOML table")
    return value


def _required(value: Mapping[str, Any], key: str) -> str:
    rendered = str(value.get(key, "")).strip()
    if not rendered:
        raise ConfigurationError(f"{key} must not be empty")
    return rendered


def _strict_bool(value: Mapping[str, Any], key: str, *, default: bool) -> bool:
    item = value.get(key, default)
    if not isinstance(item, bool):
        raise ConfigurationError(f"{key} must be a TOML boolean")
    return item


def _int(value: Mapping[str, Any], key: str, default: int) -> int:
    item = value.get(key, default)
    if isinstance(item, bool):
        raise ConfigurationError(f"{key} must be an integer")
    try:
        return int(item)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"{key} must be an integer") from error


def _positive_int(value: Mapping[str, Any], key: str, default: int) -> int:
    item = _int(value, key, default)
    if item <= 0:
        raise ConfigurationError(f"{key} must be positive")
    return item


def _enum(
    value: Mapping[str, Any],
    key: str,
    enum_type: type[StrEnum],
    default: StrEnum,
) -> Any:
    raw = value.get(key, str(default))
    if not isinstance(raw, str):
        raise ConfigurationError(f"{key} must be a string")
    try:
        return enum_type(raw)
    except ValueError as error:
        raise ConfigurationError(f"{key} is unsupported") from error


def _string_list(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
    item = value.get(key, [])
    if not isinstance(item, list):
        raise ConfigurationError(f"{key} must be a string list")
    rendered = tuple(str(entry).strip() for entry in item if str(entry).strip())
    return rendered


def _resolve(base: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _safe_name(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in value
    )


def _restrict(path: Path) -> None:
    """Restrict local scheduler state to the current account where supported."""

    try:
        path.chmod(0o600)
    except OSError:
        pass
