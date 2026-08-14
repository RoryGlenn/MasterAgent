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
from master_agent.sqlite_safety import PinnedSQLiteDatabase, path_entry_exists


class WorkflowKind(StrEnum):
    """Built-in recurring workflows. Arbitrary kinds are rejected."""

    WEEKLY_STATUS_PACKAGE = "weekly_status_package"
    COMMUNICATION_CONTEXT_PACKAGE = "communication_context_package"


class DeliveryMode(StrEnum):
    """Permitted recurring output modes."""

    LOCAL_ONLY = "local_only"
    DRAFT_ONLY = "draft_only"


class ClaimStatus(StrEnum):
    """Durable lifecycle of one scheduled occurrence claim."""

    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    RECOVERABLE = "recoverable"


@dataclass(frozen=True, slots=True)
class WeeklySchedule:
    """Fixed weekly schedule in an IANA timezone."""

    weekday: int
    hour: int
    minute: int
    timezone: str
    max_lateness_minutes: int = 1440

    def __post_init__(self) -> None:
        if not 0 <= self.weekday <= 6:
            raise ConfigurationError("weekday must be 0 (Monday) through 6 (Sunday)")
        if not 0 <= self.hour <= 23:
            raise ConfigurationError("hour must be 0 through 23")
        if not 0 <= self.minute <= 59:
            raise ConfigurationError("minute must be 0 through 59")
        if self.max_lateness_minutes < 0:
            raise ConfigurationError("max_lateness_minutes must not be negative")
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
            tzinfo=zone,
        )
        if candidate > local:
            candidate -= timedelta(days=7)
        return candidate.astimezone(UTC)


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


@dataclass(frozen=True, slots=True)
class RecurringConfig:
    """Registered recurring workflows and scheduler storage."""

    state_database: Path
    lock_dir: Path
    workflows: Mapping[str, RegisteredWorkflow]

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
        # Runtime outputs are deliberately relative to the operator's current
        # working directory, including when safe defaults come from a wheel.
        base = Path.cwd().resolve()
        scheduler = _table(raw, "scheduler")
        state_database = _resolve(base, _required(scheduler, "state_database"))
        lock_dir = _resolve(base, _required(scheduler, "lock_dir"))
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
            )
        return cls(
            state_database=state_database,
            lock_dir=lock_dir,
            workflows=workflows,
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
            connection.commit()
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
            connection.commit()
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
            connection.commit()
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
            connection.commit()
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
                connection.rollback()
                raise ConfigurationError(
                    f"recurring occurrence is not actively claimed: "
                    f"{name} at {scheduled_at.isoformat()}"
                )
            connection.commit()

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
            connection.commit()

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
