"""Authenticated cross-process attempt budgets for advisory specialists."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
from pathlib import Path
from types import TracebackType
from typing import Self

from master_agent.advisory import (
    AdvisoryBudgetReservation,
    AdvisoryRole,
)
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError
from master_agent.sqlite_safety import PinnedSQLiteDatabase

_DATABASE_NAME = "budget.sqlite3"
_KEY_NAME = ".budget.hmac-key"
_KEY_BYTES = 32
_MAX_GOAL_RECORDS = 4096
_GOAL_ID_BYTES = 256
_SCHEMA_COLUMNS = (
    "goal_digest",
    "repository_digest",
    "research_attempts",
    "review_attempts",
    "tag",
)


class AdvisoryBudgetStateError(RuntimeError):
    """Durable advisory-budget state is missing, unsafe, or invalid."""


class AdvisoryBudgetStore:
    """Atomically reserve authenticated attempts for one operator goal.

    The database persists only content-free digests, counters, and an HMAC tag.
    A private sibling key authenticates each row while ``PinnedSQLiteDatabase``
    provides cross-process locking and race-safe generation replacement.
    """

    def __init__(self, state_directory: Path, repository_root: Path) -> None:
        self._repository_digest = _repository_identity(repository_root)
        selected = Path(os.path.abspath(os.fspath(state_directory.expanduser())))
        try:
            selected.mkdir(parents=True, exist_ok=True, mode=0o700)
            state_stat = selected.lstat()
            if (
                not stat.S_ISDIR(state_stat.st_mode)
                or state_stat.st_uid != os.getuid()
                or stat.S_IMODE(state_stat.st_mode) & 0o077
            ):
                raise ConfigurationError(
                    "advisory budget directory must be current-user-owned mode 0700"
                )
            with PinnedDirectory.open(selected) as pinned:
                self._key = _load_or_create_key(pinned)
                self._database = PinnedSQLiteDatabase(
                    Path(_DATABASE_NAME),
                    parent_directory=pinned,
                )
        except (ConfigurationError, OSError, sqlite3.Error) as error:
            raise AdvisoryBudgetStateError(
                "advisory budget state could not be opened safely"
            ) from error
        try:
            self._initialize()
        except BaseException:
            self._database.close(remove_created=True)
            raise

    def reserve(
        self,
        goal_id: str,
        role: AdvisoryRole,
        *,
        max_research_tasks: int,
        max_plan_reviews: int,
    ) -> AdvisoryBudgetReservation:
        """Atomically reserve one role attempt for an authenticated goal row."""

        goal_digest = _goal_digest(goal_id)
        if max_research_tasks <= 0 or max_plan_reviews <= 0:
            raise ValueError("advisory budget limits must be positive")
        try:
            with self._database.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT repository_digest, research_attempts,
                           review_attempts, tag
                    FROM advisory_goal_budgets
                    WHERE goal_digest = ?
                    """,
                    (goal_digest,),
                ).fetchone()
                if row is None:
                    count_row = connection.execute(
                        "SELECT COUNT(*) FROM advisory_goal_budgets"
                    ).fetchone()
                    record_count = int(count_row[0]) if count_row is not None else -1
                    if not 0 <= record_count < _MAX_GOAL_RECORDS:
                        raise AdvisoryBudgetStateError(
                            "advisory budget record limit is exhausted"
                        )
                    research_attempts = 0
                    review_attempts = 0
                else:
                    research_attempts, review_attempts = self._verified_counts(
                        goal_digest,
                        row,
                    )

                allowed = False
                if role is AdvisoryRole.RESEARCH:
                    if research_attempts < max_research_tasks:
                        research_attempts += 1
                        allowed = True
                elif review_attempts < max_plan_reviews:
                    review_attempts += 1
                    allowed = True

                if allowed:
                    tag = self._tag(
                        goal_digest,
                        research_attempts,
                        review_attempts,
                    )
                    connection.execute(
                        """
                        INSERT INTO advisory_goal_budgets (
                            goal_digest, repository_digest, research_attempts,
                            review_attempts, tag
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(goal_digest) DO UPDATE SET
                            repository_digest = excluded.repository_digest,
                            research_attempts = excluded.research_attempts,
                            review_attempts = excluded.review_attempts,
                            tag = excluded.tag
                        """,
                        (
                            goal_digest,
                            self._repository_digest,
                            research_attempts,
                            review_attempts,
                            tag,
                        ),
                    )
                return AdvisoryBudgetReservation(
                    allowed=allowed,
                    research_attempts=research_attempts,
                    review_attempts=review_attempts,
                )
        except AdvisoryBudgetStateError:
            raise
        except (ConfigurationError, OSError, RuntimeError, sqlite3.Error) as error:
            raise AdvisoryBudgetStateError(
                "advisory budget reservation failed closed"
            ) from error

    def close(self) -> None:
        """Release the pinned database and transaction-lock descriptors."""

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

    def _initialize(self) -> None:
        try:
            with self._database.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS advisory_goal_budgets (
                        goal_digest TEXT PRIMARY KEY NOT NULL,
                        repository_digest TEXT NOT NULL,
                        research_attempts INTEGER NOT NULL,
                        review_attempts INTEGER NOT NULL,
                        tag TEXT NOT NULL
                    )
                    """
                )
                columns = tuple(
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(advisory_goal_budgets)"
                    )
                )
                if columns != _SCHEMA_COLUMNS:
                    raise AdvisoryBudgetStateError(
                        "advisory budget schema is incompatible"
                    )
        except AdvisoryBudgetStateError:
            raise
        except (ConfigurationError, OSError, RuntimeError, sqlite3.Error) as error:
            raise AdvisoryBudgetStateError(
                "advisory budget schema initialization failed"
            ) from error

    def _verified_counts(
        self,
        goal_digest: str,
        row: tuple[object, ...],
    ) -> tuple[int, int]:
        if len(row) != 4:
            raise AdvisoryBudgetStateError("advisory budget row is malformed")
        repository_digest, research_raw, review_raw, tag = row
        if (
            repository_digest != self._repository_digest
            or not isinstance(research_raw, int)
            or isinstance(research_raw, bool)
            or not isinstance(review_raw, int)
            or isinstance(review_raw, bool)
            or research_raw < 0
            or review_raw < 0
            or not isinstance(tag, str)
        ):
            raise AdvisoryBudgetStateError("advisory budget row is malformed")
        expected = self._tag(goal_digest, research_raw, review_raw)
        if not hmac.compare_digest(expected, tag):
            raise AdvisoryBudgetStateError("advisory budget row authentication failed")
        return research_raw, review_raw

    def _tag(
        self,
        goal_digest: str,
        research_attempts: int,
        review_attempts: int,
    ) -> str:
        material = json.dumps(
            {
                "goal_digest": goal_digest,
                "repository_digest": self._repository_digest,
                "research_attempts": research_attempts,
                "review_attempts": review_attempts,
                "schema": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()


def _goal_digest(goal_id: str) -> str:
    if (
        not isinstance(goal_id, str)
        or not goal_id
        or goal_id != goal_id.strip()
        or len(goal_id.encode("utf-8")) > _GOAL_ID_BYTES
    ):
        raise ValueError("advisory goal ID is invalid")
    return hashlib.sha256(goal_id.encode("utf-8")).hexdigest()


def _repository_identity(root: Path) -> str:
    selected = root.expanduser().resolve(strict=True)
    value = selected.stat()
    if not selected.is_dir():
        raise AdvisoryBudgetStateError("advisory repository root is not a directory")
    material = json.dumps(
        {
            "device": value.st_dev,
            "inode": value.st_ino,
            "path": os.fspath(selected),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _load_or_create_key(directory: PinnedDirectory) -> bytes:
    parent_descriptor = directory.duplicate_fd()
    descriptor: int | None = None
    created = False
    try:
        fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
        try:
            descriptor = os.open(
                _KEY_NAME,
                os.O_RDONLY | _no_follow_flag(),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            descriptor = os.open(
                _KEY_NAME,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
            key = secrets.token_bytes(_KEY_BYTES)
            _write_all(descriptor, key)
            os.fsync(descriptor)
            os.fsync(parent_descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
        identity = _validated_key_identity(os.fstat(descriptor))
        public = os.stat(
            _KEY_NAME,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not _same_key_identity(identity, public):
            raise AdvisoryBudgetStateError("advisory budget key path changed")
        payload = _read_exact_key(descriptor)
        if not _same_key_identity(identity, os.fstat(descriptor)):
            raise AdvisoryBudgetStateError("advisory budget key changed while read")
        return payload
    except BaseException:
        if created and descriptor is not None:
            try:
                public = os.stat(
                    _KEY_NAME,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                opened_identity = _validated_key_identity(os.fstat(descriptor))
                if _same_key_identity(opened_identity, public):
                    os.unlink(_KEY_NAME, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(parent_descriptor)


def _validated_key_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.getuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
    ):
        raise AdvisoryBudgetStateError(
            "advisory budget key must be a current-user-owned mode-0600 regular file"
        )
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_nlink,
        stat.S_IMODE(value.st_mode),
    )


def _same_key_identity(
    expected: tuple[int, int, int, int, int],
    value: os.stat_result,
) -> bool:
    try:
        return expected == _validated_key_identity(value)
    except AdvisoryBudgetStateError:
        return False


def _read_exact_key(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) <= _KEY_BYTES:
        chunk = os.read(descriptor, _KEY_BYTES + 1 - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) != _KEY_BYTES:
        raise AdvisoryBudgetStateError("advisory budget key has an invalid length")
    return bytes(payload)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("advisory budget key write made no progress")
        offset += written


def _no_follow_flag() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(value, int):
        raise AdvisoryBudgetStateError(
            "this platform cannot safely open the advisory budget key"
        )
    return value
