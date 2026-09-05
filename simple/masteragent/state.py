"""Small, restartable task checkpoints backed by SQLite."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self
from uuid import uuid4


class TaskStateError(RuntimeError):
    """A task transition would discard or overwrite useful state."""


class UncertainStepError(TaskStateError):
    """A write needs an observed result or confirmed absence before resuming."""


class TaskCancelledError(TaskStateError):
    """The task was cancelled before this worker could save another result."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


class TaskStore:
    """Store task inputs, step results, and an editable handoff note.

    Parameters
    ----------
    path : Path
        Local SQLite database path. Parent directories are created as needed.

    Notes
    -----
    Use one instance per worker. A step must be completed by the instance that
    began it. Interrupted reads can run again; interrupted writes require an
    observed result through ``resolve_step`` or confirmed absence through
    ``retry_step``. This prevents replaying
    a write whose remote outcome is unknown, without claiming exactly-once
    execution across a database and an external provider.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create privately before SQLite opens the file; never chmod an existing
        # parent directory, which might be the user's project or home directory.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        if os.name == "posix":
            self.path.chmod(0o600)
        self._db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, workflow TEXT NOT NULL, inputs TEXT NOT NULL,
                status TEXT NOT NULL, result TEXT, error TEXT, note TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS steps (
                task_id TEXT NOT NULL REFERENCES tasks(id), name TEXT NOT NULL,
                position INTEGER NOT NULL, is_write INTEGER NOT NULL,
                status TEXT NOT NULL, result TEXT, error TEXT,
                attempt INTEGER NOT NULL, claim TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY (task_id, name)
            );
            """
        )
        self._claims: dict[tuple[str, str], str] = {}
        self._generations: dict[str, int] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the database connection after saving each completed operation."""
        self._db.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._db.rollback()
            raise
        else:
            self._db.commit()

    def _task(self, task_id: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown task: {task_id}")
        return row

    def _active(self, task_id: str) -> sqlite3.Row:
        task = self._task(task_id)
        if task["status"] == "cancelled":
            raise TaskCancelledError(f"Task {task_id} is cancelled; resume it explicitly.")
        if task["status"] != "running":
            raise TaskStateError(f"Task {task_id} is {task['status']}; resume it first.")
        generation = self._generations.get(task_id)
        if generation is not None and generation != task["generation"]:
            raise TaskStateError("This worker was superseded; reopen the task before continuing.")
        return task

    @staticmethod
    def _step_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result.pop("claim", None)
        result["is_write"] = bool(result["is_write"])
        result["result"] = json.loads(row["result"]) if row["result"] is not None else None
        return result

    def create(self, workflow: str, inputs: dict[str, Any]) -> str:
        """Create a running task and return its stable identifier.

        Parameters
        ----------
        workflow : str
            Name of the workflow to resume after an interruption.
        inputs : dict[str, Any]
            JSON-serializable inputs, excluding credentials.

        Returns
        -------
        str
            Unique task identifier.
        """
        if not workflow.strip():
            raise ValueError("A workflow name is required.")
        task_id, timestamp = uuid4().hex, _now()
        self._db.execute(
            "INSERT INTO tasks VALUES (?, ?, ?, 'running', NULL, NULL, '', 0, ?, ?)",
            (task_id, workflow, _encode(inputs), timestamp, timestamp),
        )
        self._generations[task_id] = 0
        return task_id

    def get(self, task_id: str) -> dict[str, Any]:
        """Return one task with ordered step results and its current handoff note.

        Parameters
        ----------
        task_id : str
            Identifier returned by ``create``.

        Returns
        -------
        dict[str, Any]
            Task metadata, decoded inputs/results, and an ordered ``steps`` list.
        """
        task = dict(self._task(task_id))
        task.pop("generation")
        task["inputs"] = json.loads(task["inputs"])
        task["result"] = json.loads(task["result"]) if task["result"] is not None else None
        rows = self._db.execute(
            "SELECT * FROM steps WHERE task_id = ? ORDER BY position", (task_id,)
        )
        task["steps"] = [self._step_dict(row) for row in rows]
        return task

    def list_tasks(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent tasks, most recently updated first.

        Parameters
        ----------
        limit : int, default=20
            Maximum number of tasks to return.

        Returns
        -------
        list[dict[str, Any]]
            Task records in the same format as ``get``.
        """
        if limit < 0:
            raise ValueError("limit must be nonnegative")
        ids = self._db.execute(
            "SELECT id FROM tasks ORDER BY updated_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self.get(row["id"]) for row in ids]

    def begin_step(self, task_id: str, name: str, is_write: bool = False) -> dict[str, Any]:
        """Claim a step, or return its completed checkpoint without executing it.

        Parameters
        ----------
        task_id : str
            Task to update.
        name : str
            Stable step name, reused when resuming the workflow.
        is_write : bool, default=False
            Whether replay could duplicate an external effect.

        Returns
        -------
        dict[str, Any]
            Step with ``status`` equal to ``running`` or ``completed``.

        Raises
        ------
        UncertainStepError
            A previous write is running or has an uncertain outcome.
        """
        if not name.strip():
            raise ValueError("A step name is required.")
        with self._transaction():
            task = self._active(task_id)
            self._generations[task_id] = task["generation"]
            row = self._db.execute(
                "SELECT * FROM steps WHERE task_id = ? AND name = ?", (task_id, name)
            ).fetchone()
            if row is not None:
                if bool(row["is_write"]) != is_write:
                    raise TaskStateError("A step's write classification cannot change on resume.")
                if row["status"] == "completed":
                    return self._step_dict(row)
                if row["is_write"] and row["status"] in {"running", "uncertain"}:
                    raise UncertainStepError(
                        f"Step '{name}' may already have succeeded. Check its remote result "
                        "and resolve the step before continuing."
                    )
            claim, timestamp = uuid4().hex, _now()
            if row is None:
                self._db.execute(
                    "INSERT INTO steps VALUES (?, ?, "
                    "(SELECT COUNT(*) FROM steps WHERE task_id = ?), ?, 'running', "
                    "NULL, NULL, 1, ?, ?, ?)",
                    (task_id, name, task_id, int(is_write), claim, timestamp, timestamp),
                )
            else:
                self._db.execute(
                    "UPDATE steps SET status = 'running', result = NULL, error = NULL, "
                    "attempt = attempt + 1, claim = ?, updated_at = ? "
                    "WHERE task_id = ? AND name = ?", (claim, timestamp, task_id, name),
                )
            self._db.execute(
                "UPDATE tasks SET updated_at = ? WHERE id = ?", (timestamp, task_id)
            )
            self._claims[(task_id, name)] = claim
            current = self._db.execute(
                "SELECT * FROM steps WHERE task_id = ? AND name = ?", (task_id, name)
            ).fetchone()
            return self._step_dict(current)

    def _save_step(
        self, task_id: str, name: str, status: str, result: Any = None, error: str | None = None
    ) -> None:
        encoded = _encode(result)
        with self._transaction():
            self._active(task_id)
            claim = self._claims.get((task_id, name))
            cursor = self._db.execute(
                "UPDATE steps SET status = ?, result = ?, error = ?, claim = NULL, "
                "updated_at = ? WHERE task_id = ? AND name = ? AND claim = ? "
                "AND status = 'running'",
                (status, encoded, error, _now(), task_id, name, claim),
            )
            if cursor.rowcount != 1:
                raise TaskStateError("This worker no longer owns the running step.")
            self._db.execute("UPDATE tasks SET updated_at = ? WHERE id = ?", (_now(), task_id))
        self._claims.pop((task_id, name), None)

    def complete_step(self, task_id: str, name: str, result: Any) -> None:
        """Save a JSON-serializable result for a step claimed by this instance."""
        self._save_step(task_id, name, "completed", result=result)

    def fail_step(self, task_id: str, name: str, error: str, uncertain: bool = False) -> None:
        """Save an error; mark ambiguous write outcomes uncertain to prevent replay."""
        self._save_step(task_id, name, "uncertain" if uncertain else "failed", error=error)

    def finish(self, task_id: str, result: Any) -> None:
        """Complete an active task once every started step has a saved result."""
        encoded = _encode(result)
        with self._transaction():
            self._active(task_id)
            unfinished = self._db.execute(
                "SELECT name FROM steps WHERE task_id = ? AND status != 'completed' LIMIT 1",
                (task_id,),
            ).fetchone()
            if unfinished:
                raise TaskStateError(f"Step '{unfinished['name']}' is not complete.")
            self._db.execute(
                "UPDATE tasks SET status = 'completed', result = ?, error = NULL, "
                "updated_at = ? WHERE id = ?", (encoded, _now(), task_id),
            )

    def wait(self, task_id: str, result: Any) -> None:
        """Pause an active task with a handoff result while waiting for host work."""
        encoded = _encode(result)
        with self._transaction():
            self._active(task_id)
            self._db.execute(
                "UPDATE tasks SET status = 'waiting', result = ?, error = NULL, "
                "updated_at = ? WHERE id = ?", (encoded, _now(), task_id),
            )

    def fail(self, task_id: str, error: str, result: Any = None) -> None:
        """Mark an active task failed, saving any supplied partial result."""
        encoded = _encode(result)
        with self._transaction():
            self._active(task_id)
            self._db.execute(
                "UPDATE tasks SET status = 'failed', error = ?, "
                "result = CASE WHEN ? = 'null' THEN result ELSE ? END, updated_at = ? WHERE id = ?",
                (error, encoded, encoded, _now(), task_id),
            )

    def cancel(self, task_id: str) -> None:
        """Cancel future work and invalidate active claims without undoing remote writes."""
        with self._transaction():
            task = self._task(task_id)
            if task["status"] == "completed":
                raise TaskStateError("A completed task cannot be cancelled.")
            self._db.execute(
                "UPDATE tasks SET status = 'cancelled', generation = generation + 1, "
                "updated_at = ? WHERE id = ?", (_now(), task_id),
            )
            self._db.execute(
                "UPDATE steps SET status = CASE WHEN is_write = 1 THEN 'uncertain' "
                "ELSE 'failed' END, error = 'Task cancelled during step', claim = NULL, "
                "updated_at = ? WHERE task_id = ? AND status = 'running'", (_now(), task_id),
            )

    def resume(self, task_id: str) -> None:
        """Resume a stopped task; uncertain writes still require an observed result."""
        with self._transaction():
            task = self._task(task_id)
            if task["status"] == "completed":
                raise TaskStateError("A completed task does not need resuming.")
            generation = task["generation"] + 1
            self._db.execute(
                "UPDATE tasks SET status = 'running', error = NULL, generation = ?, "
                "updated_at = ? WHERE id = ?", (generation, _now(), task_id),
            )
        self._generations[task_id] = generation

    def resolve_step(self, task_id: str, name: str, result: Any) -> None:
        """Record an explicitly observed remote result after an interrupted write.

        Parameters
        ----------
        task_id : str
            Task containing the interrupted step.
        name : str
            Write step whose outcome the user has checked.
        result : Any
            Observed JSON-serializable result, such as the existing PR URL.
        """
        encoded = _encode(result)
        with self._transaction():
            self._task(task_id)
            cursor = self._db.execute(
                "UPDATE steps SET status = 'completed', result = ?, error = NULL, "
                "claim = NULL, updated_at = ? WHERE task_id = ? AND name = ? "
                "AND is_write = 1 AND status IN ('running', 'uncertain')",
                (encoded, _now(), task_id, name),
            )
            if cursor.rowcount != 1:
                raise TaskStateError("Only an interrupted or uncertain write can be resolved.")
            self._db.execute("UPDATE tasks SET updated_at = ? WHERE id = ?", (_now(), task_id))

    def retry_step(self, task_id: str, name: str) -> None:
        """Allow a later retry after the caller confirms no remote write was applied.

        Parameters
        ----------
        task_id : str
            Task containing the interrupted write.
        name : str
            Running or uncertain write whose absence the caller has checked.

        Notes
        -----
        This records the explicit caller decision without executing the write or
        changing the task's status. Failed or cancelled tasks still need an
        explicit ``resume``. The previous worker can no longer save results.
        """
        with self._transaction():
            task = self._task(task_id)
            cursor = self._db.execute(
                "UPDATE steps SET status = 'failed', result = NULL, error = NULL, "
                "claim = NULL, updated_at = ? WHERE task_id = ? AND name = ? "
                "AND is_write = 1 AND status IN ('running', 'uncertain')",
                (_now(), task_id, name),
            )
            if cursor.rowcount != 1:
                raise TaskStateError("Only an interrupted or uncertain write can be retried.")
            generation = task["generation"] + 1
            self._db.execute(
                "UPDATE tasks SET generation = ?, updated_at = ? WHERE id = ?",
                (generation, _now(), task_id),
            )
        self._claims.pop((task_id, name), None)
        self._generations[task_id] = generation

    def note(self, task_id: str, text: str) -> None:
        """Replace the task's editable handoff note with the supplied text."""
        with self._transaction():
            self._task(task_id)
            self._db.execute(
                "UPDATE tasks SET note = ?, updated_at = ? WHERE id = ?", (text, _now(), task_id)
            )
