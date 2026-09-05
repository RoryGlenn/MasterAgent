"""Exercise recovery and duplicate prevention using real SQLite connections."""

import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from masteragent.state import (
    TaskCancelledError,
    TaskStateError,
    TaskStore,
    UncertainStepError,
)


class TaskStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "state" / "tasks.sqlite3"

    def test_restart_preserves_steps_and_retries_interrupted_read(self) -> None:
        with TaskStore(self.path) as first:
            task_id = first.create("review", {"issue": "MA-1"})
            first.begin_step(task_id, "issue")
            first.complete_step(task_id, "issue", {"summary": "Fix caching"})
            first.begin_step(task_id, "pull_requests")
        with TaskStore(self.path) as restarted:
            restarted.resume(task_id)
            cached = restarted.begin_step(task_id, "issue")
            self.assertEqual(cached["status"], "completed")
            self.assertEqual(cached["result"], {"summary": "Fix caching"})
            self.assertEqual(cached["attempt"], 1)
            retry = restarted.begin_step(task_id, "pull_requests")
            self.assertEqual(retry["attempt"], 2)
            restarted.complete_step(task_id, "pull_requests", [])
            restarted.finish(task_id, {"summary": "No PR exists yet"})
            task = restarted.get(task_id)
            self.assertEqual(task["status"], "completed")
            self.assertEqual(task["inputs"], {"issue": "MA-1"})
            self.assertEqual(
                [step["name"] for step in task["steps"]], ["issue", "pull_requests"]
            )
            json.dumps(task)

    def test_interrupted_write_requires_observed_result(self) -> None:
        with TaskStore(self.path) as first:
            task_id = first.create("publish", {})
            first.begin_step(task_id, "open_pr", is_write=True)
        with TaskStore(self.path) as restarted:
            restarted.resume(task_id)
            with self.assertRaises(UncertainStepError):
                restarted.begin_step(task_id, "open_pr", is_write=True)
            with self.assertRaises(TaskStateError):
                restarted.begin_step(task_id, "open_pr", is_write=False)
            observed = {"url": "https://example.org/pulls/17"}
            restarted.resolve_step(task_id, "open_pr", observed)
            cached = restarted.begin_step(task_id, "open_pr", is_write=True)
            self.assertEqual(cached["result"], observed)
            self.assertEqual(cached["attempt"], 1)
            restarted.finish(task_id, observed)

    def test_partial_completion_survives_following_failure(self) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("publish", {})
            store.begin_step(task_id, "open_pr", is_write=True)
            store.complete_step(task_id, "open_pr", {"id": 17})
            store.begin_step(task_id, "update_jira", is_write=True)
            store.fail_step(task_id, "update_jira", "Connection failed before request")
            store.fail(task_id, "Jira unavailable", result={"pull_request": 17})
            failed = store.get(task_id)
            self.assertEqual(failed["result"], {"pull_request": 17})
            store.resume(task_id)
            self.assertEqual(
                store.begin_step(task_id, "open_pr", True)["result"], {"id": 17}
            )
            self.assertEqual(
                store.begin_step(task_id, "update_jira", True)["attempt"], 2
            )
            store.complete_step(task_id, "update_jira", {"updated": True})
            store.finish(task_id, {"pull_request": 17, "jira_updated": True})

    def test_unknown_write_error_cannot_be_retried(self) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("publish", {})
            store.begin_step(task_id, "post_comment", True)
            store.fail_step(task_id, "post_comment", "Response lost", uncertain=True)
            store.fail(task_id, "Check remote comment before resuming")
            store.resume(task_id)
            with self.assertRaises(UncertainStepError):
                store.begin_step(task_id, "post_comment", True)
            with self.assertRaises(TaskStateError):
                store.finish(task_id, {})

    def test_cancel_rejects_stale_worker_results_even_after_resume(self) -> None:
        with TaskStore(self.path) as worker, TaskStore(self.path) as controller:
            task_id = worker.create("publish", {})
            worker.begin_step(task_id, "open_pr", True)
            controller.cancel(task_id)
            with self.assertRaises(TaskCancelledError):
                worker.complete_step(task_id, "open_pr", {"id": 17})
            with self.assertRaises(TaskCancelledError):
                worker.finish(task_id, {})
            controller.resume(task_id)
            with self.assertRaises(TaskStateError):
                worker.complete_step(task_id, "open_pr", {"id": 17})
            with self.assertRaises(TaskStateError):
                worker.finish(task_id, {})
            with self.assertRaises(UncertainStepError):
                controller.begin_step(task_id, "open_pr", True)
            controller.resolve_step(task_id, "open_pr", {"id": 17})
            controller.finish(task_id, {"id": 17})

    def test_confirmed_absent_write_is_retriable_only_after_explicit_resume(
        self,
    ) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("publish", {})
            store.begin_step(task_id, "open_pr", True)
            store.fail_step(task_id, "open_pr", "Response lost", uncertain=True)
            store.fail(task_id, "Inspect provider before continuing")

            store.retry_step(task_id, "open_pr")

            task = store.get(task_id)
            self.assertEqual(task["status"], "failed")
            self.assertEqual(task["steps"][0]["status"], "failed")
            self.assertEqual(task["steps"][0]["attempt"], 1)
            self.assertIsNone(task["steps"][0]["result"])
            self.assertIsNone(task["steps"][0]["error"])
            with self.assertRaises(TaskStateError):
                store.begin_step(task_id, "open_pr", True)
            store.resume(task_id)
            self.assertEqual(store.begin_step(task_id, "open_pr", True)["attempt"], 2)
            store.complete_step(task_id, "open_pr", {"id": 18})
            store.finish(task_id, {"id": 18})

    def test_confirmed_absent_running_write_invalidates_previous_worker(self) -> None:
        with TaskStore(self.path) as worker, TaskStore(self.path) as controller:
            task_id = worker.create("publish", {})
            worker.begin_step(task_id, "open_pr", True)
            controller.retry_step(task_id, "open_pr")
            with self.assertRaises(TaskStateError):
                worker.complete_step(task_id, "open_pr", {"id": 17})
            controller.begin_step(task_id, "open_pr", True)
            controller.complete_step(task_id, "open_pr", {"id": 18})
            with self.assertRaises(TaskStateError):
                worker.finish(task_id, {"id": 17})
            controller.finish(task_id, {"id": 18})

    def test_retry_does_not_uncancel_tasks_or_reset_completed_steps(self) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("publish", {})
            store.begin_step(task_id, "open_pr", True)
            store.cancel(task_id)
            store.retry_step(task_id, "open_pr")
            self.assertEqual(store.get(task_id)["status"], "cancelled")
            with self.assertRaises(TaskCancelledError):
                store.begin_step(task_id, "open_pr", True)
            store.resume(task_id)
            store.begin_step(task_id, "open_pr", True)
            store.complete_step(task_id, "open_pr", {"id": 18})
            with self.assertRaises(TaskStateError):
                store.retry_step(task_id, "open_pr")
            self.assertEqual(store.get(task_id)["steps"][0]["result"], {"id": 18})
            store.begin_step(task_id, "read_issue")
            with self.assertRaises(TaskStateError):
                store.retry_step(task_id, "read_issue")

    def test_two_workers_cannot_claim_the_same_write(self) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("publish", {})
        barrier = threading.Barrier(2)

        def attempt() -> str:
            with TaskStore(self.path) as worker:
                barrier.wait(timeout=5)
                try:
                    worker.begin_step(task_id, "open_pr", True)
                except UncertainStepError:
                    return "blocked"
                return "claimed"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertCountEqual(results, ["claimed", "blocked"])
        with TaskStore(self.path) as store:
            self.assertEqual(store.get(task_id)["steps"][0]["attempt"], 1)

    def test_replacement_read_invalidates_old_workers_result(self) -> None:
        with TaskStore(self.path) as old, TaskStore(self.path) as new:
            task_id = old.create("review", {})
            old.begin_step(task_id, "issue")
            new.begin_step(task_id, "issue")
            with self.assertRaises(TaskStateError):
                old.complete_step(task_id, "issue", {"summary": "stale"})
            new.complete_step(task_id, "issue", {"summary": "current"})
            self.assertEqual(
                new.get(task_id)["steps"][0]["result"], {"summary": "current"}
            )

    def test_waiting_handoff_and_editable_note_survive_restart(self) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("develop", {})
            store.note(task_id, "First attempt")
            store.note(task_id, "Ask reviewer about cache expiry")
            store.wait(task_id, {"next": "Edit repository with Copilot"})
        with TaskStore(self.path) as store:
            task = store.get(task_id)
            self.assertEqual(task["status"], "waiting")
            self.assertEqual(task["note"], "Ask reviewer about cache expiry")
            self.assertEqual(task["result"], {"next": "Edit repository with Copilot"})
            store.resume(task_id)
            store.begin_step(task_id, "check_repository")
            store.complete_step(task_id, "check_repository", {"clean": True})
            store.finish(task_id, {"done": True})
            self.assertEqual(store.list_tasks()[0]["id"], task_id)

    def test_no_partial_json_updates_and_unknown_task_error(self) -> None:
        with TaskStore(self.path) as store:
            task_id = store.create("review", {})
            store.begin_step(task_id, "issue")
            with self.assertRaises(TypeError):
                store.complete_step(task_id, "issue", object())
            self.assertEqual(store.get(task_id)["steps"][0]["status"], "running")
            store.complete_step(task_id, "issue", None)
            with self.assertRaises(KeyError):
                store.get("missing")
            self.assertEqual(store.list_tasks(limit=0), [])

    @unittest.skipUnless(os.name == "posix", "POSIX file mode assertion")
    def test_database_created_with_owner_only_permissions(self) -> None:
        with TaskStore(self.path):
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
