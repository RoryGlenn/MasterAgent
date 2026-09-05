"""Verify task outcomes and resumptions with fake providers and real local Git."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

from masteragent.state import TaskStore
from masteragent.workflows import WorkflowError, Workflows
from masteragent.workspace import publish_branch


class UncertainProviderError(RuntimeError):
    uncertain = True


class FakeProviders:
    pr_url = "https://bitbucket.example/projects/APP/repos/backend/pull-requests/17"
    page_url = "https://docs.example/pages/123/design"
    issue_url = "https://jira.example/browse/APP-42"
    build_url = "https://builds.example/runs/88"
    created_pr: ClassVar[dict[str, Any]] = {
        "id": 18,
        "url": "https://bitbucket.example/projects/APP/repos/backend/pull-requests/18",
    }
    created_comment: ClassVar[dict[str, Any]] = {
        "id": "101",
        "url": "https://jira.example/browse/APP-42?focusedCommentId=101",
    }

    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()
        self.failures: dict[str, Exception] = {}
        self.comment_arguments: tuple[str, str, str] | None = None

    def _call(self, name: str) -> None:
        self.calls[name] += 1
        failure = self.failures.pop(name, None)
        if failure is not None:
            raise failure

    def issue(self, key: str) -> dict[str, Any]:
        self._call("issue")
        return {
            "key": key,
            "title": "Improve caching",
            "description": "Cache the slow query and document invalidation.",
            "status": "In Progress",
            "url": self.issue_url,
            "links": [self.pr_url, self.page_url],
        }

    def pull_request(self, url: str) -> dict[str, Any]:
        self._call("pull_request")
        return {"url": url, "title": "Existing caching work", "state": "OPEN"}

    def builds(self, pr: dict[str, Any]) -> list[dict[str, Any]]:
        self._call("builds")
        return [{"name": "Backend tests", "url": self.build_url, "state": "SUCCESSFUL"}]

    def page(self, url: str) -> dict[str, Any]:
        self._call("page")
        return {
            "url": url,
            "title": "Caching design",
            "body": "Invalidate on configuration changes.",
        }

    def create_pull_request(
        self,
        repository: str,
        source: str,
        target: str,
        title: str,
        description: str,
    ) -> dict[str, Any]:
        self._call("create_pull_request")
        return dict(self.created_pr)

    def comment_issue(self, key: str, body: str, marker: str) -> dict[str, Any]:
        self.comment_arguments = (key, body, marker)
        self._call("comment_issue")
        return dict(self.created_comment)


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "state"
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.git(self.repository, "init", "-b", "main")
        self.git(self.repository, "config", "user.name", "Workflow Test")
        self.git(self.repository, "config", "user.email", "workflow@example.invalid")
        (self.repository / "source.py").write_text("answer = 42\n", encoding="utf-8")
        self.git(self.repository, "add", "source.py")
        self.git(self.repository, "commit", "-m", "Initial commit")
        self.remote = self.root / "remote.git"
        self.remote.mkdir()
        self.git(self.remote, "init", "--bare")
        self.git(self.repository, "remote", "add", "origin", str(self.remote))
        self.providers = FakeProviders()
        self.store = TaskStore(self.home / "tasks.sqlite3")
        self.addCleanup(self.store.close)
        self.config: dict[str, Any] = {
            "confluence": {"url": "https://docs.example"},
            "projects": {
                "APP": {
                    "repository": str(self.repository),
                    "bitbucket_repository": "APP/backend",
                    "checks": [
                        [
                            sys.executable,
                            "-c",
                            "from pathlib import Path; assert Path('source.py').exists()",
                        ]
                    ],
                }
            },
        }
        self.workflows = Workflows(self.home, self.config, self.store, self.providers)

    @staticmethod
    def git(path: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(path), *arguments],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def ready_task(self) -> dict[str, Any]:
        task = self.workflows.develop("APP-42")
        worktree = Path(task["result"]["workspace"]["path"])
        (worktree / "source.py").write_text("answer = 43\n", encoding="utf-8")
        self.git(worktree, "commit", "-am", "Implement task")
        self.workflows.checks(task["id"])
        return task

    def publish(self, task: dict[str, Any]) -> dict[str, Any]:
        return self.workflows.publish(
            task["id"], title="Improve caching", description="Cache query results."
        )

    def assert_no_publication(self) -> None:
        self.assertEqual(self.providers.calls["create_pull_request"], 0)
        self.assertEqual(self.providers.calls["comment_issue"], 0)
        self.assertEqual(
            self.git(self.remote, "for-each-ref", "--format=%(refname)"), ""
        )

    def test_review_collects_sources_and_resumes_only_failed_reads(self) -> None:
        self.providers.failures["page"] = RuntimeError(
            "Documentation temporarily unavailable"
        )
        task = self.workflows.review("app-42")
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["result"]["issue"]["key"], "APP-42")
        self.assertEqual(len(task["result"]["pull_requests"]), 1)
        self.assertEqual(
            task["result"]["pull_requests"][0]["builds"][0]["state"], "SUCCESSFUL"
        )
        self.assertEqual(len(task["result"]["errors"]), 1)
        resumed = self.workflows.resume(task["id"])
        self.assertEqual(resumed["status"], "completed")
        self.assertEqual(resumed["result"]["errors"], [])
        self.assertEqual(
            self.providers.calls,
            {"issue": 1, "pull_request": 1, "builds": 1, "page": 2},
        )
        artifact = Path(resumed["result"]["artifact"]).read_text(encoding="utf-8")
        for source in (
            self.providers.issue_url,
            self.providers.pr_url,
            self.providers.build_url,
            self.providers.page_url,
        ):
            self.assertIn(source, artifact)

    def test_review_build_retry_reuses_successful_pull_request(self) -> None:
        self.providers.failures["builds"] = RuntimeError("Build service unavailable")
        task = self.workflows.review("APP-42")
        resumed = self.workflows.resume(task["id"])
        self.assertEqual(resumed["status"], "completed")
        self.assertEqual(
            self.providers.calls,
            {"issue": 1, "pull_request": 1, "builds": 2, "page": 1},
        )

    def test_develop_waits_for_host_in_isolated_worktree(self) -> None:
        (self.repository / "source.py").write_text(
            "original uncommitted work\n", encoding="utf-8"
        )
        (self.repository / "untracked.txt").write_text("keep this\n", encoding="utf-8")
        task = self.workflows.develop("APP-42")
        self.assertEqual(task["status"], "waiting")
        worktree = Path(task["result"]["workspace"]["path"])
        self.assertNotEqual(worktree, self.repository)
        self.assertEqual((worktree / "source.py").read_text(), "answer = 42\n")
        self.assertEqual(
            (self.repository / "source.py").read_text(), "original uncommitted work\n"
        )
        self.assertTrue((self.repository / "untracked.txt").exists())
        self.assertEqual(self.git(self.repository, "branch", "--show-current"), "main")
        self.assertIn(str(worktree), Path(task["result"]["artifact"]).read_text())
        self.assert_no_publication()

    def test_failed_checks_prevent_any_publication(self) -> None:
        self.config["projects"]["APP"]["checks"] = [
            [sys.executable, "-c", "raise SystemExit(2)"]
        ]
        task = self.workflows.develop("APP-42")
        checks = self.workflows.checks(task["id"])
        self.assertFalse(checks["evidence"]["passed"])
        with self.assertRaisesRegex(WorkflowError, "passing checks"):
            self.publish(task)
        self.assert_no_publication()

    def test_publish_recovers_incomplete_sources_before_any_writes(self) -> None:
        self.providers.failures["page"] = RuntimeError("Documentation unavailable")
        task = self.ready_task()
        self.assertEqual(task["status"], "waiting")
        self.assertTrue(task["result"]["review"]["errors"])
        self.providers.failures["page"] = RuntimeError(
            "Documentation still unavailable"
        )
        with self.assertRaisesRegex(WorkflowError, "source reads still fail"):
            self.publish(task)
        self.assert_no_publication()
        resumed = self.workflows.resume(task["id"])
        self.assertEqual(resumed["status"], "completed")
        self.assertEqual(resumed["result"]["review"]["errors"], [])
        self.assertEqual(self.providers.calls["page"], 3)
        self.assertEqual(self.providers.calls["issue"], 1)
        self.assertEqual(self.providers.calls["pull_request"], 1)
        self.assertEqual(self.providers.calls["builds"], 1)
        self.assertEqual(self.providers.calls["create_pull_request"], 1)
        self.assertEqual(self.providers.calls["comment_issue"], 1)

    def test_new_commit_after_checks_prevents_any_publication(self) -> None:
        task = self.ready_task()
        worktree = Path(task["result"]["workspace"]["path"])
        (worktree / "source.py").write_text("answer = 44\n", encoding="utf-8")
        self.git(worktree, "commit", "-am", "Additional untested change")
        with self.assertRaisesRegex(WorkflowError, "rerun checks"):
            self.publish(task)
        self.assert_no_publication()

    def test_different_branch_at_tested_commit_blocks_checks_and_publication(
        self,
    ) -> None:
        task = self.ready_task()
        worktree = Path(task["result"]["workspace"]["path"])
        tested_commit = self.git(worktree, "rev-parse", "HEAD")
        self.git(worktree, "checkout", "-b", "unrelated-work")
        self.assertEqual(self.git(worktree, "rev-parse", "HEAD"), tested_commit)
        with self.assertRaisesRegex(WorkflowError, "another branch"):
            self.workflows.checks(task["id"])
        with self.assertRaisesRegex(WorkflowError, "another branch"):
            self.publish(task)
        self.assert_no_publication()

    def test_changed_provider_target_blocks_write_but_credential_updates_allow_resume(
        self,
    ) -> None:
        self.config["bitbucket"] = {
            "url": "https://bitbucket.example",
            "deployment": "server",
            "token_env": "TOKEN_OLD",
        }
        task = self.ready_task()
        self.config["bitbucket"]["url"] = "https://another-bitbucket.example"
        with self.assertRaisesRegex(WorkflowError, "account target changed"):
            self.publish(task)
        self.assertEqual(self.providers.calls["create_pull_request"], 0)
        self.assertEqual(self.providers.calls["comment_issue"], 0)
        self.config["bitbucket"]["url"] = "https://bitbucket.example/"
        self.config["bitbucket"]["token_env"] = "TOKEN_NEW"
        resumed = self.workflows.resume(task["id"])
        self.assertEqual(resumed["status"], "completed")
        self.assertEqual(self.providers.calls["create_pull_request"], 1)
        self.assertEqual(self.providers.calls["pull_request"], 1)
        self.assertEqual(self.providers.calls["builds"], 1)

    def test_interrupted_artifact_replace_preserves_previous_files(self) -> None:
        task = self.ready_task()
        directory = self.home / "outputs" / task["id"]
        self.workflows._artifact(
            task["id"], "publication.json", '{"title": "Original title"}'
        )
        for name in ("checks.json", "publication.json"):
            with self.subTest(name=name):
                before = (directory / name).read_bytes()
                with (
                    patch(
                        "masteragent.workflows.os.replace",
                        side_effect=OSError("Interrupted replacement"),
                    ),
                    self.assertRaisesRegex(OSError, "Interrupted replacement"),
                ):
                    self.workflows._artifact(task["id"], name, '{"new": "replacement"}')
                self.assertEqual((directory / name).read_bytes(), before)
                self.assertEqual(list(directory.glob(name + "-*")), [])

    def test_premature_publish_can_change_parameters_before_any_write(self) -> None:
        task = self.workflows.develop("APP-42")
        with self.assertRaisesRegex(WorkflowError, "Run checks"):
            self.publish(task)
        self.assert_no_publication()
        self.workflows.checks(task["id"])
        with patch.object(
            self.providers,
            "create_pull_request",
            wraps=self.providers.create_pull_request,
        ) as create_pr:
            completed = self.workflows.publish(
                task["id"],
                title="Corrected title",
                description="Corrected description",
                target="release",
            )
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(
            create_pr.call_args.args[2:5],
            ("release", "Corrected title", "Corrected description"),
        )

    def test_publish_resume_after_jira_failure_does_not_repeat_push_or_pr(self) -> None:
        task = self.ready_task()
        self.providers.failures["comment_issue"] = RuntimeError(
            "Jira rejected the request before writing"
        )
        with patch(
            "masteragent.workflows.publish_branch", wraps=publish_branch
        ) as push:
            with self.assertRaisesRegex(WorkflowError, "Jira rejected"):
                self.publish(task)
            failed = self.store.get(task["id"])
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(
                next(
                    step
                    for step in failed["steps"]
                    if step["name"] == "bitbucket.create_pr"
                )["status"],
                "completed",
            )
            # Later local work must not block the outstanding Jira update or
            # change the commit recorded for the already-published PR.
            worktree = Path(task["result"]["workspace"]["path"])
            (worktree / "later-untracked-work.txt").write_text(
                "still editing\n", encoding="utf-8"
            )
            resumed = self.workflows.resume(task["id"])
            self.assertEqual(resumed["status"], "completed")
            self.assertEqual(push.call_count, 1)
            self.assertTrue((worktree / "later-untracked-work.txt").exists())
        self.assertEqual(self.providers.calls["create_pull_request"], 1)
        self.assertEqual(self.providers.calls["comment_issue"], 2)
        self.assertEqual(resumed["result"]["pull_request"], self.providers.created_pr)
        self.assertEqual(
            self.providers.comment_arguments[2], f"masteragent:{task['id']}"
        )
        self.assertIn(
            resumed["result"]["published_commit"], self.providers.comment_arguments[1]
        )

    def assert_uncertain_write_requires_resolution(
        self, operation: str, step: str, result: dict[str, Any]
    ) -> None:
        task = self.ready_task()
        self.providers.failures[operation] = UncertainProviderError(
            "Response lost after request was sent"
        )
        with patch(
            "masteragent.workflows.publish_branch", wraps=publish_branch
        ) as push:
            with self.assertRaises(WorkflowError):
                self.publish(task)
            self.assertEqual(
                next(
                    item
                    for item in self.store.get(task["id"])["steps"]
                    if item["name"] == step
                )["status"],
                "uncertain",
            )
            with self.assertRaisesRegex(WorkflowError, "resolve"):
                self.workflows.resume(task["id"])
            self.assertEqual(self.providers.calls[operation], 1)
            self.store.resolve_step(task["id"], step, result)
            resumed = self.workflows.resume(task["id"])
            self.assertEqual(resumed["status"], "completed")
            self.assertEqual(push.call_count, 1)
        self.assertEqual(self.providers.calls["create_pull_request"], 1)
        self.assertEqual(self.providers.calls["comment_issue"], 1)

    def test_uncertain_pr_requires_observed_result_before_resume(self) -> None:
        self.assert_uncertain_write_requires_resolution(
            "create_pull_request", "bitbucket.create_pr", self.providers.created_pr
        )

    def test_uncertain_jira_comment_requires_observed_result_before_resume(
        self,
    ) -> None:
        self.assert_uncertain_write_requires_resolution(
            "comment_issue", "jira.comment", self.providers.created_comment
        )

    def test_cancelled_development_task_cannot_publish(self) -> None:
        task = self.ready_task()
        self.store.cancel(task["id"])
        with self.assertRaisesRegex(WorkflowError, "cancelled"):
            self.publish(task)
        self.assertEqual(self.store.get(task["id"])["status"], "cancelled")
        self.assert_no_publication()

    def test_status_explicitly_uses_saved_history_without_provider_calls(self) -> None:
        task = self.workflows.develop("APP-42")
        self.store.note(task["id"], "Need a decision about invalidation timing.")
        calls = self.providers.calls.copy()
        status = self.workflows.status([task["id"]])
        self.assertEqual(self.providers.calls, calls)
        self.assertEqual(status["status"], "completed")
        self.assertFalse(status["result"]["sent"])
        self.assertEqual(status["result"]["task_count"], 1)
        text = Path(status["result"]["artifact"]).read_text()
        for expected in (
            "saved local task history",
            "provider states have not been refreshed",
            "APP-42",
            "waiting",
            "invalidation timing",
            "nothing has been sent",
        ):
            self.assertIn(expected, text)

    def test_early_failed_task_has_clear_checks_and_publish_errors(self) -> None:
        self.providers.failures["issue"] = RuntimeError("Jira offline")
        with self.assertRaises(WorkflowError):
            self.workflows.develop("APP-42")
        task = self.store.list_tasks()[0]
        self.assertIsNone(task["result"])
        with self.assertRaisesRegex(WorkflowError, "prepared development task"):
            self.workflows.checks(task["id"])
        with self.assertRaisesRegex(WorkflowError, "prepared development task"):
            self.publish(task)


if __name__ == "__main__":
    unittest.main()
