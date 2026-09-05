"""Exercise real workflow/state code with explicitly fictional provider data."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .settings import initialize
from .state import TaskStore
from .workflows import Workflows


class DemoProviders:
    """Fictional sources for an offline demonstration; never a live fallback."""

    def issue(self, key: str) -> dict[str, Any]:
        """Return a fictional issue with linked PR and documentation."""
        return {
            "key": key,
            "title": "Add per-section dashboard caching",
            "description": "Cache dashboard sections independently. A refresh should invalidate only the affected section. Define expiry and invalidation before implementation.",
            "status": "In Progress",
            "url": f"https://demo.atlassian.net/browse/{key}",
            "links": [
                "https://bitbucket.org/demo/dashboard/pull-requests/12",
                "https://demo.atlassian.net/wiki/spaces/ENG/pages/123/Caching",
            ],
        }

    def pull_request(self, url: str) -> dict[str, Any]:
        """Return a fictional open PR."""
        return {
            "id": 12,
            "title": "Cache dashboard sections independently",
            "state": "OPEN",
            "url": url,
            "source_branch": "feature/cache",
            "target_branch": "main",
            "commit": "demo-commit",
            "repository": "demo/dashboard",
        }

    def builds(self, pr: dict[str, Any]) -> list[dict[str, Any]]:
        """Return a fictional successful test build."""
        return [
            {
                "name": "Unit tests (demo)",
                "state": "SUCCESSFUL",
                "url": "https://bitbucket.org/demo/dashboard/pipelines/results/42",
            }
        ]

    def page(self, url: str) -> dict[str, Any]:
        """Return fictional architecture guidance."""
        return {
            "id": "123",
            "title": "Dashboard caching decisions",
            "body": "Use independent cache keys per section. Refresh invalidates only that section. The expiry interval still requires an owner decision.",
            "url": url,
        }

    def create_pull_request(
        self, repository: str, source: str, target: str, title: str, description: str
    ) -> dict[str, Any]:
        """Reject effects; the demo never simulates a live publication."""
        raise RuntimeError("The offline demo does not publish.")

    def comment_issue(self, key: str, body: str, marker: str) -> dict[str, Any]:
        """Reject effects; the demo never sends a Jira comment."""
        raise RuntimeError("The offline demo does not send comments.")


def run_demo() -> dict[str, Any]:
    """Run review and status workflows in disposable isolated local state."""
    with TemporaryDirectory(prefix="masteragent-demo-") as temporary:
        home = Path(temporary)
        initialize(home)
        config = {
            "confluence": {"url": "https://demo.atlassian.net/wiki"},
            "projects": {},
        }
        with TaskStore(home / "tasks.sqlite3") as store:
            runner = Workflows(home, config, store, DemoProviders())
            review = runner.review("DEMO-123")
            store.note(
                review["id"], "Decide the cache expiry interval before implementation."
            )
            status = runner.status([review["id"]])
            return {
                "demo": True,
                "live_connections": False,
                "review_status": review["status"],
                "review": Path(review["result"]["artifact"]).read_text(
                    encoding="utf-8"
                ),
                "status_draft": Path(status["result"]["artifact"]).read_text(
                    encoding="utf-8"
                ),
                "completed_steps": len(review["steps"]),
                "temporary_state_removed_after_run": True,
            }
