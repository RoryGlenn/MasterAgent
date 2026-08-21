"""Tests for authenticated cross-process advisory goal budgets."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from master_agent.advisory import (
    AdvisoryBroker,
    AdvisoryReport,
    AdvisoryRole,
    DelegationStatus,
    RepositoryFixture,
    load_agent_inventory,
)
from master_agent.advisory_budget import (
    AdvisoryBudgetStateError,
    AdvisoryBudgetStore,
)
from master_agent.sqlite_safety import readonly_snapshot_connection


class AdvisoryBudgetStoreTests(unittest.TestCase):
    """Prove reservations survive restarts and authenticate minimal state."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name).resolve() / "state"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_research_and_review_limits_survive_store_restart(self) -> None:
        """Independent store instances share exactly one goal budget."""

        for attempt in range(3):
            with AdvisoryBudgetStore(self.state, self.root) as store:
                reservation = store.reserve(
                    "goal-115",
                    AdvisoryRole.RESEARCH,
                    max_research_tasks=3,
                    max_plan_reviews=1,
                )
            self.assertTrue(reservation.allowed)
            self.assertEqual(reservation.research_attempts, attempt + 1)

        with AdvisoryBudgetStore(self.state, self.root) as store:
            research_denied = store.reserve(
                "goal-115",
                AdvisoryRole.RESEARCH,
                max_research_tasks=3,
                max_plan_reviews=1,
            )
            review_allowed = store.reserve(
                "goal-115",
                AdvisoryRole.PLAN_REVIEW,
                max_research_tasks=3,
                max_plan_reviews=1,
            )
            review_denied = store.reserve(
                "goal-115",
                AdvisoryRole.PLAN_REVIEW,
                max_research_tasks=3,
                max_plan_reviews=1,
            )

        self.assertFalse(research_denied.allowed)
        self.assertTrue(review_allowed.allowed)
        self.assertFalse(review_denied.allowed)

    def test_failed_workers_consume_the_durable_attempt_budget(self) -> None:
        """Retries cannot reset counters by constructing a new broker session."""

        inventory = load_agent_inventory(self.root)
        called = 0

        def failed_worker(envelope, dispatcher):  # type: ignore[no-untyped-def]
            del envelope, dispatcher
            nonlocal called
            called += 1
            raise RuntimeError("adapter unavailable")

        outcomes = []
        for attempt in range(4):
            with AdvisoryBudgetStore(self.state, self.root) as store:
                broker = AdvisoryBroker(
                    inventory,
                    RepositoryFixture({}),
                    budget=store,
                )
                session = broker.start_session(
                    "MasterAgent",
                    f"attempt-{attempt}",
                    goal_id="one-operator-goal",
                )
                outcomes.append(
                    session.delegate(
                        AdvisoryRole.RESEARCH,
                        {"task": "bounded research"},
                        worker=failed_worker,
                    )
                )

        self.assertEqual(called, 3)
        self.assertTrue(all(item.fallback_to_parent for item in outcomes))
        self.assertIn("budget exhausted", outcomes[-1].reason)

    def test_state_is_private_authenticated_and_content_minimized(self) -> None:
        """The record stores a goal digest and rejects a validly persisted bad tag."""

        goal_id = "opaque-goal-value-not-for-storage"
        with AdvisoryBudgetStore(self.state, self.root) as store:
            store.reserve(
                goal_id,
                AdvisoryRole.RESEARCH,
                max_research_tasks=3,
                max_plan_reviews=1,
            )
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        for path in self.state.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

        database = self.state / "budget.sqlite3"
        with readonly_snapshot_connection(database) as connection:
            row = connection.execute(
                """
                SELECT goal_digest, repository_digest, research_attempts,
                       review_attempts, tag
                FROM advisory_goal_budgets
                """
            ).fetchone()
        assert row is not None
        self.assertEqual(len(str(row[0])), 64)
        self.assertEqual(len(str(row[1])), 64)
        self.assertEqual((row[2], row[3]), (1, 0))
        self.assertEqual(len(str(row[4])), 64)
        self.assertNotIn(goal_id.encode("utf-8"), database.read_bytes())

        with (
            AdvisoryBudgetStore(self.state, self.root) as store,
            store._database.connect() as connection,  # type: ignore[attr-defined]
        ):
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE advisory_goal_budgets SET tag = ?",
                ("0" * 64,),
            )
        with (
            AdvisoryBudgetStore(self.state, self.root) as store,
            self.assertRaises(AdvisoryBudgetStateError),
        ):
            store.reserve(
                goal_id,
                AdvisoryRole.RESEARCH,
                max_research_tasks=3,
                max_plan_reviews=1,
            )

    def test_unsafe_state_directory_fails_before_reservation(self) -> None:
        """Group- or world-readable budget roots are never silently accepted."""

        self.state.mkdir()
        os.chmod(self.state, 0o755)
        with self.assertRaises(AdvisoryBudgetStateError):
            AdvisoryBudgetStore(self.state, self.root)

    def test_symlinked_state_ancestor_is_rejected_without_writes(self) -> None:
        """A repository symlink cannot redirect private budget-state creation."""

        base = Path(self.temporary.name).resolve()
        repository = base / "repository"
        outside = base / "outside"
        repository.mkdir()
        outside.mkdir(mode=0o700)
        (repository / ".master-agent").symlink_to(
            outside,
            target_is_directory=True,
        )

        with self.assertRaises(AdvisoryBudgetStateError):
            AdvisoryBudgetStore(
                repository / ".master-agent/advisory",
                repository,
            )

        self.assertEqual(tuple(outside.iterdir()), ())

    def test_budget_failure_keeps_worker_on_parent_path(self) -> None:
        """An authenticated-state failure produces fallback before worker startup."""

        inventory = load_agent_inventory(self.root)
        with AdvisoryBudgetStore(self.state, self.root) as store:
            store.reserve(
                "tampered-goal",
                AdvisoryRole.RESEARCH,
                max_research_tasks=3,
                max_plan_reviews=1,
            )
            with store._database.connect() as connection:  # type: ignore[attr-defined]
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE advisory_goal_budgets SET tag = ?",
                    ("f" * 64,),
                )
        called = False

        def worker(envelope, dispatcher):  # type: ignore[no-untyped-def]
            del envelope, dispatcher
            nonlocal called
            called = True
            return AdvisoryReport("unused", (), ())

        with AdvisoryBudgetStore(self.state, self.root) as store:
            broker = AdvisoryBroker(
                inventory,
                RepositoryFixture({}),
                budget=store,
            )
            outcome = broker.start_session(
                "MasterAgent",
                "tampered-attempt",
                goal_id="tampered-goal",
            ).delegate(
                AdvisoryRole.RESEARCH,
                {"task": "must remain on parent"},
                worker=worker,
            )

        self.assertEqual(outcome.status, DelegationStatus.FALLBACK)
        self.assertFalse(called)
        self.assertNotIn("goal", outcome.reason)


if __name__ == "__main__":
    unittest.main()
