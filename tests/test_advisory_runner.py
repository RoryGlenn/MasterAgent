"""Real-process regression tests for the governed advisory CLI runner."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from master_agent.advisory import (
    AdvisoryReport,
    AdvisoryRole,
    SemanticRouteSlice,
)
from scripts import advisory_subagent

_FAKE_RUNNER = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from master_agent.advisory import AdvisoryReport, AdvisoryRole, SemanticRouteSlice
    from scripts import advisory_subagent as runner

    ROUTE = SemanticRouteSlice(
        route="agent-topology",
        title="Parent and bounded advisory topology",
        lifecycle="released",
        summary="Bounded advisory test route.",
        authority=(),
        implementation=(),
        configuration=(),
        tests=(),
        release_gates=(),
        dependencies=(),
    )

    class Worker:
        def __call__(self, envelope, dispatcher):
            del envelope, dispatcher
            return AdvisoryReport("bounded", (), ())

    runner.CopilotSdkAdvisoryWorker = lambda root, scope=None: Worker()
    runner._validated_semantic_route = lambda root, route: ROUTE
    role = (
        AdvisoryRole.RESEARCH
        if sys.argv[3] == "research"
        else AdvisoryRole.PLAN_REVIEW
    )
    raise SystemExit(
        runner.run(
            Path(sys.argv[1]),
            role,
            "runner process test",
            ("README.md",),
            route="agent-topology",
            goal_id=sys.argv[4],
            state_directory=Path(sys.argv[2]),
        )
    )
    """
)

_TEST_ROUTE = SemanticRouteSlice(
    route="agent-topology",
    title="Parent and bounded advisory topology",
    lifecycle="released",
    summary="Bounded advisory test route.",
    authority=("specs/current/security/MA-ADVISORY-001.md",),
    implementation=("src/master_agent/advisory.py",),
    configuration=(),
    tests=("tests/test_advisory_integration.py",),
    release_gates=("scripts/validate_release.py",),
    dependencies=(),
)


class AdvisoryRunnerProcessTests(unittest.TestCase):
    """Prove one goal budget cannot be reset by real process boundaries."""

    def setUp(self) -> None:
        self.source = Path(__file__).resolve().parents[1]
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name).resolve()
        self.root = base / "repository"
        profiles = self.root / ".github/agents"
        profiles.mkdir(parents=True)
        for name in (
            "MasterAgent.agent.md",
            "MasterAgent-Read-Researcher.agent.md",
            "MasterAgent-Plan-Reviewer.agent.md",
        ):
            shutil.copy2(self.source / ".github/agents" / name, profiles / name)
        shutil.copy2(self.source / "README.md", self.root / "README.md")
        docs = self.root / "docs"
        docs.mkdir()
        shutil.copy2(
            self.source / "docs/advisory-subagents.md",
            docs / "advisory-subagents.md",
        )
        subprocess.run(("git", "init", "-q"), cwd=self.root, check=True)
        subprocess.run(
            ("git", "config", "user.email", "test@example.invalid"),
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ("git", "config", "user.name", "MasterAgent Test"),
            cwd=self.root,
            check=True,
        )
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-qm", "fixture"), cwd=self.root, check=True)
        self.state = base / "state"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _command(self, role: str, goal_id: str) -> tuple[str, ...]:
        return (
            sys.executable,
            "-c",
            _FAKE_RUNNER,
            str(self.root),
            str(self.state),
            role,
            goal_id,
        )

    def test_repeated_processes_and_restart_share_role_limits(self) -> None:
        """Fresh interpreters cannot exceed three research and one review."""

        research = [
            subprocess.run(
                self._command("research", "restart-goal"),
                cwd=self.source,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            for _ in range(4)
        ]
        review = [
            subprocess.run(
                self._command("plan-review", "restart-goal"),
                cwd=self.source,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            for _ in range(2)
        ]

        self.assertEqual([item.returncode for item in research], [0, 0, 0, 2])
        self.assertEqual([item.returncode for item in review], [0, 2])
        final = json.loads(research[-1].stdout)
        self.assertEqual(final["status"], "fallback")
        self.assertIn("budget exhausted", final["reason"])
        self.assertNotIn("restart-goal", research[-1].stdout)

    def test_concurrent_processes_reserve_only_three_research_attempts(self) -> None:
        """The durable transaction serializes simultaneous reservations."""

        processes = [
            subprocess.Popen(
                self._command("research", "concurrent-goal"),
                cwd=self.source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(10)
        ]
        results = [process.communicate(timeout=30) for process in processes]
        return_codes = [process.returncode for process in processes]

        self.assertEqual(return_codes.count(0), 3, results)
        self.assertEqual(return_codes.count(2), 7, results)
        for stdout, stderr in results:
            self.assertEqual(stderr, "")
            payload = json.loads(stdout)
            self.assertIn(payload["status"], {"completed", "fallback"})
            self.assertNotIn("concurrent-goal", stdout)

    def test_out_of_scope_citation_falls_back_without_disclosure(self) -> None:
        """Parent evidence revalidation uses the same technical route scope."""

        class Worker:
            def __call__(self, envelope, dispatcher):  # type: ignore[no-untyped-def]
                del envelope, dispatcher
                return AdvisoryReport(
                    "invented",
                    (),
                    ("docs/advisory-subagents.md",),
                )

        output = StringIO()
        with (
            patch.object(
                advisory_subagent,
                "CopilotSdkAdvisoryWorker",
                side_effect=lambda root, scope=None: Worker(),
            ),
            patch.object(
                advisory_subagent,
                "_validated_semantic_route",
                return_value=_TEST_ROUTE,
            ),
            redirect_stdout(output),
        ):
            return_code = advisory_subagent.run(
                self.root,
                AdvisoryRole.RESEARCH,
                "read only the README",
                ("README.md",),
                route="agent-topology",
                goal_id="citation-goal",
                state_directory=self.state,
            )

        self.assertEqual(return_code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "fallback")


class AdvisoryRunnerSemanticRouteTests(unittest.TestCase):
    """Bind one validated selected route before starting a live worker."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name).resolve() / "state"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_validated_route_slice_reaches_worker_and_changes_task_identity(
        self,
    ) -> None:
        """Only canonical route-local fields enter the envelope and task hash."""

        envelopes = []

        class Worker:
            def __call__(self, envelope, dispatcher):  # type: ignore[no-untyped-def]
                del dispatcher
                envelopes.append(envelope)
                return AdvisoryReport("bounded", (), ())

        output = StringIO()
        with (
            patch.object(
                advisory_subagent,
                "CopilotSdkAdvisoryWorker",
                side_effect=lambda root, scope=None: Worker(),
            ),
            redirect_stdout(output),
        ):
            results = [
                advisory_subagent.run(
                    self.root,
                    AdvisoryRole.RESEARCH,
                    "inspect one bounded file",
                    ("src/master_agent/advisory.py",),
                    route=route,
                    goal_id="route-binding-goal",
                    state_directory=self.state,
                )
                for route in ("agent-topology", "direct-read")
            ]

        self.assertEqual(results, [0, 0])
        self.assertEqual(len(envelopes), 2)
        self.assertNotEqual(envelopes[0].task_id, envelopes[1].task_id)
        route_payload = envelopes[0].semantic_route.to_payload()
        self.assertEqual(
            set(route_payload),
            {
                "route",
                "title",
                "lifecycle",
                "summary",
                "authority",
                "implementation",
                "configuration",
                "tests",
                "release_gates",
                "dependencies",
            },
        )
        self.assertEqual(route_payload["route"], "agent-topology")
        self.assertNotIn("agent", route_payload)
        self.assertNotIn("aliases", route_payload)
        self.assertNotIn("routing_cases", route_payload)

    def test_missing_and_unknown_routes_fail_before_worker_creation(self) -> None:
        """No live adapter is constructed without one known exact route ID."""

        created = False

        def worker_factory(root, scope=None):  # type: ignore[no-untyped-def]
            del root, scope
            nonlocal created
            created = True
            raise AssertionError("worker must not be created")

        for route in (None, "unknown-route"):
            with self.subTest(route=route):
                output = StringIO()
                with (
                    patch.object(
                        advisory_subagent,
                        "CopilotSdkAdvisoryWorker",
                        side_effect=worker_factory,
                    ),
                    patch.object(
                        advisory_subagent._semantic_router,
                        "validate_repository",
                        return_value=[],
                    ),
                    redirect_stdout(output),
                ):
                    result = advisory_subagent.run(
                        self.root,
                        AdvisoryRole.RESEARCH,
                        "inspect one bounded file",
                        ("src/master_agent/advisory.py",),
                        route=route,
                        goal_id="invalid-route-goal",
                        state_directory=self.state,
                    )

                self.assertEqual(result, 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "fallback")
        self.assertFalse(created)

    def test_duplicate_cli_routes_fail_before_runner_dispatch(self) -> None:
        """Repeated --route arguments cannot silently choose the final value."""

        output = StringIO()
        arguments = [
            "advisory_subagent.py",
            "research",
            "--task",
            "inspect one file",
            "--route",
            "agent-topology",
            "--route",
            "direct-read",
            "--goal-id",
            "duplicate-route-goal",
            "--path",
            "README.md",
        ]
        with patch.object(sys, "argv", arguments), redirect_stdout(output):
            result = advisory_subagent.main()

        self.assertEqual(result, 2)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "fallback")
        self.assertIn("exactly one", payload["reason"])

    def test_duplicate_manifest_route_ids_fail_before_worker_creation(self) -> None:
        """A malformed ambiguous registry never reaches scope or SDK setup."""

        root = Path(self.temporary.name).resolve() / "duplicate-manifest"
        manifest_path = root / ".ai/semantic-router.toml"
        manifest_path.parent.mkdir(parents=True)
        manifest = (self.root / ".ai/semantic-router.toml").read_text(encoding="utf-8")
        duplicate = manifest.replace(
            'id = "specification-lifecycle"',
            'id = "agent-topology"',
            1,
        )
        self.assertNotEqual(duplicate, manifest)
        manifest_path.write_text(duplicate, encoding="utf-8")
        output = StringIO()
        with redirect_stdout(output):
            result = advisory_subagent.run(
                root,
                AdvisoryRole.RESEARCH,
                "inspect one file",
                ("missing.txt",),
                route="agent-topology",
                goal_id="duplicate-manifest-goal",
                state_directory=self.state,
            )

        self.assertEqual(result, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "fallback")


class AdvisoryRunnerMutationTests(unittest.TestCase):
    """Exercise stale-result fallback through the full runner and live worker."""

    def test_editing_an_already_untracked_file_rejects_runner_result(self) -> None:
        """The live worker cannot return across an untracked-content mutation."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "repository"
            state = base / "state"
            repository.mkdir()
            source = Path(__file__).resolve().parents[1]
            profiles = repository / ".github/agents"
            profiles.mkdir(parents=True)
            for name in (
                "MasterAgent.agent.md",
                "MasterAgent-Read-Researcher.agent.md",
                "MasterAgent-Plan-Reviewer.agent.md",
            ):
                shutil.copy2(source / ".github/agents" / name, profiles / name)
            scoped = repository / "scope"
            scoped.mkdir()
            (scoped / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(("git", "init", "-q"), cwd=repository, check=True)
            subprocess.run(
                ("git", "config", "user.email", "test@example.invalid"),
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ("git", "config", "user.name", "MasterAgent Test"),
                cwd=repository,
                check=True,
            )
            subprocess.run(("git", "add", "."), cwd=repository, check=True)
            subprocess.run(
                ("git", "commit", "-qm", "initial"),
                cwd=repository,
                check=True,
            )
            untracked = scoped / "untracked.txt"
            untracked.write_text("before\n", encoding="utf-8")

            program = textwrap.dedent(
                """
                import sys
                import types
                from pathlib import Path
                from master_agent.advisory import AdvisoryRole, SemanticRouteSlice
                from master_agent.copilot_advisory import CopilotSdkAdvisoryWorker as RealWorker
                from scripts import advisory_subagent as runner

                class Tool:
                    def __init__(self, **kwargs): self.__dict__.update(kwargs)
                class ToolResult:
                    def __init__(self, **kwargs): self.__dict__.update(kwargs)
                class Approve: pass
                class Reject:
                    def __init__(self, *, feedback): self.feedback = feedback
                rpc = types.ModuleType("copilot.rpc")
                rpc.PermissionDecisionApproveOnce = Approve
                rpc.PermissionDecisionReject = Reject
                copilot = types.ModuleType("copilot")
                copilot.__path__ = []
                copilot.Tool = Tool
                copilot.ToolResult = ToolResult
                copilot.rpc = rpc
                sys.modules["copilot"] = copilot
                sys.modules["copilot.rpc"] = rpc

                class Data:
                    content = '{"summary":"stale","findings":[],"citations":[]}'
                class Response:
                    data = Data()
                class Session:
                    async def send_and_wait(self, prompt):
                        del prompt
                        Path(sys.argv[3]).write_text("after\\n", encoding="utf-8")
                        return Response()
                    async def disconnect(self): pass
                class Client:
                    async def start(self): pass
                    async def stop(self): pass
                    async def create_session(self, **kwargs):
                        del kwargs
                        return Session()

                def factory(root, scope=None):
                    return RealWorker(
                        root,
                        scope=scope,
                        client_factory=lambda selected: Client(),
                    )
                runner.CopilotSdkAdvisoryWorker = factory
                runner._validated_semantic_route = lambda root, route: SemanticRouteSlice(
                    route="agent-topology",
                    title="Parent and bounded advisory topology",
                    lifecycle="released",
                    summary="Bounded advisory test route.",
                    authority=(),
                    implementation=(),
                    configuration=(),
                    tests=(),
                    release_gates=(),
                    dependencies=(),
                )
                raise SystemExit(
                    runner.run(
                        Path(sys.argv[1]),
                        AdvisoryRole.RESEARCH,
                        "inspect scoped files",
                        ("scope",),
                        route="agent-topology",
                        goal_id="mutation-goal",
                        state_directory=Path(sys.argv[2]),
                    )
                )
                """
            )
            completed = subprocess.run(
                (
                    sys.executable,
                    "-c",
                    program,
                    str(repository),
                    str(state),
                    str(untracked),
                ),
                cwd=source,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "fallback")
        self.assertIn("changed during delegation", payload["reason"])
        self.assertNotIn("before", completed.stdout)
        self.assertNotIn("after", completed.stdout)


if __name__ == "__main__":
    unittest.main()
