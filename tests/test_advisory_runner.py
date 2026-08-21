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

from master_agent.advisory import AdvisoryReport, AdvisoryRole
from scripts import advisory_subagent

_FAKE_RUNNER = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from master_agent.advisory import AdvisoryReport, AdvisoryRole
    from scripts import advisory_subagent as runner

    class Worker:
        def __call__(self, envelope, dispatcher):
            del envelope, dispatcher
            return AdvisoryReport("bounded", (), ())

    runner.CopilotSdkAdvisoryWorker = lambda root, scope=None: Worker()
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
            goal_id=sys.argv[4],
            state_directory=Path(sys.argv[2]),
        )
    )
    """
)


class AdvisoryRunnerProcessTests(unittest.TestCase):
    """Prove one goal budget cannot be reset by real process boundaries."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name) / "state"

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
                cwd=self.root,
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
                cwd=self.root,
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
                cwd=self.root,
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
            redirect_stdout(output),
        ):
            return_code = advisory_subagent.run(
                self.root,
                AdvisoryRole.RESEARCH,
                "read only the README",
                ("README.md",),
                goal_id="citation-goal",
                state_directory=self.state,
            )

        self.assertEqual(return_code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "fallback")


class AdvisoryRunnerMutationTests(unittest.TestCase):
    """Exercise stale-result fallback through the full runner and live worker."""

    def test_editing_an_already_untracked_file_rejects_runner_result(self) -> None:
        """The live worker cannot return across an untracked-content mutation."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
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
                from master_agent.advisory import AdvisoryRole
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
                raise SystemExit(
                    runner.run(
                        Path(sys.argv[1]),
                        AdvisoryRole.RESEARCH,
                        "inspect scoped files",
                        ("scope",),
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
