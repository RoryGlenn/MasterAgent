"""Tests for the optional broker-owned Copilot SDK advisory worker."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from master_agent.advisory import (
    AdvisoryBroker,
    AdvisoryRole,
    DelegationStatus,
    RepositoryFixture,
    load_agent_inventory,
)
from master_agent.copilot_advisory import (
    AdvisoryPathScope,
    CopilotRepositoryScanRejected,
    CopilotSdkAdvisoryWorker,
    CopilotSdkUnavailable,
    ScopedRepositoryTools,
    repository_state_digest,
)


class _ApproveOnce:
    pass


class _Reject:
    def __init__(self, *, feedback: str) -> None:
        self.feedback = feedback


class _FakeTool:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


class _FakeToolResult:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


class _Data:
    def __init__(self, content: str) -> None:
        self.content = content


class _Response:
    def __init__(self, content: str) -> None:
        self.data = _Data(content)


class _FakeSession:
    def __init__(self, content: str, *, disconnect_error: bool = False) -> None:
        self._content = content
        self._disconnect_error = disconnect_error
        self.prompts: list[str] = []
        self.disconnected = False

    async def send_and_wait(self, prompt: str) -> object:
        self.prompts.append(prompt)
        return _Response(self._content)

    async def disconnect(self) -> None:
        self.disconnected = True
        if self._disconnect_error:
            raise RuntimeError("session disconnect failed")


class _FakeClient:
    def __init__(self, content: str, *, disconnect_error: bool = False) -> None:
        self._content = content
        self._disconnect_error = disconnect_error
        self.session = _FakeSession(content, disconnect_error=disconnect_error)
        self.sessions: list[_FakeSession] = []
        self.started = False
        self.stopped = False
        self.start_count = 0
        self.stop_count = 0
        self.session_kwargs: dict[str, object] | None = None

    async def start(self) -> None:
        self.started = True
        self.start_count += 1

    async def stop(self) -> None:
        self.stopped = True
        self.stop_count += 1

    async def create_session(self, **kwargs: object) -> _FakeSession:
        self.session_kwargs = kwargs
        self.session = _FakeSession(
            self._content,
            disconnect_error=self._disconnect_error,
        )
        self.sessions.append(self.session)
        return self.session


class CopilotAdvisoryWorkerTests(unittest.TestCase):
    """Prove live SDK wiring cannot bypass the existing advisory broker."""

    def setUp(self) -> None:
        source = Path(__file__).resolve().parents[1]
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        profiles = self.root / ".github/agents"
        profiles.mkdir(parents=True)
        for name in (
            "MasterAgent.agent.md",
            "MasterAgent-Read-Researcher.agent.md",
            "MasterAgent-Plan-Reviewer.agent.md",
        ):
            shutil.copy2(source / ".github/agents" / name, profiles / name)
        shutil.copy2(source / "README.md", self.root / "README.md")
        docs = self.root / "docs"
        docs.mkdir()
        shutil.copy2(
            source / "docs/advisory-subagents.md",
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
        self.inventory = load_agent_inventory(self.root)
        self.repository = RepositoryFixture(
            {
                "README.md": "MasterAgent repository overview",
                "docs/advisory-subagents.md": "read-only advisory boundary",
            }
        )
        self.broker = AdvisoryBroker(self.inventory, self.repository)
        rpc = types.ModuleType("copilot.rpc")
        rpc.PermissionDecisionApproveOnce = _ApproveOnce  # type: ignore[attr-defined]
        rpc.PermissionDecisionReject = _Reject  # type: ignore[attr-defined]
        copilot = types.ModuleType("copilot")
        copilot.__path__ = []  # type: ignore[attr-defined]
        copilot.rpc = rpc  # type: ignore[attr-defined]
        copilot.Tool = _FakeTool  # type: ignore[attr-defined]
        copilot.ToolResult = _FakeToolResult  # type: ignore[attr-defined]
        self.modules = {"copilot": copilot, "copilot.rpc": rpc}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _delegate(
        self,
        role: AdvisoryRole,
        content: str,
        *,
        states: list[str] | None = None,
    ) -> tuple[object, _FakeClient]:
        client = _FakeClient(content)
        state_values = iter(states or ["same", "same"])

        def state_reader(root: Path) -> str:
            self.assertEqual(root, self.root)
            return next(state_values)

        worker = CopilotSdkAdvisoryWorker(
            self.root,
            client_factory=lambda root: client,
            state_reader=state_reader,
        )
        session = self.broker.start_session("MasterAgent", f"sdk-{role.value}")
        with patch.dict(sys.modules, self.modules):
            outcome = session.delegate(
                role,
                {"task": "Inspect repository behavior", "paths": ["README.md"]},
                worker=worker,
            )
        return outcome, client

    def test_research_uses_one_preselected_read_only_agent(self) -> None:
        """The SDK receives one explicit role and no ambient effect-bearing tools."""

        outcome, client = self._delegate(
            AdvisoryRole.RESEARCH,
            '{"summary":"Found evidence","findings":["README is present"],'
            '"citations":["README.md"]}',
        )

        self.assertEqual(outcome.status, DelegationStatus.COMPLETED)
        self.assertTrue(client.started)
        self.assertTrue(client.stopped)
        self.assertTrue(client.session.disconnected)
        assert client.session_kwargs is not None
        kwargs = client.session_kwargs
        self.assertEqual(kwargs["agent"], "masteragent-researcher")
        self.assertEqual(
            kwargs["available_tools"],
            ["masteragent_read", "masteragent_search", "masteragent_list"],
        )
        tools = kwargs["tools"]
        self.assertIsInstance(tools, list)
        assert isinstance(tools, list)
        self.assertEqual(
            [item.name for item in tools],
            ["masteragent_read", "masteragent_search", "masteragent_list"],
        )
        self.assertFalse(kwargs["enable_config_discovery"])
        self.assertEqual(kwargs["mcp_servers"], {})
        custom_agents = kwargs["custom_agents"]
        self.assertIsInstance(custom_agents, list)
        assert isinstance(custom_agents, list)
        self.assertEqual(len(custom_agents), 1)
        self.assertEqual(custom_agents[0]["name"], "masteragent-researcher")
        self.assertEqual(
            custom_agents[0]["tools"],
            ["masteragent_read", "masteragent_search", "masteragent_list"],
        )
        self.assertNotIn("agent", custom_agents[0]["tools"])
        self.assertNotIn("bash", custom_agents[0]["tools"])
        self.assertIn("task_digest:", client.session.prompts[0])
        permission_handler = kwargs["on_permission_request"]
        rejected = permission_handler(object(), object())
        self.assertIsInstance(rejected, _Reject)
        self.assertIn("deny ambient SDK permissions", rejected.feedback)
        assert outcome.report is not None
        verified = self.broker.recheck_report(outcome.report)
        self.assertEqual(verified.citations, ("README.md",))

    def test_plan_review_preselects_only_reviewer(self) -> None:
        """Plan review cannot infer or fan out to another specialist."""

        outcome, client = self._delegate(
            AdvisoryRole.PLAN_REVIEW,
            '{"summary":"Plan reviewed","findings":[],"citations":[]}',
        )

        self.assertEqual(outcome.status, DelegationStatus.COMPLETED)
        assert client.session_kwargs is not None
        self.assertEqual(client.session_kwargs["agent"], "masteragent-plan-reviewer")
        agents = client.session_kwargs["custom_agents"]
        assert isinstance(agents, list)
        self.assertEqual(
            [item["name"] for item in agents], ["masteragent-plan-reviewer"]
        )

    def test_one_goal_worker_reuses_client_with_isolated_sessions(self) -> None:
        """Safe same-process calls share a client but never an SDK session."""

        client = _FakeClient(
            '{"summary":"Found evidence","findings":[],"citations":[]}'
        )
        worker = CopilotSdkAdvisoryWorker(
            self.root,
            reuse_client=True,
            client_factory=lambda root: client,
            state_reader=lambda root: "same",
        )
        session = self.broker.start_session(
            "MasterAgent",
            "reuse-goal",
            goal_id="reuse-goal",
        )
        with patch.dict(sys.modules, self.modules):
            outcomes = [
                session.delegate(
                    AdvisoryRole.RESEARCH,
                    {"task": f"research-{index}", "paths": ["README.md"]},
                    worker=worker,
                )
                for index in range(2)
            ]
        worker.close()

        self.assertTrue(
            all(item.status is DelegationStatus.COMPLETED for item in outcomes)
        )
        self.assertEqual(client.start_count, 1)
        self.assertEqual(len(client.sessions), 2)
        self.assertIsNot(client.sessions[0], client.sessions[1])
        self.assertTrue(all(session.disconnected for session in client.sessions))
        self.assertEqual(client.stop_count, 1)

    def test_disconnect_failure_discards_reusable_client(self) -> None:
        """A session cleanup failure cannot leak its client into the next call."""

        content = '{"summary":"Found evidence","findings":[],"citations":[]}'
        failed_client = _FakeClient(content, disconnect_error=True)
        healthy_client = _FakeClient(content)
        clients = iter((failed_client, healthy_client))
        worker = CopilotSdkAdvisoryWorker(
            self.root,
            reuse_client=True,
            client_factory=lambda root: next(clients),
            state_reader=lambda root: "same",
        )
        session = self.broker.start_session("MasterAgent", "disconnect-goal")
        with patch.dict(sys.modules, self.modules):
            failed = session.delegate(
                AdvisoryRole.RESEARCH,
                {"task": "first", "paths": ["README.md"]},
                worker=worker,
            )
            completed = session.delegate(
                AdvisoryRole.RESEARCH,
                {"task": "second", "paths": ["README.md"]},
                worker=worker,
            )
        worker.close()

        self.assertEqual(failed.status, DelegationStatus.FALLBACK)
        self.assertEqual(completed.status, DelegationStatus.COMPLETED)
        self.assertEqual(failed_client.stop_count, 1)
        self.assertEqual(healthy_client.start_count, 1)
        self.assertEqual(healthy_client.stop_count, 1)

    def test_pre_tool_hook_denies_writes_shell_and_outside_paths(self) -> None:
        """A second SDK hook gate blocks widened or escaping tool requests."""

        outcome, client = self._delegate(
            AdvisoryRole.RESEARCH,
            '{"summary":"Safe","findings":[],"citations":[]}',
        )
        self.assertEqual(outcome.status, DelegationStatus.COMPLETED)
        assert client.session_kwargs is not None
        hooks = client.session_kwargs["hooks"]
        assert isinstance(hooks, dict)
        hook = hooks["on_pre_tool_use"]

        denied_shell = asyncio.run(hook({"toolName": "bash", "toolArgs": {}}, {}))
        self.assertEqual(denied_shell["permissionDecision"], "deny")
        denied_path = asyncio.run(
            hook(
                {
                    "toolName": "masteragent_read",
                    "toolArgs": {"path": "/etc/passwd"},
                },
                {},
            )
        )
        self.assertEqual(denied_path["permissionDecision"], "deny")
        denied_route = asyncio.run(
            hook(
                {
                    "toolName": "masteragent_read",
                    "toolArgs": {"path": "docs/advisory-subagents.md"},
                },
                {},
            )
        )
        self.assertEqual(denied_route["permissionDecision"], "deny")
        allowed = asyncio.run(
            hook(
                {
                    "toolName": "masteragent_read",
                    "toolArgs": {"path": "README.md"},
                },
                {},
            )
        )
        self.assertEqual(allowed["permissionDecision"], "allow")

    def test_repository_owned_tools_enforce_scope_in_the_handler(self) -> None:
        """The actual tool handler repeats scope checks before every read."""

        outcome, client = self._delegate(
            AdvisoryRole.RESEARCH,
            '{"summary":"Safe","findings":[],"citations":[]}',
        )
        self.assertEqual(outcome.status, DelegationStatus.COMPLETED)
        assert client.session_kwargs is not None
        tools = client.session_kwargs["tools"]
        assert isinstance(tools, list)
        read_tool = tools[0]
        denied = asyncio.run(
            read_tool.handler(
                types.SimpleNamespace(arguments={"path": "docs/advisory-subagents.md"})
            )
        )
        self.assertEqual(denied.result_type, "denied")
        allowed = asyncio.run(
            read_tool.handler(types.SimpleNamespace(arguments={"path": "README.md"}))
        )
        self.assertEqual(allowed.result_type, "success")
        self.assertIn('"path":"README.md"', allowed.text_result_for_llm)

    def test_repository_change_during_call_falls_back(self) -> None:
        """A result cannot survive a repository-state race."""

        outcome, _ = self._delegate(
            AdvisoryRole.RESEARCH,
            '{"summary":"Stale","findings":[],"citations":[]}',
            states=["before", "after"],
        )

        self.assertEqual(outcome.status, DelegationStatus.FALLBACK)
        self.assertTrue(outcome.fallback_to_parent)
        self.assertIn("changed during delegation", outcome.reason)

    def test_malformed_or_authority_bearing_json_falls_back(self) -> None:
        """The adapter accepts only the narrow advisory result schema."""

        for content in (
            "not json",
            '{"summary":"unsafe","findings":[],"citations":[],"target":"prod"}',
            '{"summary":"unsafe","findings":"not-a-list","citations":[]}',
        ):
            with self.subTest(content=content):
                outcome, _ = self._delegate(AdvisoryRole.RESEARCH, content)
                self.assertEqual(outcome.status, DelegationStatus.FALLBACK)
                self.assertTrue(outcome.fallback_to_parent)

    def test_sensitive_payload_is_denied_before_sdk_client_creation(self) -> None:
        """Existing broker sanitization remains ahead of the live worker."""

        created = False

        def factory(root: Path) -> _FakeClient:
            nonlocal created
            created = True
            return _FakeClient('{"summary":"unused","findings":[],"citations":[]}')

        worker = CopilotSdkAdvisoryWorker(
            self.root,
            client_factory=factory,
            state_reader=lambda root: "same",
        )
        session = self.broker.start_session("MasterAgent", "sensitive-live-sdk")
        outcome = session.delegate(
            AdvisoryRole.RESEARCH,
            {"task": "research", "credential": "ghp_1234567890"},
            worker=worker,
        )

        self.assertEqual(outcome.status, DelegationStatus.DENIED)
        self.assertFalse(created)

    def test_unavailable_sdk_is_an_explicit_parent_fallback(self) -> None:
        """Preview adapter availability never becomes a runtime requirement."""

        def unavailable(root: Path) -> _FakeClient:
            del root
            raise CopilotSdkUnavailable("provider detail must not be reflected")

        worker = CopilotSdkAdvisoryWorker(
            self.root,
            client_factory=unavailable,
            state_reader=lambda root: "same",
        )
        session = self.broker.start_session("MasterAgent", "missing-sdk")
        outcome = session.delegate(
            AdvisoryRole.RESEARCH,
            {"task": "research", "paths": ["README.md"]},
            worker=worker,
        )

        self.assertEqual(outcome.status, DelegationStatus.FALLBACK)
        self.assertIn("unavailable", outcome.reason)


class RepositoryStateDigestTests(unittest.TestCase):
    """Exercise exact bounded Git state binding with real repositories."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
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
        (self.root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(("git", "add", "tracked.txt"), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-qm", "initial"), cwd=self.root, check=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_every_tracked_staged_and_untracked_transition_changes_digest(self) -> None:
        """Adds, edits, stages, renames, and deletes all invalidate state."""

        digests = [repository_state_digest(self.root)]
        (self.root / "untracked.txt").write_text("alpha\n", encoding="utf-8")
        digests.append(repository_state_digest(self.root))
        (self.root / "untracked.txt").write_text("bravo\n", encoding="utf-8")
        digests.append(repository_state_digest(self.root))
        (self.root / "untracked.txt").rename(self.root / "renamed.txt")
        digests.append(repository_state_digest(self.root))
        subprocess.run(("git", "add", "renamed.txt"), cwd=self.root, check=True)
        digests.append(repository_state_digest(self.root))
        (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        digests.append(repository_state_digest(self.root))
        (self.root / "renamed.txt").unlink()
        digests.append(repository_state_digest(self.root))
        self.assertEqual(len(digests), len(set(digests)))

    def test_oversized_untracked_file_fails_closed(self) -> None:
        """Untracked content is never silently truncated from the binding."""

        with patch(
            "master_agent.copilot_advisory._MAX_UNTRACKED_FILE_BYTES",
            8,
        ):
            (self.root / "too-large.txt").write_bytes(b"123456789")
            with self.assertRaises(CopilotRepositoryScanRejected):
                repository_state_digest(self.root)


class AdvisoryPathScopeTests(unittest.TestCase):
    """Prove pathless search remains confined to the explicit route."""

    def test_search_and_list_cannot_cross_route_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            denied = root / "denied"
            allowed.mkdir()
            denied.mkdir()
            (allowed / "inside.txt").write_text("needle inside", encoding="utf-8")
            (allowed / "ignored.env").write_text("needle secret", encoding="utf-8")
            (denied / "outside.txt").write_text("needle outside", encoding="utf-8")
            (root / ".gitignore").write_text("*.env\n", encoding="utf-8")
            subprocess.run(("git", "init", "-q"), cwd=root, check=True)
            scope = AdvisoryPathScope.bind(root, ("allowed",))
            tools = ScopedRepositoryTools(scope)

            search = json.loads(tools.invoke("masteragent_search", {"query": "needle"}))
            listed = json.loads(tools.invoke("masteragent_list", {"pattern": "**/*"}))

            self.assertEqual(
                [item["path"] for item in search["matches"]],
                ["allowed/inside.txt"],
            )
            self.assertEqual(listed["paths"], ["allowed/inside.txt"])
            self.assertFalse(
                tools.authorize(
                    "masteragent_read",
                    {"path": "denied/outside.txt"},
                )
            )


if __name__ == "__main__":
    unittest.main()
