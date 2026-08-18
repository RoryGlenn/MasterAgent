"""Tests for the optional broker-owned Copilot SDK advisory worker."""

from __future__ import annotations

import asyncio
import sys
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
from master_agent.copilot_advisory import CopilotSdkAdvisoryWorker


class _ApproveOnce:
    pass


class _Reject:
    def __init__(self, *, feedback: str) -> None:
        self.feedback = feedback


class _Data:
    def __init__(self, content: str) -> None:
        self.content = content


class _Response:
    def __init__(self, content: str) -> None:
        self.data = _Data(content)


class _FakeSession:
    def __init__(self, content: str) -> None:
        self._content = content
        self.prompts: list[str] = []
        self.disconnected = False

    async def send_and_wait(self, prompt: str) -> object:
        self.prompts.append(prompt)
        return _Response(self._content)

    async def disconnect(self) -> None:
        self.disconnected = True


class _FakeClient:
    def __init__(self, content: str) -> None:
        self.session = _FakeSession(content)
        self.started = False
        self.stopped = False
        self.session_kwargs: dict[str, object] | None = None

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def create_session(self, **kwargs: object) -> _FakeSession:
        self.session_kwargs = kwargs
        return self.session


class CopilotAdvisoryWorkerTests(unittest.TestCase):
    """Prove live SDK wiring cannot bypass the existing advisory broker."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
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
        self.modules = {"copilot.rpc": rpc}

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
            kwargs["available_tools"], ["view", "read_file", "grep", "glob"]
        )
        self.assertFalse(kwargs["enable_config_discovery"])
        self.assertEqual(kwargs["mcp_servers"], {})
        custom_agents = kwargs["custom_agents"]
        self.assertIsInstance(custom_agents, list)
        assert isinstance(custom_agents, list)
        self.assertEqual(len(custom_agents), 1)
        self.assertEqual(custom_agents[0]["name"], "masteragent-researcher")
        self.assertEqual(
            custom_agents[0]["tools"], ["view", "read_file", "grep", "glob"]
        )
        self.assertNotIn("agent", custom_agents[0]["tools"])
        self.assertNotIn("bash", custom_agents[0]["tools"])
        self.assertIn("task_digest:", client.session.prompts[0])
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
        self.assertEqual([item["name"] for item in agents], ["masteragent-plan-reviewer"])

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
            hook({"toolName": "view", "toolArgs": {"path": "/etc/passwd"}}, {})
        )
        self.assertEqual(denied_path["permissionDecision"], "deny")
        allowed = asyncio.run(
            hook({"toolName": "view", "toolArgs": {"path": "README.md"}}, {})
        )
        self.assertEqual(allowed["permissionDecision"], "allow")

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
            raise RuntimeError("github-copilot-sdk unavailable")

        worker = CopilotSdkAdvisoryWorker(
            self.root,
            client_factory=unavailable,
            state_reader=lambda root: "same",
        )
        session = self.broker.start_session("MasterAgent", "missing-sdk")
        outcome = session.delegate(
            AdvisoryRole.RESEARCH,
            {"task": "research"},
            worker=worker,
        )

        self.assertEqual(outcome.status, DelegationStatus.FALLBACK)
        self.assertIn("unavailable", outcome.reason)


if __name__ == "__main__":
    unittest.main()
