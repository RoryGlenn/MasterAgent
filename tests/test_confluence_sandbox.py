"""Offline safety-contract tests for the live Confluence sandbox harness."""

from __future__ import annotations

import os
import stat
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from master_agent.models import AuthoritySource, RiskLevel
from scripts.confluence_sandbox import (
    RuntimePaths,
    SandboxError,
    SandboxTarget,
    _cleanup_page,
    _initialize_runtime,
    _page_create_action,
    _page_update_action,
    _persist_page_state,
    _sandbox_cql,
    _write_private_json,
    build_page_ownership,
    build_space_ownership,
    is_stale_candidate,
    page_body,
    page_body_text,
    validate_sandbox_origin,
    validate_target,
)
from tests.helpers import private_temporary_directory

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://masteragent-sandbox.atlassian.net"
OWNERSHIP_KEY = "sandbox-owner-" + "o" * 48
APPROVAL_SECRET = "sandbox-approval-" + "a" * 48
MARKER = "0123456789abcdef0123456789abcdef"
CREATED_AT = "2026-08-14T12:00:00Z"


class ConfluenceSandboxPreflightTests(unittest.TestCase):
    """Prove unsafe destinations fail before any network-capable code runs."""

    def test_exact_non_production_atlassian_origin_is_accepted_offline(self) -> None:
        with patch("socket.getaddrinfo", side_effect=AssertionError("network used")):
            target = validate_target(
                configured_origin=ORIGIN,
                allowlisted_origin=f"{ORIGIN}/",
                non_production_attestation="true",
                space_id="12345",
                space_key="sand",
                parent_id="987",
                require_space=True,
            )

        self.assertEqual(target.origin, ORIGIN)
        self.assertEqual(target.space_id, "12345")
        self.assertEqual(target.space_key, "SAND")
        self.assertEqual(target.parent_id, "987")

    def test_origin_rejects_every_credential_or_routing_ambiguity(self) -> None:
        rejected = (
            "",
            " http://masteragent-sandbox.atlassian.net",
            "http://masteragent-sandbox.atlassian.net",
            "https://user:secret@masteragent-sandbox.atlassian.net",
            "https://masteragent-sandbox.atlassian.net:443",
            "https://masteragent-sandbox.atlassian.net/wiki",
            "https://masteragent-sandbox.atlassian.net?token=value",
            "https://masteragent-sandbox.atlassian.net#fragment",
            "https://atlassian.net",
            "https://sandbox.example.com",
            "https://-bad.atlassian.net",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(SandboxError):
                validate_sandbox_origin(value, ORIGIN, "true")

    def test_origin_requires_exact_allowlist_and_explicit_nonproduction_flag(
        self,
    ) -> None:
        with self.assertRaisesRegex(SandboxError, "exact approved"):
            validate_sandbox_origin(
                ORIGIN,
                "https://another-sandbox.atlassian.net",
                "true",
            )
        with self.assertRaisesRegex(SandboxError, "non-production"):
            validate_sandbox_origin(ORIGIN, ORIGIN, "false")
        with self.assertRaisesRegex(SandboxError, "placeholder"):
            validate_sandbox_origin(
                "https://example.atlassian.net",
                "https://example.atlassian.net",
                "true",
            )

    def test_page_target_requires_both_preprovisioned_space_identifiers(self) -> None:
        for space_id, space_key in ((None, None), ("123", None), (None, "SAND")):
            with (
                self.subTest(space_id=space_id, space_key=space_key),
                self.assertRaises(SandboxError),
            ):
                validate_target(
                    configured_origin=ORIGIN,
                    allowlisted_origin=ORIGIN,
                    non_production_attestation="true",
                    space_id=space_id,
                    space_key=space_key,
                    require_space=True,
                )


class ConfluenceSandboxOwnershipTests(unittest.TestCase):
    """Prove cleanup markers are collision-resistant, exact, and authenticated."""

    def setUp(self) -> None:
        self.target = SandboxTarget(
            origin=ORIGIN,
            space_id="12345",
            space_key="SAND",
            parent_id="987",
        )
        self.ownership = build_page_ownership(
            self.target,
            run_label="gha-123-1-page",
            ownership_key=OWNERSHIP_KEY,
            marker=MARKER,
            created_at=CREATED_AT,
        )

    def test_page_marker_binds_origin_space_marker_and_creation_time(self) -> None:
        same = build_page_ownership(
            self.target,
            run_label="gha-123-1-page",
            ownership_key=OWNERSHIP_KEY,
            marker=MARKER,
            created_at=CREATED_AT,
        )
        another_space = build_page_ownership(
            SandboxTarget(
                origin=ORIGIN,
                space_id="54321",
                space_key="OTHER",
            ),
            run_label="gha-123-1-page",
            ownership_key=OWNERSHIP_KEY,
            marker=MARKER,
            created_at=CREATED_AT,
        )

        self.assertEqual(self.ownership.owner_tag, same.owner_tag)
        self.assertNotEqual(self.ownership.owner_tag, another_space.owner_tag)
        self.assertEqual(self.ownership.title, f"MA-SANDBOX-{MARKER}")
        self.assertNotIn(OWNERSHIP_KEY, page_body(self.ownership, "create"))

    def test_reaper_accepts_only_exact_old_authenticated_content(self) -> None:
        candidate = {
            "id": "7001",
            "title": self.ownership.title,
            "body_text": page_body_text(self.ownership, "update"),
            "updated_at": "2026-08-14T12:05:00Z",
            "space_id": "12345",
            "status": "current",
            "version": 2,
        }
        cutoff = datetime(2026, 8, 16, tzinfo=UTC)

        matched = is_stale_candidate(
            candidate,
            target=self.target,
            ownership_key=OWNERSHIP_KEY,
            cutoff=cutoff,
        )

        self.assertIsNotNone(matched)
        assert matched is not None
        self.assertEqual(matched[0].marker, MARKER)
        self.assertEqual(matched[1], "update")

    def test_reaper_rejects_forgery_recent_content_and_version_drift(self) -> None:
        base = {
            "id": "7001",
            "title": self.ownership.title,
            "body_text": page_body_text(self.ownership, "create"),
            "updated_at": "2026-08-14T12:05:00Z",
            "space_id": "12345",
            "status": "current",
            "version": 1,
        }
        cutoff = datetime(2026, 8, 16, tzinfo=UTC)
        variants = (
            {**base, "body_text": base["body_text"].replace("owner=", "owner=f")},
            {**base, "updated_at": "2026-08-16T12:00:00Z"},
            {**base, "version": 3},
            {**base, "space_id": "999"},
            {**base, "title": f"Human page {MARKER}"},
        )
        for candidate in variants:
            with self.subTest(candidate=candidate):
                self.assertIsNone(
                    is_stale_candidate(
                        candidate,
                        target=self.target,
                        ownership_key=OWNERSHIP_KEY,
                        cutoff=cutoff,
                    )
                )

    def test_space_marker_uses_a_separate_random_key_and_authenticated_name(
        self,
    ) -> None:
        ownership = build_space_ownership(
            SandboxTarget(origin=ORIGIN),
            run_label="gha-123-1-space",
            ownership_key=OWNERSHIP_KEY,
            marker=MARKER,
            created_at=CREATED_AT,
        )

        self.assertEqual(ownership.key, "MAS0123456789ABCDEF0123")
        self.assertIn(MARKER, ownership.name)
        self.assertIn(ownership.owner_tag[:16], ownership.name)
        self.assertNotIn(OWNERSHIP_KEY, ownership.name)

    def test_search_queries_are_fixed_and_injection_resistant(self) -> None:
        title = f"MA-SANDBOX-{MARKER}"

        self.assertEqual(
            _sandbox_cql(space_key="SAND", title=title),
            f'type = page AND space = "SAND" AND title = "\\"{title}\\""',
        )
        self.assertEqual(
            _sandbox_cql(space_key="SAND", title=None),
            'type = page AND space = "SAND" '
            'AND title ~ "MA-SANDBOX-*" ORDER BY lastmodified ASC',
        )
        for space_key, unsafe_title in (
            ('SAND" OR type = blogpost', title),
            ("SAND", f'{title}" OR type = blogpost'),
        ):
            with (
                self.subTest(space_key=space_key, title=unsafe_title),
                self.assertRaises(SandboxError),
            ):
                _sandbox_cql(space_key=space_key, title=unsafe_title)


class ConfluenceSandboxPlanTests(unittest.TestCase):
    """Prove the live mutation path remains typed and approval-bound."""

    def setUp(self) -> None:
        self.ownership = build_page_ownership(
            SandboxTarget(
                origin=ORIGIN,
                space_id="12345",
                space_key="SAND",
                parent_id="987",
            ),
            run_label="gha-123-1-page",
            ownership_key=OWNERSHIP_KEY,
            marker=MARKER,
            created_at=CREATED_AT,
        )

    def test_create_and_update_are_registered_workflow_reversible_writes(self) -> None:
        create = _page_create_action(self.ownership).actions[0]
        update = _page_update_action(self.ownership, "7001").actions[0]

        self.assertEqual(create.capability, "confluence.page.create")
        self.assertEqual(update.capability, "confluence.page.update")
        self.assertEqual(create.risk, RiskLevel.REVERSIBLE_WRITE)
        self.assertEqual(update.risk, RiskLevel.REVERSIBLE_WRITE)
        self.assertEqual(create.authority_source, AuthoritySource.REGISTERED_WORKFLOW)
        self.assertEqual(update.authority_source, AuthoritySource.REGISTERED_WORKFLOW)
        self.assertTrue(create.requires_approval)
        self.assertTrue(update.requires_approval)
        self.assertEqual(update.target.expected_version, "1")
        self.assertEqual(create.parameters["space_id"], "12345")
        self.assertEqual(create.parameters["parent_id"], "987")
        self.assertEqual(update.parameters["status"], "current")

    def test_runtime_files_are_private_and_credentials_use_normal_schema(self) -> None:
        with private_temporary_directory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir(mode=0o700)
            paths = RuntimePaths(root)
            environment = {
                "CONFLUENCE_SANDBOX_EMAIL": "sandbox@example.test",
                "CONFLUENCE_SANDBOX_API_TOKEN": "not-a-real-token",
                "CONFLUENCE_SANDBOX_APPROVAL_SECRET": APPROVAL_SECRET,
                "CONFLUENCE_SANDBOX_OWNERSHIP_KEY": OWNERSHIP_KEY,
            }
            with patch.dict(os.environ, environment, clear=False):
                _initialize_runtime(paths, ORIGIN)

            self.assertEqual(stat.S_IMODE(paths.credentials.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(paths.integrations.stat().st_mode), 0o600)
            credentials = paths.credentials.read_text(encoding="utf-8")
            self.assertIn("master-agent/credential-store@1", credentials)
            self.assertIn("MASTER_AGENT_CONFLUENCE_USERNAME", credentials)
            self.assertIn("MASTER_AGENT_CONFLUENCE_TOKEN", credentials)
            self.assertNotIn("not-a-real-token", paths.integrations.read_text())
            self.assertNotIn(APPROVAL_SECRET, paths.authorities.read_text())

    def test_safe_state_never_persists_retrieved_page_content(self) -> None:
        with private_temporary_directory() as directory:
            paths = RuntimePaths(Path(directory))
            _persist_page_state(
                paths,
                page_id="7001",
                phase="update",
                reference=f"{ORIGIN}/wiki/api/v2/pages/7001?body-format=storage",
            )
            payload = paths.page_state("update").read_text(encoding="utf-8")

        self.assertIn('"page_id": "7001"', payload)
        self.assertNotIn("body", payload)
        self.assertNotIn("body-format", payload)
        self.assertNotIn("No user content", payload)

    def test_cleanup_recovers_an_update_that_completed_after_cli_failure(self) -> None:
        ownership = build_page_ownership(
            SandboxTarget(
                origin=ORIGIN,
                space_id="12345",
                space_key="SAND",
                parent_id="987",
            ),
            run_label="gha-123-1-page",
            ownership_key=OWNERSHIP_KEY,
            marker=MARKER,
            created_at=CREATED_AT,
        )
        with private_temporary_directory() as directory:
            paths = RuntimePaths(Path(directory))
            _write_private_json(paths.page_metadata, ownership.to_dict())
            _write_private_json(
                paths.target,
                {
                    "schema": "master-agent/confluence-sandbox-target@1",
                    "origin": ORIGIN,
                },
            )
            _write_private_json(
                paths.page_state("create"),
                {
                    "schema": "master-agent/confluence-sandbox-safe-state@1",
                    "page_id": "7001",
                    "phase": "create",
                    "version": 1,
                    "reference": None,
                },
            )
            with (
                patch.dict(
                    os.environ,
                    {"CONFLUENCE_SANDBOX_OWNERSHIP_KEY": OWNERSHIP_KEY},
                ),
                patch(
                    "scripts.confluence_sandbox._find_exact_page",
                    return_value=({"id": "7001"}, "update"),
                ),
                patch(
                    "scripts.confluence_sandbox._page_is_terminal",
                    return_value=False,
                ),
                patch(
                    "scripts.confluence_sandbox._delete_verified_page",
                    return_value=None,
                ) as delete,
            ):
                result = _cleanup_page(SimpleNamespace(root=paths.root))

        self.assertEqual(result, 0)
        self.assertEqual(delete.call_args.kwargs["page_id"], "7001")
        self.assertEqual(delete.call_args.kwargs["phase"], "update")


class ConfluenceSandboxWorkflowContractTests(unittest.TestCase):
    """Pin the trusted trigger, gating, bounds, and no-artifact workflow contract."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/confluence-sandbox.yml").read_text(
            encoding="utf-8"
        )
        cls.harness = (ROOT / "scripts/confluence_sandbox.py").read_text(
            encoding="utf-8"
        )

    def test_workflow_never_runs_on_pull_request_code(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("schedule:", self.workflow)
        self.assertNotIn("pull_request:", self.workflow)
        self.assertNotIn("pull_request_target:", self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("github.event.repository.default_branch"), 3
        )
        self.assertGreaterEqual(
            self.workflow.count("vars.CONFLUENCE_SANDBOX_ENABLED == 'true'"),
            2,
        )
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)

    def test_runner_temp_is_bound_only_where_the_context_is_valid(self) -> None:
        runtime_roots = [
            line
            for line in self.workflow.splitlines()
            if "SANDBOX_ROOT: ${{ runner.temp }}" in line
        ]
        self.assertEqual(len(runtime_roots), 9)
        self.assertTrue(all(line.startswith("          ") for line in runtime_roots))
        self.assertEqual(self.workflow.count("umask 077"), 3)

    def test_page_cleanup_and_limits_are_mandatory(self) -> None:
        self.assertIn(
            "if: always() && steps.private-root.outcome == 'success'", self.workflow
        )
        self.assertIn("cleanup-page", self.workflow)
        self.assertIn("cleanup-space", self.workflow)
        self.assertIn("timeout-minutes: 20", self.workflow)
        self.assertIn("--max-resources 5", self.workflow)
        self.assertIn("--min-age-hours 24", self.workflow)
        self.assertNotIn("upload-artifact", self.workflow)

    def test_approval_handoff_and_connect_probe_are_real_cli_commands(self) -> None:
        for command in (
            '"connect"',
            '"inspect-approval-request"',
            '"approve-request"',
            '"resume-approval"',
        ):
            with self.subTest(command=command):
                self.assertIn(command, self.harness)
        self.assertIn("expected_status=2", self.harness)
        self.assertIn("discard_stdout=True", self.harness)

    def test_space_and_reaper_deletion_have_separate_explicit_gates(self) -> None:
        self.assertIn("environment: confluence-sandbox", self.workflow)
        self.assertIn("environment: confluence-space-sandbox", self.workflow)
        self.assertIn("CONFLUENCE_SANDBOX_ENABLE_SPACE_LIFECYCLE", self.workflow)
        self.assertIn("CONFLUENCE_SANDBOX_ENABLE_STALE_DELETE", self.workflow)
        self.assertIn("CONFLUENCE_SPACE_SANDBOX_API_TOKEN", self.workflow)
        self.assertIn("reaper_mode == 'delete'", self.workflow)


if __name__ == "__main__":
    unittest.main()
