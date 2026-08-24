"""Static and local contracts for the credentialed connector workflow."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from master_agent.auth import AuthMode
from master_agent.config import ConnectorConfig, DeploymentType, IntegrationConfig
from master_agent.models import ActionState, ExecutionResult, RiskLevel
from master_agent.oauth import AccessToken, write_token_file
from tests.helpers import action_for
from tests.test_connector_integration_matrix import (
    _MICROSOFT_EFFECT_SCOPES,
    _MICROSOFT_READ_SCOPES,
    _execute_verify_and_compensate,
    _read_recovery_entry,
    _replay_recovery_entries,
    _require_microsoft_delegated_token,
    _write_recovery_entry,
)

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "live-connector-integration.yml"
_HARNESS = _ROOT / "tests" / "test_connector_integration_matrix.py"


class LiveConnectorWorkflowContractTests(unittest.TestCase):
    """Pin the protected-environment and no-artifact workflow boundary."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = _WORKFLOW.read_text(encoding="utf-8")
        cls.harness = _HARNESS.read_text(encoding="utf-8")

    def test_full_matrix_is_manual_only_and_rejects_mixed_privileges(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        for trigger in ("schedule:", "pull_request:", "pull_request_target:", "push:"):
            with self.subTest(trigger=trigger):
                self.assertNotIn(trigger, self.workflow)
        self.assertIn("validate-selection:", self.workflow)
        self.assertIn(
            'if test "$RUN_EFFECTS" = "true" && test "$RUN_GITHUB_ADMIN" = "true";',
            self.workflow,
        )
        self.assertIn(
            "run_effects and run_github_admin are mutually exclusive",
            self.workflow,
        )
        self.assertIn("test_case:", self.workflow)
        self.assertIn("default: disabled", self.workflow)
        self.assertIn("- T1-EWIR-001", self.workflow)
        self.assertIn(
            "a protected test case cannot overlap effect or administration modes",
            self.workflow,
        )
        self.assertEqual(self.workflow.count("needs: validate-selection"), 4)
        self.assertEqual(
            self.workflow.count(
                "github.ref == format('refs/heads/{0}', "
                "github.event.repository.default_branch)"
            ),
            4,
        )
        self.assertEqual(self.workflow.count("inputs.test_case == 'disabled'"), 3)
        self.assertEqual(self.workflow.count("inputs.test_case == 'T1-EWIR-001'"), 1)

    def test_jobs_pin_least_privilege_github_permissions_and_tokens(self) -> None:
        read_job = _job_source(
            self.workflow,
            "credentialed-read",
            "tier1-engineering-work-item-review",
        )
        tier1_job = _job_source(
            self.workflow,
            "tier1-engineering-work-item-review",
            "sandbox-effects",
        )
        effect_job = _job_source(
            self.workflow, "sandbox-effects", "github-admin-sandbox"
        )
        admin_job = _job_source(self.workflow, "github-admin-sandbox", None)
        self.assertIn("permissions:\n      contents: read", read_job)
        self.assertNotIn("issues: write", read_job)
        self.assertIn("permissions:\n      contents: read", tier1_job)
        self.assertNotIn("issues: write", tier1_job)
        self.assertIn(
            "permissions:\n      contents: read\n      issues: write",
            effect_job,
        )
        self.assertIn("permissions:\n      contents: read", admin_job)
        self.assertNotIn("issues: write", admin_job)
        self.assertIn(
            "MASTER_AGENT_GITHUB_TOKEN: ${{ github.token }}",
            read_job,
        )
        self.assertGreaterEqual(
            effect_job.count("MASTER_AGENT_GITHUB_TOKEN: ${{ github.token }}"),
            2,
        )
        self.assertNotIn(
            "secrets.MASTER_AGENT_GITHUB_TOKEN",
            self.workflow,
        )
        self.assertNotIn("MASTER_AGENT_GITHUB_TOKEN", tier1_job)
        self.assertNotIn("github.token", tier1_job)
        self.assertGreaterEqual(
            admin_job.count("secrets.MASTER_AGENT_LIVE_GITHUB_ADMIN_TOKEN"),
            2,
        )
        self.assertNotIn("github.token", admin_job)

    def test_jobs_pin_protected_environments_and_opt_in_gates(self) -> None:
        for environment in (
            "connector-integration-read",
            "connector-integration-effects",
            "connector-integration-admin",
        ):
            with self.subTest(environment=environment):
                expected = 2 if environment == "connector-integration-read" else 1
                self.assertEqual(
                    self.workflow.count(f"environment: {environment}"), expected
                )
        for gate in (
            "MASTER_AGENT_LIVE_CONNECTOR_TESTS_ENABLED",
            "MASTER_AGENT_LIVE_EFFECT_TESTS_ENABLED",
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_TESTS_ENABLED",
            "MASTER_AGENT_LIVE_NON_PRODUCTION",
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_NON_PRODUCTION",
        ):
            with self.subTest(gate=gate):
                self.assertIn(gate, self.workflow)
        self.assertIn("inputs.run_effects", self.workflow)
        self.assertIn("inputs.run_github_admin", self.workflow)
        self.assertIn('disabled=frozenset({"admin_enabled"})', self.harness)
        self.assertIn('disabled=frozenset({"writes_enabled"})', self.harness)

    def test_each_privilege_uses_distinct_configuration_and_credentials(self) -> None:
        for secret in (
            "MASTER_AGENT_LIVE_READ_INTEGRATIONS_TOML",
            "MASTER_AGENT_LIVE_EFFECT_INTEGRATIONS_TOML",
            "MASTER_AGENT_LIVE_GITHUB_ADMIN_INTEGRATIONS_TOML",
            "MASTER_AGENT_LIVE_READ_GRAPH_TOKEN_FILE_JSON",
            "MASTER_AGENT_LIVE_EFFECT_GRAPH_TOKEN_FILE_JSON",
            "MASTER_AGENT_LIVE_READ_BITBUCKET_EMAIL",
            "MASTER_AGENT_LIVE_EFFECT_BITBUCKET_EMAIL",
        ):
            with self.subTest(secret=secret):
                self.assertIn(f"secrets.{secret}", self.workflow)
        self.assertNotIn(
            "secrets.MASTER_AGENT_LIVE_INTEGRATIONS_TOML",
            self.workflow,
        )
        self.assertNotIn("MASTER_AGENT_BITBUCKET_USERNAME", self.workflow)
        self.assertEqual(self.workflow.count("MASTER_AGENT_BITBUCKET_EMAIL:"), 5)
        read_job = _job_source(
            self.workflow,
            "credentialed-read",
            "tier1-engineering-work-item-review",
        )
        tier1_job = _job_source(
            self.workflow,
            "tier1-engineering-work-item-review",
            "sandbox-effects",
        )
        effect_job = _job_source(
            self.workflow, "sandbox-effects", "github-admin-sandbox"
        )
        admin_job = _job_source(self.workflow, "github-admin-sandbox", None)
        self.assertIn(
            "MASTER_AGENT_PROXY_USERNAME: "
            "${{ secrets.MASTER_AGENT_LIVE_READ_PROXY_USERNAME }}",
            read_job,
        )
        self.assertIn(
            "MASTER_AGENT_PROXY_PASSWORD: "
            "${{ secrets.MASTER_AGENT_LIVE_READ_PROXY_PASSWORD }}",
            read_job,
        )
        self.assertGreaterEqual(
            tier1_job.count("secrets.MASTER_AGENT_LIVE_READ_PROXY_USERNAME"), 2
        )
        self.assertGreaterEqual(
            tier1_job.count("secrets.MASTER_AGENT_LIVE_READ_PROXY_PASSWORD"), 2
        )
        for source in (effect_job, admin_job):
            self.assertNotIn("MASTER_AGENT_LIVE_READ_PROXY_USERNAME", source)
            self.assertNotIn("MASTER_AGENT_LIVE_READ_PROXY_PASSWORD", source)
        for application_credential in (
            "MASTER_AGENT_ENTRA_APP_CLIENT_ID",
            "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET",
            "MASTER_AGENT_GRAPH_ACCESS_TOKEN:",
            "MASTER_AGENT_GRAPH_ACCESS_TOKEN_EXPIRES_AT",
        ):
            with self.subTest(application_credential=application_credential):
                self.assertNotIn(application_credential, self.workflow)

    def test_delegated_token_files_and_lifetime_budget_are_materialized(self) -> None:
        self.assertEqual(self.workflow.count("GRAPH_TOKEN_FILE_JSON:"), 2)
        self.assertEqual(self.workflow.count('test -n "$GRAPH_TOKEN_FILE_JSON"'), 2)
        self.assertEqual(
            self.workflow.count("MASTER_AGENT_GRAPH_TOKEN_FILE=$token_file"),
            2,
        )
        self.assertIn('MASTER_AGENT_LIVE_JOB_TIMEOUT_SECONDS: "1500"', self.workflow)
        self.assertIn('MASTER_AGENT_LIVE_JOB_TIMEOUT_SECONDS: "2100"', self.workflow)
        self.assertIn('MASTER_AGENT_LIVE_CLEANUP_MARGIN_SECONDS: "600"', self.workflow)
        self.assertIn("RestrictedTokenFileProvider", self.harness)
        self.assertIn("configured_scopes != required_scopes", self.harness)
        self.assertIn("remaining_seconds < minimum_remaining_seconds", self.harness)

    def test_recovery_is_private_bounded_and_independent(self) -> None:
        self.assertEqual(self.workflow.count("install -d -m 0700"), 2)
        self.assertEqual(self.workflow.count("if: always()"), 2)
        self.assertIn("recover --mode effects", self.workflow)
        self.assertIn("recover --mode admin", self.workflow)
        self.assertEqual(self.workflow.count("MASTER_AGENT_LIVE_RECOVERY_ROOT"), 2)
        self.assertIn("_RECOVERY_MAX_ENTRIES = 8", self.harness)
        self.assertIn("_RECOVERY_MAX_BYTES = 1024 * 1024", self.harness)
        self.assertIn("provider commit followed by a lost response", self.harness)

    def test_communications_are_after_reversible_recovery(self) -> None:
        reversible = self.workflow.index(
            "Run reversible sandbox writes and compensation"
        )
        recovery = self.workflow.index(
            "Recover returned reversible effects after ordinary failure"
        )
        communications = self.workflow.index("Send dedicated test communications last")
        self.assertLess(reversible, recovery)
        self.assertLess(recovery, communications)

    def test_tier1_selector_is_exact_private_and_content_free(self) -> None:
        read_job = _job_source(
            self.workflow,
            "credentialed-read",
            "tier1-engineering-work-item-review",
        )
        tier1_job = _job_source(
            self.workflow,
            "tier1-engineering-work-item-review",
            "sandbox-effects",
        )
        for condition in (
            "inputs.test_case == 'disabled'",
            "!inputs.run_effects",
            "!inputs.run_github_admin",
        ):
            with self.subTest(read_condition=condition):
                self.assertIn(condition, read_job)
        for condition in (
            "inputs.test_case == 'T1-EWIR-001'",
            "!inputs.run_effects",
            "!inputs.run_github_admin",
            "vars.MASTER_AGENT_LIVE_CONNECTOR_TESTS_ENABLED == 'true'",
            "environment: connector-integration-read",
        ):
            with self.subTest(tier1_condition=condition):
                self.assertIn(condition, tier1_job)
        self.assertEqual(tier1_job.count('test "$(git rev-parse HEAD)"'), 2)
        self.assertIn(
            "secrets.MASTER_AGENT_LIVE_READ_T1_EWIR_WORKFLOW_TOML",
            tier1_job,
        )
        self.assertIn(
            "vars.MASTER_AGENT_LIVE_JIRA_ISSUE_ID",
            tier1_job,
        )
        self.assertEqual(
            tier1_job.count("python -m tests.test_connector_integration_matrix"),
            2,
        )
        self.assertEqual(
            self.workflow.count("python -m tests.test_connector_integration_matrix"),
            4,
        )
        self.assertNotIn(
            "python tests/test_connector_integration_matrix.py", self.workflow
        )
        self.assertIn("prepare-t1-ewir --root", tier1_job)
        self.assertIn("verify-t1-ewir", tier1_job)
        self.assertIn(
            "master-agent engineering-work-item-review",
            tier1_job,
        )
        self.assertIn(
            '--profile "$MASTER_AGENT_LIVE_T1_EWIR_PROFILE"',
            tier1_job,
        )
        self.assertIn('>> "$GITHUB_STEP_SUMMARY"', tier1_job)
        self.assertIn('> "$MASTER_AGENT_LIVE_T1_EWIR_COMMAND_OUTPUT" 2>&1', tier1_job)
        for forbidden in (
            "GRAPH_TOKEN",
            "MASTER_AGENT_GITHUB_TOKEN",
            "MASTER_AGENT_LIVE_GITHUB_",
            "MASTER_AGENT_LIVE_MICROSOFT_",
            "MASTER_AGENT_ENTRA_",
            "MASTER_AGENT_RUN_LIVE_CONNECTOR_TESTS",
            "upload-artifact",
            "download-artifact",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, tier1_job)
        for harness_contract in (
            "_t1_ewir_plan_dimensions",
            "len(settings.confluence_page_ids) != 1",
            "if settings.include_diffstat:",
            "provider_calls <= 14",
            "PerformanceCounter.GOVERNANCE_INTERACTIONS",
            "PerformanceCounter.APPROVAL_INTERACTIONS",
            "protected Tier-1 unselected-provider activity found",
            "T1-EWIR-001 protected preflight failed",
            "T1-EWIR-001 protected evidence verification failed",
        ):
            with self.subTest(harness_contract=harness_contract):
                self.assertIn(harness_contract, self.harness)

    def test_tier1_harness_module_entrypoint_resolves_without_pythonpath(self) -> None:
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        canary = "protected-environment-value-must-not-appear"
        environment["MASTER_AGENT_JIRA_TOKEN"] = canary

        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                "tests.test_connector_integration_matrix",
                "prepare-t1-ewir",
                "--help",
            ),
            cwd=_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertIn(
            "Prepare or verify the protected T1-EWIR-001 live case.",
            completed.stdout,
        )
        self.assertNotIn(canary, completed.stdout + completed.stderr)

    def test_no_credential_artifacts_or_mutable_actions_are_used(self) -> None:
        self.assertNotIn("upload-artifact", self.workflow)
        self.assertNotIn("download-artifact", self.workflow)
        self.assertEqual(self.workflow.count("persist-credentials: false"), 4)
        uses = re.findall(r"^\s*- uses:\s+([^\s#]+)", self.workflow, re.MULTILINE)
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")


class LiveConnectorPreflightTests(unittest.TestCase):
    """Validate exact delegated scope and expiry checks without network I/O."""

    def test_read_token_requires_exact_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_path = _write_test_token(
                Path(directory),
                scopes=tuple(sorted(_MICROSOFT_READ_SCOPES | {"Mail.Send"})),
                expires_at=datetime.now(UTC) + timedelta(hours=2),
            )
            config = _microsoft_config(_MICROSOFT_READ_SCOPES)
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_path)},
                    clear=False,
                ),
                self.assertRaisesRegex(AssertionError, "exactly match"),
            ):
                _require_microsoft_delegated_token(
                    config,
                    required_scopes=_MICROSOFT_READ_SCOPES,
                    minimum_remaining_seconds=600,
                )

    def test_effect_token_must_outlive_timeout_and_cleanup(self) -> None:
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as directory:
            token_path = _write_test_token(
                Path(directory),
                scopes=tuple(sorted(_MICROSOFT_EFFECT_SCOPES)),
                expires_at=now + timedelta(seconds=2699),
            )
            config = _microsoft_config(_MICROSOFT_EFFECT_SCOPES)
            with (
                patch.dict(
                    os.environ,
                    {"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_path)},
                    clear=False,
                ),
                self.assertRaisesRegex(AssertionError, "cleanup reserve"),
            ):
                _require_microsoft_delegated_token(
                    config,
                    required_scopes=_MICROSOFT_EFFECT_SCOPES,
                    minimum_remaining_seconds=2700,
                    now=now,
                )

    def test_exact_effect_token_with_sufficient_lifetime_passes(self) -> None:
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as directory:
            token_path = _write_test_token(
                Path(directory),
                scopes=tuple(sorted(_MICROSOFT_EFFECT_SCOPES)),
                expires_at=now + timedelta(seconds=2701),
            )
            config = _microsoft_config(_MICROSOFT_EFFECT_SCOPES)
            with patch.dict(
                os.environ,
                {"MASTER_AGENT_GRAPH_TOKEN_FILE": str(token_path)},
                clear=False,
            ):
                _require_microsoft_delegated_token(
                    config,
                    required_scopes=_MICROSOFT_EFFECT_SCOPES,
                    minimum_remaining_seconds=2700,
                    now=now,
                )

    def test_application_identity_is_rejected_before_provider_use(self) -> None:
        config = _microsoft_config(
            _MICROSOFT_EFFECT_SCOPES,
            auth_mode=AuthMode.OAUTH_APPLICATION,
        )
        with self.assertRaisesRegex(AssertionError, "oauth_delegated"):
            _require_microsoft_delegated_token(
                config,
                required_scopes=_MICROSOFT_EFFECT_SCOPES,
                minimum_remaining_seconds=2700,
            )


class LiveConnectorRecoveryTests(unittest.TestCase):
    """Exercise the bounded returned-result journal and its honest residual."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.root.chmod(0o700)
        self.action = action_for(
            "github.issue.create",
            system="github",
            resource_type="issue",
            resource_id="integration-test",
            risk=RiskLevel.REVERSIBLE_WRITE,
            parameters={
                "owner": "owner",
                "repository": "sandbox",
                "title": "integration",
                "body": "temporary",
            },
        )
        self.result = ExecutionResult(
            action_id=self.action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after={"number": 17, "state": "open"},
            connector_reference="https://github.example/issues/17",
            message="created",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_entry_is_private_bounded_and_round_trips(self) -> None:
        path = _write_recovery_entry(
            self.root,
            self.action,
            self.result,
            run_label="run-1",
            mode="effects",
        )
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "master-agent/live-connector-recovery@1")
        restored_action, restored_result = _read_recovery_entry(
            path,
            expected_run_label="run-1",
            expected_mode="effects",
        )
        self.assertEqual(restored_action, self.action)
        self.assertEqual(restored_result, self.result)

    def test_independent_replay_verifies_then_deletes(self) -> None:
        path = _write_recovery_entry(
            self.root,
            self.action,
            self.result,
            run_label="run-2",
            mode="effects",
        )
        connector = _FakeConnector()
        recovered = _replay_recovery_entries(
            _FakeRegistry(connector),
            self.root,
            run_label="run-2",
            mode="effects",
        )
        self.assertEqual(recovered, 1)
        self.assertEqual(connector.compensations, 1)
        self.assertFalse(path.exists())

    def test_failed_recovery_verification_retains_entry(self) -> None:
        path = _write_recovery_entry(
            self.root,
            self.action,
            self.result,
            run_label="run-3",
            mode="effects",
        )
        connector = _FakeConnector(compensation_verified=False)
        with self.assertRaisesRegex(AssertionError, "could not be verified"):
            _replay_recovery_entries(
                _FakeRegistry(connector),
                self.root,
                run_label="run-3",
                mode="effects",
            )
        self.assertTrue(path.exists())

    def test_execute_failure_before_return_is_an_explicit_residual(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "response was lost"):
            _execute_verify_and_compensate(
                _LostResponseConnector(),
                self.action,
                recovery_root=self.root,
                run_label="run-4",
                mode="effects",
            )
        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_journal_write_failure_still_compensates_returned_effect(self) -> None:
        self.root.chmod(0o755)
        connector = _FakeConnector(execution_result=self.result)
        with self.assertRaisesRegex(AssertionError, "mode 0700"):
            _execute_verify_and_compensate(
                connector,
                self.action,
                recovery_root=self.root,
                run_label="run-5",
                mode="effects",
            )
        self.assertEqual(connector.compensations, 1)

    def test_recovery_root_rejects_special_permission_bits(self) -> None:
        self.root.chmod(0o1700)
        connector = _FakeConnector(execution_result=self.result)
        with self.assertRaisesRegex(AssertionError, "mode 0700"):
            _execute_verify_and_compensate(
                connector,
                self.action,
                recovery_root=self.root,
                run_label="run-6",
                mode="effects",
            )
        self.assertEqual(connector.compensations, 1)


class _FakeConnector:
    def __init__(
        self,
        *,
        compensation_verified: bool = True,
        execution_result: ExecutionResult | None = None,
    ) -> None:
        self.compensation_verified = compensation_verified
        self.execution_result = execution_result
        self.compensations = 0

    def execute(self, action: object) -> ExecutionResult:
        if self.execution_result is None:
            raise AssertionError("fake connector has no execution result")
        return self.execution_result

    def verify(
        self,
        action: object,
        result: ExecutionResult,
    ) -> SimpleNamespace:
        return SimpleNamespace(verified=True)

    def compensate(self, action: object, result: ExecutionResult) -> ExecutionResult:
        self.compensations += 1
        return ExecutionResult(
            action_id=result.action_id,
            state=ActionState.SUCCEEDED,
            before=result.after,
            after={"number": 17, "state": "closed"},
            connector_reference=result.connector_reference,
            message="closed",
        )

    def verify_compensation(
        self,
        action: object,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> SimpleNamespace:
        return SimpleNamespace(verified=self.compensation_verified)


class _LostResponseConnector:
    def execute(self, action: object) -> ExecutionResult:
        raise RuntimeError("provider committed but the response was lost")


class _FakeRegistry:
    def __init__(self, connector: _FakeConnector) -> None:
        self.connector = connector

    def resolve(self, system: str, capability: str) -> _FakeConnector:
        return self.connector


def _job_source(workflow: str, start: str, end: str | None) -> str:
    begin = workflow.index(f"  {start}:")
    finish = workflow.index(f"  {end}:", begin) if end else len(workflow)
    return workflow[begin:finish]


def _microsoft_config(
    scopes: frozenset[str],
    *,
    auth_mode: AuthMode = AuthMode.OAUTH_DELEGATED,
) -> IntegrationConfig:
    return IntegrationConfig(
        connectors={
            "microsoft": ConnectorConfig(
                system="microsoft",
                enabled=True,
                deployment=DeploymentType.CLOUD,
                base_url="https://graph.microsoft.com/v1.0",
                base_url_env=None,
                auth_mode=auth_mode,
                username_env=None,
                secret_env=None,
                extra={
                    "oauth_flow": "token_file",
                    "token_file_env": "MASTER_AGENT_GRAPH_TOKEN_FILE",
                    "identity_mode": "delegated",
                    "scopes": sorted(scopes),
                },
            )
        }
    )


def _write_test_token(
    directory: Path,
    *,
    scopes: tuple[str, ...],
    expires_at: datetime,
) -> Path:
    directory.chmod(0o700)
    return write_token_file(
        directory / "graph-token.json",
        AccessToken(
            value="test-token",
            expires_at=expires_at,
            scopes=scopes,
            source="test",
        ),
    )


if __name__ == "__main__":
    unittest.main()
