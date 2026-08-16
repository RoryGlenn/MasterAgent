"""Adversarial regressions for core authorization and execution invariants."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import unittest
from collections.abc import Mapping
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from master_agent.approvals import ApprovalAuthority, HmacApprovalAuthenticator
from master_agent.audit import AuditLog, IdempotencyClaimState
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.cli import main
from master_agent.errors import PreEffectError, ValidationError, VersionConflictError
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
)
from master_agent.orchestrator import RunReport, WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry

ROOT = Path(__file__).resolve().parents[1]


class _StateConnector:
    def __init__(
        self,
        *,
        system: str = "test",
        capabilities: frozenset[str] = frozenset({"test.resource.update"}),
        entered: threading.Event | None = None,
        release: threading.Event | None = None,
        verify: bool = True,
        raise_after_effect: bool = False,
        raise_before_effect_once: bool = False,
        raise_pre_effect_during_verification: bool = False,
        raise_version_conflict_once: bool = False,
    ) -> None:
        self._system = system
        self._capabilities = capabilities
        self._entered = entered
        self._release = release
        self._verify = verify
        self._raise_after_effect = raise_after_effect
        self._raise_before_effect_once = raise_before_effect_once
        self._raise_pre_effect_during_verification = (
            raise_pre_effect_during_verification
        )
        self._raise_version_conflict_once = raise_version_conflict_once
        self.execute_count = 0
        self.compensate_count = 0
        self.state: dict[str, object] = {}

    @property
    def system(self) -> str:
        return self._system

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    def execute(self, action: AgentAction) -> ExecutionResult:
        self.execute_count += 1
        if self._raise_before_effect_once:
            self._raise_before_effect_once = False
            raise PreEffectError("provider rejected the request before mutation")
        if self._raise_version_conflict_once:
            self._raise_version_conflict_once = False
            raise VersionConflictError("provider version changed before mutation")
        self.state[action.target.resource_id] = action.parameters.get("value")
        if self._raise_after_effect:
            raise RuntimeError("provider response failed after the mutation")
        if self._entered is not None:
            self._entered.set()
        if self._release is not None:
            self._release.wait(timeout=5)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after={"value": action.parameters.get("value")},
            compensation={"kind": "restore"},
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        return {"value": self.state.get(resource.resource_id)}

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        if self._raise_pre_effect_during_verification:
            raise PreEffectError("invalid pre-effect signal during verification")
        return VerificationResult(
            action_id=action.action_id,
            verified=self._verify,
            observed=self.read(action.target),
            message="injected verification result",
        )

    def verify_completed(
        self,
        action: AgentAction,
        prior_result: Mapping[str, Any],
    ) -> VerificationResult:
        observed = self.read(action.target)
        verified = observed == {"value": action.parameters.get("value")}
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message="prior state reverified",
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        self.compensate_count += 1
        self.state.pop(action.target.resource_id, None)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=result.after,
            after={"value": None},
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        return VerificationResult(
            action_id=action.action_id,
            verified=True,
            observed=compensation.after,
            message="compensated",
        )


class CoreRuntimeHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authenticator = HmacApprovalAuthenticator(
            {
                "rory": ApprovalAuthority(
                    key_id="rory",
                    subject="rory@example.test",
                    issuer="master-agent.test",
                    tenant="test-tenant",
                    roles=("change-approver",),
                    secret=b"runtime-hardening-test-secret-32-bytes",
                )
            }
        )

    def test_tampered_or_untrusted_approval_never_authorizes_apply(self) -> None:
        action = _write_action("one", "approved")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        engine = _policy(self.authenticator)

        self.assertTrue(engine.evaluate(plan, action, (approval,)).permitted)
        self.assertFalse(
            engine.evaluate(
                plan,
                action,
                (replace(approval, signature="0" * 64),),
            ).permitted
        )
        self.assertFalse(_policy(None).evaluate(plan, action, (approval,)).permitted)

    def test_nested_plan_parameters_are_immutable_and_copied(self) -> None:
        source = {"message": {"body": ["approved"]}}
        action = _write_action("one", source)
        source["message"]["body"][0] = "mutated"

        self.assertEqual(
            action.parameters["value"]["message"]["body"][0],
            "approved",
        )
        with self.assertRaises((TypeError, AttributeError)):
            action.parameters["value"]["message"]["body"].append("evil")
        with self.assertRaises(TypeError):
            action.parameters["value"]["message"]["body"] = ["evil"]
        plan = _plan(action)
        fingerprint = plan.fingerprint
        nested = action.parameters["value"]["message"]
        body = nested["body"]
        with self.assertRaises(TypeError):
            dict.__setitem__(nested, "body", ("evil",))
        with self.assertRaises(TypeError):
            dict.__ior__(nested, {"body": ("evil",)})
        with self.assertRaises(TypeError):
            list.append(body, "evil")
        self.assertEqual(plan.fingerprint, fingerprint)

    def test_terminal_controls_are_rejected_from_approval_manifest_fields(self) -> None:
        action = _write_action("one", "approved")
        with self.assertRaisesRegex(ValidationError, "control characters"):
            ChangePlan(
                goal="safe-looking\x1b[2Jspoofed",
                actions=(action,),
                created_by="test",
            )
        with self.assertRaisesRegex(ValidationError, "control characters"):
            ResourceRef("test", "resource", "safe\x1b[8mhidden")
        with self.assertRaisesRegex(ValidationError, "control characters"):
            ChangePlan(
                goal="safe\u202espoofed",
                actions=(action,),
                created_by="test",
            )

    def test_inspect_escapes_controls_inside_action_parameters(self) -> None:
        action = _write_action("one", "safe\x1b[2Jhidden")
        plan = _plan(action)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["inspect", str(path)])

        self.assertEqual(status, 0)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn("\\u001b", output.getvalue())

    def test_cli_approval_requires_the_inspected_fingerprint(self) -> None:
        action = _write_action("one", "approved")
        plan = _plan(action)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            authorities = root / "authorities.toml"
            output = root / "approval.json"
            plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
            authorities.write_text(
                "[authorities.rory]\n"
                'subject = "rory@example.test"\n'
                'issuer = "master-agent.test"\n'
                'tenant = "test-tenant"\n'
                'roles = ["change-approver"]\n'
                'secret_env = "TEST_APPROVAL_SECRET"\n',
                encoding="utf-8",
            )
            with (
                patch.dict(
                    os.environ,
                    {"TEST_APPROVAL_SECRET": "x" * 32},
                    clear=False,
                ),
                redirect_stderr(StringIO()),
            ):
                status = main(
                    [
                        "approve",
                        str(plan_path),
                        "--actions",
                        str(action.action_id),
                        "--key-id",
                        "rory",
                        "--approval-authorities",
                        str(authorities),
                        "--expected-fingerprint",
                        "0" * 64,
                        "--output",
                        str(output),
                    ]
                )

        self.assertEqual(status, 1)
        self.assertFalse(output.exists())

    def test_idempotency_reservation_prevents_concurrent_double_execution(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        connector = _StateConnector(entered=entered, release=release)
        action = _write_action("one", "approved", key="shared")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            first_orchestrator = _orchestrator(
                connector,
                audit,
                self.authenticator,
            )
            second_orchestrator = _orchestrator(
                connector,
                audit,
                self.authenticator,
            )
            first: list[RunReport] = []
            thread = threading.Thread(
                target=lambda: first.append(
                    first_orchestrator.run(
                        plan,
                        approvals=(approval,),
                        dry_run=False,
                    )
                )
            )
            thread.start()
            self.assertTrue(entered.wait(timeout=5))
            second = second_orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )
            release.set()
            thread.join(timeout=5)

        self.assertEqual(connector.execute_count, 1)
        self.assertEqual(second.actions[0].state, ActionState.CONFLICTED)
        self.assertEqual(first[0].actions[0].state, ActionState.VERIFIED)

    def test_completed_idempotent_effect_is_reused_only_after_reverification(
        self,
    ) -> None:
        connector = _StateConnector()
        action = _write_action("one", "approved", key="shared")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)
            first = orchestrator.run(plan, approvals=(approval,), dry_run=False)
            retry = orchestrator.run(plan, approvals=(approval,), dry_run=False)

        self.assertEqual(first.actions[0].state, ActionState.VERIFIED)
        self.assertEqual(retry.actions[0].state, ActionState.REUSED)
        self.assertTrue(retry.successful)
        self.assertEqual(connector.execute_count, 1)

    def test_content_bearing_connector_retry_metadata_is_not_persisted(self) -> None:
        class UnsafeRecordConnector(_StateConnector):
            def idempotency_record(self, action, result):
                return {"body": "SECRET-CANARY"}

        connector = UnsafeRecordConnector()
        action = _write_action("one", "approved", key="safe-record")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            report = _orchestrator(
                connector,
                audit,
                self.authenticator,
            ).run(plan, approvals=(approval,), dry_run=False)
            prior = audit.claim_action(
                idempotency_key=action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
                plan_id=plan.plan_id,
                action_id=action.action_id,
            )

        self.assertTrue(report.successful)
        self.assertEqual(prior.state, IdempotencyClaimState.COMPLETED)
        self.assertNotIn("SECRET-CANARY", str(prior.result))

    def test_exception_after_mutation_claim_is_indeterminate(self) -> None:
        connector = _StateConnector(raise_after_effect=True)
        action = _write_action("one", "possibly-written", key="claimed-write")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)

            first = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )
            first_outcome = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )
            retry = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )

        self.assertEqual(connector.state["one"], "possibly-written")
        self.assertEqual(first.actions[0].state, ActionState.INDETERMINATE)
        self.assertEqual(first_outcome, IdempotencyClaimState.INDETERMINATE)
        self.assertEqual(retry.actions[0].state, ActionState.CONFLICTED)
        self.assertIn("durable indeterminate outcome", retry.actions[0].message)

    def test_certified_pre_effect_failure_is_durable_and_retryable(self) -> None:
        connector = _StateConnector(raise_before_effect_once=True)
        action = _write_action("one", "written-on-retry", key="retryable-write")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)

            first = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )
            failed_outcome = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )
            retry = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )

        self.assertEqual(first.actions[0].state, ActionState.FAILED)
        self.assertEqual(failed_outcome, IdempotencyClaimState.FAILED)
        self.assertEqual(retry.actions[0].state, ActionState.VERIFIED)
        self.assertEqual(connector.execute_count, 2)
        self.assertEqual(connector.state["one"], "written-on-retry")

    def test_pre_effect_signal_after_execution_stays_indeterminate(self) -> None:
        connector = _StateConnector(raise_pre_effect_during_verification=True)
        action = _write_action("one", "written", key="post-execution-signal")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)

            first = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )
            first_outcome = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )
            retry = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )
            reconciled_outcome = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )

        self.assertEqual(first.actions[0].state, ActionState.INDETERMINATE)
        self.assertEqual(first_outcome, IdempotencyClaimState.INDETERMINATE)
        self.assertEqual(retry.actions[0].state, ActionState.REUSED)
        self.assertEqual(reconciled_outcome, IdempotencyClaimState.COMPLETED)
        self.assertEqual(connector.execute_count, 1)

    def test_version_conflict_is_durable_and_retryable(self) -> None:
        connector = _StateConnector(raise_version_conflict_once=True)
        action = _write_action("one", "written-on-retry", key="versioned-write")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)

            first = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )
            failed_outcome = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )
            retry = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )

        self.assertEqual(first.actions[0].state, ActionState.CONFLICTED)
        self.assertEqual(failed_outcome, IdempotencyClaimState.FAILED)
        self.assertEqual(retry.actions[0].state, ActionState.VERIFIED)
        self.assertEqual(connector.execute_count, 2)

    def test_stale_completed_idempotent_effect_is_not_reused(self) -> None:
        connector = _StateConnector()
        action = _write_action("one", "approved", key="shared")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)
            first = orchestrator.run(plan, approvals=(approval,), dry_run=False)
            connector.state["one"] = "changed-out-of-band"
            retry = orchestrator.run(plan, approvals=(approval,), dry_run=False)

        self.assertEqual(first.actions[0].state, ActionState.VERIFIED)
        self.assertEqual(retry.actions[0].state, ActionState.CONFLICTED)
        self.assertFalse(retry.successful)
        self.assertEqual(connector.execute_count, 1)

    def test_execution_uses_snapshot_even_if_caller_mutates_after_policy(self) -> None:
        action = _write_action("one", "approved")
        plan = _plan(action)
        approval = _approval(self.authenticator, plan)

        class MutatingPolicy(PolicyEngine):
            def evaluate(self, *args, **kwargs):
                decision = super().evaluate(*args, **kwargs)
                object.__setattr__(action, "parameters", {"value": "unapproved"})
                return decision

        connector = _StateConnector()
        registry = ConnectorRegistry()
        registry.register(connector)
        with TemporaryDirectory() as directory:
            orchestrator = WorkflowOrchestrator(
                policy=MutatingPolicy(
                    PolicyConfig.from_toml(ROOT / "config/policy.toml"),
                    approval_authenticator=self.authenticator,
                ),
                sources=SourceOfTruthRegistry(()),
                connectors=registry,
                audit=AuditLog(Path(directory) / "audit.sqlite3"),
            )
            report = orchestrator.run(
                plan,
                approvals=(approval,),
                dry_run=False,
            )

        self.assertTrue(report.successful)
        self.assertEqual(connector.state["one"], "approved")
        self.assertEqual(action.parameters["value"], "unapproved")

    def test_same_key_cannot_launder_a_different_action(self) -> None:
        connector = _StateConnector()
        first_action = _write_action("one", "first", key="shared")
        second_action = _write_action("two", "second", key="shared")
        first_plan = _plan(first_action)
        second_plan = _plan(second_action)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            orchestrator = _orchestrator(connector, audit, self.authenticator)
            first = orchestrator.run(
                first_plan,
                approvals=(_approval(self.authenticator, first_plan),),
                dry_run=False,
            )
            second = orchestrator.run(
                second_plan,
                approvals=(_approval(self.authenticator, second_plan),),
                dry_run=False,
            )

        self.assertTrue(first.successful)
        self.assertFalse(second.successful)
        self.assertEqual(second.actions[0].state, ActionState.CONFLICTED)
        self.assertNotIn("two", connector.state)

    def test_failed_claim_is_durable_and_atomically_retryable(self) -> None:
        action = _write_action("one", "approved", key="failed-retry")
        plan = _plan(action)
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            first = audit.claim_action(
                idempotency_key=action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
                plan_id=plan.plan_id,
                action_id=action.action_id,
            )
            audit.fail_action(
                idempotency_key=action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
                claim_token=first.token or "",
                outcome={"error": {"reason_code": "pre_effect_failure"}},
            )
            failed = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )
            retry = audit.claim_action(
                idempotency_key=action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
                plan_id=plan.plan_id,
                action_id=action.action_id,
            )

        self.assertEqual(first.state, IdempotencyClaimState.CLAIMED)
        self.assertEqual(failed, IdempotencyClaimState.FAILED)
        self.assertEqual(retry.state, IdempotencyClaimState.CLAIMED)
        self.assertEqual(retry.prior_state, IdempotencyClaimState.FAILED)
        self.assertNotEqual(first.token, retry.token)

    def test_legacy_idempotency_rows_migrate_fail_closed(self) -> None:
        action = _write_action("one", "approved", key="legacy")
        plan = _plan(action)
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    CREATE TABLE completed_actions (
                        idempotency_key TEXT PRIMARY KEY,
                        plan_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        completed_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO completed_actions VALUES (?, ?, ?, ?, ?)",
                    (
                        "legacy",
                        str(plan.plan_id),
                        str(action.action_id),
                        "{}",
                        datetime.now(UTC).isoformat(),
                    ),
                )
                connection.commit()
            database.chmod(0o600)
            audit = AuditLog(database)
            legacy = audit.claim_action(
                idempotency_key="legacy",
                action_fingerprint=action.effect_fingerprint,
                plan_id=plan.plan_id,
                action_id=action.action_id,
            )
            fresh = audit.claim_action(
                idempotency_key="fresh",
                action_fingerprint=action.effect_fingerprint,
                plan_id=plan.plan_id,
                action_id=action.action_id,
            )

        self.assertEqual(legacy.state, IdempotencyClaimState.CONFLICT)
        self.assertEqual(fresh.state, IdempotencyClaimState.CLAIMED)

    def test_skipped_dependency_never_counts_as_success(self) -> None:
        missing = _read_action("missing", "missing.item.read")
        middle = _read_action(
            "middle",
            "ok.item.read",
            dependencies=(missing.action_id,),
        )
        final = _read_action(
            "final",
            "ok.item.read",
            dependencies=(middle.action_id,),
        )
        plan = ChangePlan(
            goal="dependency propagation",
            actions=(missing, middle, final),
            created_by="test",
        )
        connector = _StateConnector(
            system="ok",
            capabilities=frozenset({"ok.item.read"}),
        )
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            report = _orchestrator(
                connector,
                audit,
                self.authenticator,
            ).run(plan, dry_run=False)

        self.assertEqual(
            tuple(item.state for item in report.actions),
            (ActionState.FAILED, ActionState.SKIPPED, ActionState.SKIPPED),
        )
        self.assertEqual(connector.execute_count, 0)
        self.assertFalse(report.successful)

    def test_unverified_effect_is_not_blindly_compensated(self) -> None:
        connector = _StateConnector(verify=False)
        action = _write_action("one", "possibly-written")
        plan = ChangePlan(
            goal="indeterminate effect",
            actions=(action,),
            created_by="test",
            compensate_on_failure=True,
        )
        with TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.sqlite3")
            report = _orchestrator(
                connector,
                audit,
                self.authenticator,
            ).run(
                plan,
                approvals=(_approval(self.authenticator, plan),),
                dry_run=False,
            )
            outcome = audit.idempotency_outcome(
                action.idempotency_key,
                action_fingerprint=action.effect_fingerprint,
            )

        self.assertEqual(report.actions[0].state, ActionState.COMPENSATION_FAILED)
        self.assertEqual(connector.compensate_count, 0)
        self.assertEqual(connector.state["one"], "possibly-written")
        self.assertEqual(outcome, IdempotencyClaimState.INDETERMINATE)
        self.assertIn("no longer matches", report.actions[0].message)


def _policy(
    authenticator: HmacApprovalAuthenticator | None,
) -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig.from_toml(ROOT / "config/policy.toml"),
        approval_authenticator=authenticator,
    )


def _approval(
    authenticator: HmacApprovalAuthenticator,
    plan: ChangePlan,
):
    now = datetime.now(UTC)
    return authenticator.issue(
        plan=plan,
        approved_action_ids=tuple(action.action_id for action in plan.actions),
        key_id="rory",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )


def _orchestrator(
    connector: _StateConnector,
    audit: AuditLog,
    authenticator: HmacApprovalAuthenticator,
) -> WorkflowOrchestrator:
    registry = ConnectorRegistry()
    registry.register(connector)
    return WorkflowOrchestrator(
        policy=_policy(authenticator),
        sources=SourceOfTruthRegistry(()),
        connectors=registry,
        audit=audit,
    )


def _write_action(
    resource_id: str,
    value: object,
    *,
    key: str | None = None,
) -> AgentAction:
    return AgentAction(
        capability="test.resource.update",
        target=ResourceRef("test", "resource", resource_id, expected_version="1"),
        parameters={"value": value},
        risk=RiskLevel.REVERSIBLE_WRITE,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=True,
        idempotency_key=key or f"test:{resource_id}",
        justification="adversarial regression",
    )


def _read_action(
    resource_id: str,
    capability: str,
    *,
    dependencies: tuple = (),
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef(capability.split(".")[0], "item", resource_id),
        parameters={"value": resource_id},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"read:{resource_id}",
        justification="adversarial regression",
        dependencies=dependencies,
    )


def _plan(action: AgentAction) -> ChangePlan:
    return ChangePlan(goal="test", actions=(action,), created_by="test")


if __name__ == "__main__":
    unittest.main()
