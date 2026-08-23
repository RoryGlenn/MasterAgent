"""Tests for authenticated exact-bound recurring occurrences."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import textwrap
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Self

from master_agent.approval_handoff import ApprovalRunInvocation
from master_agent.cli import main
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ConfigurationExecutionBinding,
    ExecutionContext,
    ResourceRef,
    RiskLevel,
    RuntimeExecutionBinding,
    RuntimePathExecutionBinding,
    SystemsAssessment,
)
from master_agent.planners.base import (
    bind_fast_path_governance,
    bind_systems_governance,
)
from master_agent.recurring import (
    DstFoldPolicy,
    OccurrenceStatus,
    RecurringConfig,
    RecurringStateStore,
    WeeklySchedule,
)
from master_agent.recurring_occurrence import (
    _validate_plan_scope,
    bind_local_occurrence,
    load_occurrence,
    parse_occurrence,
    timezone_identity,
)


class RecurringOccurrenceTests(unittest.TestCase):
    """Verify artifact, time, scope, claim, and dry-run boundaries."""

    def test_local_bind_publishes_and_authenticates_exact_artifact(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            artifact = fixture.root / "occurrences" / "weekly.json"

            self.assertEqual(load_occurrence(artifact), occurrence)
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            store = RecurringStateStore(fixture.config.state_database)
            try:
                status = store.authenticate_occurrence_artifact(
                    workflow_name=occurrence.workflow_name,
                    scheduled_at=occurrence.scheduled_at,
                    artifact_fingerprint=occurrence.fingerprint,
                    artifact_sha256=occurrence.artifact_sha256,
                    registration_digest=occurrence.registration_digest,
                    execution_key=occurrence.execution_key,
                )
            finally:
                store.close()
            self.assertIs(status, OccurrenceStatus.BOUND)

    def test_artifact_parser_rejects_duplicates_unknowns_and_noncanonical_json(
        self,
    ) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            payload = occurrence.to_dict()
            canonical = (
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode()
                + b"\n"
            )
            duplicate = canonical.replace(
                b'{\n  "approval_resume_deadline"',
                b'{\n  "schema": "master-agent/recurring-occurrence@1",\n  "approval_resume_deadline"',
                1,
            )
            with self.assertRaisesRegex(ValidationError, "valid UTF-8 JSON"):
                parse_occurrence(duplicate)

            unknown = dict(payload)
            unknown["ambient_command"] = "run anything"
            with self.assertRaisesRegex(ValidationError, "incomplete or unknown"):
                parse_occurrence(
                    (json.dumps(unknown, indent=2, sort_keys=True) + "\n").encode()
                )

            with self.assertRaisesRegex(ValidationError, "canonical JSON"):
                parse_occurrence(json.dumps(payload, sort_keys=True).encode())

            with self.assertRaisesRegex(ValidationError, "string is too large"):
                parse_occurrence(
                    json.dumps({"unknown": "x" * (256 * 1024 + 1)}).encode()
                )

    def test_self_contained_digest_is_not_artifact_authentication(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            alternate = replace(
                fixture.config,
                state_database=fixture.root / "claim" / "alternate.sqlite3",
            )
            from master_agent.recurring_occurrence import authenticate_occurrence

            with self.assertRaisesRegex(ConfigurationError, "not registered"):
                store = authenticate_occurrence(
                    occurrence,
                    config=alternate,
                    now=datetime(2026, 8, 20, 20, 30, tzinfo=UTC),
                )
                store.close()

    def test_effect_idempotency_is_occurrence_scoped_but_reads_remain_fresh(
        self,
    ) -> None:
        with _recurring_fixture(include_effect=True) as fixture:
            occurrence = _bind_fixture(fixture)
            source = fixture.plan.actions
            scoped = occurrence.plan.actions

            self.assertEqual(scoped[0].idempotency_key, source[0].idempotency_key)
            self.assertNotEqual(scoped[1].idempotency_key, source[1].idempotency_key)
            self.assertTrue(
                scoped[1].idempotency_key.startswith(occurrence.execution_key + ":")
            )

    def test_local_generation_uses_occurrence_keyed_create_only_name(self) -> None:
        with _recurring_fixture(include_local=True) as fixture:
            occurrence = _bind_fixture(fixture)
            generated = occurrence.plan.actions[1]

            self.assertIs(generated.risk, RiskLevel.LOCAL_GENERATION)
            self.assertIn(occurrence.execution_key[:20], generated.target.resource_id)
            self.assertEqual(
                generated.parameters["output_name"],
                f"review-{occurrence.execution_key[:20]}.pptx",
            )

    def test_approval_invocation_round_trip_binds_occurrence_and_generation(
        self,
    ) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            bound = replace(
                fixture.invocation,
                recurring_occurrence=str(
                    (fixture.root / "occurrences" / "weekly.json").resolve()
                ),
                recurring_fingerprint=occurrence.fingerprint,
                recurring_claim_generation=3,
            )

            self.assertEqual(
                ApprovalRunInvocation.from_dict(bound.to_dict()),
                bound,
            )
            with self.assertRaisesRegex(ValidationError, "must be complete"):
                replace(bound, recurring_claim_generation=None)

    def test_claim_generation_fences_approval_resume_and_stale_attempt(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            store = RecurringStateStore(fixture.config.state_database)
            started = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
            try:
                first_generation, first_token = store.reserve_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    started_at=started,
                )
                store.validate_occurrence_fence(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=first_generation,
                    claim_token=first_token,
                    now=started,
                )
                store.block_occurrence_for_approval(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=first_generation,
                    claim_token=first_token,
                    request_fingerprint="a" * 64,
                )
                second_generation, second_token = (
                    store.resume_approval_blocked_occurrence(
                        artifact_fingerprint=occurrence.fingerprint,
                        prior_generation=first_generation,
                        request_fingerprint="a" * 64,
                        started_at=started,
                    )
                )
                self.assertGreater(second_generation, first_generation)
                with self.assertRaisesRegex(ConfigurationError, "fence was lost"):
                    store.validate_occurrence_fence(
                        artifact_fingerprint=occurrence.fingerprint,
                        claim_generation=first_generation,
                        claim_token=first_token,
                        now=started,
                    )
                store.finalize_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=second_generation,
                    claim_token=second_token,
                    status=OccurrenceStatus.SUCCEEDED,
                    finished_at=started,
                )
            finally:
                store.close()

    def test_concurrent_exact_claims_allow_only_one_fenced_attempt(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            started = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)

            def reserve() -> bool:
                store = RecurringStateStore(fixture.config.state_database)
                try:
                    store.reserve_occurrence(
                        artifact_fingerprint=occurrence.fingerprint,
                        started_at=started,
                    )
                    return True
                except ConfigurationError:
                    return False
                finally:
                    store.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(pool.map(lambda _index: reserve(), range(2)))
            self.assertEqual(sorted(results), [False, True])

    def test_expired_claim_cannot_be_renewed(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            started = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
            store = RecurringStateStore(
                fixture.config.state_database,
                lease_duration=timedelta(seconds=5),
            )
            try:
                generation, token = store.reserve_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    started_at=started,
                )
                expired_at = started + timedelta(seconds=5)
                self.assertFalse(
                    store.renew_occurrence_fence(
                        artifact_fingerprint=occurrence.fingerprint,
                        claim_generation=generation,
                        claim_token=token,
                        now=expired_at,
                    )
                )
                with self.assertRaisesRegex(ConfigurationError, "fence was lost"):
                    store.validate_occurrence_fence(
                        artifact_fingerprint=occurrence.fingerprint,
                        claim_generation=generation,
                        claim_token=token,
                        now=expired_at,
                    )
            finally:
                store.close()

    def test_all_communication_recipient_fields_are_allowlisted(self) -> None:
        parameter_cases = (
            {"to": ["allowed@example.test", "blocked@example.test"]},
            {"to": "allowed@example.test", "cc": ["blocked@example.test"]},
            {"to": "allowed@example.test", "bcc": ["blocked@example.test"]},
            {"recipient_id": "blocked-team-recipient"},
        )
        with _recurring_fixture(include_effect=True) as fixture:
            workflow = replace(
                fixture.config.workflows["weekly"],
                allowed_capabilities=("outlook.email.send",),
                allowed_recipients=("allowed@example.test",),
                canonical_sources=("outlook://mailbox",),
            )
            for parameters in parameter_cases:
                with self.subTest(parameters=parameters):
                    action = AgentAction(
                        capability="outlook.email.send",
                        target=ResourceRef(
                            system="outlook",
                            resource_type="mailbox",
                            resource_id="mailbox",
                        ),
                        parameters=parameters,
                        risk=RiskLevel.EXTERNAL_COMMUNICATION,
                        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
                        requires_approval=True,
                        idempotency_key="weekly:communication",
                        justification="Send the approved recurring review.",
                    )
                    with self.assertRaisesRegex(
                        ConfigurationError,
                        "exceeds recipient scope",
                    ):
                        _validate_plan_scope(
                            replace(fixture.plan, actions=(action,)),
                            workflow,
                        )

    def test_cancellation_invalidates_pending_or_running_attempts(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            store = RecurringStateStore(fixture.config.state_database)
            started = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
            try:
                generation, token = store.reserve_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    started_at=started,
                )
                self.assertIs(
                    store.cancel_occurrence(
                        artifact_fingerprint=occurrence.fingerprint,
                    ),
                    OccurrenceStatus.INDETERMINATE,
                )
                with self.assertRaisesRegex(ConfigurationError, "fence was lost"):
                    store.validate_occurrence_fence(
                        artifact_fingerprint=occurrence.fingerprint,
                        claim_generation=generation,
                        claim_token=token,
                        now=started,
                    )
            finally:
                store.close()

    def test_pre_effect_failure_requires_explicit_exact_recovery(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            store = RecurringStateStore(fixture.config.state_database)
            started = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
            try:
                generation, token = store.reserve_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    started_at=started,
                )
                store.finalize_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=generation,
                    claim_token=token,
                    status=OccurrenceStatus.FAILED_PRE_EFFECT,
                    finished_at=started,
                )
                with self.assertRaisesRegex(ConfigurationError, "not eligible"):
                    store.reserve_occurrence(
                        artifact_fingerprint=occurrence.fingerprint,
                        started_at=started,
                    )
                store.mark_occurrence_recoverable(
                    artifact_fingerprint=occurrence.fingerprint,
                )
                next_generation, next_token = store.reserve_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    started_at=started,
                )
                self.assertGreater(next_generation, generation)
                store.finalize_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    claim_generation=next_generation,
                    claim_token=next_token,
                    status=OccurrenceStatus.SUCCEEDED,
                    finished_at=started,
                )
            finally:
                store.close()

    def test_expired_running_claim_reconciles_conservatively(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            started = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
            store = RecurringStateStore(
                fixture.config.state_database,
                lease_duration=timedelta(seconds=1),
            )
            try:
                store.reserve_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    started_at=started,
                )
                with self.assertRaisesRegex(ConfigurationError, "no expired"):
                    store.reconcile_expired_occurrence(
                        artifact_fingerprint=occurrence.fingerprint,
                        status=OccurrenceStatus.RECOVERABLE,
                        now=started,
                    )
                store.reconcile_expired_occurrence(
                    artifact_fingerprint=occurrence.fingerprint,
                    status=OccurrenceStatus.INDETERMINATE,
                    now=started + timedelta(seconds=2),
                )
                self.assertIs(
                    store.authenticate_occurrence_artifact(
                        workflow_name=occurrence.workflow_name,
                        scheduled_at=occurrence.scheduled_at,
                        artifact_fingerprint=occurrence.fingerprint,
                        artifact_sha256=occurrence.artifact_sha256,
                        registration_digest=occurrence.registration_digest,
                        execution_key=occurrence.execution_key,
                    ),
                    OccurrenceStatus.INDETERMINATE,
                )
            finally:
                store.close()

    def test_dst_gap_fold_and_timezone_identity_fail_closed(self) -> None:
        gap = WeeklySchedule(
            weekday=6,
            hour=2,
            minute=30,
            timezone="America/New_York",
        )
        with self.assertRaisesRegex(ConfigurationError, "does not exist"):
            gap.resolve_occurrence(_naive_datetime(2026, 3, 8, 2, 30))

        ambiguous = WeeklySchedule(
            weekday=6,
            hour=1,
            minute=30,
            timezone="America/New_York",
        )
        with self.assertRaisesRegex(ConfigurationError, "ambiguous"):
            ambiguous.resolve_occurrence(_naive_datetime(2026, 11, 1, 1, 30))
        first = replace(ambiguous, fold_policy=DstFoldPolicy.FIRST).resolve_occurrence(
            _naive_datetime(2026, 11, 1, 1, 30)
        )
        second = replace(
            ambiguous,
            fold_policy=DstFoldPolicy.SECOND,
        ).resolve_occurrence(_naive_datetime(2026, 11, 1, 1, 30))
        self.assertNotEqual(first, second)
        self.assertEqual(len(timezone_identity("America/New_York")), 64)

        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            with self.assertRaisesRegex(ValidationError, "timezone facts changed"):
                replace(
                    occurrence,
                    utc_offset_minutes=occurrence.utc_offset_minutes + 60,
                )

    def test_occurrence_rejects_ambient_shell_or_environment_selection(self) -> None:
        with _recurring_fixture(include_effect=True) as fixture:
            occurrence = _bind_fixture(fixture)
            action = replace(
                occurrence.plan.actions[1],
                parameters={"command": "echo unsafe"},
            )
            with self.assertRaisesRegex(ValidationError, "unbound command"):
                replace(
                    occurrence,
                    plan=replace(
                        occurrence.plan,
                        actions=(occurrence.plan.actions[0], action),
                    ),
                )

    def test_relative_config_paths_bind_to_config_source_not_apply_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as cwd:
            root = Path(raw)
            path = root / "recurring.toml"
            path.write_text(
                _config_text(root, relative=True),
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(cwd)
                config = RecurringConfig.from_toml(path)
            finally:
                os.chdir(previous)
            self.assertEqual(
                config.state_database,
                (root / "claim" / "state.sqlite3").resolve(),
            )
            self.assertEqual(config.occurrence_root, (root / "occurrences").resolve())

    def test_registration_change_blocks_authentication(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            changed_path = fixture.root / "changed.toml"
            changed_path.write_text(
                _config_text(fixture.root).replace("generation = 1", "generation = 2"),
                encoding="utf-8",
            )
            changed = RecurringConfig.from_toml(changed_path)
            from master_agent.recurring_occurrence import authenticate_occurrence

            with self.assertRaisesRegex(ConfigurationError, "registration changed"):
                store = authenticate_occurrence(
                    occurrence,
                    config=changed,
                    now=datetime(2026, 8, 20, 20, 30, tzinfo=UTC),
                )
                store.close()

    def test_bound_root_identity_substitution_fails_before_claim(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            identities = dict(occurrence.root_identities)
            identities["claim"] = identities["lock"]
            changed = replace(occurrence, root_identities=identities)
            from master_agent.recurring_occurrence import authenticate_occurrence

            with self.assertRaisesRegex(ConfigurationError, "root identity changed"):
                store = authenticate_occurrence(
                    changed,
                    config=fixture.config,
                    now=datetime(2026, 8, 20, 20, 30, tzinfo=UTC),
                )
                store.close()

    def test_early_late_and_approval_resume_windows_fail_closed(self) -> None:
        with _recurring_fixture() as fixture:
            occurrence = _bind_fixture(fixture)
            from master_agent.recurring_occurrence import authenticate_occurrence

            with self.assertRaisesRegex(ConfigurationError, "not due"):
                store = authenticate_occurrence(
                    occurrence,
                    config=fixture.config,
                    now=occurrence.not_before - timedelta(seconds=1),
                )
                store.close()
            with self.assertRaisesRegex(ConfigurationError, "outside its time window"):
                store = authenticate_occurrence(
                    occurrence,
                    config=fixture.config,
                    now=occurrence.expires_at + timedelta(seconds=1),
                )
                store.close()
            with self.assertRaisesRegex(ConfigurationError, "outside its time window"):
                store = authenticate_occurrence(
                    occurrence,
                    config=fixture.config,
                    now=occurrence.approval_resume_deadline + timedelta(seconds=1),
                    allow_approval_resume=True,
                )
                store.close()

    def test_dry_run_does_not_read_config_or_mutate_claim_state(self) -> None:
        with _recurring_fixture() as fixture:
            _bind_fixture(fixture)
            artifact = fixture.root / "occurrences" / "weekly.json"
            before = fixture.config.state_database.stat().st_mtime_ns
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status_code = main(
                    [
                        "recurring-run",
                        str(artifact),
                        "--recurring",
                        str(fixture.root / "does-not-exist.toml"),
                        "--dry-run",
                    ]
                )
            self.assertEqual(status_code, 0, stderr.getvalue())
            self.assertIn("no claim, audit, credential, provider", stdout.getvalue())
            self.assertEqual(fixture.config.state_database.stat().st_mtime_ns, before)

    def test_force_flag_and_legacy_name_are_not_an_execution_path(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            status = main(
                [
                    "recurring-run",
                    "weekly",
                    "--recurring",
                    "/tmp/recurring.toml",
                    "--force",
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("recurring-run execution is disabled", stderr.getvalue())


class _Fixture:
    def __init__(
        self,
        *,
        temporary: tempfile.TemporaryDirectory[str],
        root: Path,
        config_path: Path,
        config: RecurringConfig,
        plan: ChangePlan,
        invocation: ApprovalRunInvocation,
    ) -> None:
        self.temporary = temporary
        self.root = root
        self.config_path = config_path
        self.config = config
        self.plan = plan
        self.invocation = invocation

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.temporary.cleanup()


def _recurring_fixture(
    *, include_effect: bool = False, include_local: bool = False
) -> _Fixture:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name).resolve()
    for name in (
        "claim",
        "occurrences",
        "locks",
        "audit",
        "artifacts",
        "workspace",
        "results",
        "workflow-output",
    ):
        (root / name).mkdir(mode=0o700)
    for name in (
        "integrations.toml",
        "workflow.toml",
        "identities.toml",
        "retention.toml",
        "approval-authorities.toml",
    ):
        (root / name).write_text(f"# {name}\n", encoding="utf-8")
    config_path = root / "recurring.toml"
    config_path.write_text(
        _config_text(
            root,
            include_effect=include_effect,
            include_local=include_local,
        ),
        encoding="utf-8",
    )
    config = RecurringConfig.from_toml(config_path)
    runtime = RuntimeExecutionBinding(
        connector_mode="mock",
        include_writes=include_effect,
        include_communications=False,
        audit_database=str(root / "audit" / "audit.sqlite3"),
        artifact_root=str(root / "artifacts"),
        workspace_root=str(root / "workspace"),
        result_json=str(root / "results" / "result.json"),
        evidence_type="run-result/full",
        configurations=(
            ConfigurationExecutionBinding(
                name="approval_authorities",
                sha256="a" * 64,
            ),
        ),
        runtime_paths=tuple(
            _runtime_path(name, path)
            for name, path in (
                ("audit.parent", root / "audit"),
                ("artifact.root", root / "artifacts"),
                ("workspace.root", root / "workspace"),
                ("result.parent", root / "results"),
            )
        ),
    )
    actions = [
        AgentAction(
            capability="jira.issue.search",
            target=ResourceRef(
                system="jira",
                resource_type="issue_collection",
                resource_id="PROJECT",
            ),
            parameters={"limit": 10},
            risk=RiskLevel.READ_ONLY,
            authority_source=AuthoritySource.REGISTERED_WORKFLOW,
            requires_approval=False,
            idempotency_key="weekly:jira",
            justification="Collect fresh operating-review source data.",
        )
    ]
    if include_local:
        actions.append(
            AgentAction(
                capability="powerpoint.presentation.generate",
                target=ResourceRef(
                    system="powerpoint",
                    resource_type="presentation",
                    resource_id="review",
                ),
                parameters={
                    "title": "Weekly review",
                    "sections": ["Summary"],
                    "output_name": "review.pptx",
                },
                risk=RiskLevel.LOCAL_GENERATION,
                authority_source=AuthoritySource.REGISTERED_WORKFLOW,
                requires_approval=False,
                idempotency_key="weekly:local",
                justification="Generate the local-only review artifact.",
                dependencies=(actions[0].action_id,),
            )
        )
    if include_effect:
        actions.append(
            AgentAction(
                capability="jira.issue.update",
                target=ResourceRef(
                    system="jira",
                    resource_type="issue",
                    resource_id="PROJECT",
                    expected_version="1",
                ),
                parameters={"fields": {"labels": ["reviewed"]}},
                risk=RiskLevel.REVERSIBLE_WRITE,
                authority_source=AuthoritySource.REGISTERED_WORKFLOW,
                requires_approval=True,
                idempotency_key="weekly:jira:update",
                justification="Propose the separately approved review marker.",
            )
        )
    unbound = ChangePlan(
        goal="Generate the exact weekly operating review",
        actions=tuple(actions),
        created_by="registered-workflow",
        workflow_id="weekly",
        workflow_fingerprint="weekly-v1",
        execution_context=ExecutionContext(
            integrations_sha256="b" * 64,
            runtime=runtime,
        ),
    )
    if include_effect:
        plan = bind_systems_governance(
            unbound,
            SystemsAssessment(
                desired_outcome=unbound.goal,
                current_behavior="the review marker is not yet applied",
                constraint="the effect requires normal approval and verification",
                stocks=("the registered workflow",),
                flows=("verified evidence reaches the review package",),
                feedback_loops=("verification feeds the next occurrence",),
                delays=("approval can outlive the initial claim",),
                leverage_point="reuse the exact governed applied-run path",
                simplest_intervention="run only the occurrence-bound plan",
                success_metric="the exact occurrence is verified and finalized",
                failure_condition="any stale or broadened occurrence is rejected",
                unintended_consequences=("a duplicate provider effect",),
                removable_complexity=("the optional marker action",),
                alternatives_considered=("local generation without the marker",),
                reversibility_strategy="verify and compensate the marker update",
                low_risk=False,
                reversible=True,
                well_understood=True,
            ),
        )
    else:
        plan = bind_fast_path_governance(
            unbound,
            current_behavior="the review has not run for this occurrence",
            constraint="the schedule may select time but never authority",
            leverage_point="reuse the exact governed applied-run path",
            success_metric="the exact occurrence is verified and finalized",
            failure_condition="any stale or broadened occurrence is rejected",
        )
    invocation = ApprovalRunInvocation.capture(
        plan_path=root / "bound-plan.json",
        approval_paths=(),
        approval_authorities=root / "approval-authorities.toml",
        database=Path(runtime.audit_database),
        connector_mode=runtime.connector_mode,
        integrations=root / "integrations.toml",
        result_json=Path(runtime.result_json or ""),
        retention=root / "retention.toml",
        evidence_type=runtime.evidence_type or "run-result/full",
        identities=root / "identities.toml",
        include_writes=runtime.include_writes,
        include_communications=runtime.include_communications,
        workspace_root=Path(runtime.workspace_root or ""),
        draft_output_dir=Path(runtime.artifact_root),
        capabilities=None,
        governance=None,
        policy=None,
        sources_of_truth=None,
        plugin_names=(),
        plugin_lock=None,
        credentials_file=None,
        credential_mappings=(),
        connector_urls=(),
        recurring_config=config_path,
    )
    return _Fixture(
        temporary=temporary,
        root=root,
        config_path=config_path,
        config=config,
        plan=plan,
        invocation=invocation,
    )


def _bind_fixture(fixture: _Fixture):
    return bind_local_occurrence(
        config=fixture.config,
        workflow_name="weekly",
        requested_local_time=_naive_datetime(2026, 8, 20, 16, 0),
        plan=fixture.plan,
        invocation=fixture.invocation,
        output=fixture.root / "occurrences" / "weekly.json",
        created_at=datetime(2026, 8, 20, 19, 0, tzinfo=UTC),
    )


def _runtime_path(name: str, path: Path) -> RuntimePathExecutionBinding:
    value = path.stat()
    return RuntimePathExecutionBinding(
        name=name,
        path=str(path),
        anchor_path=str(path),
        device=value.st_dev,
        inode=value.st_ino,
        owner=value.st_uid,
        mode=stat.S_IMODE(value.st_mode),
    )


def _naive_datetime(
    year: int, month: int, day: int, hour: int, minute: int
) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC).replace(tzinfo=None)


def _config_text(
    root: Path,
    *,
    include_effect: bool = False,
    include_local: bool = False,
    relative: bool = False,
) -> str:
    def path(value: str) -> str:
        return value if relative else str(root / value)

    allowed = ["jira.issue.search"]
    if include_effect:
        allowed.append("jira.issue.update")
    if include_local:
        allowed.append("powerpoint.presentation.generate")
    capabilities = json.dumps(allowed)
    return textwrap.dedent(
        f"""
        [scheduler]
        state_database = "{path("claim/state.sqlite3")}"
        lock_dir = "{path("locks")}"
        occurrence_root = "{path("occurrences")}"

        [workflows.weekly]
        enabled = true
        revoked = false
        generation = 1
        kind = "weekly_status_package"
        delivery_mode = "local_only"
        weekday = 3
        hour = 16
        minute = 0
        timezone = "America/New_York"
        dst_fold = "reject"
        max_lateness_minutes = 120
        catch_up_policy = "latest_only"
        approval_resume_minutes = 240
        output_dir = "{path("workflow-output")}"
        integration_config = "{path("integrations.toml")}"
        workflow_config = "{path("workflow.toml")}"
        identity_config = "{path("identities.toml")}"
        retention_config = "{path("retention.toml")}"
        allowed_capabilities = {capabilities}
        allowed_recipients = []
        canonical_sources = ["jira://PROJECT"]
        """
    )


if __name__ == "__main__":
    unittest.main()
