"""Bounded governance-performance schema and deterministic benchmark tests."""

from __future__ import annotations

import json
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from master_agent.config import IntegrationConfig
from master_agent.connectors.factory import build_live_registry
from master_agent.execution_context import capture_connector_executions
from master_agent.http import SafeHttpClient
from master_agent.performance import (
    NATIVE_CONNECTOR_IMPLEMENTATION,
    PENDING_CONNECTOR_IMPLEMENTATION,
    PERFORMANCE_SCHEMA,
    ConnectorImplementationDimension,
    DeterministicClock,
    MeasurementMode,
    PerformanceCase,
    PerformanceCounter,
    PerformanceOutcome,
    PerformanceRecorder,
    PerformanceSnapshot,
    PerformanceStage,
    RetryReason,
    StageMeasurement,
    TransportPhase,
    current_performance_recorder,
    ensure_performance_run,
    percentile,
    performance_run,
    performance_stage,
    performance_transport_phase,
)
from scripts.benchmark_governance import _repository_commit, run_case
from tests.fakes import ScriptedTransport


class _FailingTransport:
    """Transport whose failure text must never enter performance evidence."""

    def request(self, **_: object) -> object:
        raise RuntimeError("provider secret path=/private/example token=canary")


class PerformanceSchemaTests(unittest.TestCase):
    """Prove the runtime recorder is bounded, deterministic, and isolated."""

    def test_fixed_schema_orders_every_stage_and_counter(self) -> None:
        clock = DeterministicClock()
        with performance_run(
            measurement_mode=MeasurementMode.DETERMINISTIC,
            case_id=PerformanceCase.ISOLATED_READ,
            wall_clock=clock.wall,
            cpu_clock=clock.cpu,
        ) as recorder:
            with recorder.span(PerformanceStage.REQUEST_PARSE_ROUTE):
                clock.advance(wall_seconds=0.25, cpu_seconds=0.1)
            snapshot = recorder.snapshot()

        payload = snapshot.to_dict()
        self.assertEqual(payload["schema"], PERFORMANCE_SCHEMA)
        self.assertEqual(
            [item["stage"] for item in payload["stages"]],
            [str(stage) for stage in PerformanceStage],
        )
        self.assertEqual(
            list(payload["counters"]),
            [str(counter) for counter in PerformanceCounter],
        )
        self.assertGreater(snapshot.summary()["total_wall_seconds"], 0.0)
        self.assertEqual(snapshot.summary()["local_governance_wall_seconds"], 0.25)

    def test_wall_and_cpu_clocks_remain_distinguishable(self) -> None:
        clock = DeterministicClock()
        recorder = PerformanceRecorder(wall_clock=clock.wall, cpu_clock=clock.cpu)
        with recorder.span(PerformanceStage.POLICY_EVALUATION):
            clock.advance(wall_seconds=1.5, cpu_seconds=0.4)

        stage = recorder.snapshot().stages[
            tuple(PerformanceStage).index(PerformanceStage.POLICY_EVALUATION)
        ]
        self.assertEqual(stage.wall_seconds, 1.5)
        self.assertEqual(stage.cpu_seconds, 0.4)

    def test_arbitrary_dimensions_map_to_fixed_other_bucket(self) -> None:
        canaries = (
            "https://attacker.test/private?token=secret",
            "/Users/private/file",
            "recipient@example.test",
            "EXAMPLE_SECRET_NAME",
        )
        recorder = PerformanceRecorder(commit_identity=canaries[0])
        recorder.record_dimensions(
            capabilities=(canaries[0],),
            risk_tiers=(canaries[1],),
            systems=(canaries[2],),
        )
        with self.assertRaisesRegex(ValueError, "unsupported"):
            recorder.record_connector_implementation(canaries[3], canaries[0])
        serialized = recorder.snapshot().serialize()

        for canary in canaries:
            self.assertNotIn(canary, serialized)
        self.assertIn('"other"', serialized)
        self.assertIn('"commit_identity":"unbound"', serialized)

    def test_snapshot_constructor_cannot_bypass_bounded_dimensions(self) -> None:
        snapshot = PerformanceRecorder().snapshot()
        with self.assertRaisesRegex(ValueError, "unbounded"):
            replace(snapshot, systems=("private-provider-secret",))

        sanitized = replace(snapshot, master_agent_version="private-version-secret")
        self.assertEqual(sanitized.master_agent_version, "unbound")
        self.assertNotIn("private-version-secret", sanitized.serialize())

    def test_snapshot_freezes_sequences_and_rejects_custom_stage_objects(self) -> None:
        recorder = PerformanceRecorder()
        recorder.record_connector_implementation(
            "jira",
            NATIVE_CONNECTOR_IMPLEMENTATION,
        )
        original = recorder.snapshot()
        mutable_stages = list(original.stages)
        mutable_implementations = list(original.connector_implementations)
        frozen = replace(
            original,
            stages=mutable_stages,  # type: ignore[arg-type]
            connector_implementations=mutable_implementations,  # type: ignore[arg-type]
        )
        mutable_stages.clear()
        mutable_implementations.clear()
        self.assertEqual(len(frozen.stages), len(tuple(PerformanceStage)))
        self.assertEqual(len(frozen.connector_implementations), 1)

        class ContentBearingStage:
            stage = PerformanceStage.REQUEST_PARSE_ROUTE

            def to_dict(self) -> dict[str, object]:
                return {"stage": str(self.stage), "content": "SECRET-CANARY"}

        forged_stages: list[object] = [ContentBearingStage(), *original.stages[1:]]
        with self.assertRaisesRegex(TypeError, "fixed measurements"):
            replace(original, stages=forged_stages)  # type: ignore[arg-type]

        class ContentBearingStageSubclass(StageMeasurement):
            def to_dict(self) -> dict[str, object]:
                return {"stage": str(self.stage), "content": "STAGE-SECRET-CANARY"}

        first = original.stages[0]
        evil_stage = ContentBearingStageSubclass(
            stage=first.stage,
            wall_seconds=first.wall_seconds,
            cpu_seconds=first.cpu_seconds,
            occurrences=first.occurrences,
        )
        with self.assertRaisesRegex(TypeError, "fixed measurements"):
            replace(original, stages=(evil_stage, *original.stages[1:]))

        class ContentBearingImplementationSubclass(ConnectorImplementationDimension):
            def to_dict(self) -> dict[str, object]:
                return {
                    "system": self.system,
                    "content": "IMPLEMENTATION-SECRET-CANARY",
                }

        with self.assertRaisesRegex(TypeError, "fixed dimensions"):
            replace(
                original,
                connector_implementations=(
                    ContentBearingImplementationSubclass(system="jira"),
                ),
            )

    def test_runtime_setup_touches_only_the_selected_provider(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.jira]
enabled = true
deployment = "cloud"
base_url = "https://example.atlassian.net"
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"

[connectors.github]
enabled = true
deployment = "cloud"
base_url = "https://api.github.com"
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GITHUB_TOKEN"
""".strip(),
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(path)
            environment = {
                "MASTER_AGENT_JIRA_USERNAME": "selected@example.test",
                "MASTER_AGENT_JIRA_TOKEN": "selected-secret",
                "MASTER_AGENT_GITHUB_TOKEN": "unselected-secret",
            }
            with performance_run() as recorder:
                captured = capture_connector_executions(
                    config,
                    environ=environment,
                    systems={"jira"},
                )
                registry = build_live_registry(
                    config,
                    environ=environment,
                    systems={"jira"},
                    captured_executions=captured,
                )
                snapshot = recorder.snapshot()

        self.assertEqual(registry.systems(), ("jira",))
        self.assertEqual(
            snapshot.counters[PerformanceCounter.CREDENTIAL_RESOLUTIONS],
            1,
        )
        self.assertEqual(
            snapshot.counters[PerformanceCounter.CONNECTOR_INITIALIZATIONS],
            1,
        )
        self.assertEqual(
            snapshot.counters[PerformanceCounter.PRINCIPAL_ATTESTATIONS],
            1,
        )
        self.assertEqual(
            snapshot.provider_activity["github"],
            {activity: 0 for activity in snapshot.provider_activity["github"]},
        )

    def test_native_facets_count_as_one_initialized_implementation(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "integrations.toml"
            path.write_text(
                """
[connectors.microsoft]
enabled = true
deployment = "cloud"
implementation = "native"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "none"
identity_mode = "delegated"
onenote_read_enabled = true
""".strip()
                + "\n",
                encoding="utf-8",
            )
            config = IntegrationConfig.from_toml(path)
            systems = {
                "microsoft",
                "sharepoint",
                "outlook",
                "teams",
                "onenote",
            }
            with performance_run() as recorder:
                captured = capture_connector_executions(
                    config,
                    environ={},
                    systems=systems,
                    require_trusted_principal=False,
                )
                registry = build_live_registry(
                    config,
                    environ={},
                    systems=systems,
                    captured_executions=captured,
                )
                snapshot = recorder.snapshot()

        self.assertEqual(
            {system for system in systems if registry.connectors(system)},
            systems,
        )
        self.assertEqual(
            snapshot.counters[PerformanceCounter.CONNECTOR_INITIALIZATIONS],
            1,
        )
        self.assertEqual(
            [item.to_dict() for item in snapshot.connector_implementations],
            [{"system": "microsoft", "implementation": "native", "bound": True}],
        )

    def test_snapshot_round_trip_rejects_derived_field_forgery(self) -> None:
        snapshot = PerformanceRecorder().snapshot()
        restored = PerformanceSnapshot.from_dict(snapshot.to_dict())
        self.assertEqual(restored.serialize(), snapshot.serialize())

        forged = snapshot.to_dict()
        forged["baseline_eligible"] = True
        with self.assertRaisesRegex(ValueError, "eligibility"):
            PerformanceSnapshot.from_dict(forged)

        forged_activity = snapshot.to_dict()
        activity = forged_activity["provider_activity"]
        assert isinstance(activity, dict)
        activity["private-provider-secret"] = {}
        with self.assertRaisesRegex(ValueError, "activity systems"):
            PerformanceSnapshot.from_dict(forged_activity)

        counter_forgeries = {
            "selected_systems": 1,
            "selected_connector_implementations": 1,
            "credential_resolutions": 1,
            "connector_initializations": 1,
            "principal_attestations": 1,
            "provider_transport_calls": 1,
            "verification_calls": 1,
            "retries": 1,
        }
        for counter, value in counter_forgeries.items():
            with self.subTest(counter=counter):
                forged_counter = snapshot.to_dict()
                counters = forged_counter["counters"]
                assert isinstance(counters, dict)
                counters[counter] = value
                with self.assertRaisesRegex(ValueError, "inconsistent"):
                    PerformanceSnapshot.from_dict(forged_counter)

        forged_phase = snapshot.to_dict()
        phases = forged_phase["transport_calls_by_phase"]
        assert isinstance(phases, dict)
        phases["execution"] = 1
        with self.assertRaisesRegex(ValueError, "phases are inconsistent"):
            PerformanceSnapshot.from_dict(forged_phase)

    def test_fixed_types_reject_free_form_labels(self) -> None:
        recorder = PerformanceRecorder()
        with self.assertRaises(TypeError):
            recorder.increment("custom_counter")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            recorder.record_outcome("custom_outcome")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            recorder.set_case("custom-case")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ConnectorImplementationDimension(
                system="jira",
                bound=0,  # type: ignore[arg-type]
            )

    def test_nested_and_exceptional_contexts_restore_prior_state(self) -> None:
        self.assertIsNone(current_performance_recorder())
        with performance_run() as outer:
            self.assertIs(current_performance_recorder(), outer)
            with (
                self.assertRaisesRegex(RuntimeError, "controlled"),
                performance_run() as inner,
            ):
                self.assertIs(current_performance_recorder(), inner)
                with performance_stage(PerformanceStage.POLICY_EVALUATION):
                    raise RuntimeError("controlled")
            self.assertIs(current_performance_recorder(), outer)
        self.assertIsNone(current_performance_recorder())

    def test_completed_recorder_cannot_be_reused_for_another_run(self) -> None:
        clock = DeterministicClock()
        recorder = PerformanceRecorder(wall_clock=clock.wall, cpu_clock=clock.cpu)
        recorder.begin_total()
        clock.advance(wall_seconds=1.0, cpu_seconds=0.1)
        recorder.end_total()
        with self.assertRaisesRegex(RuntimeError, "reused"):
            recorder.begin_total()

    def test_early_finalized_context_is_sealed_and_not_reused(self) -> None:
        with performance_run() as completed:
            completed.finish_total()
            with self.assertRaisesRegex(RuntimeError, "finalized"):
                completed.increment(PerformanceCounter.GOVERNANCE_INTERACTIONS)
            with ensure_performance_run() as fresh:
                self.assertIsNot(fresh, completed)
                self.assertTrue(fresh.total_active)
                fresh.increment(PerformanceCounter.GOVERNANCE_INTERACTIONS)
            self.assertEqual(
                fresh.snapshot().counters[PerformanceCounter.GOVERNANCE_INTERACTIONS],
                1,
            )

    def test_sequential_runs_do_not_accumulate_metrics(self) -> None:
        snapshots = []
        for _ in range(2):
            with performance_run() as recorder:
                recorder.record_credential_resolution("jira")
                snapshots.append(recorder.snapshot())
        for snapshot in snapshots:
            self.assertEqual(
                snapshot.counters[PerformanceCounter.CREDENTIAL_RESOLUTIONS], 1
            )

    def test_failed_transport_is_counted_before_dispatch(self) -> None:
        client = SafeHttpClient(
            base_url="https://example.test/api",
            transport=_FailingTransport(),
            retry_attempts=0,
        )
        with performance_run() as recorder:
            with (
                performance_transport_phase(TransportPhase.EXECUTION, "jira"),
                self.assertRaisesRegex(RuntimeError, "provider secret"),
            ):
                client.request_json("GET", "items")
            snapshot = recorder.snapshot()

        payload = snapshot.to_dict()
        self.assertEqual(payload["counters"]["provider_transport_calls"], 1)
        self.assertEqual(payload["transport_calls_by_phase"]["execution"], 1)
        self.assertEqual(
            payload["provider_activity"]["jira"]["provider_transport_calls"],
            1,
        )
        self.assertNotIn("provider secret", snapshot.serialize())
        self.assertNotIn("/private/example", snapshot.serialize())

    def test_retry_counts_only_attempts_after_the_initial_dispatch(self) -> None:
        transport = ScriptedTransport()
        transport.add_json("GET", "/api/items", {"retry": True}, status=503)
        transport.add_json("GET", "/api/items", {"ok": True}, status=200)
        client = SafeHttpClient(
            base_url="https://example.test/api",
            transport=transport,
            retry_attempts=1,
        )
        with (
            patch("master_agent.http.time.sleep", return_value=None),
            performance_run() as recorder,
        ):
            with performance_transport_phase(TransportPhase.VERIFICATION, "jira"):
                payload, _ = client.request_json("GET", "items")
            snapshot = recorder.snapshot()

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(
            snapshot.counters[PerformanceCounter.PROVIDER_TRANSPORT_CALLS], 2
        )
        self.assertEqual(snapshot.counters[PerformanceCounter.RETRIES], 1)
        self.assertEqual(snapshot.retries_by_reason[RetryReason.HTTP_503], 1)
        self.assertEqual(
            snapshot.transport_calls_by_phase[TransportPhase.VERIFICATION], 2
        )

    def test_percentile_uses_stable_nearest_rank(self) -> None:
        values = tuple(float(value) for value in range(1, 21))
        self.assertEqual(percentile(values, 50), 10.0)
        self.assertEqual(percentile(values, 95), 19.0)
        with self.assertRaises(ValueError):
            percentile((), 50)


class DeterministicBenchmarkTests(unittest.TestCase):
    """Verify representative cases and exact Tier-1 budgets."""

    def test_t1_case_is_byte_stable_and_meets_provisional_budgets(self) -> None:
        first = run_case(
            PerformanceCase.T1_EWIR_001,
            iterations=20,
            commit_identity="a" * 40,
        )
        second = run_case(
            PerformanceCase.T1_EWIR_001,
            iterations=20,
            commit_identity="a" * 40,
        )
        rendered_first = json.dumps(first, sort_keys=True, separators=(",", ":"))
        rendered_second = json.dumps(second, sort_keys=True, separators=(",", ":"))
        self.assertEqual(rendered_first, rendered_second)
        self.assertFalse(first["baseline_eligible"])
        self.assertEqual(first["iteration_count"], 20)
        self.assertTrue(first["aggregate"]["budget"]["passed"])
        self.assertLessEqual(
            first["aggregate"]["summary"]["total_wall_seconds"]["p50"],
            30.0,
        )
        self.assertLessEqual(
            first["aggregate"]["summary"]["total_wall_seconds"]["p95"],
            60.0,
        )
        self.assertLess(
            first["aggregate"]["summary"]["local_governance_percentage"]["p95"],
            5.0,
        )

    def test_t1_exact_counts_and_native_identity(self) -> None:
        payload = run_case(PerformanceCase.T1_EWIR_001, iterations=20)
        counters = payload["aggregate"]["counters"]
        self.assertEqual(counters["connector_initializations"], 3)
        self.assertEqual(counters["selected_connector_implementations"], 3)
        self.assertEqual(counters["credential_resolutions"], 3)
        self.assertEqual(counters["principal_attestations"], 3)
        self.assertEqual(counters["governance_interactions"], 0)
        self.assertEqual(counters["approval_interactions"], 0)
        self.assertLess(counters["provider_transport_calls"], 20)
        implementations = payload["iterations"][0]["dimensions"][
            "connector_implementations"
        ]
        self.assertEqual(
            [item["system"] for item in implementations],
            ["bitbucket", "confluence", "jira"],
        )
        self.assertTrue(
            all(
                item
                == {
                    "system": item["system"],
                    "implementation": NATIVE_CONNECTOR_IMPLEMENTATION,
                    "bound": True,
                }
                for item in implementations
            )
        )

    def test_historical_pending_170_dimension_remains_readable(self) -> None:
        payload = PerformanceRecorder().snapshot().to_dict()
        dimensions = payload["dimensions"]
        counters = payload["counters"]
        assert isinstance(dimensions, dict)
        assert isinstance(counters, dict)
        dimensions["systems"] = ["jira"]
        dimensions["connector_implementations"] = [
            {
                "system": "jira",
                "implementation": PENDING_CONNECTOR_IMPLEMENTATION,
                "bound": False,
            }
        ]
        counters["selected_systems"] = 1
        counters["selected_connector_implementations"] = 1

        restored = PerformanceSnapshot.from_dict(payload)

        self.assertEqual(
            restored.connector_implementations[0].implementation,
            PENDING_CONNECTOR_IMPLEMENTATION,
        )
        self.assertFalse(restored.connector_implementations[0].bound)

    def test_unselected_provider_activity_is_explicitly_zero(self) -> None:
        payload = run_case(PerformanceCase.T1_EWIR_001, iterations=20)
        activity = payload["aggregate"]["provider_activity"]
        for system in ("github", "microsoft", "outlook", "reddit", "teams"):
            self.assertTrue(
                all(value == 0 for value in activity[system].values()),
                system,
            )

    def test_high_risk_denial_has_zero_provider_specific_work(self) -> None:
        payload = run_case(PerformanceCase.HIGH_RISK_DENIAL, iterations=1)
        counters = payload["aggregate"]["counters"]
        self.assertEqual(counters["credential_resolutions"], 0)
        self.assertEqual(counters["connector_initializations"], 0)
        self.assertEqual(counters["provider_transport_calls"], 0)
        self.assertEqual(counters["verification_calls"], 0)
        self.assertEqual(payload["aggregate"]["outcomes"]["failed_pre_effect"], 1)

    def test_representative_and_controlled_cases_are_available(self) -> None:
        expected_outcome = {
            PerformanceCase.ISOLATED_READ: PerformanceOutcome.VERIFIED,
            PerformanceCase.REVERSIBLE_WRITE: PerformanceOutcome.VERIFIED,
            PerformanceCase.CONSEQUENTIAL_COMMUNICATION: PerformanceOutcome.VERIFIED,
            PerformanceCase.HIGH_RISK_DENIAL: PerformanceOutcome.FAILED_PRE_EFFECT,
            PerformanceCase.CONTROLLED_FALSE_SUCCESS: (
                PerformanceOutcome.CONTROLLED_FALSE_SUCCESS
            ),
            PerformanceCase.CONTROLLED_DUPLICATE_EFFECT: (
                PerformanceOutcome.DUPLICATE_EFFECT
            ),
        }
        for case_id, outcome in expected_outcome.items():
            with self.subTest(case_id=case_id):
                payload = run_case(case_id, iterations=2)
                self.assertGreater(payload["aggregate"]["outcomes"][str(outcome)], 0)
                self.assertFalse(payload["baseline_eligible"])

        false_success = run_case(
            PerformanceCase.CONTROLLED_FALSE_SUCCESS,
            iterations=1,
        )
        duplicate = run_case(
            PerformanceCase.CONTROLLED_DUPLICATE_EFFECT,
            iterations=1,
        )
        self.assertEqual(
            false_success["aggregate"]["counters"]["provider_transport_calls"],
            2,
        )
        self.assertEqual(
            duplicate["aggregate"]["counters"]["provider_transport_calls"],
            3,
        )

    def test_runtime_case_is_not_a_deterministic_benchmark_fixture(self) -> None:
        with self.assertRaisesRegex(ValueError, "not supported"):
            run_case(PerformanceCase.RUNTIME, iterations=1)

    def test_t1_budget_depends_on_production_outcome_instrumentation(self) -> None:
        with patch(
            "master_agent.orchestrator._record_run_performance_outcomes",
            return_value=None,
        ):
            payload = run_case(PerformanceCase.T1_EWIR_001, iterations=20)

        budget = payload["aggregate"]["budget"]
        self.assertFalse(budget["passed"])
        self.assertFalse(budget["checks"]["verified_outcomes_exactly_6"])

    def test_benchmark_output_contains_no_prohibited_runtime_content(self) -> None:
        payload = run_case(PerformanceCase.T1_EWIR_001, iterations=20)
        rendered = json.dumps(payload, sort_keys=True)
        prohibited = (
            "https://",
            "Authorization",
            "recipient@",
            "/Users/",
            "\\Users\\",
            "request_body",
            "response_body",
            "timestamp",
        )
        for value in prohibited:
            self.assertNotIn(value, rendered)

    def test_cli_output_file_is_valid_stable_json(self) -> None:
        from scripts.benchmark_governance import main

        with TemporaryDirectory() as directory:
            output = Path(directory) / "benchmark.json"
            with patch(
                "scripts.benchmark_governance._repository_commit",
                return_value="b" * 40,
            ):
                result = main(
                    (
                        "--iterations",
                        "20",
                        "--case-id",
                        "T1-EWIR-001",
                        "--output",
                        str(output),
                    )
                )
            self.assertEqual(result, 0)
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["iteration_count"], 20)
            self.assertTrue(parsed["aggregate"]["budget"]["passed"])

    def test_t1_rejects_nonconforming_iteration_counts(self) -> None:
        for iterations in (1, 19, 21):
            with (
                self.subTest(iterations=iterations),
                self.assertRaisesRegex(ValueError, "exactly 20"),
            ):
                run_case(
                    PerformanceCase.T1_EWIR_001,
                    iterations=iterations,
                )

    def test_repository_commit_is_unbound_for_dirty_worktree(self) -> None:
        canary = b"?? SECRET-CANARY\n"
        with patch(
            "scripts.benchmark_governance.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("git", "status"),
                returncode=0,
                stdout=canary,
            ),
        ) as run:
            identity = _repository_commit()

        self.assertEqual(identity, "unbound")
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("SECRET-CANARY", identity)

    def test_repository_commit_accepts_clean_exact_commit(self) -> None:
        commit = b"b" * 40 + b"\n"
        with patch(
            "scripts.benchmark_governance.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=("git", "status"),
                    returncode=0,
                    stdout=b"",
                ),
                subprocess.CompletedProcess(
                    args=("git", "rev-parse"),
                    returncode=0,
                    stdout=commit,
                ),
            ),
        ):
            identity = _repository_commit()

        self.assertEqual(identity, "b" * 40)


if __name__ == "__main__":
    unittest.main()
