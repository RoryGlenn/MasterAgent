#!/usr/bin/env python3
"""Run deterministic, baseline-ineligible governance performance cases."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from master_agent.audit import AuditLog
from master_agent.auth import AuthMode
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.config import (
    ConnectorConfig,
    DeploymentType,
    IntegrationConfig,
    ResolvedConnectorConfig,
)
from master_agent.connectors.factory import build_live_registry
from master_agent.execution_context import capture_connector_executions
from master_agent.governance import (
    ApprovalTier,
    EnvironmentKind,
    GovernanceProfile,
    GovernanceRule,
)
from master_agent.http import HttpResponse, SafeHttpClient
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    CompensationDescriptor,
    CompensationMode,
    DataClassification,
    ExecutionContext,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    StrategyActionIntent,
    StrategyKernel,
    SystemsAssessment,
    VerificationResult,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.performance import (
    PENDING_CONNECTOR_IMPLEMENTATION,
    PERFORMANCE_BENCHMARK_SCHEMA,
    PERFORMANCE_SCHEMA,
    DeterministicClock,
    MeasurementMode,
    PerformanceCase,
    PerformanceCounter,
    PerformanceOutcome,
    PerformanceSnapshot,
    PerformanceStage,
    percentile,
    performance_run,
)
from master_agent.planners.base import (
    bind_fast_path_governance,
    bind_static_intervention_governance,
)
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.provider_egress import (
    ModelContextRule,
    ProviderDataEgressPolicy,
    ProviderDataHandling,
    ProviderDataRoute,
)
from master_agent.registry import ConnectorRegistry

_MAX_ITERATIONS = 1_000
_T1_ITERATIONS = 20


_CASES = frozenset(
    {
        PerformanceCase.ISOLATED_READ,
        PerformanceCase.REVERSIBLE_WRITE,
        PerformanceCase.CONSEQUENTIAL_COMMUNICATION,
        PerformanceCase.HIGH_RISK_DENIAL,
        PerformanceCase.T1_EWIR_001,
        PerformanceCase.CONTROLLED_FALSE_SUCCESS,
        PerformanceCase.CONTROLLED_DUPLICATE_EFFECT,
    }
)


@dataclass(frozen=True, slots=True)
class _Scenario:
    """One fixed governed workload and its selected provider setup."""

    plan: ChangePlan
    provider_systems: tuple[str, ...]
    registry: ConnectorRegistry
    include_writes: bool = False
    include_communications: bool = False


class _BenchmarkClock:
    """Deterministic clock with fixed local ticks and explicit network waits."""

    def __init__(self) -> None:
        self._clock = DeterministicClock()

    def wall(self) -> float:
        value = self._clock.wall()
        self._clock.advance(wall_seconds=0.001, cpu_seconds=0.0)
        return value

    def cpu(self) -> float:
        value = self._clock.cpu()
        self._clock.advance(wall_seconds=0.0, cpu_seconds=0.0005)
        return value

    def network_wait(self) -> None:
        """Advance one fixed provider fixture request."""

        self._clock.advance(wall_seconds=1.5, cpu_seconds=0.0)


class _BenchmarkTransport:
    """Content-free fake transport reached through the production HTTP client."""

    def __init__(self, clock: _BenchmarkClock) -> None:
        self._clock = clock
        self.calls = 0

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HttpResponse:
        del method, headers, body, timeout_seconds, max_response_bytes
        self.calls += 1
        self._clock.network_wait()
        return HttpResponse(
            status=200,
            headers={},
            body=(
                b'{"schema":"benchmark/provider-result@1",'
                b'"fixture_state":"verified","version":"1"}'
            ),
            url=url,
        )


class _BenchmarkConnector:
    """Typed deterministic connector that drives actual HTTP instrumentation."""

    def __init__(
        self,
        system: str,
        capabilities: Sequence[str],
        clock: _BenchmarkClock,
        *,
        controlled_mode: str = "normal",
    ) -> None:
        self._system = system
        self._capabilities = frozenset(capabilities)
        self._transport = _BenchmarkTransport(clock)
        self._client = SafeHttpClient(
            base_url=f"https://{system}.example.test/v1",
            transport=self._transport,
            retry_attempts=0,
            allowed_methods=frozenset({"GET", "POST"}),
        )
        self._controlled_mode = controlled_mode
        self._config: ResolvedConnectorConfig | None = None

    @property
    def system(self) -> str:
        return self._system

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    def bind_config(self, config: ResolvedConnectorConfig) -> None:
        """Bind the exact resolved fixture configuration used by setup."""

        self._config = config

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Return the fixed content-free fixture state."""

        del resource
        return {"fixture_state": "verified", "version": "1"}

    def execute(self, action: AgentAction) -> ExecutionResult:
        if action.risk is RiskLevel.LOCAL_GENERATION:
            after: Mapping[str, Any] = {
                "artifact": "deterministic-review",
                "version": "1",
            }
        else:
            payload, _ = self._client.request_json(
                "POST" if action.risk is not RiskLevel.READ_ONLY else "GET",
                f"fixture/{action.target.resource_id}",
                json_body=(
                    {"fixture": "effect"}
                    if action.risk is not RiskLevel.READ_ONLY
                    else None
                ),
            )
            if self._controlled_mode == "duplicate":
                self._client.request_json(
                    "POST",
                    f"fixture/{action.target.resource_id}",
                    json_body={"fixture": "duplicate"},
                )
            after = payload if isinstance(payload, Mapping) else {"value": payload}
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=after,
            connector_reference="fixture:bounded",
            message="deterministic fixture execution",
            compensation=(
                CompensationDescriptor(
                    kind="fixture_manual_recovery",
                    mode=CompensationMode.MANUAL,
                    target_resource_id=action.target.resource_id,
                    reason="controlled benchmark",
                )
                if action.risk is RiskLevel.REVERSIBLE_WRITE
                else None
            ),
        )

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        if action.risk is RiskLevel.LOCAL_GENERATION:
            verified = True
            observed = result.after
        else:
            observed, _ = self._client.request_json(
                "GET",
                f"fixture/{action.target.resource_id}",
            )
            verified = self._controlled_mode == "normal" and observed == result.after
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=("fixture verified" if verified else "controlled mismatch"),
        )

    def compensate(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=result.after,
            after=result.before,
            connector_reference="fixture:bounded",
            message="deterministic fixture compensation",
        )

    def verify_compensation(
        self,
        action: AgentAction,
        original: ExecutionResult,
        compensation: ExecutionResult,
    ) -> VerificationResult:
        del original
        return VerificationResult(
            action_id=action.action_id,
            verified=compensation.after is None,
            observed=compensation.after,
            message="fixture compensation verified",
        )


def run_case(
    case_id: PerformanceCase,
    *,
    iterations: int,
    commit_identity: str = "unbound",
) -> dict[str, object]:
    """Run one fixed deterministic case and return aggregate evidence."""

    if not isinstance(case_id, PerformanceCase) or case_id not in _CASES:
        raise ValueError("benchmark case is not supported")
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise TypeError("benchmark iterations must be an integer")
    if not 1 <= iterations <= _MAX_ITERATIONS:
        raise ValueError(
            f"benchmark iterations must be between 1 and {_MAX_ITERATIONS}"
        )
    if case_id is PerformanceCase.T1_EWIR_001 and iterations != _T1_ITERATIONS:
        raise ValueError(
            f"T1-EWIR-001 benchmark evidence requires exactly {_T1_ITERATIONS} "
            "iterations"
        )
    snapshots = tuple(
        _run_iteration(case_id, commit_identity=commit_identity)
        for _ in range(iterations)
    )
    first = snapshots[0].to_dict()
    for snapshot in snapshots[1:]:
        current = snapshot.to_dict()
        for key in (
            "dimensions",
            "stages",
            "summary",
            "counters",
            "transport_calls_by_phase",
            "retries_by_reason",
            "outcomes",
            "provider_activity",
        ):
            if current[key] != first[key]:
                raise RuntimeError("deterministic benchmark iterations diverged")
    summaries = [snapshot.summary() for snapshot in snapshots]
    aggregate_summary = {
        name: {
            "p50": percentile((summary[name] for summary in summaries), 50),
            "p95": percentile((summary[name] for summary in summaries), 95),
        }
        for name in summaries[0]
    }
    budget = _budget_result(case_id, first, aggregate_summary)
    return {
        "schema": PERFORMANCE_BENCHMARK_SCHEMA,
        "performance_schema": PERFORMANCE_SCHEMA,
        "measurement_mode": str(MeasurementMode.DETERMINISTIC),
        "baseline_eligible": False,
        "case_id": str(case_id),
        "iteration_count": iterations,
        "stage_order": [str(stage) for stage in PerformanceStage],
        "counter_order": [str(counter) for counter in PerformanceCounter],
        "connector_implementation": {
            "implementation": PENDING_CONNECTOR_IMPLEMENTATION,
            "bound": False,
        },
        "iterations": [snapshot.to_dict() for snapshot in snapshots],
        "aggregate": {
            "summary": aggregate_summary,
            "counters": first["counters"],
            "transport_calls_by_phase": first["transport_calls_by_phase"],
            "outcomes": first["outcomes"],
            "provider_activity": first["provider_activity"],
            "budget": budget,
        },
    }


def _run_iteration(
    case_id: PerformanceCase,
    *,
    commit_identity: str,
) -> PerformanceSnapshot:
    clock = _BenchmarkClock()
    scenario = _scenario(case_id, clock)
    temp_root = Path("/private/tmp") if sys.platform == "darwin" else None
    prior_umask = os.umask(0o077)
    try:
        with (
            TemporaryDirectory(dir=temp_root) as directory,
            performance_run(
                measurement_mode=MeasurementMode.DETERMINISTIC,
                case_id=case_id,
                wall_clock=clock.wall,
                cpu_clock=clock.cpu,
                commit_identity=commit_identity,
            ) as recorder,
        ):
            execution_context = _exercise_selected_provider_setup(scenario)
            plan = _govern_plan(
                replace(scenario.plan, execution_context=execution_context)
            )
            audit = AuditLog(Path(directory) / "benchmark-audit.sqlite3")
            try:
                report = WorkflowOrchestrator(
                    policy=_benchmark_policy(case_id),
                    sources=SourceOfTruthRegistry(()),
                    connectors=scenario.registry,
                    audit=audit,
                    capabilities=_benchmark_catalog(plan),
                    governance=(
                        _benchmark_governance(plan)
                        if any(
                            action.risk is RiskLevel.READ_ONLY
                            for action in plan.actions
                        )
                        else None
                    ),
                ).run(plan, dry_run=False)
                _validate_controlled_result(case_id, report)
                if case_id is PerformanceCase.CONTROLLED_FALSE_SUCCESS:
                    recorder.record_outcome(PerformanceOutcome.CONTROLLED_FALSE_SUCCESS)
                elif case_id is PerformanceCase.CONTROLLED_DUPLICATE_EFFECT:
                    recorder.record_outcome(PerformanceOutcome.DUPLICATE_EFFECT)
                with recorder.span(PerformanceStage.RENDER):
                    report.to_dict()
            finally:
                audit.close()
            recorder.finish_total()
            return recorder.snapshot()
    finally:
        os.umask(prior_umask)


def _scenario(case_id: PerformanceCase, clock: _BenchmarkClock) -> _Scenario:
    if case_id is PerformanceCase.T1_EWIR_001:
        reads = (
            _action("jira.issue.read", "jira", RiskLevel.READ_ONLY, "issue"),
            _action(
                "bitbucket.repository.read",
                "bitbucket",
                RiskLevel.READ_ONLY,
                "repository",
            ),
            _action(
                "bitbucket.pull_request.read",
                "bitbucket",
                RiskLevel.READ_ONLY,
                "pull_request",
            ),
            _action(
                "bitbucket.build_status.read",
                "bitbucket",
                RiskLevel.READ_ONLY,
                "build_status",
            ),
            _action(
                "confluence.page.read",
                "confluence",
                RiskLevel.READ_ONLY,
                "page",
            ),
        )
        generated = replace(
            _action(
                "repository.patch.generate",
                "repository",
                RiskLevel.LOCAL_GENERATION,
                "review_package",
            ),
            dependencies=tuple(action.action_id for action in reads),
        )
        actions = (*reads, generated)
        return _build_scenario(
            actions,
            clock,
            provider_systems=("jira", "bitbucket", "confluence"),
        )
    if case_id is PerformanceCase.ISOLATED_READ:
        return _build_scenario(
            (_action("jira.issue.read", "jira", RiskLevel.READ_ONLY, "issue"),),
            clock,
            provider_systems=("jira",),
        )
    if case_id is PerformanceCase.CONSEQUENTIAL_COMMUNICATION:
        return _build_scenario(
            (
                _action(
                    "teams.chat.message.send",
                    "teams",
                    RiskLevel.EXTERNAL_COMMUNICATION,
                    "message",
                ),
            ),
            clock,
            provider_systems=("teams",),
            include_communications=True,
        )
    if case_id is PerformanceCase.HIGH_RISK_DENIAL:
        return _build_scenario(
            (
                _action(
                    "github.repository.settings.update",
                    "github",
                    RiskLevel.HIGH_IMPACT,
                    "settings",
                ),
            ),
            clock,
            provider_systems=(),
        )
    controlled_mode = (
        "false_success"
        if case_id is PerformanceCase.CONTROLLED_FALSE_SUCCESS
        else "duplicate"
        if case_id is PerformanceCase.CONTROLLED_DUPLICATE_EFFECT
        else "normal"
    )
    return _build_scenario(
        (
            _action(
                "jira.issue.update",
                "jira",
                RiskLevel.REVERSIBLE_WRITE,
                "issue",
            ),
        ),
        clock,
        provider_systems=("jira",),
        include_writes=True,
        controlled_mode=controlled_mode,
    )


def _build_scenario(
    actions: Sequence[AgentAction],
    clock: _BenchmarkClock,
    *,
    provider_systems: tuple[str, ...],
    include_writes: bool = False,
    include_communications: bool = False,
    controlled_mode: str = "normal",
) -> _Scenario:
    registry = ConnectorRegistry()
    capabilities_by_system: dict[str, list[str]] = {}
    for action in actions:
        capabilities_by_system.setdefault(action.target.system, []).append(
            action.capability
        )
    for system, capabilities in capabilities_by_system.items():
        registry.register(
            _BenchmarkConnector(
                system,
                capabilities,
                clock,
                controlled_mode=controlled_mode if system == "jira" else "normal",
            )
        )
    plan = ChangePlan(
        goal="Execute one fixed content-free benchmark workflow.",
        actions=tuple(actions),
        created_by="deterministic-benchmark",
        compensate_on_failure=False,
    )
    return _Scenario(
        plan=plan,
        provider_systems=provider_systems,
        registry=registry,
        include_writes=include_writes,
        include_communications=include_communications,
    )


def _action(
    capability: str,
    system: str,
    risk: RiskLevel,
    resource_type: str,
) -> AgentAction:
    return AgentAction(
        capability=capability,
        target=ResourceRef(system, resource_type, "fixture-resource"),
        parameters={},
        risk=risk,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key=f"benchmark:{capability}",
        justification="Exercise the fixed deterministic governed path.",
    )


def _govern_plan(plan: ChangePlan) -> ChangePlan:
    if all(
        action.risk in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
        for action in plan.actions
    ):
        return bind_fast_path_governance(
            plan,
            current_behavior="the fixed fixture has not run",
            constraint="all activity stays inside deterministic fakes",
            leverage_point="the typed governed execution boundary",
            success_metric="the expected fixture state is independently verified",
            failure_condition="the expected fixture state is not verified",
        )
    kernel = StrategyKernel(
        diagnosis="the controlled fixture effect has not run",
        guiding_policy="exercise only the typed deterministic boundary",
        proximate_objective="classify the controlled fixture result",
        tradeoffs=("provider realism is reserved for the managed pilot",),
        coherent_actions=tuple(
            StrategyActionIntent(
                intent_id=f"benchmark_action_{index}",
                description=action.justification,
                expected_effect="the controlled fixture result is classified",
            )
            for index, action in enumerate(plan.actions, start=1)
        ),
    )
    assessment = SystemsAssessment.for_static_intervention(
        desired_outcome=plan.goal,
        current_behavior="the controlled fixture has not run",
        constraint="all activity stays inside deterministic fakes",
        stocks=("the isolated fixture state",),
        flows=("one typed action through the governed runtime",),
        feedback_loops=("verification classifies the observed state",),
        delays=("one deterministic provider wait",),
        leverage_point="the typed governed execution boundary",
        simplest_intervention="run the single controlled fixture action",
        success_metric="the controlled result is classified",
        failure_condition="the controlled result is not classified",
        unintended_consequences=("the fixture could become indeterminate",),
        removable_complexity=("the disposable fixture",),
        strategy_kernel=kernel,
        reversible=True,
        well_understood=True,
    )
    return bind_static_intervention_governance(plan, assessment)


def _exercise_selected_provider_setup(scenario: _Scenario) -> ExecutionContext:
    if not scenario.provider_systems:
        return ExecutionContext(integrations_sha256="a" * 64)
    configs: dict[str, ConnectorConfig] = {}
    environment: dict[str, str] = {}
    for selected in scenario.provider_systems:
        system = "microsoft" if selected == "teams" else selected
        username_name = f"BENCHMARK_{system.upper()}_USERNAME"
        secret_name = f"BENCHMARK_{system.upper()}_SECRET"
        extra: dict[str, object] = {}
        if system == "jira" and scenario.include_writes:
            extra.update(write_enabled=True, writes_enabled=True)
        if system == "microsoft" and scenario.include_communications:
            extra.update(
                send_enabled=True,
                teams_send_enabled=True,
                outlook_send_enabled=False,
            )
        configs[system] = ConnectorConfig(
            system=system,
            enabled=True,
            deployment=DeploymentType.CLOUD,
            base_url=_benchmark_base_url(system),
            base_url_env=None,
            auth_mode=AuthMode.BASIC,
            username_env=username_name,
            secret_env=secret_name,
            extra=extra,
        )
        environment[username_name] = "fixture-principal"
        environment[secret_name] = "fixture-secret"
    integrations = IntegrationConfig(configs)
    selected_systems = set(scenario.provider_systems)
    captured = capture_connector_executions(
        integrations,
        environ=environment,
        systems=selected_systems,
        require_trusted_principal=True,
    )
    build_live_registry(
        integrations,
        environ=environment,
        systems=selected_systems,
        include_writes=scenario.include_writes,
        include_communications=scenario.include_communications,
        captured_executions=captured,
    )
    resolved_by_system = {
        item.binding.system: item.resolved
        for item in captured
        if item.resolved is not None
    }
    for connector in scenario.registry.connectors():
        if not isinstance(connector, _BenchmarkConnector):
            continue
        configuration_system = (
            "microsoft" if connector.system == "teams" else connector.system
        )
        resolved = resolved_by_system.get(configuration_system)
        if resolved is not None:
            connector.bind_config(resolved)
    return ExecutionContext(
        integrations_sha256="a" * 64,
        connectors=tuple(item.binding for item in captured),
    )


def _benchmark_base_url(system: str) -> str:
    return {
        "jira": "https://fixture.atlassian.net",
        "confluence": "https://fixture.atlassian.net",
        "bitbucket": "https://api.bitbucket.org/2.0",
        "microsoft": "https://graph.microsoft.com",
    }[system]


def _benchmark_catalog(plan: ChangePlan) -> CapabilityCatalog:
    definitions: dict[str, CapabilityDefinition] = {}
    for action in plan.actions:
        local = action.risk is RiskLevel.LOCAL_GENERATION
        read = action.risk is RiskLevel.READ_ONLY
        definitions[action.capability] = CapabilityDefinition(
            name=action.capability,
            enabled=True,
            authentication="local" if local else "configured_connector",
            risk=action.risk,
            reversible=action.risk is RiskLevel.REVERSIBLE_WRITE,
            target_system=action.target.system,
            target_resource_types=(action.target.resource_type,),
            parameter_schema=({"fixture": "string?"} if not read else {}),
            read_result_schema=("benchmark/provider-result@1" if read else ""),
            read_result_resources=(
                {"fixture_state": "value", "version": "value"} if read else {}
            ),
            max_input_bytes=4096 if local else None,
            max_output_bytes=4096 if local else None,
        )
    return CapabilityCatalog(definitions)


def _benchmark_governance(plan: ChangePlan) -> GovernanceProfile:
    model_rule = ModelContextRule(
        name="benchmark-provider-data",
        providers=tuple(
            sorted(
                {
                    action.target.system
                    for action in plan.actions
                    if action.risk is RiskLevel.READ_ONLY
                }
            )
        )
        or ("none",),
        capabilities=tuple(
            sorted(
                action.capability
                for action in plan.actions
                if action.risk is RiskLevel.READ_ONLY
            )
        )
        or ("none.read",),
        data_classifications=frozenset({DataClassification.INTERNAL}),
        destinations=frozenset({"benchmark-agent"}),
        model_tenancies=frozenset({"benchmark-nonproduction"}),
        routes=frozenset({ProviderDataRoute.AUDITED}),
        handling=ProviderDataHandling.ALLOW,
        audit_required=True,
        dlp_required=False,
        redacted_fields=frozenset(),
        allowed_fields=frozenset({"*"}),
        max_items=100,
        max_output_bytes=65536,
    )
    rules = tuple(
        GovernanceRule(
            pattern=action.capability,
            owner="benchmark-owner",
            authentication=(
                "local"
                if action.risk is RiskLevel.LOCAL_GENERATION
                else "configured_connector"
            ),
            data_classifications=frozenset({DataClassification.INTERNAL}),
            approval_tier=ApprovalTier.AUTOMATIC,
            environments=frozenset({EnvironmentKind.DEVELOPMENT}),
        )
        for action in plan.actions
    )
    return GovernanceProfile(
        organization="deterministic-benchmark",
        environment=EnvironmentKind.DEVELOPMENT,
        secret_manager="in-memory-fixture",
        audit_sink="local-sqlite-for-development",
        external_model_policy="bounded-fixture-policy",
        rules=rules,
        metadata={},
        model_context=ProviderDataEgressPolicy(
            destination="benchmark-agent",
            model_tenancy="benchmark-nonproduction",
            source_data_environment="nonproduction",
            dlp_adapter="none",
            development_default_classification=DataClassification.INTERNAL,
            rules=(model_rule,),
        ),
    )


def _benchmark_policy(case_id: PerformanceCase) -> PolicyEngine:
    all_risks = frozenset(RiskLevel)
    prohibited = (
        frozenset({RiskLevel.HIGH_IMPACT})
        if case_id is PerformanceCase.HIGH_RISK_DENIAL
        else frozenset()
    )
    return PolicyEngine(
        PolicyConfig(
            auto_permit_risks=all_risks - prohibited,
            require_approval_risks=frozenset(),
            prohibit_risks=prohibited,
            prohibited_capabilities=(),
            write_capability_patterns=("*.update", "*.send"),
        )
    )


def _validate_controlled_result(case_id: PerformanceCase, report: object) -> None:
    actions = getattr(report, "actions", ())
    states = tuple(getattr(action, "state", None) for action in actions)
    if case_id in {
        PerformanceCase.CONTROLLED_FALSE_SUCCESS,
        PerformanceCase.CONTROLLED_DUPLICATE_EFFECT,
    }:
        if states != (ActionState.INDETERMINATE,):
            raise RuntimeError("controlled benchmark was not caught by verification")
    elif case_id is PerformanceCase.HIGH_RISK_DENIAL:
        if states != (ActionState.PROHIBITED,):
            raise RuntimeError("high-risk benchmark was not denied before effect")
    elif not states or any(state is not ActionState.VERIFIED for state in states):
        raise RuntimeError("benchmark workflow did not verify every action")


def _budget_result(
    case_id: PerformanceCase,
    first: Mapping[str, object],
    aggregate_summary: Mapping[str, Mapping[str, float]],
) -> dict[str, object]:
    counters = first["counters"]
    if not isinstance(counters, Mapping):
        raise TypeError("benchmark counters are invalid")
    dimensions = first["dimensions"]
    if not isinstance(dimensions, Mapping):
        raise TypeError("benchmark dimensions are invalid")
    outcomes = first["outcomes"]
    if not isinstance(outcomes, Mapping):
        raise TypeError("benchmark outcomes are invalid")
    checks: dict[str, bool] = {
        "deterministic_baseline_ineligible": first["baseline_eligible"] is False,
    }
    if case_id is PerformanceCase.T1_EWIR_001:
        checks.update(
            {
                "p50_total_at_most_30_seconds": aggregate_summary["total_wall_seconds"][
                    "p50"
                ]
                <= 30.0,
                "p95_total_at_most_60_seconds": aggregate_summary["total_wall_seconds"][
                    "p95"
                ]
                <= 60.0,
                "local_governance_below_5_percent": aggregate_summary[
                    "local_governance_percentage"
                ]["p95"]
                < 5.0,
                "provider_content_calls_below_20": int(
                    counters["provider_transport_calls"]
                )
                < 20,
                "connector_initializations_exactly_3": int(
                    counters["connector_initializations"]
                )
                == 3,
                "credential_resolutions_exactly_3": int(
                    counters["credential_resolutions"]
                )
                == 3,
                "principal_attestations_exactly_3": int(
                    counters["principal_attestations"]
                )
                == 3,
                "selected_implementations_exactly_3": int(
                    counters["selected_connector_implementations"]
                )
                == 3,
                "governance_interactions_zero": int(counters["governance_interactions"])
                == 0,
                "approval_interactions_zero": int(counters["approval_interactions"])
                == 0,
                "verified_outcomes_exactly_6": int(outcomes["verified"]) == 6,
                "implementations_unbound_pending_170": all(
                    isinstance(item, Mapping)
                    and item.get("implementation") == PENDING_CONNECTOR_IMPLEMENTATION
                    and item.get("bound") is False
                    for item in dimensions["connector_implementations"]
                ),
            }
        )
    return {"passed": all(checks.values()), "checks": checks}


def _repository_commit() -> str:
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if status.returncode != 0 or status.stdout:
            return "unbound"
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unbound"
    value = completed.stdout.decode("ascii", errors="ignore").strip().casefold()
    return (
        value
        if completed.returncode == 0
        and len(value) in {40, 64}
        and all(character in "0123456789abcdef" for character in value)
        else "unbound"
    )


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "run a deterministic governance benchmark; output is never a managed "
            "or live-provider baseline"
        )
    )
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument(
        "--case-id",
        choices=tuple(str(case_id) for case_id in _CASES),
        default=str(PerformanceCase.T1_EWIR_001),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected deterministic case and write stable JSON evidence."""

    args = _parse_args(argv)
    try:
        payload = run_case(
            PerformanceCase(args.case_id),
            iterations=args.iterations,
            commit_identity=_repository_commit(),
        )
    except (TypeError, ValueError, RuntimeError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    try:
        args.output.write_text(rendered, encoding="utf-8")
    except OSError as error:
        print(f"benchmark output failed: {type(error).__name__}", file=sys.stderr)
        return 2
    budget = payload["aggregate"]
    if not isinstance(budget, Mapping):
        return 2
    budget_result = budget.get("budget")
    passed = isinstance(budget_result, Mapping) and budget_result.get("passed") is True
    print(f"case: {args.case_id}")
    print(f"iterations: {args.iterations}")
    print("measurement_mode: deterministic (baseline-ineligible)")
    print(f"budget_passed: {passed}")
    print(f"wrote: {args.output}")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
