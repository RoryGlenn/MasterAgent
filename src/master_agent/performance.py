"""Bounded, content-free performance evidence for governed execution.

The module deliberately exposes no free-form span, tag, or event API. Runtime
callers select from fixed enums and pass provider/capability identifiers through
bounded mappers before any value can reach serialized evidence.
"""

from __future__ import annotations

import json
import math
import re
import sys
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from functools import wraps
from importlib import metadata
from types import MappingProxyType

PERFORMANCE_SCHEMA = "master-agent/performance@1"
PERFORMANCE_BENCHMARK_SCHEMA = "master-agent/performance-benchmark@1"
PENDING_CONNECTOR_IMPLEMENTATION = "unbound_pending_170"
_OTHER = "other"
_UNBOUND = "unbound"
_MAX_COUNT = 1_000_000
_ROUND_DIGITS = 9


class MeasurementMode(StrEnum):
    """Fixed evidence modes with distinct baseline eligibility."""

    DETERMINISTIC = "deterministic"
    LOCAL_RUNTIME = "local_runtime"
    MANAGED_RUNTIME = "managed_runtime"


class PerformanceCase(StrEnum):
    """Fixed benchmark and runtime case identifiers."""

    RUNTIME = "runtime"
    ISOLATED_READ = "isolated_read"
    REVERSIBLE_WRITE = "reversible_write"
    CONSEQUENTIAL_COMMUNICATION = "consequential_communication"
    HIGH_RISK_DENIAL = "high_risk_denial"
    T1_EWIR_001 = "T1-EWIR-001"
    CONTROLLED_FALSE_SUCCESS = "controlled_false_success"
    CONTROLLED_DUPLICATE_EFFECT = "controlled_duplicate_effect"


class PerformanceStage(StrEnum):
    """Complete fixed stage vocabulary in stable lifecycle order."""

    REQUEST_PARSE_ROUTE = "request_parse_route"
    SELECTION = "capability_risk_system_implementation_selection"
    GOVERNANCE_VALIDATION = "governance_catalog_source_egress_validation"
    POLICY_EVALUATION = "policy_evaluation"
    APPROVAL = "approval_preparation_resumption"
    CREDENTIAL_RESOLUTION = "credential_resolution"
    PRINCIPAL_ATTESTATION = "principal_attestation"
    CONNECTOR_INITIALIZATION = "connector_initialization"
    PROVIDER_EXECUTION = "provider_execution"
    PROVIDER_NETWORK = "provider_network_wait"
    VERIFICATION = "verification"
    VERIFICATION_NETWORK = "verification_network_wait"
    IDEMPOTENCY_RECONCILIATION = "idempotency_reconciliation"
    COMPENSATION = "compensation"
    AUDIT_RETENTION = "audit_retention"
    SANITIZATION = "sanitization"
    RENDER = "render"
    END_TO_END_TOTAL = "end_to_end_total"


class TransportPhase(StrEnum):
    """Fixed provider-transport phases."""

    EXECUTION = "execution"
    VERIFICATION = "verification"
    PRINCIPAL_ATTESTATION = "principal_attestation"
    RECONCILIATION = "reconciliation"
    COMPENSATION = "compensation"


class PerformanceCounter(StrEnum):
    """Fixed run counters."""

    SELECTED_SYSTEMS = "selected_systems"
    SELECTED_CONNECTOR_IMPLEMENTATIONS = "selected_connector_implementations"
    CONNECTOR_INITIALIZATIONS = "connector_initializations"
    CREDENTIAL_RESOLUTIONS = "credential_resolutions"
    PRINCIPAL_ATTESTATIONS = "principal_attestations"
    PROVIDER_TRANSPORT_CALLS = "provider_transport_calls"
    VERIFICATION_CALLS = "verification_calls"
    RETRIES = "retries"
    MODEL_ADVISORY_CALLS = "model_advisory_calls"
    GOVERNANCE_INTERACTIONS = "governance_interactions"
    APPROVAL_INTERACTIONS = "approval_interactions"


class RetryReason(StrEnum):
    """Bounded retry reasons; the initial attempt is never represented here."""

    HTTP_429 = "http_429"
    HTTP_502 = "http_502"
    HTTP_503 = "http_503"
    HTTP_504 = "http_504"
    NETWORK_TIMEOUT = "network_timeout"
    NETWORK_DNS = "network_dns"
    TRANSPORT_FAILURE = "transport_failure"


class PerformanceOutcome(StrEnum):
    """Fixed terminal and controlled-observation outcomes."""

    VERIFIED = "verified"
    FAILED_PRE_EFFECT = "failed_pre_effect"
    COMPENSATED = "compensated"
    PARTIAL = "partial"
    INDETERMINATE = "indeterminate"
    CONTROLLED_FALSE_SUCCESS = "controlled_false_success"
    DUPLICATE_EFFECT = "duplicate_effect"


class ProviderActivity(StrEnum):
    """Per-system work whose absence proves an unselected provider stayed idle."""

    CREDENTIAL_RESOLUTIONS = "credential_resolutions"
    CONNECTOR_INITIALIZATIONS = "connector_initializations"
    PRINCIPAL_ATTESTATIONS = "principal_attestations"
    PROVIDER_TRANSPORT_CALLS = "provider_transport_calls"
    VERIFICATION_CALLS = "verification_calls"


_KNOWN_SYSTEMS = (
    "bitbucket",
    "confluence",
    "github",
    "identity",
    "jira",
    "microsoft",
    "onenote",
    "outlook",
    "reddit",
    "repository",
    "sharepoint",
    "teams",
    _OTHER,
)
_KNOWN_SYSTEM_SET = frozenset(_KNOWN_SYSTEMS)
_KNOWN_RISKS = frozenset(
    {
        "read_only",
        "local_generation",
        "reversible_write",
        "external_communication",
        "high_impact",
        "destructive",
    }
)
_KNOWN_CAPABILITIES = frozenset(
    """
    bitbucket.branch.push bitbucket.build_status.read bitbucket.instance.read
    bitbucket.public_repository.list bitbucket.pull_request.create
    bitbucket.pull_request.diffstat bitbucket.pull_request.merge
    bitbucket.pull_request.read bitbucket.pull_request.search
    bitbucket.repository.read confluence.page.compensate confluence.page.create
    confluence.page.create.draft confluence.page.read confluence.page.search
    confluence.page.update confluence.page.update.draft confluence.space.create
    github.checks.read github.collaborator.access.update github.issue.create
    github.public_repository.list github.pull_request.create
    github.pull_request.read github.pull_request.search github.repository.list
    github.repository.read github.repository.settings.update
    identity.identifier.resolve identity.person.list identity.person.resolve
    jira.issue.comment.create jira.issue.comment.draft jira.issue.compensate
    jira.issue.read jira.issue.search jira.issue.transition
    jira.issue.transition.draft jira.issue.update jira.issue.update.draft
    jira.server.info microsoft.identity.read microsoft.identity.search
    onenote.notebook.list onenote.page.create onenote.page.list
    onenote.page.read onenote.page.update onenote.section.list
    outlook.attachment.list outlook.attachment.text.read outlook.email.draft
    outlook.email.send outlook.mail_folder.list outlook.message.read
    outlook.message.search powerpoint.presentation.generate reddit.comment.create
    reddit.comment.draft reddit.comment.reply reddit.comment.reply.draft
    reddit.content.delete reddit.content.edit reddit.content.read reddit.inbox.read
    reddit.post.create reddit.post.draft reddit.search reddit.subreddit.rules.read
    reddit.user.comments.read reddit.user.submitted.read repository.branch.create
    repository.branch.plan repository.branch.push repository.commit.create
    repository.patch.apply repository.patch.generate sharepoint.drive.children
    sharepoint.drive.list sharepoint.file.metadata.read sharepoint.file.text.read
    sharepoint.file.upload sharepoint.site.read sharepoint.site.search
    teams.channel.list teams.channel.message.list teams.channel.message.read
    teams.channel.message.replies.list teams.channel.message.reply
    teams.channel.message.send teams.chat.list teams.chat.message.list
    teams.chat.message.read teams.chat.message.send teams.message.draft
    teams.team.list
    """.split()  # noqa: SIM905 - compact immutable capability vocabulary
)
_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9.+-]{0,16})?")


@dataclass(frozen=True, slots=True)
class ConnectorImplementationDimension:
    """One selected system with the explicit issue #170 placeholder."""

    system: str
    implementation: str = PENDING_CONNECTOR_IMPLEMENTATION
    bound: bool = False

    def __post_init__(self) -> None:
        """Reject any premature or arbitrary implementation identity."""

        if not isinstance(self.system, str):
            raise TypeError("connector implementation system must be a string")
        if self.system not in _KNOWN_SYSTEM_SET:
            raise ValueError("connector implementation system is not bounded")
        if not isinstance(self.implementation, str):
            raise TypeError("connector implementation identity must be a string")
        if not isinstance(self.bound, bool):
            raise TypeError("connector implementation binding must be boolean")
        if (
            self.implementation != PENDING_CONNECTOR_IMPLEMENTATION
            or self.bound is not False
        ):
            raise ValueError("issue #164 cannot claim a bound connector implementation")

    def to_dict(self) -> dict[str, object]:
        """Return the fixed placeholder representation."""

        return {
            "system": self.system,
            "implementation": self.implementation,
            "bound": self.bound,
        }


@dataclass(frozen=True, slots=True)
class StageMeasurement:
    """Accumulated monotonic wall and CPU time for one fixed stage."""

    stage: PerformanceStage
    wall_seconds: float
    cpu_seconds: float
    occurrences: int

    def __post_init__(self) -> None:
        """Normalize durations so round trips cannot change derived summaries."""

        if not isinstance(self.stage, PerformanceStage):
            raise TypeError("performance stage measurement requires a fixed stage")
        object.__setattr__(
            self,
            "wall_seconds",
            _rounded(
                _finite_non_negative(
                    self.wall_seconds,
                    "performance stage wall time",
                )
            ),
        )
        object.__setattr__(
            self,
            "cpu_seconds",
            _rounded(
                _finite_non_negative(
                    self.cpu_seconds,
                    "performance stage CPU time",
                )
            ),
        )
        if isinstance(self.occurrences, bool) or not isinstance(self.occurrences, int):
            raise TypeError("performance stage occurrences must be an integer")
        if not 0 <= self.occurrences <= _MAX_COUNT:
            raise ValueError("performance stage occurrences are out of range")

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible stage measurement."""

        return {
            "stage": str(self.stage),
            "wall_seconds": _rounded(self.wall_seconds),
            "cpu_seconds": _rounded(self.cpu_seconds),
            "occurrences": self.occurrences,
        }


@dataclass(frozen=True, slots=True)
class PerformanceSnapshot:
    """Immutable content-free evidence for one execution attempt."""

    measurement_mode: MeasurementMode
    case_id: PerformanceCase
    platform: str
    runtime_backend: str
    master_agent_version: str
    commit_identity: str
    capabilities: tuple[str, ...]
    risk_tiers: tuple[str, ...]
    systems: tuple[str, ...]
    connector_implementations: tuple[ConnectorImplementationDimension, ...]
    stages: tuple[StageMeasurement, ...]
    counters: Mapping[PerformanceCounter, int]
    transport_calls_by_phase: Mapping[TransportPhase, int]
    retries_by_reason: Mapping[RetryReason, int]
    outcomes: Mapping[PerformanceOutcome, int]
    provider_activity: Mapping[str, Mapping[ProviderActivity, int]]
    schema: str = PERFORMANCE_SCHEMA

    def __post_init__(self) -> None:
        """Freeze nested mappings and validate the fixed schema."""

        if self.schema != PERFORMANCE_SCHEMA:
            raise ValueError("unsupported performance schema")
        if not isinstance(self.measurement_mode, MeasurementMode):
            raise TypeError("performance measurement mode is invalid")
        if not isinstance(self.case_id, PerformanceCase):
            raise TypeError("performance case is invalid")
        _bounded_runtime_value(self.platform)
        _bounded_runtime_value(self.runtime_backend)
        object.__setattr__(
            self,
            "master_agent_version",
            _bounded_version(self.master_agent_version),
        )
        object.__setattr__(
            self,
            "commit_identity",
            _bounded_commit(self.commit_identity),
        )
        _require_ordered_bounded_values(
            self.capabilities,
            mapper=bounded_capability,
            name="performance capabilities",
        )
        _require_ordered_bounded_values(
            self.risk_tiers,
            mapper=bounded_risk,
            name="performance risk tiers",
        )
        _require_ordered_bounded_values(
            self.systems,
            mapper=bounded_system,
            name="performance systems",
        )
        connector_implementations = tuple(self.connector_implementations)
        if not all(
            type(item) is ConnectorImplementationDimension
            for item in connector_implementations
        ):
            raise TypeError(
                "performance connector implementations require fixed dimensions"
            )
        object.__setattr__(
            self,
            "connector_implementations",
            connector_implementations,
        )
        implementation_systems = tuple(
            item.system for item in connector_implementations
        )
        if implementation_systems != tuple(sorted(set(implementation_systems))):
            raise ValueError(
                "performance connector implementations are not unique and ordered"
            )
        if not set(implementation_systems).issubset(self.systems):
            raise ValueError(
                "performance connector implementations are not selected systems"
            )
        stages = tuple(self.stages)
        if not all(type(item) is StageMeasurement for item in stages):
            raise TypeError("performance stages require fixed measurements")
        object.__setattr__(self, "stages", stages)
        expected_stages = tuple(PerformanceStage)
        if tuple(item.stage for item in stages) != expected_stages:
            raise ValueError("performance stages are not complete and ordered")
        object.__setattr__(
            self, "counters", _freeze_enum_counts(self.counters, PerformanceCounter)
        )
        object.__setattr__(
            self,
            "transport_calls_by_phase",
            _freeze_enum_counts(self.transport_calls_by_phase, TransportPhase),
        )
        object.__setattr__(
            self,
            "retries_by_reason",
            _freeze_enum_counts(self.retries_by_reason, RetryReason),
        )
        object.__setattr__(
            self,
            "outcomes",
            _freeze_enum_counts(self.outcomes, PerformanceOutcome),
        )
        provider_rows: dict[str, Mapping[ProviderActivity, int]] = {}
        if tuple(self.provider_activity) != _KNOWN_SYSTEMS:
            raise ValueError("performance provider activity systems are not ordered")
        for system in _KNOWN_SYSTEMS:
            provider_rows[system] = _freeze_enum_counts(
                self.provider_activity[system], ProviderActivity
            )
        object.__setattr__(self, "provider_activity", MappingProxyType(provider_rows))
        self._validate_derived_counts()

    def _validate_derived_counts(self) -> None:
        """Reject counter combinations that the recorder cannot produce."""

        expected_counts = {
            PerformanceCounter.SELECTED_SYSTEMS: len(self.systems),
            PerformanceCounter.SELECTED_CONNECTOR_IMPLEMENTATIONS: len(
                self.connector_implementations
            ),
            PerformanceCounter.CREDENTIAL_RESOLUTIONS: sum(
                row[ProviderActivity.CREDENTIAL_RESOLUTIONS]
                for row in self.provider_activity.values()
            ),
            PerformanceCounter.CONNECTOR_INITIALIZATIONS: sum(
                row[ProviderActivity.CONNECTOR_INITIALIZATIONS]
                for row in self.provider_activity.values()
            ),
            PerformanceCounter.PRINCIPAL_ATTESTATIONS: sum(
                row[ProviderActivity.PRINCIPAL_ATTESTATIONS]
                for row in self.provider_activity.values()
            ),
            PerformanceCounter.PROVIDER_TRANSPORT_CALLS: sum(
                row[ProviderActivity.PROVIDER_TRANSPORT_CALLS]
                for row in self.provider_activity.values()
            ),
            PerformanceCounter.VERIFICATION_CALLS: sum(
                row[ProviderActivity.VERIFICATION_CALLS]
                for row in self.provider_activity.values()
            ),
            PerformanceCounter.RETRIES: sum(self.retries_by_reason.values()),
        }
        for counter, expected in expected_counts.items():
            if self.counters[counter] != expected:
                raise ValueError(f"performance counter is inconsistent: {counter}")
        phase_provider_calls = sum(
            count
            for phase, count in self.transport_calls_by_phase.items()
            if phase is not TransportPhase.PRINCIPAL_ATTESTATION
        )
        if (
            self.counters[PerformanceCounter.PROVIDER_TRANSPORT_CALLS]
            != phase_provider_calls
        ):
            raise ValueError("performance provider transport phases are inconsistent")

    @property
    def baseline_eligible(self) -> bool:
        """Return whether the evidence came from the managed runtime mode."""

        return self.measurement_mode is MeasurementMode.MANAGED_RUNTIME

    def summary(self) -> dict[str, float]:
        """Return stable headline latency and governance-overhead fields."""

        by_stage = {item.stage: item.wall_seconds for item in self.stages}
        total = by_stage[PerformanceStage.END_TO_END_TOTAL]
        local_governance = sum(
            by_stage[stage]
            for stage in (
                PerformanceStage.REQUEST_PARSE_ROUTE,
                PerformanceStage.SELECTION,
                PerformanceStage.GOVERNANCE_VALIDATION,
                PerformanceStage.POLICY_EVALUATION,
                PerformanceStage.APPROVAL,
                PerformanceStage.IDEMPOTENCY_RECONCILIATION,
            )
        )
        return {
            "total_wall_seconds": _rounded(total),
            "total_cpu_seconds": _rounded(
                next(
                    item.cpu_seconds
                    for item in self.stages
                    if item.stage is PerformanceStage.END_TO_END_TOTAL
                )
            ),
            "local_governance_wall_seconds": _rounded(local_governance),
            "connector_initialization_wall_seconds": _rounded(
                by_stage[PerformanceStage.CONNECTOR_INITIALIZATION]
            ),
            "credential_resolution_wall_seconds": _rounded(
                by_stage[PerformanceStage.CREDENTIAL_RESOLUTION]
            ),
            "provider_execution_wall_seconds": _rounded(
                by_stage[PerformanceStage.PROVIDER_EXECUTION]
            ),
            "verification_wall_seconds": _rounded(
                by_stage[PerformanceStage.VERIFICATION]
            ),
            "audit_retention_wall_seconds": _rounded(
                by_stage[PerformanceStage.AUDIT_RETENTION]
            ),
            "render_wall_seconds": _rounded(by_stage[PerformanceStage.RENDER]),
            "provider_network_wall_seconds": _rounded(
                by_stage[PerformanceStage.PROVIDER_NETWORK]
            ),
            "verification_network_wall_seconds": _rounded(
                by_stage[PerformanceStage.VERIFICATION_NETWORK]
            ),
            "local_governance_percentage": _rounded(
                0.0 if total <= 0 else (local_governance / total) * 100.0
            ),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-compatible representation."""

        return {
            "schema": self.schema,
            "measurement_mode": str(self.measurement_mode),
            "baseline_eligible": self.baseline_eligible,
            "case_id": str(self.case_id),
            "runtime": {
                "platform": self.platform,
                "backend": self.runtime_backend,
                "master_agent_version": self.master_agent_version,
                "commit_identity": self.commit_identity,
            },
            "dimensions": {
                "capabilities": list(self.capabilities),
                "risk_tiers": list(self.risk_tiers),
                "systems": list(self.systems),
                "connector_implementations": [
                    item.to_dict() for item in self.connector_implementations
                ],
            },
            "stages": [item.to_dict() for item in self.stages],
            "summary": self.summary(),
            "counters": {
                str(counter): self.counters[counter] for counter in PerformanceCounter
            },
            "transport_calls_by_phase": {
                str(phase): self.transport_calls_by_phase[phase]
                for phase in TransportPhase
            },
            "retries_by_reason": {
                str(reason): self.retries_by_reason[reason] for reason in RetryReason
            },
            "outcomes": {
                str(outcome): self.outcomes[outcome] for outcome in PerformanceOutcome
            },
            "provider_activity": {
                system: {
                    str(activity): self.provider_activity[system][activity]
                    for activity in ProviderActivity
                }
                for system in _KNOWN_SYSTEMS
            },
        }

    def serialize(self) -> str:
        """Return byte-stable compact JSON without timestamps or free-form data."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PerformanceSnapshot:
        """Parse one serialized snapshot while rejecting schema expansion."""

        if set(data) != {
            "schema",
            "measurement_mode",
            "baseline_eligible",
            "case_id",
            "runtime",
            "dimensions",
            "stages",
            "summary",
            "counters",
            "transport_calls_by_phase",
            "retries_by_reason",
            "outcomes",
            "provider_activity",
        }:
            raise ValueError("performance snapshot fields are invalid")
        runtime = _require_mapping(data["runtime"], "performance runtime")
        dimensions = _require_mapping(data["dimensions"], "performance dimensions")
        raw_stages = _require_list(data["stages"], "performance stages")
        stages = tuple(_parse_stage(item) for item in raw_stages)
        counters = _parse_enum_counts(
            data["counters"], PerformanceCounter, "performance counters"
        )
        phases = _parse_enum_counts(
            data["transport_calls_by_phase"],
            TransportPhase,
            "performance transport phases",
        )
        retries = _parse_enum_counts(
            data["retries_by_reason"], RetryReason, "performance retries"
        )
        outcomes = _parse_enum_counts(
            data["outcomes"], PerformanceOutcome, "performance outcomes"
        )
        raw_activity = _require_mapping(
            data["provider_activity"], "performance provider activity"
        )
        if tuple(raw_activity) != _KNOWN_SYSTEMS:
            raise ValueError("performance provider activity systems are invalid")
        provider_activity = {
            system: _parse_enum_counts(
                raw_activity.get(system),
                ProviderActivity,
                f"performance provider activity {system}",
            )
            for system in _KNOWN_SYSTEMS
        }
        implementations_raw = _require_list(
            dimensions.get("connector_implementations"),
            "performance connector implementations",
        )
        implementations = tuple(
            _parse_connector_implementation(item) for item in implementations_raw
        )
        snapshot = cls(
            schema=str(data["schema"]),
            measurement_mode=MeasurementMode(str(data["measurement_mode"])),
            case_id=PerformanceCase(str(data["case_id"])),
            platform=_bounded_runtime_value(runtime.get("platform")),
            runtime_backend=_bounded_runtime_value(runtime.get("backend")),
            master_agent_version=_bounded_version(runtime.get("master_agent_version")),
            commit_identity=_bounded_commit(runtime.get("commit_identity")),
            capabilities=_parse_bounded_strings(
                dimensions.get("capabilities"),
                mapper=bounded_capability,
                name="performance capabilities",
            ),
            risk_tiers=_parse_bounded_strings(
                dimensions.get("risk_tiers"),
                mapper=bounded_risk,
                name="performance risk tiers",
            ),
            systems=_parse_bounded_strings(
                dimensions.get("systems"),
                mapper=bounded_system,
                name="performance systems",
            ),
            connector_implementations=implementations,
            stages=stages,
            counters=counters,
            transport_calls_by_phase=phases,
            retries_by_reason=retries,
            outcomes=outcomes,
            provider_activity=provider_activity,
        )
        if data["baseline_eligible"] is not snapshot.baseline_eligible:
            raise ValueError("performance baseline eligibility is inconsistent")
        if data["summary"] != snapshot.summary():
            raise ValueError("performance summary is inconsistent")
        return snapshot


@dataclass(slots=True)
class _StageAccumulator:
    wall_seconds: float = 0.0
    cpu_seconds: float = 0.0
    occurrences: int = 0


@dataclass(frozen=True, slots=True)
class _TransportContext:
    phase: TransportPhase
    system: str


WallClock = Callable[[], float]
CpuClock = Callable[[], float]


class PerformanceRecorder:
    """Mutable run-local recorder that emits immutable bounded snapshots.

    Parameters
    ----------
    measurement_mode
        Fixed evidence source classification.
    case_id
        Fixed runtime or benchmark case.
    wall_clock, cpu_clock
        Injectable monotonic clocks. Neither clock may return a wall timestamp.
    commit_identity
        Optional exact Git object ID. Invalid values map to ``unbound``.
    """

    def __init__(
        self,
        *,
        measurement_mode: MeasurementMode = MeasurementMode.LOCAL_RUNTIME,
        case_id: PerformanceCase = PerformanceCase.RUNTIME,
        wall_clock: WallClock = time.perf_counter,
        cpu_clock: CpuClock = time.process_time,
        commit_identity: str = _UNBOUND,
    ) -> None:
        if not isinstance(measurement_mode, MeasurementMode):
            raise TypeError("performance measurement mode must be fixed")
        if not isinstance(case_id, PerformanceCase):
            raise TypeError("performance case must be fixed")
        self._measurement_mode = measurement_mode
        self._case_id = case_id
        self._wall_clock = wall_clock
        self._cpu_clock = cpu_clock
        self._commit_identity = _bounded_commit(commit_identity)
        self._platform, self._runtime_backend = _runtime_identity()
        self._master_agent_version = _installed_version()
        self._stages = {stage: _StageAccumulator() for stage in PerformanceStage}
        self._counters = {counter: 0 for counter in PerformanceCounter}
        self._transport_calls = {phase: 0 for phase in TransportPhase}
        self._retries = {reason: 0 for reason in RetryReason}
        self._outcomes = {outcome: 0 for outcome in PerformanceOutcome}
        self._provider_activity = {
            system: {activity: 0 for activity in ProviderActivity}
            for system in _KNOWN_SYSTEMS
        }
        self._capabilities: set[str] = set()
        self._risks: set[str] = set()
        self._systems: set[str] = set()
        self._implementations: set[str] = set()
        self._credential_resolution_systems: set[str] = set()
        self._total_started: tuple[float, float] | None = None
        self._sealed = False

    @property
    def case_id(self) -> PerformanceCase:
        """Return the fixed case selected for this recorder."""

        return self._case_id

    def set_case(self, case_id: PerformanceCase) -> None:
        """Select one fixed case before evidence is emitted."""

        self._ensure_mutable()
        if not isinstance(case_id, PerformanceCase):
            raise TypeError("performance case must be fixed")
        self._case_id = case_id

    @contextmanager
    def span(self, stage: PerformanceStage) -> Iterator[None]:
        """Accumulate one fixed monotonic stage, including exceptional exits."""

        if not isinstance(stage, PerformanceStage):
            raise TypeError("performance stage must be fixed")
        self._ensure_mutable()
        wall_started = _clock_value(self._wall_clock, "wall")
        cpu_started = _clock_value(self._cpu_clock, "CPU")
        try:
            yield
        finally:
            self._ensure_mutable()
            wall_finished = _clock_value(self._wall_clock, "wall")
            cpu_finished = _clock_value(self._cpu_clock, "CPU")
            wall_elapsed = wall_finished - wall_started
            cpu_elapsed = cpu_finished - cpu_started
            if wall_elapsed < 0 or cpu_elapsed < 0:
                raise RuntimeError("performance clocks must be monotonic")
            accumulator = self._stages[stage]
            accumulator.wall_seconds += wall_elapsed
            accumulator.cpu_seconds += cpu_elapsed
            accumulator.occurrences = _bounded_add(accumulator.occurrences, 1)

    def begin_total(self) -> None:
        """Start the one end-to-end run interval."""

        if self._sealed:
            raise RuntimeError("performance recorder cannot be reused for another run")
        self._ensure_mutable()
        if self._total_started is not None:
            raise RuntimeError("performance total interval is already active")
        if self._stages[PerformanceStage.END_TO_END_TOTAL].occurrences:
            raise RuntimeError("performance recorder cannot be reused for another run")
        self._total_started = (
            _clock_value(self._wall_clock, "wall"),
            _clock_value(self._cpu_clock, "CPU"),
        )

    def end_total(self) -> None:
        """Finish the active end-to-end interval exactly once."""

        started = self._total_started
        if started is None:
            raise RuntimeError("performance total interval is not active")
        wall_finished = _clock_value(self._wall_clock, "wall")
        cpu_finished = _clock_value(self._cpu_clock, "CPU")
        wall_elapsed = wall_finished - started[0]
        cpu_elapsed = cpu_finished - started[1]
        if wall_elapsed < 0 or cpu_elapsed < 0:
            raise RuntimeError("performance clocks must be monotonic")
        accumulator = self._stages[PerformanceStage.END_TO_END_TOTAL]
        accumulator.wall_seconds += wall_elapsed
        accumulator.cpu_seconds += cpu_elapsed
        accumulator.occurrences = _bounded_add(accumulator.occurrences, 1)
        self._total_started = None
        self._sealed = True

    @property
    def total_active(self) -> bool:
        """Return whether the end-to-end interval is still accumulating."""

        return self._total_started is not None

    def finish_total(self) -> None:
        """Finish the total interval when this boundary owns finalization."""

        if self._total_started is not None:
            self.end_total()

    def record_dimensions(
        self,
        *,
        capabilities: Iterable[object] = (),
        risk_tiers: Iterable[object] = (),
        systems: Iterable[object] = (),
    ) -> None:
        """Record only bounded plan-selection dimensions."""

        self._ensure_mutable()
        self._capabilities.update(bounded_capability(value) for value in capabilities)
        self._risks.update(bounded_risk(value) for value in risk_tiers)
        self._systems.update(bounded_system(value) for value in systems)

    def record_connector_implementation(self, system: object) -> None:
        """Record only the explicit unbound issue #170 placeholder."""

        self._ensure_mutable()
        selected = bounded_system(system)
        self._systems.add(selected)
        self._implementations.add(selected)

    def record_connector_initialization(self, system: object) -> None:
        """Count one successfully initialized connector for a bounded system."""

        self._ensure_mutable()
        selected = bounded_system(system)
        self.record_connector_implementation(selected)
        self.increment(PerformanceCounter.CONNECTOR_INITIALIZATIONS)
        self._increment_provider(selected, ProviderActivity.CONNECTOR_INITIALIZATIONS)

    def record_credential_resolution(self, system: object) -> None:
        """Count one selected provider credential-resolution attempt."""

        self._ensure_mutable()
        selected = bounded_system(system)
        self._systems.add(selected)
        if selected in self._credential_resolution_systems:
            return
        self._credential_resolution_systems.add(selected)
        self.increment(PerformanceCounter.CREDENTIAL_RESOLUTIONS)
        self._increment_provider(selected, ProviderActivity.CREDENTIAL_RESOLUTIONS)

    def record_principal_attestation(self, system: object) -> None:
        """Count one selected provider principal-attestation call."""

        self._ensure_mutable()
        selected = bounded_system(system)
        self._systems.add(selected)
        self.increment(PerformanceCounter.PRINCIPAL_ATTESTATIONS)
        self._increment_provider(selected, ProviderActivity.PRINCIPAL_ATTESTATIONS)

    def record_verification_call(self, system: object) -> None:
        """Count one independent connector verification call."""

        self._ensure_mutable()
        selected = bounded_system(system)
        self._systems.add(selected)
        self.increment(PerformanceCounter.VERIFICATION_CALLS)
        self._increment_provider(selected, ProviderActivity.VERIFICATION_CALLS)

    def record_transport_attempt(self, context: _TransportContext) -> None:
        """Count an observable network attempt immediately before dispatch."""

        self._ensure_mutable()
        if not isinstance(context.phase, TransportPhase):
            raise TypeError("performance transport phase must be fixed")
        self._transport_calls[context.phase] = _bounded_add(
            self._transport_calls[context.phase], 1
        )
        if context.phase is TransportPhase.PRINCIPAL_ATTESTATION:
            return
        self.increment(PerformanceCounter.PROVIDER_TRANSPORT_CALLS)
        self._increment_provider(
            context.system, ProviderActivity.PROVIDER_TRANSPORT_CALLS
        )

    def record_retry(self, reason: RetryReason) -> None:
        """Count one retry after an initial attempt using a bounded reason."""

        self._ensure_mutable()
        if not isinstance(reason, RetryReason):
            raise TypeError("performance retry reason must be fixed")
        self.increment(PerformanceCounter.RETRIES)
        self._retries[reason] = _bounded_add(self._retries[reason], 1)

    def record_outcome(self, outcome: PerformanceOutcome, amount: int = 1) -> None:
        """Count one fixed terminal or controlled observation."""

        self._ensure_mutable()
        if not isinstance(outcome, PerformanceOutcome):
            raise TypeError("performance outcome must be fixed")
        self._outcomes[outcome] = _bounded_add(self._outcomes[outcome], amount)

    def increment(self, counter: PerformanceCounter, amount: int = 1) -> None:
        """Increment one fixed counter by a bounded non-negative amount."""

        self._ensure_mutable()
        if not isinstance(counter, PerformanceCounter):
            raise TypeError("performance counter must be fixed")
        self._counters[counter] = _bounded_add(self._counters[counter], amount)

    def snapshot(self) -> PerformanceSnapshot:
        """Freeze the current deterministic run evidence."""

        active_total_wall = 0.0
        active_total_cpu = 0.0
        active_total_occurrences = 0
        if self._total_started is not None:
            active_total_wall = (
                _clock_value(self._wall_clock, "wall") - self._total_started[0]
            )
            active_total_cpu = (
                _clock_value(self._cpu_clock, "CPU") - self._total_started[1]
            )
            if active_total_wall < 0 or active_total_cpu < 0:
                raise RuntimeError("performance clocks must be monotonic")
            active_total_occurrences = 1
        counters = dict(self._counters)
        counters[PerformanceCounter.SELECTED_SYSTEMS] = len(self._systems)
        counters[PerformanceCounter.SELECTED_CONNECTOR_IMPLEMENTATIONS] = len(
            self._implementations
        )
        implementations = tuple(
            ConnectorImplementationDimension(system=system)
            for system in sorted(self._implementations)
        )
        return PerformanceSnapshot(
            measurement_mode=self._measurement_mode,
            case_id=self._case_id,
            platform=self._platform,
            runtime_backend=self._runtime_backend,
            master_agent_version=self._master_agent_version,
            commit_identity=self._commit_identity,
            capabilities=tuple(sorted(self._capabilities)),
            risk_tiers=tuple(sorted(self._risks)),
            systems=tuple(sorted(self._systems)),
            connector_implementations=implementations,
            stages=tuple(
                StageMeasurement(
                    stage=stage,
                    wall_seconds=(
                        self._stages[stage].wall_seconds
                        + (
                            active_total_wall
                            if stage is PerformanceStage.END_TO_END_TOTAL
                            else 0.0
                        )
                    ),
                    cpu_seconds=(
                        self._stages[stage].cpu_seconds
                        + (
                            active_total_cpu
                            if stage is PerformanceStage.END_TO_END_TOTAL
                            else 0.0
                        )
                    ),
                    occurrences=(
                        self._stages[stage].occurrences
                        + (
                            active_total_occurrences
                            if stage is PerformanceStage.END_TO_END_TOTAL
                            else 0
                        )
                    ),
                )
                for stage in PerformanceStage
            ),
            counters=counters,
            transport_calls_by_phase=dict(self._transport_calls),
            retries_by_reason=dict(self._retries),
            outcomes=dict(self._outcomes),
            provider_activity={
                system: dict(self._provider_activity[system])
                for system in _KNOWN_SYSTEMS
            },
        )

    def _increment_provider(
        self,
        system: object,
        activity: ProviderActivity,
        amount: int = 1,
    ) -> None:
        self._ensure_mutable()
        selected = bounded_system(system)
        self._systems.add(selected)
        self._provider_activity[selected][activity] = _bounded_add(
            self._provider_activity[selected][activity], amount
        )

    def _ensure_mutable(self) -> None:
        """Reject writes after the one end-to-end interval is finalized."""

        if self._sealed:
            raise RuntimeError("performance recorder is finalized")


class DeterministicClock:
    """Manually advanced monotonic wall and CPU clocks for stable benchmarks."""

    def __init__(self) -> None:
        self._wall = 0.0
        self._cpu = 0.0

    def wall(self) -> float:
        """Return the current deterministic wall value."""

        return self._wall

    def cpu(self) -> float:
        """Return the current deterministic CPU value."""

        return self._cpu

    def advance(self, *, wall_seconds: float, cpu_seconds: float) -> None:
        """Advance both monotonic clocks by finite non-negative durations."""

        for value, name in (
            (wall_seconds, "wall"),
            (cpu_seconds, "CPU"),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"deterministic {name} duration must be numeric")
            if not math.isfinite(float(value)) or value < 0:
                raise ValueError(f"deterministic {name} duration is invalid")
        self._wall += float(wall_seconds)
        self._cpu += float(cpu_seconds)


_CURRENT_RECORDER: ContextVar[PerformanceRecorder | None] = ContextVar(
    "master_agent_performance_recorder", default=None
)
_CURRENT_TRANSPORT: ContextVar[_TransportContext | None] = ContextVar(
    "master_agent_performance_transport",
    default=None,
)
_ERROR_SNAPSHOT_ATTRIBUTE = "_master_agent_performance_snapshot"


def current_performance_recorder() -> PerformanceRecorder | None:
    """Return the active run-local recorder, if any."""

    return _CURRENT_RECORDER.get()


def performance_snapshot_from_error(
    error: BaseException,
) -> PerformanceSnapshot | None:
    """Return content-free run evidence attached at an exceptional boundary."""

    try:
        snapshot = getattr(error, _ERROR_SNAPSHOT_ATTRIBUTE, None)
    except (AttributeError, TypeError):  # pragma: no cover - hostile exception.
        return None
    return snapshot if isinstance(snapshot, PerformanceSnapshot) else None


def _attach_performance_snapshot(
    error: BaseException,
    snapshot: PerformanceSnapshot,
) -> bool:
    """Attach bounded evidence when an exception instance accepts attributes."""

    try:
        setattr(error, _ERROR_SNAPSHOT_ATTRIBUTE, snapshot)
    except (AttributeError, TypeError):  # pragma: no cover - hostile exception.
        return False
    return True


def performance_entrypoint[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    """Wrap one synchronous entrypoint in a fresh or enclosing active recorder."""

    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        with ensure_performance_run():
            return function(*args, **kwargs)

    return wrapped


def performance_stage_call[**P, R](
    stage: PerformanceStage,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorate one synchronous function with a fixed optional stage."""

    if not isinstance(stage, PerformanceStage):
        raise TypeError("performance stage must be fixed")

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        @wraps(function)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            with performance_stage(stage):
                return function(*args, **kwargs)

        return wrapped

    return decorate


@contextmanager
def performance_run(
    *,
    measurement_mode: MeasurementMode = MeasurementMode.LOCAL_RUNTIME,
    case_id: PerformanceCase = PerformanceCase.RUNTIME,
    wall_clock: WallClock = time.perf_counter,
    cpu_clock: CpuClock = time.process_time,
    commit_identity: str = _UNBOUND,
) -> Iterator[PerformanceRecorder]:
    """Activate one fresh recorder and restore prior nested context on exit."""

    recorder = PerformanceRecorder(
        measurement_mode=measurement_mode,
        case_id=case_id,
        wall_clock=wall_clock,
        cpu_clock=cpu_clock,
        commit_identity=commit_identity,
    )
    recorder.begin_total()
    token = _CURRENT_RECORDER.set(recorder)
    transport_token = _CURRENT_TRANSPORT.set(
        _TransportContext(TransportPhase.EXECUTION, _OTHER)
    )
    try:
        yield recorder
    except Exception as error:
        if recorder.total_active:
            active_snapshot = recorder.snapshot()
            transport_calls = active_snapshot.counters[
                PerformanceCounter.PROVIDER_TRANSPORT_CALLS
            ]
            effect_free = bool(active_snapshot.risk_tiers) and set(
                active_snapshot.risk_tiers
            ).issubset({"read_only", "local_generation"})
            recorder.record_outcome(
                PerformanceOutcome.FAILED_PRE_EFFECT
                if transport_calls == 0 or effect_free
                else PerformanceOutcome.INDETERMINATE
            )
            recorder.finish_total()
        _attach_performance_snapshot(error, recorder.snapshot())
        raise
    finally:
        try:
            recorder.finish_total()
        finally:
            _CURRENT_TRANSPORT.reset(transport_token)
            _CURRENT_RECORDER.reset(token)


@contextmanager
def ensure_performance_run() -> Iterator[PerformanceRecorder]:
    """Reuse one active top-level run or create a fresh direct-runtime run."""

    recorder = current_performance_recorder()
    if recorder is not None and recorder.total_active:
        yield recorder
        return
    with performance_run() as fresh:
        yield fresh


@contextmanager
def performance_stage(stage: PerformanceStage) -> Iterator[None]:
    """Record a fixed stage only when a run-local recorder is active."""

    recorder = current_performance_recorder()
    if recorder is None:
        yield
        return
    with recorder.span(stage):
        yield


@contextmanager
def performance_transport_phase(
    phase: TransportPhase,
    system: object,
) -> Iterator[None]:
    """Activate one fixed transport phase and bounded provider system."""

    if not isinstance(phase, TransportPhase):
        raise TypeError("performance transport phase must be fixed")
    token = _CURRENT_TRANSPORT.set(
        _TransportContext(phase=phase, system=bounded_system(system))
    )
    try:
        yield
    finally:
        _CURRENT_TRANSPORT.reset(token)


def record_transport_attempt() -> None:
    """Count one attempt before dispatch when performance evidence is active."""

    recorder = current_performance_recorder()
    if recorder is not None:
        recorder.record_transport_attempt(
            _CURRENT_TRANSPORT.get()
            or _TransportContext(TransportPhase.EXECUTION, _OTHER)
        )


@contextmanager
def observable_network_wait() -> Iterator[None]:
    """Measure observable network wait under the active fixed phase."""

    recorder = current_performance_recorder()
    if recorder is None:
        yield
        return
    context = _CURRENT_TRANSPORT.get()
    phase = context.phase if context is not None else TransportPhase.EXECUTION
    stage = (
        PerformanceStage.VERIFICATION_NETWORK
        if phase in {TransportPhase.VERIFICATION, TransportPhase.RECONCILIATION}
        else PerformanceStage.PROVIDER_NETWORK
    )
    with recorder.span(stage):
        yield


def record_retry_status(status: int) -> None:
    """Map a retryable HTTP status to one bounded retry reason."""

    reason_by_status = {
        429: RetryReason.HTTP_429,
        502: RetryReason.HTTP_502,
        503: RetryReason.HTTP_503,
        504: RetryReason.HTTP_504,
    }
    reason = reason_by_status.get(status)
    if reason is None:
        raise ValueError("retry status is not in the bounded retry vocabulary")
    recorder = current_performance_recorder()
    if recorder is not None:
        recorder.record_retry(reason)


def bounded_system(value: object) -> str:
    """Map arbitrary system input to one fixed identifier or ``other``."""

    rendered = str(value) if isinstance(value, (str, StrEnum)) else ""
    return rendered if rendered in _KNOWN_SYSTEM_SET else _OTHER


def bounded_capability(value: object) -> str:
    """Map arbitrary capability input to one shipped identifier or ``other``."""

    rendered = str(value) if isinstance(value, (str, StrEnum)) else ""
    return rendered if rendered in _KNOWN_CAPABILITIES else _OTHER


def bounded_risk(value: object) -> str:
    """Map arbitrary risk input to one fixed risk tier or ``other``."""

    rendered = str(value) if isinstance(value, (str, StrEnum)) else ""
    return rendered if rendered in _KNOWN_RISKS else _OTHER


def percentile(values: Iterable[float], percentile_value: int) -> float:
    """Return a deterministic nearest-rank percentile.

    Parameters
    ----------
    values
        Finite non-negative observations.
    percentile_value
        Integer percentile in the inclusive range 1 through 100.
    """

    if isinstance(percentile_value, bool) or not isinstance(percentile_value, int):
        raise TypeError("percentile must be an integer")
    if not 1 <= percentile_value <= 100:
        raise ValueError("percentile must be between 1 and 100")
    normalized = sorted(float(value) for value in values)
    if not normalized:
        raise ValueError("percentile requires at least one observation")
    if any(not math.isfinite(value) or value < 0 for value in normalized):
        raise ValueError("percentile observations must be finite and non-negative")
    index = max(0, math.ceil((percentile_value / 100) * len(normalized)) - 1)
    return _rounded(normalized[index])


def _runtime_identity() -> tuple[str, str]:
    if sys.platform == "darwin":
        return "macos", "posix-macos"
    if sys.platform in {"linux", "linux2"}:
        return "linux", "posix-linux"
    if sys.platform == "win32":
        return "windows", "windows-native-partial"
    return "unsupported", "unsupported"


def _installed_version() -> str:
    try:
        value = metadata.version("master-agent")
    except metadata.PackageNotFoundError:
        return _UNBOUND
    return _bounded_version(value)


def _bounded_runtime_value(value: object) -> str:
    rendered = str(value)
    allowed = {
        "macos",
        "linux",
        "windows",
        "unsupported",
        "posix-macos",
        "posix-linux",
        "windows-native-partial",
        "windows-unavailable",
    }
    if rendered not in allowed:
        raise ValueError("performance runtime identity is invalid")
    return rendered


def _bounded_version(value: object) -> str:
    rendered = str(value)
    return rendered if _VERSION_PATTERN.fullmatch(rendered) else _UNBOUND


def _bounded_commit(value: object) -> str:
    rendered = str(value).casefold()
    if rendered == _UNBOUND:
        return rendered
    if len(rendered) in {40, 64} and all(
        character in "0123456789abcdef" for character in rendered
    ):
        return rendered
    return _UNBOUND


def _clock_value(clock: Callable[[], float], name: str) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"performance {name} clock must return a number")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"performance {name} clock returned a non-finite value")
    return normalized


def _bounded_add(current: int, amount: int) -> int:
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise TypeError("performance count increments must be integers")
    if amount < 0 or current + amount > _MAX_COUNT:
        raise ValueError("performance count exceeds its bounded range")
    return current + amount


def _rounded(value: float) -> float:
    normalized = round(float(value), _ROUND_DIGITS)
    return 0.0 if normalized == 0 else normalized


def _freeze_enum_counts[E: StrEnum](
    values: Mapping[E, int], enum_type: type[E]
) -> Mapping[E, int]:
    expected = tuple(enum_type)
    if set(values) != set(expected):
        raise ValueError("performance count keys are incomplete")
    normalized: dict[E, int] = {}
    for key in expected:
        value = values[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("performance counts must be integers")
        if not 0 <= value <= _MAX_COUNT:
            raise ValueError("performance count is outside its bounded range")
        normalized[key] = value
    return MappingProxyType(normalized)


def _parse_enum_counts[E: StrEnum](
    value: object,
    enum_type: type[E],
    name: str,
) -> dict[E, int]:
    mapping = _require_mapping(value, name)
    expected = {str(item): item for item in enum_type}
    if set(mapping) != set(expected):
        raise ValueError(f"{name} keys are invalid")
    result: dict[E, int] = {}
    for rendered, item in expected.items():
        count = mapping[rendered]
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError(f"{name} values must be integers")
        if not 0 <= count <= _MAX_COUNT:
            raise ValueError(f"{name} values are outside the bounded range")
        result[item] = count
    return result


def _parse_stage(value: object) -> StageMeasurement:
    mapping = _require_mapping(value, "performance stage")
    if set(mapping) != {"stage", "wall_seconds", "cpu_seconds", "occurrences"}:
        raise ValueError("performance stage fields are invalid")
    wall = _finite_non_negative(mapping["wall_seconds"], "performance wall time")
    cpu = _finite_non_negative(mapping["cpu_seconds"], "performance CPU time")
    occurrences = mapping["occurrences"]
    if isinstance(occurrences, bool) or not isinstance(occurrences, int):
        raise TypeError("performance stage occurrences must be an integer")
    if not 0 <= occurrences <= _MAX_COUNT:
        raise ValueError("performance stage occurrences are out of range")
    return StageMeasurement(
        stage=PerformanceStage(str(mapping["stage"])),
        wall_seconds=wall,
        cpu_seconds=cpu,
        occurrences=occurrences,
    )


def _parse_connector_implementation(
    value: object,
) -> ConnectorImplementationDimension:
    mapping = _require_mapping(value, "performance connector implementation")
    if set(mapping) != {"system", "implementation", "bound"}:
        raise ValueError("performance connector implementation fields are invalid")
    bound = mapping["bound"]
    if not isinstance(bound, bool):
        raise TypeError("performance connector implementation bound must be boolean")
    return ConnectorImplementationDimension(
        system=bounded_system(mapping["system"]),
        implementation=str(mapping["implementation"]),
        bound=bound,
    )


def _parse_bounded_strings(
    value: object,
    *,
    mapper: Callable[[object], str],
    name: str,
) -> tuple[str, ...]:
    items = _require_list(value, name)
    normalized = tuple(mapper(item) for item in items)
    if normalized != tuple(sorted(set(normalized))):
        raise ValueError(f"{name} are not unique and ordered")
    return normalized


def _require_ordered_bounded_values(
    values: tuple[str, ...],
    *,
    mapper: Callable[[object], str],
    name: str,
) -> None:
    if not all(isinstance(item, str) for item in values):
        raise TypeError(f"{name} must contain strings")
    if tuple(mapper(item) for item in values) != values:
        raise ValueError(f"{name} contain unbounded values")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{name} are not unique and ordered")


def _require_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise TypeError(f"{name} keys must be strings")
    return value


def _require_list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{name} must be a list")
    return value


def _finite_non_negative(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return normalized
