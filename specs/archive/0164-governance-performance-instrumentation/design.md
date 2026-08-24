# Design

## Approach

Add `master_agent.performance` as a dependency-free recorder with fixed enums
for measurement mode, case, stage, transport phase, counter, retry reason, and
outcome. The recorder accepts injectable monotonic wall and CPU clocks, uses a
context variable only for the current run and phase, and serializes in enum
order. Unknown system and capability identifiers map to fixed `other` buckets.

Top-level CLI execution activates one fresh recorder before plan, credential,
or connector work. Direct orchestrator/session callers receive a fresh recorder
when no CLI recorder is active. Runtime reports receive immutable snapshots.
The HTTP client records an attempt immediately before transport dispatch and
attributes observable wait to the current fixed phase. Orchestration surrounds
execution, verification, reconciliation, and compensation with phase tags.

Connector implementation evidence uses only
`id = "unbound_pending_170", bound = false` until issue #170 introduces a
trusted configuration-owned identity. The benchmark uses deterministic clocks
and fixed workloads; its output is always `baseline_eligible = false`.

## Affected components

- New runtime schema: `src/master_agent/performance.py`.
- Runtime integration: CLI, execution context, connector factory/registry, HTTP,
  orchestrator, and direct-read modules.
- New deterministic harness: `scripts/benchmark_governance.py`.
- New performance tests plus focused existing lifecycle tests.
- New current requirement, benchmark documentation, and semantic-router entries.

## Data flow

1. A top-level run creates one recorder and activates it context-locally.
2. Plan selection records only bounded capability, risk, system, platform, and
   placeholder implementation dimensions.
3. Fixed spans accumulate local wall and CPU time.
4. HTTP attempts increment counters before dispatch and accumulate observable
   network wait under a fixed execution phase.
5. Terminal action states map to fixed outcomes.
6. The recorder emits one deterministic immutable snapshot attached to the
   report; no content-bearing input is retained.
7. The benchmark aggregates identical-schema snapshots into stable p50/p95
   summaries and budget results.

For CLI calls, report payload and terminal-line preparation are measured as
rendering before the end-to-end interval is sealed. Operational audit,
idempotency, and approval-artifact writes are measured as audit/retention.
Emitting the final performance-bearing result file and its retention sidecar is
excluded because the write cannot contain a snapshot that also measures that
same write without self-reference. API-only callers return typed objects and
therefore do not claim a render-stage occurrence.

## Compatibility

Existing report fields and behavior remain unchanged; the new `performance`
field is optional when reading historical governed reports. Direct-read reports
retain their existing schema and add the same optional field. No provider
capability, approval rule, persistence default, or connector contract is
widened.

## Security

The recorder has no arbitrary tag API. Stage, phase, retry, mode, and outcome
values are enums. Systems and capabilities pass through fixed bounded mappers.
It records no wall-clock timestamp and never accepts provider bodies, goals,
targets, resource IDs, URLs, headers, credential names/values, paths, usernames,
environment values, or exception text. Context reset occurs in `finally` blocks.

## Rejected alternatives

- OpenTelemetry or another tracing dependency: unnecessary service and schema
  surface for the required local evidence.
- Free-form span names or dictionaries: unbounded and content-bearing.
- Reconstructing timings from audit logs: misses pre-orchestrator setup and
  conflates evidence persistence with measurement.
- Naming #164 connector identities `native`: that would preempt #170 without a
  trusted binding or drift validation.
