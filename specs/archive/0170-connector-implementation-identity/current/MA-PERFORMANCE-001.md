# MA-PERFORMANCE-001 — Bounded governance-performance evidence

## Status

Active

## Requirement

Every governed applied run and direct-read session MUST be able to produce one
immutable, deterministic, content-free performance snapshot using a versioned
schema and fixed stage, phase, counter, retry-reason, outcome, measurement-mode,
and case identifiers. A top-level invocation MUST activate a fresh recorder
before credential resolution, principal attestation, or connector construction;
direct runtime callers MUST receive a fresh recorder when none is active. The
context and phase MUST be restored on success and every exception, and a recorder
from a completed run MUST NOT accumulate data for a later run.

The recorder MUST use injectable monotonic wall and CPU clocks. It MUST time
request parsing and routing; capability, risk, system, and implementation
selection; governance, catalog, source-of-truth, egress, and policy validation;
approval preparation and resumption; credential resolution; principal
attestation; connector initialization; provider execution and observable network
wait; independent verification and observable verification network wait;
idempotency and reconciliation; compensation; audit and retention; sanitization;
rendering; and end-to-end total. Stable summaries MUST distinguish total, local
governance, connector initialization, credential resolution, provider execution,
verification, audit/retention, rendering, and observable provider/network time,
and MUST calculate local-governance percentage.

The snapshot MUST count selected systems, selected connector implementations,
connector initialization, credential resolution, provider-principal attestation,
transport attempts, verification calls, retries by bounded reason, model or
advisory calls, governance-induced user interactions, approval interactions, and
fixed terminal outcomes. The initial transport attempt MUST NOT be a retry, and
every transport attempt MUST be counted immediately before dispatch so failed
attempts remain visible. Execution, verification, principal attestation,
reconciliation, and compensation phases MUST remain independently attributable.

The serializer MUST NOT contain prompts, goals, request or response bodies,
resource identifiers, recipients, URLs, headers, credential names or values,
environment values, paths, usernames, exception text, confidential content, or
wall-clock timestamps. It MUST reject or map arbitrary identifiers to fixed
buckets, use bounded dimensions and deterministic ordering, and serialize only
JSON-compatible scalar or fixed aggregate values.

Every selected live connector implementation MUST be sourced from the exact
configuration-owned connector execution binding and represented as `native`
with `bound = true`. The recorder MUST NOT infer implementation identity from a
connector class, action parameter, prompt, provider result, or arbitrary label.
One provider configuration MUST count as one selected and initialized
implementation even when its native implementation exposes several
capability-specific connector objects.

The deterministic benchmark MUST cover isolated read, reversible write,
consequential communication/write, destructive or high-risk denial, controlled
false-success, controlled duplicate-effect, and the exact `T1-EWIR-001` workflow.
It MUST use injectable clocks, stable iteration ordering, deterministic p50/p95
calculation, and CI-checkable budgets. Deterministic evidence MUST be marked
baseline-ineligible and MUST NOT be described as a live-provider, Windows, or
managed-workstation measurement.

For `T1-EWIR-001`, the deterministic benchmark MUST select Jira, Bitbucket, and
Confluence; record exactly three connector initializations and three explicit
bound `native` implementations; record zero governance-induced and approval
interactions; keep provider content calls below 20 excluding principal
attestation; keep provisional p50 at or below 30 seconds and p95 at or below 60
seconds; and keep local governance overhead below five percent. Tests MUST prove
unselected systems have zero provider-specific credential resolution,
construction, principal attestation, transport, and verification work. Copying
an environment mapping is not itself a provider-specific access and MUST NOT be
misreported as touching every provider.

## Rationale

Fixed content-free evidence makes governance cost and selected-provider work
measurable without weakening the runtime or creating a new sensitive telemetry
channel. Deterministic CI evidence catches local regressions, while real network
and managed-workstation claims remain reserved for the bounded pilot.

## Scenarios

### A selected provider run is attributable

- GIVEN one governed run selects a bounded capability and system
- WHEN credential, connector, provider, verification, audit, and rendering work occurs
- THEN one report snapshot distinguishes those stages, counts, phases, and outcome

### A failed transport remains counted

- GIVEN a provider transport raises before returning a response
- WHEN the runtime classifies the failure
- THEN the transport attempt was already counted and no exception text is serialized

### An unselected provider stays inactive

- GIVEN a run selects Jira but not GitHub
- WHEN setup and execution complete
- THEN GitHub has zero credential, initialization, attestation, transport, and verification observations

### Nested or exceptional execution restores context

- GIVEN a recorder is active and a nested phase or run raises
- WHEN control leaves that boundary
- THEN the prior context and phase are restored without leaking metrics to the next run

### Deterministic Tier-1 evidence is honest

- GIVEN the fixed `T1-EWIR-001` harness runs repeatedly
- WHEN it emits p50/p95 and budget results
- THEN every iteration and aggregate are byte-stable and baseline-ineligible

### Arbitrary metadata cannot become telemetry

- GIVEN a caller supplies a malicious or content-bearing identifier
- WHEN the recorder maps or serializes the dimension
- THEN only a fixed enum or `other` bucket appears and the original text is absent

## Implementation

- `src/master_agent/performance.py`
- `src/master_agent/cli.py`
- `src/master_agent/execution_context.py`
- `src/master_agent/connectors/factory.py`
- `src/master_agent/registry.py`
- `src/master_agent/http.py`
- `src/master_agent/orchestrator.py`
- `src/master_agent/direct_read.py`
- `scripts/benchmark_governance.py`

## Verification

- `tests/test_performance.py`
- `tests/test_orchestrator.py`
- `tests/test_direct_read.py`
- `tests/test_http.py`
- `tests/test_http_lifecycle_budget.py`
- `tests/test_execution_context.py`
- `tests/test_credentials.py`
- `tests/test_connector_contract_matrix.py`
- `tests/test_semantic_router.py`

## History

- Introduced by GitHub issue #164.
- Strengthened with exact native connector implementation identity by GitHub issue #170.
