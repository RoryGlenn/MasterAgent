# Governance-performance evidence

MasterAgent emits bounded performance evidence so maintainers can distinguish
local governance cost from credential setup, connector construction, provider
work, verification, audit, sanitization, and rendering. The evidence is
diagnostic data only. It cannot approve an action, select a connector, widen a
capability, or establish that a workflow is certified.

## Evidence contract

`master-agent/performance@1` contains one ordered row for every fixed lifecycle
stage, monotonic wall and CPU durations, fixed counters and outcomes, transport
attempts split by execution phase, and provider-specific activity for a bounded
system vocabulary. `RunReport` and `DirectReadReport` include the snapshot as an
optional `performance` field so historical reports remain readable.

The end-to-end interval begins at the CLI entrypoint and ends after connector
resource cleanup and preparation of the report payload and terminal lines.
API-only callers do not claim a render stage because they return typed objects.
`audit_retention` covers operational audit, idempotency, and approval-artifact
writes. The final write of a performance-bearing result file and its retention
sidecar is outside the interval: including that write in the snapshot stored by
the same write would be self-referential. This exclusion is a schema boundary,
not an unmeasured claim that final evidence emission has no cost.

The recorder deliberately has no generic span, event, label, or tag API. It
does not retain prompts, goals, provider bodies, resource identifiers,
recipients, URLs, headers, credential names or values, environment values,
paths, usernames, exception text, confidential content, or wall-clock
timestamps. Unknown capability, risk, and system dimensions become the fixed
`other` value. Invalid version or commit identities become `unbound`.

Every provider transport attempt is counted immediately before dispatch. The
initial attempt is not a retry. Execution, verification, principal attestation,
reconciliation, and compensation remain separate phases, and principal
attestation is excluded from the provider-content-call total.

Connector implementation identity remains deliberately unresolved in this
change. Every selected implementation is serialized as:

```json
{"bound":false,"implementation":"unbound_pending_170","system":"jira"}
```

Issue #170 owns the trusted configuration binding needed to replace that
placeholder. Do not rename it to `native` or infer an implementation from a
connector class.

## Deterministic regression benchmark

Run the default Tier-1 Engineering Work Item Review case:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/benchmark_governance.py \
  --iterations 20 \
  --output /tmp/master-agent-performance.json
```

Select another representative case with `--case-id`; the accepted values are
`isolated_read`, `reversible_write`, `consequential_communication`,
`high_risk_denial`, `controlled_false_success`, and
`controlled_duplicate_effect`. For example:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/benchmark_governance.py \
  --iterations 20 \
  --case-id isolated_read \
  --output /tmp/isolated-read.json
```

The harness uses injected deterministic clocks and fixed work definitions. Its
output is byte-stable for the same arguments and commit identity and is always
`baseline_eligible = false`. It is useful for schema, attribution, privacy,
selection, counter, percentile, and budget regression checks. It is not a
measurement of live providers, Windows, corporate networking, or a managed
workstation.

The provisional `T1-EWIR-001` gates are:

- 20 iterations in stable order;
- p50 end-to-end time at most 30 seconds and p95 at most 60 seconds;
- p95 local-governance overhead below 5 percent;
- exactly three selected connector implementations, initializations,
  credential resolutions, and principal attestations for Jira, Bitbucket, and
  Confluence;
- fewer than 20 provider-content transport calls, excluding principal
  attestation;
- zero governance-induced and approval interactions; and
- zero provider-specific work for every unselected system.

The representative cases also include isolated read, reversible write,
consequential communication, high-risk denial, controlled false-success, and
controlled duplicate-effect outcomes.

## Reading results

Use `summary` for total and major-stage wall time. Use `stages` when a summary
moves, `transport_calls_by_phase` to distinguish execution from verification or
recovery traffic, and `provider_activity` to prove that unselected providers
remained inactive. A budget failure is a regression signal, not permission to
skip governance or verification.

Only managed-workstation evidence collected under the #172 pilot may use
`measurement_mode = managed_runtime` and become baseline-eligible. Local
runtime snapshots and deterministic benchmark output must stay
baseline-ineligible and must not be compared as if they came from the same
environment.

## Maintainer validation

Before changing the schema or instrumentation boundaries, run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_performance \
  tests.test_orchestrator \
  tests.test_direct_read \
  tests.test_http \
  tests.test_http_lifecycle_budget \
  tests.test_execution_context \
  tests.test_credentials \
  tests.test_connector_contract_matrix
python3 scripts/specs.py validate
python3 scripts/semantic_router.py validate
```

Treat serialized evidence as untrusted input. `PerformanceSnapshot.from_dict`
recomputes derived fields and rejects incomplete counters, reordered stages,
unknown fields, or forged baseline eligibility.
