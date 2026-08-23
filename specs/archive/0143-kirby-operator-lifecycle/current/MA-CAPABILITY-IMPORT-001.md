# MA-CAPABILITY-IMPORT-001 — Governed custom-agent capability import

## Status

Active

## Requirement

MasterAgent MUST accept only a bounded, versioned, declarative local export for
custom-agent capability inspection. It MUST capture the export as immutable
bytes, reject duplicate keys and unknown or malformed structures, preserve the
exact source digest and declared publisher, and MUST NOT execute source code,
prompts, hooks, plugins, shell commands, network calls, or recursive agents
during inspection.

The inspection result MUST classify each ability as already supported, safely
importable, conflicting, unsupported, or unsafe. It MUST report bounded
dependencies, constraints, proposed mappings, and actionable reasons. Duplicate
ability names or proposed mappings MUST fail closed. Existing catalog names
MUST NOT be shadowed.

The installed CLI MUST support read-only preview and explicit selection of
exactly one safely importable ability using the exact digest returned by
preview. Selection MUST re-read and reclassify the source before creating a
signed quarantined capsule whose policy identity binds that source digest and
publisher. Quarantine MUST NOT add the ability to planning, routing, the typed
catalog, credentials, policy, or execution.

The installed CLI MUST expose authenticated promotion, state inspection,
policy-first intent routing, governed execution, deprecation, and revocation
for the supported dependency-free pure capsule boundary. Capsule authorities
MUST use explicit environment-backed secrets and MUST have distinct keys and
subjects for generation, validation, sandbox validation, review, publication,
and revocation. Only the latest enabled exact manifest MAY become a routing
candidate, and execution MUST bind that manifest into a typed `ChangePlan` and
use the normal catalog, governance, policy, connector registry, audit log,
isolated worker, verification, and `WorkflowOrchestrator` path.

Imported authority, credentials, approvals, identity, trust, background access,
and recursion MUST NOT transfer. Updates MUST use a new immutable version and a
freshly previewed digest, then repeat the complete lifecycle without overwriting
prior history. Deprecation or revocation MUST remove the ability from future
routing without destructively deleting its audit history. Provider, side-effect,
dependent, raw-plugin, whole-agent, recursive-agent, and production capsules
without all live production controls MUST remain fail closed.

## Rationale

A foreign agent is an untrusted description of possible behavior, not an
authority source. One typed capability is the smallest unit that MasterAgent
can independently govern and later revoke without inheriting the source
agent's identity or execution environment. A shipped lifecycle is required so
the behavior is a usable product feature rather than an internal library seam.

## Scenarios

### Read-only preview does not activate foreign behavior

- GIVEN a valid custom-agent export containing source code and prompt-like text
- WHEN an operator inspects it
- THEN MasterAgent reports compatibility and exact source provenance without
  running the source or changing the capability catalog

### Explicit selection remains quarantined

- GIVEN a safely importable ability and its previewed source digest
- WHEN an operator selects that one ability through the installed CLI
- THEN MasterAgent creates only the signed quarantined capsule state
- AND planning and routing cannot advertise it before independent promotion

### Promotion makes the exact capability routable and governed

- GIVEN an exact quarantine and distinct trusted role authorities
- WHEN worker validation, sandbox validation, review, publication, and enablement succeed
- THEN policy-first routing may advertise only the latest enabled exact manifest
- AND execution uses the normal typed orchestrator and audit path

### Authority, source, worker, and policy drift fail closed

- GIVEN a changed source, reused authority identity, different worker, disabled
  manifest, or policy-prohibited route
- WHEN selection, promotion, routing, or execution is attempted
- THEN MasterAgent rejects the operation before foreign behavior executes

### Update and revocation preserve history

- GIVEN an enabled imported ability
- WHEN a new version is imported or the current version is deprecated or revoked
- THEN the new version repeats the exact-digest lifecycle
- AND terminal old versions stop routing without deleting immutable history

## Implementation

- `src/master_agent/capability_import.py`
- `src/master_agent/capsule_authorities.py`
- `src/master_agent/capsule_promotion.py`
- `src/master_agent/capsule_runtime.py`
- `src/master_agent/capability_routing.py`
- `src/master_agent/cli.py`
- `src/master_agent/config_sources.py`

## Verification

- `tests/test_capability_import.py`
- `tests/test_capability_capsules.py`
- `tests/test_capsule_broker_and_routing.py`

## History

- Introduced by GitHub issue #129.
- Completed as an installed operator workflow by GitHub issue #143.
