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

Import MUST require the explicit selection of exactly one safely importable
ability and the exact digest returned by inspection. Selection MUST re-read and
reclassify the source before creating a signed quarantined capsule whose policy
identity binds that source digest and publisher. Quarantine MUST NOT add the
ability to planning, routing, the typed catalog, credentials, policy, or
execution.

Imported functionality MAY become routable only after the existing independent
test, sandbox-validation, review, signing, publication, enablement, catalog,
governance, policy, approval, and execution gates succeed. Capsule promotion
MUST accept only a canonical `EnvironmentKind`, require the signed quarantine
environment to equal the promotion service environment, and derive production
readiness from that immutable environment. Before the TESTED transition,
promotion MUST require one exact worker identity across the signed quarantine,
promotion worker, validator, validation evidence, and sandbox evidence. Unknown
environments or any identity mismatch MUST fail without appending a promoted
lifecycle state.

The worker identity MUST bind the selected native isolation backend and the
exact security-relevant isolation adapter, process boundary, runtime,
interpreter, and restricted worker digests. Validation and sandbox evidence
MUST expose the same bounded component identity, and activation MUST recompute
it so any component drift fails before capsule code runs.

Imported authority, credentials, approvals, identity, trust, background access,
and recursion MUST NOT transfer. Updates MUST use a new immutable version and
freshly previewed digest. Deprecation or revocation MUST remove the ability from
future routing without destructively deleting its audit history.

## Rationale

A foreign agent is an untrusted description of possible behavior, not an
authority source. One typed capability is the smallest unit that MasterAgent
can independently govern and later revoke without inheriting the source agent's
identity or execution environment. Environment and worker bindings ensure that
the readiness and sandbox evidence reviewed during promotion describe the exact
execution boundary later authorized by the enabled manifest.

## Scenarios

### Read-only preview does not activate foreign behavior

- GIVEN a valid custom-agent export containing source code and prompt-like text
- WHEN an operator inspects it
- THEN MasterAgent reports compatibility and exact source provenance without
  running the source or changing the capability catalog

### Explicit import remains quarantined

- GIVEN a safely importable ability and its previewed source digest
- WHEN a developer selects that one ability for import
- THEN MasterAgent creates only the signed quarantined capsule state
- AND planning and routing cannot advertise it before independent promotion

### Promotion identity drift fails closed

- GIVEN a signed quarantine whose environment or worker differs from the
  promotion service, validator, validation evidence, or sandbox evidence
- WHEN independent promotion is attempted
- THEN MasterAgent rejects the attempt before appending a promoted state
- AND a production-labeled quarantine cannot bypass production readiness

### Authority and drift fail closed

- GIVEN an import that requests credentials, approval, identity, hooks, shell,
  network access, recursion, or source bytes that differ from the preview
- WHEN inspection or selection occurs
- THEN MasterAgent rejects selection with an actionable bounded reason
- AND no imported code, provider, credential, or effect path runs

### Revocation removes routing without erasing history

- GIVEN an imported ability that completed promotion
- WHEN its publisher deprecates it or an authorized revoker removes it
- THEN the capsule is no longer resolvable for activation or routing
- AND its immutable promotion history remains available for audit

## Implementation

- `src/master_agent/capability_import.py`
- `src/master_agent/capsule_promotion.py`
- `src/master_agent/capsule_runtime.py`
- `src/master_agent/cli.py`
- `src/master_agent/config_sources.py`

## Verification

- `tests/test_capability_import.py`
- `tests/test_capability_capsules.py`

## History

- Introduced by GitHub issue #129.
- Bound promotion environment and worker identity in GitHub issue #132.
- Bound native isolation components in GitHub issue #104.
