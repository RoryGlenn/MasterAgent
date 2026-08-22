# Design

## Approach

Parse the promotion service environment through `EnvironmentKind`, retain its
canonical value, and compare every imported quarantine before validation. Bind
the service to one captured worker digest, expose the validator's worker digest,
and verify both validation evidence mappings before appending TESTED.

## Affected components

- `src/master_agent/capsule_promotion.py`
- `src/master_agent/capsule_runtime.py`
- `tests/test_capability_import.py`
- `tests/test_capability_capsules.py`
- `docs/capability-capsules.md`
- `specs/current/runtime/MA-CAPABILITY-IMPORT-001.md`

## Data flow

The service canonicalizes its environment and snapshots its worker identity at
construction. Direct promotion creates a quarantine with those values. Existing
quarantine promotion compares its signed values before validation. Validation
then runs through the already-bound validator, and both returned evidence
objects must repeat the same worker digest before any promoted state is signed.

## Compatibility

Canonical `development`, `non_production`, and `production` environments remain
supported. The prior internal `test` string and validators that cannot identify
their worker are rejected because they cannot prove the security invariant.

## Security

Environment mismatch is rejected before a production-labeled quarantine can
use weaker readiness. Worker mismatch is rejected before validation or before
the TESTED state, depending on whether it appears in the manifest, validator,
or evidence. A failed attempt leaves the signed chain at QUARANTINED.

## Rejected alternatives

Checking only at import would not protect direct or future quarantine sources.
Checking only the runtime worker would not prove that execution uses the worker
whose sandbox evidence was reviewed.
