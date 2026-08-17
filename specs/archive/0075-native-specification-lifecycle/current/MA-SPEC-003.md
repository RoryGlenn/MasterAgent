# MA-SPEC-003 — Verified and safe specification archival

## Status

Active

## Requirement

The archive operation MUST refuse incomplete or invalid changes, apply declared
add, modify, and remove deltas only within `specs/current/`, verify the final
specification tree, and retain the terminal change under `specs/archive/`.

## Rationale

Archival converts a proposed delta into maintained current intent. A partial,
unsafe, or unverified transition would make the specification set less
trustworthy than the code it is intended to explain.

## Scenarios

### A verified add delta is archived

- GIVEN a valid change is in `verifying` and every task is complete
- WHEN the archive command runs
- THEN the current requirement is installed and the change becomes archived

### An unsafe path is supplied

- GIVEN a delta contains traversal, a backslash-ambiguous path, or a symlink
- WHEN validation or archival runs
- THEN the operation MUST fail before changing current requirements

### Verification is incomplete

- GIVEN at least one implementation task remains unchecked
- WHEN archival is requested
- THEN the operation MUST fail without moving the active change

## Implementation

- `scripts/specs.py`

## Verification

- `tests/test_specifications.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #75.
