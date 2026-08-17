# MA-SPEC-001 — Maintained current behavioral requirements

## Status

Active

## Requirement

The repository MUST maintain accepted behavioral requirements in
`specs/current/` separately from active and historical change records.

## Rationale

A future developer or coding agent must be able to discover required behavior
without reconstructing intent from conversations, closed issues, source code,
and tests alone.

## Scenarios

### Accepted behavior remains discoverable

- GIVEN a behavioral change has been implemented and verified
- WHEN the change is archived
- THEN its accepted requirement state is present in `specs/current/`

## Implementation

- `specs/README.md`
- `scripts/specs.py`

## Verification

- `tests/test_specifications.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #75.
