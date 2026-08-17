# MA-SPEC-002 — Structured behavioral change records

## Status

Active

## Requirement

A non-trivial behavioral change MUST use a normalized change directory with
machine-readable metadata, a proposal, requirement deltas, implementation
tasks, and a design unless the metadata explicitly marks the design as
unnecessary.

## Rationale

Structured deltas keep requirements, implementation intent, and completion
criteria durable across agents and development sessions without replacing
GitHub issues.

## Scenarios

### A security-relevant behavior changes

- GIVEN a change affects authorization, policy, a connector, or verification
- WHEN implementation begins
- THEN a linked change specification records the behavioral delta and design

### A mechanical refactor changes no behavior

- GIVEN a refactor has no observable or security-relevant effect
- WHEN the refactor is implemented
- THEN a full behavioral change specification MAY be omitted

## Implementation

- `specs/README.md`
- `specs/templates/change.toml`
- `scripts/specs.py`
- `AGENTS.md`

## Verification

- `tests/test_specifications.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #75.
