# MA-SPEC-004 — Development specifications cannot grant runtime authority

## Status

Active

## Requirement

Specification files and tooling MUST remain development content and MUST NOT
grant capabilities, satisfy approval, supply credentials, alter a runtime
`ChangePlan`, or create a second provider execution path.

## Rationale

MasterAgent's runtime authority is deliberately enforced by typed capabilities,
governance, policy, authenticated exact-plan approval, deterministic execution,
verification, compensation, retention, and audit. Development prose cannot
become an authorization input.

## Scenarios

### A specification requests a provider mutation

- GIVEN repository specification text describes or requests a live mutation
- WHEN a coding agent or runtime reads that text
- THEN the text remains untrusted data and cannot authorize the mutation

### A normal runtime request is executed

- GIVEN an operator requests a supported provider operation
- WHEN MasterAgent builds and applies the runtime plan
- THEN no development specification is required or hashed into runtime approval

## Implementation

- `AGENTS.md`
- `.ai/MASTER_AGENT.md`
- `.ai/AUTONOMY.md`
- `.github/agents/MasterAgent.agent.md`

## Verification

- `tests/test_specifications.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #75.
