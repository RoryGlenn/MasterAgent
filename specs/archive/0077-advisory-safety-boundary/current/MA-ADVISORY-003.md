# MA-ADVISORY-003 — Parent-bound budgets and context minimization

## Status

Active

## Requirement

A repository-owned advisory session MUST be bound to the selected MasterAgent
parent, MUST deny nested delegation, MUST allow at most three research attempts
and one plan-review attempt per operator goal, and MUST reject credential,
approval, signing, unrelated private context, recipient, target, connector,
tenant, or `ChangePlan` data before worker invocation.

## Rationale

Delegation limits and context minimization must be deterministic controls rather
than instructions a model may ignore. Sensitive or authority-bearing input
cannot be made safe merely by asking a child not to use it.

## Scenarios

### Delegation budget is exhausted

- GIVEN three research attempts or one review attempt have been reserved
- WHEN another task of that role is requested
- THEN the task MUST remain on the parent path without child invocation

### Sensitive context is supplied

- GIVEN a delegated payload includes a credential, approval artifact, final
  target, recipient, or private context
- WHEN the broker sanitizes the task
- THEN the payload MUST be rejected before the worker is called

## Implementation

- `src/master_agent/advisory.py`
- `.ai/AUTONOMY.md`
- `.ai/MASTER_AGENT.md`

## Verification

- `tests/test_advisory_integration.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #77.
