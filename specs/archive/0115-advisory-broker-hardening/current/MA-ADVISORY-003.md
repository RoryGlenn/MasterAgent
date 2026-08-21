# MA-ADVISORY-003 — Parent-bound budgets and context minimization

## Status

Active

## Requirement

A repository-owned advisory session MUST be bound to the selected MasterAgent
parent, MUST deny nested delegation, MUST allow at most three research attempts
and one plan-review attempt per operator goal, and MUST reject credential,
approval, signing, unrelated private context, recipient, target, connector,
tenant, or `ChangePlan` data before worker invocation.

The live runner MUST share one authenticated, content-minimized goal budget
across retries, failures, process restarts, and concurrent CLI processes. It
MUST reserve every attempt atomically before worker startup. Missing, corrupt,
unsafe, or exhausted budget state MUST keep the task on the direct-parent path
without disclosing task, repository-content, or credential data.

## Rationale

Delegation limits and context minimization must be deterministic controls rather
than instructions a model may ignore. A process-local counter can be reset by
the real CLI boundary, and sensitive or authority-bearing input cannot be made
safe merely by asking a child not to use it.

## Scenarios

### Delegation budget is exhausted across processes

- GIVEN three research attempts or one review attempt have been atomically
  reserved for one operator goal, including failed calls from other processes
- WHEN another task of that role is requested with the same goal identity
- THEN the task MUST remain on the parent path without child invocation

### Budget state is unsafe

- GIVEN a goal budget record cannot be authenticated, locked, or read safely
- WHEN a live advisory attempt requests a reservation
- THEN the worker MUST NOT start
- AND the diagnostic MUST remain content-minimized

### Sensitive context is supplied

- GIVEN a delegated payload includes a credential, approval artifact, final
  target, recipient, or private context
- WHEN the broker sanitizes the task
- THEN the payload MUST be rejected before the worker is called

## Implementation

- `src/master_agent/advisory.py`
- `src/master_agent/advisory_budget.py`
- `scripts/advisory_subagent.py`
- `.ai/AUTONOMY.md`
- `.ai/MASTER_AGENT.md`

## Verification

- `tests/test_advisory_integration.py`
- `tests/test_advisory_budget.py`
- `tests/test_advisory_runner.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #77.
- Hardened across real runner processes by GitHub issue #115.
