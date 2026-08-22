# MA-USER-WORKFLOW-001 — One-command governed user workflow

## Status

Active

## Requirement

MasterAgent MUST provide one high-level command that accepts an unbound typed
plan or an existing approval request, validates it against the active
organization profile, and internally selects the existing stateless direct-read
or manifest-bound applied runtime. The command MUST preserve exact provider
selection, catalog, governance, policy, source-of-truth, authenticated
approval, verification, idempotency, compensation or reconciliation, audit,
and effect-gate checks. It MUST NOT invoke arbitrary shell, provider CLI,
generic HTTP, raw plugin, or unreviewed capsule paths.

An allowed direct-user, single-provider read MUST require no audit database,
artifact directory, approval state, or persistent plan copy unless organization
policy requires an audited path. Draft and effect work MAY automatically
provision only the minimum descriptor-safe, user-owned private state needed by
the existing runtime. An approval-required effect MUST pause once with a
private request bound to the exact plan, profile, configuration, identities,
paths, provider destination, gates, and pending actions. The same high-level
command MUST resume that request without accepting replacement targets,
configuration, credentials, paths, or gates.

High-impact sends, deletes, permissions, administration, merges, recurring
execution, and comparable operations MUST retain exact-plan approval,
verification, idempotency, recovery, and disabled-at-rest controls. The
existing low-level readiness, direct-read, bind, inspect, apply,
approval-inspection, and resume commands MUST remain available for automation
and debugging.

## Rationale

One user-facing command removes internal ceremony while preserving one
deterministic authority path. Risk determines whether the session stays in
memory, creates private local state, or pauses for authenticated approval.

## Scenarios

### Allowed read stays stateless

- GIVEN an employee profile lists one built-in read capability and a direct-
  user plan selects exactly one provider
- WHEN the employee invokes the high-level command
- THEN it enters the verified direct-read route without creating audit,
  artifact, approval, or plan state

### Reversible effect pauses and resumes once

- GIVEN an allowed reversible provider effect whose policy requires approval
- WHEN the employee invokes the high-level command
- THEN MasterAgent binds and inspects the exact plan, provisions only private
  runtime state, and returns one resumable authenticated-approval request
- AND after the trusted approval artifact is supplied, the same high-level
  command resumes the captured invocation and independently verifies the effect

### Simplification cannot bypass a gate

- GIVEN a plan requests a disabled high-impact capability, a second provider,
  a changed target, or an unreviewed extension
- WHEN the high-level command validates or resumes it
- THEN it fails before the prohibited connector effect and does not fall back
  to a shell, provider CLI, generic HTTP, plugin, or capsule bypass

## Implementation

- `src/master_agent/operating.py`
- `src/master_agent/cli.py`
- `src/master_agent/approval_handoff.py`

## Verification

- `tests/test_operating.py`
- `tests/test_operating_modes.py`
- `tests/test_approval_handoff.py`
- `tests/test_cli.py`

## History

- Introduced by GitHub issue #110.
