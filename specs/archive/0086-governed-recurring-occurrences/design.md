# Design

## Approach

Extend the recurring registration with explicit generation, revocation, fold,
catch-up, resume-deadline, and occurrence-root fields. Bind creates a strict
`master-agent/recurring-occurrence@1` document containing the exact registered
snapshot, time facts, bound plan, execution context, runtime identity, scoped
idempotency namespace, roots, and structured non-secret invocation. It
publishes create-only under a pinned private root and atomically registers the
artifact digest in the configured recurring state database.

Apply authenticates the artifact against both current registration and trusted
state, performs structural/time/context checks without credentials, atomically
reserves the occurrence, and then calls the existing applied-run path. The
orchestrator receives a pre-effect fence callback. Approval-required reports
transition to durable `approval_blocked`; exact resume validates the same
artifact/request and reclaims that occurrence. Terminal state is derived from
the governed run report rather than a generic callback result.

## Affected components

- `src/master_agent/recurring.py` and a focused occurrence module.
- `src/master_agent/cli.py`, `src/master_agent/approval_handoff.py`, and
  `src/master_agent/orchestrator.py` for exact dispatch and fencing.
- `src/master_agent/workflows/weekly_operating_review.py` for the constrained
  Jira, GitHub, Confluence, and local PowerPoint reference path.
- Recurring defaults/configuration and CLI/reference documentation.
- Recurring, CLI, approval, orchestration, specification, and release tests.

## Data flow

1. Resolve one trusted recurring configuration and exact registered workflow.
2. Normalize a requested local time to one canonical UTC occurrence; reject
   gaps, unselected folds, offset drift, and out-of-window instances.
3. Scope effect idempotency, publish the artifact create-only, and register its
   digest in trusted state.
4. Inspect or dry-run using only artifact bytes and no configuration, runtime
   state, credentials, providers, audit sink, or output roots.
5. Apply authenticates, reserves, resolves only selected credentials through
   the existing run, revalidates the context and fence before each effect, and
   finalizes from the exact report.
6. Approval blocking stores no live lease; resume revalidates registration,
   deadline, artifact, request, approvals, provider context, and claim fence.

## Compatibility

Packaged workflows remain disabled. Legacy `recurring-run NAME`,
`weekly-status`, and `communication-context` execution continue to reject
before configuration or credentials. Registration/status parsing accepts
legacy files with safe defaults, but exact bind requires explicit private
roots and exact-bound fields.

## Security

The artifact never authenticates itself. Trusted state and the separately
selected recurring configuration identify the allowed workflow and digest.
All active roots pre-exist and are pinned; publication is restricted and
create-only. Their native object identities, the runtime executable, and the
installed Python package tree are bound and revalidated. The claim generation
is checked directly before each effect-bearing action. Cancellation invalidates
the exact generation, and a lost fence after dispatch is indeterminate, not
retryable. Local SQLite guarantees one active fenced attempt only on the single
configured host.

## Rejected alternatives

Reusing the callback runner, force flags, current-directory path resolution,
mutable output names, generic command strings, or a second connector/policy
engine were rejected because each would weaken an existing boundary.
