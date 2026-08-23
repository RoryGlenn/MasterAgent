# MA-RECURRING-001 — Governed exact-bound recurring occurrences

## Status

Active

## Requirement

A schedule MUST decide only when one already registered exact occurrence is
eligible. It MUST NOT grant a capability, select or broaden a target, resolve
credentials during inspection, satisfy approval, or bypass the normal
`ChangePlan` policy, governance, approval, connector, verification,
compensation, retention, and audit path.

Each occurrence MUST use a bounded canonical versioned artifact containing its
current registration generation and digest, canonical UTC instant, IANA zone,
offset, fold and timezone identity, lateness and `latest_only` catch-up facts,
approval-resume deadline, immutable plan and execution context, exact provider
resource identities, runtime/package identity, selected gates and
configurations, pre-existing pinned roots, strict structured non-secret run
invocation, and an execution key. Effect-bearing idempotency keys MUST be
namespaced by that execution key; reads and local generation MUST run fresh.

A local artifact MUST be create-only beneath the configured pinned private
occurrence root and atomically digest-registered in the configured trusted
claim state. A self-contained digest MUST NOT authenticate an artifact. An
external artifact MAY be accepted only with a configured scheduler trust
anchor and valid signature; scheduler authentication MUST NOT count as plan
approval.

Apply MUST perform bounded pre-secret artifact, registration, time, path, plan,
and context validation; atomically reserve the occurrence; resolve only
plan-selected credentials and attest the current principal and scopes through
the existing run; revalidate the exact context, registration, deadline, and
claim generation immediately before every effect; and reconcile/finalize from
exact run, audit, idempotency, verification, and provider metadata.

The local claim backend MUST be documented and enforced as single-host. Every
reservation MUST use a monotonically increasing generation and unguessable
claim token. A stale generation MUST NOT renew, resume, finalize, or authorize
an effect. Claim loss before dispatch is a certified pre-effect failure; claim
loss while an effect may be in flight is indeterminate. Verified completion
MAY be reused only after independent re-verification. Indeterminate outcomes
MUST remain blocked pending reconciliation.

Approval-required occurrences MUST enter a durable `approval_blocked` state
without a running lease and reuse one occurrence-bound approval request. Resume
MUST atomically reclaim only that artifact and request, then recheck the current
registration generation, enabled/revoked state, resume deadline, plan,
execution context, provider identity/scopes, and authenticated approvals.

DST gaps, folds, timezone-data drift, offset mismatch, early/late occurrences,
disable/revoke, and catch-up MUST be deterministic and fail closed. Exact apply
MUST reject force bypasses. All active security-boundary roots MUST be absolute,
pre-existing, private, pinned, and pairwise distinct where independently
writable. Inspection and dry-run MUST perform no credential resolution,
provider request, audit/claim mutation, output publication, or boundary
creation. Legacy non-manifest commands MUST continue rejecting before they
open configuration or authority.

## Rationale

Scheduling is timing, not authority. Authenticating one complete artifact and
fencing one existing governed execution preserves operator intent without
turning a scheduler, local file, lease, or retrieved content into approval.

## Scenarios

### Local occurrence is bound and applied

- GIVEN an enabled exact registration, pre-existing private roots, and a bound plan
- WHEN the local binder publishes and trusted-state-registers one due occurrence
- THEN inspection is inert and apply reserves exactly that artifact
- AND execution proceeds only through the normal governed run
- AND the current fence is checked before each effect

### Approval is not yet available

- GIVEN a valid reserved occurrence whose normal policy requires approval
- WHEN the governed run reports pending approval
- THEN the occurrence becomes `approval_blocked` without a running lease
- AND one request binds the occurrence fingerprint and claim generation
- AND exact resume cannot broaden or reconstruct the occurrence

### Time, registration, or claim identity changes

- GIVEN a bound occurrence
- WHEN its registration is disabled, revoked, regenerated, late, timezone-drifted, or its claim fence is lost
- THEN no new effect begins
- AND any possibly in-flight outcome remains indeterminate rather than retried

### Dry-run isolation

- GIVEN an occurrence file
- WHEN inspect or dry-run is requested
- THEN no credentials, provider, audit, claim, output, or security-boundary creation is touched

## Implementation

- `src/master_agent/recurring.py`
- `src/master_agent/recurring_occurrence.py`
- `src/master_agent/cli.py`
- `src/master_agent/approval_handoff.py`
- `src/master_agent/orchestrator.py`

## Verification

- `tests/test_recurring.py`
- `tests/test_recurring_occurrence.py`
- `tests/test_orchestrator.py`
- `tests/test_cli.py`
- `scripts/specs.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #86.
