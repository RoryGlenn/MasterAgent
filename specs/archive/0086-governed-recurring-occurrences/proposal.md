# Governed exact-bound recurring occurrences

## Problem

MasterAgent can register schedules and calculate due state, but its execution
entry points intentionally fail closed. The legacy callback runner resolves
paths from the current directory, permits forced recovery, and cannot bind an
occurrence to the normal execution-context, approval, idempotency, and audit
boundaries strongly enough to authorize unattended work.

## Desired outcome

A schedule can make one already registered, immutable occurrence eligible for
execution without granting authority. A local binder authenticates the exact
artifact in private trusted state. Inspection is inert. Apply reserves one
single-host fenced claim before credentials, reuses the normal governed run,
and reconciles completion, approval blocking, and indeterminate outcomes.

## Scope

- Strict occurrence schema, bounded parser, local-state authentication, and
  create-only publication.
- Canonical UTC, IANA zone, offset, fold, timezone identity, lateness,
  catch-up, generation, disable, and revoke bindings.
- Single-host SQLite reservation with monotonically increasing fencing.
- Occurrence-scoped idempotency for write and send actions.
- Exact non-secret run invocation, pinned pre-existing roots, inspection,
  dry-run, apply, and approval resume.
- A local-generation Weekly Operating Review reference workflow.

## Rationale

This preserves the existing policy, approval, connector, verification,
compensation, retention, and audit engines. The scheduler decides only when an
exact plan may attempt those gates; it never creates a parallel authority path.

## Alternatives considered

- Cron-driven commands or prompts were rejected because command parsing,
  environment, and current-directory state are not immutable authority.
- A self-contained artifact digest was rejected because an attacker could
  replace both the artifact and digest.
- Cross-host claims over independent SQLite databases were rejected because
  they cannot provide shared compare-and-swap fencing.

## Non-goals

- Generic shell, prompt, or HTTP scheduling.
- Distributed transactions or exactly-once provider effects.
- Scheduler signatures acting as plan approval.
- Enabling provider writes or communications by default.

## Risks

Crash timing around provider effects can leave an outcome indeterminate.
Claims therefore fail closed and use the existing action reconciliation data;
only certified pre-effect failures may be retried. Local trusted state does not
defend against a malicious same-user process replacing a complete consistent
state and is documented as single-host development/pilot scope.
