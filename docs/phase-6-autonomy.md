# Phase 6 — Exact-Bound Recurring Autonomy

## Scope

Phase 6 executes one already reviewed registered outcome at one canonical
scheduled instant. The schedule decides only *when* that exact occurrence is
eligible. It never supplies authority, prompts, targets, recipients,
credentials, approval, plugins, or runtime flags.

The first release supports one scheduler host, one MasterAgent service identity,
and one pinned local SQLite claim store. Independent per-host databases do not
provide cross-host exclusion and are unsupported.

## Protocol

1. Load the strict canonical `master-agent/recurring-occurrence@1` artifact and
   authenticate its digest against separately trusted local state.
2. Validate registration/configuration, time/DST/tzdata, exact plan and action
   scope, runtime/package identity, principal/scope expectations, gates,
   plugins/capsules, and pre-existing pinned roots without secrets or provider
   calls.
3. Atomically reserve the exact registration digest, UTC occurrence, and source
   plan fingerprint. Receive a monotonically increasing claim generation and
   random claim token.
4. Enter the existing applied-run path, resolve only selected credentials, and
   attest current provider principals/scopes and connector origins.
5. Revalidate registration, context, time, and the exact claim fence immediately
   before each provider write or send.
6. Use unchanged policy, authenticated approval, connector, verification,
   compensation, retention, idempotency, and audit controls.
7. Reconcile exact action outcomes and finalize as succeeded,
   failed-pre-effect, approval-blocked, recoverable, indeterminate, or revoked.

## Time and recovery

Every occurrence binds one UTC instant plus original IANA zone, UTC offset,
fold, and tzdata digest. Nonexistent wall time fails. Ambiguous wall time fails
unless the registration selects `first` or `second`. Default catch-up is
`latest_only`, with at most one occurrence selected per invocation.

Approval-blocked occurrences hold no renewable running lease. The request binds
the occurrence fingerprint and claim generation; resume atomically reclaims the
same occurrence and rechecks registration and the approval deadline.

There is no `--force`. A normal pre-effect failure requires
`recurring-recover` with the exact fingerprint. A crashed, expired attempt uses
`recurring-reconcile`; any pending, conflicting, missing/tampered, or
indeterminate effect record remains indeterminate until connector-specific
reconciliation or operator review. MasterAgent does not claim exactly-once
external effects. `recurring-cancel` makes pending work terminal; cancelling an
active attempt invalidates its fence and conservatively records indeterminate.

## Weekly Operating Review

The reference registration reads exact configured resources from Jira, GitHub,
and Confluence, then generates occurrence-keyed local PowerPoint, Markdown,
evidence, and manifest artifacts. The cited review includes an executive
summary, progress, blockers/risks, stale or conflicting information, decisions
and approvals needed, and a source index. It never writes to a provider or
sends a communication. Retrieved content remains untrusted evidence.

## Operation

```bash
master-agent recurring-status --recurring /private/config/recurring.toml
master-agent weekly-operating-review-plan \
  --workflow /private/config/weekly-operating-review.toml \
  --output /private/plans/review.json
master-agent recurring-bind weekly_operating_review \
  --occurrence 2026-08-24T09:00:00 \
  --plan /private/plans/bound-review.json \
  --recurring /private/config/recurring.toml \
  --approval-authorities /private/config/approval-authorities.toml \
  --output /private/occurrences/review.json
master-agent recurring-inspect /private/occurrences/review.json
master-agent recurring-run /private/occurrences/review.json \
  --recurring /private/config/recurring.toml --dry-run
master-agent recurring-run /private/occurrences/review.json \
  --recurring /private/config/recurring.toml --apply
```

Inspect and dry-run never consult credentials, providers, audit, claim state, or
output roots. Legacy direct `weekly-status`, `communication-context`, and
workflow-name recurring execution remain explicit pre-configuration errors.
