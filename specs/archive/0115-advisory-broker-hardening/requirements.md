# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-ADVISORY-003 — Parent-bound budgets and context minimization

The three-research/one-plan-review budget MUST be one authenticated,
content-minimized operator-goal record shared by retries and independent or
concurrent runner processes. Every attempt MUST be reserved atomically before
worker startup, including failed adapter attempts. Budget-state failure or
exhaustion MUST keep work on the direct-parent path without disclosing task or
credential content.

### MA-ADVISORY-005 — Broker-owned live specialist adapter

The adapter MUST bind the sanitized task, selected profile, normalized allowed
route scope, HEAD, index, tracked worktree state, untracked paths, and bounded
untracked file contents. It MUST reject unreadable, oversized, truncated,
special-file, or raced snapshots and any state change during execution.

The live SDK session MUST expose only repository-owned read/search tools whose
handlers technically enforce the bound route scope. Tool requests and parent
citation revalidation MUST reject paths outside that scope. The optional current
adapter MUST otherwise retain isolated sessions, depth one, no ambient
discovery, narrow untrusted reports, and direct-parent fallback.

## REMOVED

None.
