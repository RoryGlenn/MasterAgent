# Requirement deltas

## ADDED

### MA-OPERATING-MODES-001 — Capability-scoped operating modes

MasterAgent MUST report separate capability-scoped readiness levels for local
installation, selected-provider reads, local drafts, governed effects, and
enterprise deployment. A strict organization profile MUST select either employee or
trusted developer mode, bind reviewed configuration locations, define the
installed capability allowlist, and keep optional providers or missing user
credentials from making local installation appear broken. Employee mode MUST
execute only installed, reviewed capabilities and MUST NOT scaffold, load,
self-promote, or execute missing capability code. Trusted developer mode MAY
support explicit scaffolding, but generated effect code MUST remain quarantined
until independent review, tests, specification archival, signing, deployment,
and normal runtime admission complete. Diagnostics MUST distinguish unsupported
capability, missing organization setup, missing user authentication, blocked
policy, and runtime defect without exposing secrets or provider content.

### MA-USER-WORKFLOW-001 — One-command governed user workflow

MasterAgent MUST provide one high-level command that accepts an unbound typed
plan or an existing approval request, validates it against the active
organization profile, and internally selects the existing stateless direct-read
or manifest-bound applied runtime. The command MUST preserve exact provider
selection, catalog, governance, policy, source-of-truth, authenticated
approval, verification, idempotency, compensation or reconciliation, audit,
and effect-gate checks. It MUST provision only the minimum descriptor-safe,
user-private local state required for draft or effect work, and MUST require no
audit, artifact, or approval state for an allowed stateless read. An
approval-required effect MUST pause once with a private exact-plan request and
resume through the same high-level command without reconstructing targets,
configuration, credentials, paths, or gates. High-impact operations MUST retain
their existing mandatory controls and disabled-at-rest posture, and every
existing low-level command MUST remain available for automation and debugging.

## MODIFIED

None.

## REMOVED

None.
