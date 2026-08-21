# Requirement deltas

## ADDED

### MA-DIRECT-READ-001 — Direct read-only provider session

The runtime MUST provide an explicit direct-read route for a plan containing
only direct-user, `read_only` actions for exactly one built-in typed provider.
The route MUST validate each action through the capability catalog,
governance, policy, source-of-truth, authenticated connector identity/scope,
fixed provider endpoint, bounded transport, prompt-injection marking, and an
independent provider re-read. It MUST not require a persisted audit database,
artifact directory, approval artifact, or pre-bound runtime context.

The route MUST reject a plan that contains a non-read risk, non-direct
authority, more than one provider, plugin or capsule binding, persisted output,
or a connector that is not a typed `ReadOnlyConnector`, before it dispatches a
provider request. Provider effects, communications, administration, deletes,
merges, raw plugins, capsules, and recurring execution MUST continue to use
their existing governed boundaries.

### MA-DIRECT-READ-002 — Lightweight local bootstrap reuse

The bootstrap MUST install a dependency-light core runtime without requiring
draft-rendering dependencies. When a pre-existing repository-local virtual
environment has a usable interpreter and MasterAgent entry point but has no
bootstrap freshness marker, bootstrap MUST run only offline readiness and MUST
not modify that environment or assert that it is trusted. A malformed,
non-directory, symbolic-link, or interpreter-missing environment MUST still be
rejected. Credential stores, provider effect paths, and approval-bound runtime
paths remain subject to their existing trust requirements.

## MODIFIED

None.

## REMOVED

None.
