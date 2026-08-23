# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-CAPABILITY-IMPORT-001 — Governed custom-agent capability import

The installed CLI MUST expose the complete supported non-production pure
capability workflow: read-only preview, exact-digest single-ability quarantine,
independently signed promotion, authenticated status, policy-first intent
routing, execution through the normal governed orchestrator, immutable-version
updates, deprecation, and revocation. Routing and execution MUST accept only the
latest enabled exact manifest. Authority keys and subjects MUST be distinct by
role and secrets MUST come from explicit environment-backed operator
configuration. Unsupported ability classes and production promotion without
live production controls MUST remain fail closed.

Promotion MUST preflight every role for the selected environment and resume an
authenticated partial chain without replacing prior evidence. Routing and
execution MUST reject capsule/governance environment mismatches before foreign
behavior or audit mutation.

## REMOVED

None.
