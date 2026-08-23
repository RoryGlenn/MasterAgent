# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-OPERATING-MODES-001 — Capability-scoped operating modes

MasterAgent MUST provide an offline helpdesk support bundle that contains only
allowlisted doctor fields, bounded product/runtime version facts, a unique
correlation identifier, and integrity metadata. It MUST remove local paths and
MUST NOT collect or upload credentials, provider content, environment values,
host or user identity, logs, or command history. Publication MUST use the
private create-only output boundary and remain useful when setup is missing or
readiness is false.

## REMOVED

None.
