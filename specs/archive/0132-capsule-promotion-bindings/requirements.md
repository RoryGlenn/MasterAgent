# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-CAPABILITY-IMPORT-001 — Governed custom-agent capability import

Capsule promotion MUST accept only a canonical `EnvironmentKind`, require the
signed quarantine environment to equal the promotion service environment, and
derive production readiness from that immutable environment. Before the TESTED
transition, promotion MUST require one exact worker identity across the signed
quarantine, promotion worker, validator, validation evidence, and sandbox
evidence. Unknown environments or any identity mismatch MUST fail without
appending a promoted lifecycle state.

## REMOVED

None.
