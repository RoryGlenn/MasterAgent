# Requirement deltas

## ADDED

### MA-REDDIT-001 — Governed Reddit provider integration

The runtime MUST provide typed official-API Reddit reads, local drafts, and
exact approval-bound post/comment/reply operations through fixed origins,
in-memory refresh-token OAuth, purpose-separated read and communication
credentials, provider-attested identity/scopes, bounded untrusted-content
handling, zero write retries, and independent verification. Missing or
out-of-profile provider scope reports MUST fail closed, and canonical content
references MUST preserve the required post/comment target kind.
Typed edit/delete adapters MUST remain catalog-disabled while Reddit lacks an
atomic provider precondition.

## MODIFIED

None.

## REMOVED

None.
