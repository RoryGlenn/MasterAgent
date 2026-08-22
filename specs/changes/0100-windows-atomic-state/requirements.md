# Requirement deltas

## ADDED

### MA-WINDOWS-ATOMIC-STATE-001 — Native Windows atomic local state and recovery

On native Windows 11, MasterAgent MUST implement
`atomic_publication_recovery` with retained-handle, protected-DACL, bounded,
serialized local-state transactions. A replacement MUST exclusively create and
flush a private temporary generation, record and flush an exact old/new prepare
state, revalidate the approved parent and destination, replace by handle
relative to the retained parent, verify destination identity, digest, owner SID,
and DACL, and record a durable commit. Recovery MUST accept only the recorded
old or new generation and MUST report every other or uninspectable state as
indeterminate. Removal and quarantine MUST remain exact-identity-bound. All
protected persistence callers MUST select these native operations on Windows
without a pathname-only or POSIX fallback, while byte limits, redaction, and
POSIX behavior remain unchanged.

## MODIFIED

### MA-PLATFORM-001 — Platform runtime contracts

The native Windows runtime MUST advertise `atomic_publication_recovery` only
when protected state transactions, deterministic recovery, and every required
protected persistence caller are available. Stateful Windows operations MUST
then admit the complete filesystem, locking, and atomic-publication contract
set while unrelated incomplete process, Git, and capsule-isolation contracts
remain unavailable.

### MA-RETENTION-001 — Descriptor-safe retained-evidence expiration

Native Windows retained-evidence publication, preview, apply, repair, and
quarantine MUST use the native pinned-handle and atomic-state contracts. Pair
deletion and quarantine MUST be serialized and recovery-recorded, validate
exact file identity/content/security before mutation, and reconcile only the
recorded before/after states. Windows MUST no longer fail merely because POSIX
descriptors or mode bits are unavailable, and MUST NOT fall back to pathname-
only mutation.

## REMOVED

None.
