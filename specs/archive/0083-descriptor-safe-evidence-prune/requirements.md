# Requirement deltas

## ADDED

### MA-RETENTION-001 — Descriptor-safe retained-evidence expiration

MasterAgent MUST derive preview and apply from the same bounded,
descriptor-relative validation plan under an owner-controlled pinned root.
Apply MUST delete only complete expired evidence-and-sidecar pairs, MUST hold
an exclusive selected-root retention lock plus shared existing eligible
owner-controlled ancestor locks and every discovered evidence-parent
publication lock through an exact descriptor rescan, MUST hold the same
source-parent lock before transaction recovery mutates a descendant pair, MUST
recover or report interrupted pair transactions, and MUST fail before new
deletion when any discovered sidecar, referenced evidence, directory, identity,
manifest, digest, size, limit, lock, rescan, filesystem, or transaction state
is unsafe. Retained writers MUST expose and exclusively lock their exact parent
before sharing existing eligible ancestor retention locks. Orphan repair apply
MUST acquire every discovered descendant record-parent or publication lock and
repeat its descriptor scan before classification or quarantine, so a
child-first partial publication fails closed. Recovery MUST durably
fsync an absent common source parent before discarding staged links, and an
ancestor scan MUST report pending nested-root transaction state for exact-root
recovery. Unreferenced regular files MUST NOT be classified as prune candidates.
Output MUST be deterministic and content-free. Native Windows preview and apply
MUST remain unavailable until equivalent filesystem and atomic-state guarantees
exist.

## MODIFIED

None.

## REMOVED

None.
