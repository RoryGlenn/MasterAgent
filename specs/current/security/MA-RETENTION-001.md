# MA-RETENTION-001 — Descriptor-safe retained-evidence expiration

## Status

Active

## Requirement

MasterAgent MUST derive retained-evidence expiration preview and apply from the
same deterministic, bounded, descriptor-relative plan beneath one
owner-controlled `PinnedDirectory`. It MUST validate every discovered retention
sidecar and its referenced evidence as a restricted, owner-matching,
single-link regular file; revalidate the complete manifest schema, aware timestamps, positive
retention interval, persistence relationship, lowercase content digest,
evidence filename, canonical sibling-sidecar relationship, and evidence bytes;
and reject symlinks, traversal, duplicate or conflicting pairs, hard links,
identity substitution, unsafe directories, and scan truncation. Unreferenced
regular files MUST NOT be classified as prune candidates; orphan classification
remains the separate `evidence-repair` boundary.

Preview MUST be non-mutating, MUST coordinate with the existing pinned-root and
discovered evidence-parent retention locks, MUST perform an exact descriptor
rescan after acquiring them, and MUST report the deterministic expired
candidate order that a safe apply would process. Retained publication MUST hold
an exclusive exact-parent retention lock before shared-locking every existing
eligible owner-controlled ancestor retention boundary; maintenance MUST use the
same handshake with its selected root as the exclusive leaf so ancestor,
descendant, and nested-publication operations cannot overlap unsafely. Apply
MUST be explicit, MUST hold those locks without racing publication, repair, or
another prune, and MUST hold the same descendant source-parent lock before
transaction recovery mutates that pair. It MUST refuse new deletion if any
scan, validation, lock, rescan, recovery, size, or filesystem-identity error
exists. Pair deletion
MUST use a bounded descriptor-bound same-filesystem recoverable transaction so
interruption cannot silently leave an apparently valid half-record. Apply MAY
normalize an exact owner-owned internal transaction directory or known
lock/marker file only when its mode is a subset of `0700` or `0600`; preview
MUST NOT perform that normalization. Before discarding staged recovery links in
a commit-complete state, apply MUST verify both public names are absent and
fsync their common source parent. An ancestor scan MUST report a nonempty nested
transaction stage and refuse new deletion until the exact child root is
recovered. Repeated apply MUST be an honest, successful no-op after deletion.
Results and errors MUST be deterministic and MUST NOT contain retained evidence
content. Native Windows preview and apply MUST fail closed until equivalent
native filesystem identity and atomic-state guarantees are implemented.

Descriptor-relative orphan repair apply MUST acquire the selected-root lock,
the eligible existing ancestor locks, and every discovered descendant
record-parent or publication lock before a validating rescan, classification,
or quarantine. An active or partial child-first publication MUST make ancestor
repair fail closed without moving either member.

## Rationale

Expiration is a destructive confidentiality control. The same pinned identity
that authorizes the scan must bind every read, staging action, and unlink so
untrusted names or concurrent namespace changes cannot broaden deletion.

## Scenarios

### Safe preview and apply

- GIVEN one expired valid pair and one future valid pair under a private root
- WHEN preview and then apply run at the same time boundary
- THEN both select the expired pair in the same order, only apply removes it,
  and the future pair remains unchanged.

### Unsafe tree fails closed

- GIVEN a malformed sidecar, symlink, hard link, unsafe mode, digest mismatch,
  traversal name, conflicting pair, substituted identity, or truncated scan
- WHEN apply builds its deletion plan
- THEN it reports content-free errors and removes no new pair.

### Interrupted pair transaction

- GIVEN apply was interrupted after recording a descriptor-bound pair
  transaction
- WHEN apply runs again under the retention lock
- THEN it safely completes a fully staged deletion or rolls back incomplete
  staging before considering a new plan.

### Nested-root transaction

- GIVEN an interrupted transaction exists beneath a child retention root
- WHEN apply scans an ancestor root
- THEN it reports exact-child-root recovery and starts no new deletion.

### Concurrent publication

- GIVEN nested publication, repair, or prune holds a conflicting hierarchy or
  retention lock
- WHEN another prune attempts to run
- THEN it performs no scan-dependent deletion and reports or raises a
  deterministic busy result.

### Repeated apply

- GIVEN a valid expired pair was removed successfully
- WHEN apply runs again
- THEN it reports no expired or removed pair and succeeds without mutation.

## Implementation

- `src/master_agent/retention.py`
- `src/master_agent/cli.py`

## Verification

- `tests/test_retention.py`
- `tests/test_cli_phase_completion.py`
- `tests/test_identity_retention.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #83.
