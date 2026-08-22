# Design

## Approach

Open the requested retention root as one private `PinnedDirectory`. Preview
opens the existing root lock without creating it; apply creates or opens it.
Both maintenance modes acquire without waiting. Same-parent retained writers
keep their existing serialized publication behavior: a later writer waits on
the exact-parent lock without holding another retention lock. The active writer
first exposes and exclusively holds that exact-parent lock, then shared-locks
every existing retention boundary in eligible owner-controlled pinned
ancestors. Maintenance
uses the same handshake with its selected root as the exclusive leaf. A parent
operation therefore either already owns an ancestor lock before a child starts
or discovers the child's visible leaf lock during its bounded scan. A bounded
descriptor scan discovers active records and their immediate parent
directories. The runtime acquires every existing descendant-parent publication
lock in deterministic order for preview and creates or opens the same locks for
apply, then repeats the exact descriptor scan and revalidates every held
identity. Preview detects a lock created in a previously unlocked discovered
parent during that window and fails the snapshot.

Orphan repair uses the same descendant-lock discovery and validating rescan
before classification or quarantine. A child-first publication is therefore
visible through its exact-parent lock even while only its manifest has been
published, and ancestor repair fails closed instead of quarantining that
in-progress sidecar.

Both modes reject symlinks and unsafe directory state, validate every discovered
sidecar and referenced evidence inode, parse bounded sidecar bytes against the exact
manifest contract, verify sibling naming and the evidence digest, and sort
complete pairs by root-relative sidecar path. Directory entries, sidecars,
transaction directories, transaction members, JSON nesting, and retained-file
reads all have explicit bounds. Unreferenced regular files are not prune
candidates; orphan classification stays within `evidence-repair`.

Apply refuses the entire new plan if scanning or validation reports any error.
It bounded-reads pending transaction markers and holds each descendant source
parent through the same retention-lock set before recovery mutation. For each
expired pair, it records a content-free transaction under a private,
descriptor-bound staging directory on the selected-root filesystem,
create-only hard-links both exact inodes, removes the public names by identity,
and then removes the staged inodes and transaction record. A later apply
completes a fully staged interrupted transaction or rolls back a transaction
that never staged the complete pair. Before deleting the only recovery links in
a commit-complete state, it verifies that both public names remain absent and
fsyncs their common source parent. Apply may normalize only an exact owner-owned
internal directory or known lock/marker file whose mode is a strict subset of
`0700` or `0600`, closing the crash window between creation and mode
normalization without making preview mutate state. A nonempty nested-root stage
is reported by an ancestor scan and requires recovery at the exact child root;
empty recovered stages are ignored.

## Affected components

- `src/master_agent/retention.py`
- `src/master_agent/cli.py`
- `tests/test_retention.py`
- `tests/test_cli_phase_completion.py`
- `tests/test_identity_retention.py`
- `scripts/validate_release.py`
- CLI, operations, configuration, architecture, threat-model, roadmap,
  changelog, semantic-index, and release-validation documentation

## Data flow

The caller supplies a root and optional time. The runtime pins the root,
coordinates through the content-free root and discovered evidence-parent
locks plus the exact-leaf/shared-existing-ancestor retention handshake,
descriptor-rescans the tree, validates exact pairs, and builds a deterministic
list of expired pairs. Preview returns their display paths without mutation.
Apply locks transaction source parents before recovery, stages and removes each
exact pair, then returns only deterministic counts, paths, and sanitized error
categories.

## Compatibility

Preview remains the default and keeps the existing result schema. `--apply`
changes from an unconditional refusal to the guarded deletion behavior on
supported POSIX systems. Repeated apply is a successful no-op after the pair is
gone. Orphan repair remains a separate command and ignores internal prune
transactions. All Windows preview and apply execution remains explicitly
capability-gated.

## Security

No destructive operation uses recursive pathname traversal, resolved-path
authorization, or symlink following. File owner, mode, regular-file type,
single-link identity, bounded size, manifest shape, timestamps, digest, and
sibling relationship are validated before planning. Create-only hard links
bind same-filesystem staging to the scanned inodes; exact identity checks bind
every unlink. Malformed trees, truncated scans, active nested publication,
unsafe staging state, missing source-parent durability, and substitution fail
closed. Writer output is serialized once and validated against the same schema,
digest, and size contract used by prune. Results never contain retained bytes.

## Rejected alternatives

Path-based deletion, best-effort per-record deletion after a partial scan,
following symlinks, and broad recursive removal were rejected because they do
not preserve the pinned retention boundary or deterministic pair semantics.
