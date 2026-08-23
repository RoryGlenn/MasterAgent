# Design

## Approach

`WorkMemory` owns one explicitly selected `PinnedSQLiteDatabase`. The database
contains an immutable `work_events` table and a singleton `work_memory_state`
checkpoint. Every append runs under `BEGIN IMMEDIATE`, verifies the complete
existing journal, validates the requested transition, computes the next
canonical event hash, inserts exactly one row, and advances the count and head
checkpoint in the same transaction.

Current work state is derived by replaying events. No independently mutable
work-status row exists. `show` and `verify` use a read-only pinned snapshot so
inspection cannot create or repair state. A schema version and exact table
definition, constraint, and column validation reject ambiguous or partially
migrated databases. Replay
requires the stored timestamp to use its exact canonical representation so an
equivalent textual rewrite is still detected. Every CLI action preflights
journal and state-file aliases before JSON publication. Mutating actions also
preflight a create-only JSON output name before opening or appending to the
journal. They validate the exact prospective JSON size inside the transaction
before commit and hold a native create-only output reservation through journal
commit and publication. `record` opens the pinned SQLite boundary with creation
disabled, while `start` validates every retained field before opening the
create-enabled boundary. SQLite initialization permits
new transaction and integrity bookkeeping only when it exclusively created the
database in the same operation; existing state with missing bookkeeping is
never repaired implicitly.

## Affected components

- `src/master_agent/work_memory.py`: bounded event types, validation, replay,
  append, inspection, and verification.
- `src/master_agent/cli.py`: `work-memory` subcommands and deterministic JSON
  publication.
- `tests/test_work_memory.py`: persistence, lifecycle, tampering, concurrency,
  bounds, safety, and CLI coverage.
- `.ai/semantic-router.toml`: exact retention-audit ownership and routing.
- README, CLI reference, operations, threat model, and changelog.

## Data flow

```text
explicit CLI input
  -> bounded field and lifecycle validation
  -> pinned private SQLite transaction
  -> verify existing global event chain and checkpoint
  -> append canonical event and update checkpoint
  -> read-only replay
  -> deterministic JSON inspection or verification
```

## Compatibility

The feature is additive. Existing commands, audit records, evidence retention,
approval behavior, and provider integrations are unchanged. No database is
opened unless the operator invokes a `work-memory` command.

## Security

The pinned SQLite boundary provides owner-private files, stable parent and file
identity, cross-process serialization, and durable generation replacement.
Canonical SHA-256 chaining and a stored checkpoint detect edits, gaps,
reordering, and partial logical history. Verification is read-only and a
missing database fails closed. Stored data is a deliberately small metadata
allowlist. All summaries and references remain untrusted data and never enter
an authority or approval decision.

## Rejected alternatives

- A mutable current-state table could disagree with history and create another
  integrity surface.
- Per-work chains would not detect deletion or reordering across records.
- Automatic provider enrichment would violate the local credential-free
  boundary and retain more content than necessary.
- A browser UI or daemon would add deployment and lifecycle complexity.
