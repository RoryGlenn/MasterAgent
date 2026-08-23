# MA-WORK-MEMORY-001 — Bounded persistent work memory

## Status

Active

## Requirement

MasterAgent MUST provide an explicit local CLI workflow that starts one work
record from a bounded work identifier, issue reference, and summary; appends
bounded decisions, checkpoints, and references; advances monotonically through
`issue`, `planned`, `implementing`, `reviewing`, `verified`, and `merged`; and
inspects the derived current state and complete bounded event history after a
process restart.

The journal MUST use an explicitly selected owner-private SQLite database and
the certified pinned SQLite persistence boundary. Events MUST be append-only
and globally hash-chained with a durable count and head checkpoint. Verification
MUST fail closed on an unsafe or missing path, unexpected complete schema
definition or constraint, malformed row, unsupported event kind or stage,
duplicate or missing start, lifecycle
regression, event after merge, sequence gap, previous-hash mismatch, event-hash
mismatch, deletion, reordering, or checkpoint mismatch. Concurrent writers
MUST serialize through the native database boundary without losing events.

Inputs, event count, stored fields, and serialized output MUST be bounded and
deterministic. The maximum permitted journal MUST fit within the certified
native database publication boundary on every supported platform. The journal
MUST retain only operator-supplied identifiers,
short summaries, and references. It MUST NOT retain provider response bodies,
credentials, authentication material, approval artifacts, execution
transcripts, or arbitrary attachments. Remembered content MUST remain untrusted
metadata and MUST NOT grant identity, authority, approval, or capability.
Mutating CLI actions given an occupied create-only output target, an output that
aliases the journal or its state files, or a snapshot that exceeds the
output-size boundary MUST fail before appending to the journal; an occupied or
aliased target MUST also fail before creating a missing journal.
`record` MUST open only an existing initialized journal and MUST NOT create
database or bookkeeping state for a missing path. A mutating output name MUST
remain exclusively reserved from preflight through append commit and output
publication. `start` MUST validate every retained field before initializing a
missing journal.

The feature MUST NOT perform provider access, network synchronization,
background polling, hook installation, or server startup. It MUST NOT claim
that hash-chain integrity authenticates an author or proves an event true.

## Rationale

A small local event journal preserves development continuity without requiring
hosted infrastructure or expanding provider and authority boundaries. Replay
from one tamper-evident log prevents mutable status from silently disagreeing
with recorded history.

## Scenarios

### Resume after restart

- GIVEN a work record with an issue, decisions, and an implementing checkpoint
- WHEN a new process inspects the same explicitly selected database
- THEN it returns the same bounded history and derived implementing stage

### Monotonic lifecycle

- GIVEN a work record at reviewing
- WHEN a caller records an earlier stage or appends after merged
- THEN the append fails and the existing history remains unchanged

### Concurrent writers

- GIVEN independent processes append valid records to the same database
- WHEN the operations overlap
- THEN native serialization preserves every event in one valid global chain

### Tampered journal

- GIVEN a row, including its exact timestamp representation, was edited,
  deleted, or reordered, or the checkpoint disagrees
- WHEN inspection or verification opens a read-only snapshot
- THEN it fails closed without creating or repairing state

### Invalid output

- GIVEN a mutating command selects an occupied create-only output name, aliases
  the journal or its state files, or its prospective serialized snapshot
  exceeds the output-size boundary
- WHEN the command validates its output boundary
- THEN it fails without creating or appending to the journal

### Missing record journal

- GIVEN `record` selects a database path that does not exist
- WHEN the command opens the journal
- THEN it fails without creating the database or its bookkeeping state

### Invalid start

- GIVEN `start` contains an invalid work ID, issue reference, or summary
- WHEN the command validates its inputs
- THEN it fails before creating the database or its bookkeeping state

### Untrusted metadata

- GIVEN a remembered summary or reference claims approval or authority
- WHEN MasterAgent later plans or executes work
- THEN the remembered content grants no identity, authority, capability, or
  approval

## Implementation

- `src/master_agent/work_memory.py`
- `src/master_agent/cli.py`
- `src/master_agent/sqlite_safety.py`

## Verification

- `tests/test_work_memory.py`
- `scripts/semantic_router.py`
- `scripts/specs.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #161.
