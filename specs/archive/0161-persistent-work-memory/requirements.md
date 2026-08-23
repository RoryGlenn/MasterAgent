# Requirement deltas

## ADDED

### MA-WORK-MEMORY-001 — Bounded persistent work memory

MasterAgent MUST provide an explicit local CLI workflow that starts one work
record from a bounded work identifier, issue reference, and summary; appends
bounded decisions, checkpoints, and references; advances monotonically through
`issue`, `planned`, `implementing`, `reviewing`, `verified`, and `merged`; and
inspects the derived current state and complete bounded event history after a
process restart.

The journal MUST use an explicitly selected owner-private SQLite database and
the certified pinned SQLite persistence boundary. Events MUST be append-only
and globally hash-chained with a durable count and head checkpoint. Verification
MUST fail closed on an unsafe or missing path, unexpected schema, malformed
row, unsupported event kind or stage, duplicate or missing start, lifecycle
regression, event after merge, sequence gap, previous-hash mismatch, event-hash
mismatch, deletion, reordering, or checkpoint mismatch. Concurrent writers
MUST serialize through the native database boundary without losing events.

Inputs, event count, stored fields, and serialized output MUST be bounded and
deterministic. The journal MUST retain only operator-supplied identifiers,
short summaries, and references. It MUST NOT retain provider response bodies,
credentials, authentication material, approval artifacts, execution
transcripts, or arbitrary attachments. Remembered content MUST remain untrusted
metadata and MUST NOT grant identity, authority, approval, or capability.
Mutating CLI actions given an occupied create-only output target, an output that
aliases the journal or its state files, or a snapshot that exceeds the
output-size boundary MUST fail before appending to the journal; an occupied or
aliased target MUST also fail before creating a missing journal.

The feature MUST NOT perform provider access, network synchronization,
background polling, hook installation, or server startup. It MUST NOT claim
that hash-chain integrity authenticates an author or proves an event true.

## MODIFIED

None.

## REMOVED

None.
