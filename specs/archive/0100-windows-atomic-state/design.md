# Design

## Approach

Extend the atomic-publication contract with bounded file-transaction
operations and implement it twice: the existing POSIX callers retain their
current descriptor-bound implementations, while the Windows backend owns a
native state directory and transaction object. Windows creation uses the
protected security descriptor from the filesystem backend. Replacement and
deletion use live file handles and a retained parent handle. Each mutation is
serialized through a stable protected lock file and accompanied by a compact,
bounded, checksummed prepare/commit ledger that names exact native file IDs and
content digests.

The common protected-persistence entry points select the Windows backend only
on a native Windows runtime. SQLite continues to execute in memory and stores
serialized database generations through the state transaction. Other callers
use bounded JSON/text/byte publication, exact removal, directory enumeration,
or pair/quarantine transactions as appropriate. POSIX paths keep their
existing implementation and tests.

## Affected components

- platform atomic contracts and Windows runtime selection
- Win32 native create-directory, handle-relative rename/delete, and flush APIs
- protected state transaction and recovery implementation
- SQLite/audit and recurring state
- approval/readiness output, configuration snapshots, credential/token files
- retention publication, expiration, repair, and quarantine
- capsule, plugin, advisory, and draft local stores
- Windows startup/native tests, semantic routing, specifications, and operator
  documentation

## Data flow

A caller requests persistent-state admission, pins or creates its private root,
and opens the stable per-target lock by retained handle. A read validates the
full parent chain, file ID, owner SID, DACL, size, and digest before returning
bounded bytes. A write creates a protected temporary file exclusively, writes,
flushes, reads back, and captures its identity. The ledger is flushed with a
prepare record containing the expected public generation and prepared
generation. Initial ledger publication is itself staged so interruption cannot
leave a torn public ledger. After a final revalidation, the temporary handle is renamed over
the exact target relative to the retained parent. The backend reopens and
verifies that the public identity equals the prepared handle, then flushes and
records commit. On restart, the public entry must match exactly the recorded old
or new generation; the backend commits or aborts that outcome and rejects every
third state. Retention pair removal and quarantine add one coordinator-held,
content-free intent that records exact source identities and the required final
state before either member is removed or copied.

## Compatibility

Public Python and CLI behavior, serialized application payloads, limits, and
POSIX filesystem semantics remain unchanged. Windows readiness changes only
the atomic contract from unavailable to available; process supervision,
trusted Git, and capsule isolation remain separately unavailable. Existing
POSIX state and ledgers require no migration. Windows state created by this
change is rejected rather than guessed if its ledger or ACL is malformed.

## Security

All path, ledger, ACL, identity, and content data are untrusted. No caller may
replace, delete, or quarantine a destination after reopening an unvalidated
path. Public identity and security are checked before and after mutation, and
the target parent remains pinned. Every temporary, lock, and ledger file is
created with an explicit protected private DACL. Records and payloads are
bounded and secrets never appear in errors. Rename failure is treated as
indeterminate until exact recovery proves old or new. A target or ACL race, a
third identity, sidecar, reparse object, or broadened writer fails closed.

## Rejected alternatives

`MoveFileExW` with absolute paths was rejected because it does not bind the
destination to the retained parent. Direct in-place writes were rejected
because torn payloads cannot be reconciled. A single global lock was rejected
because unrelated stores should not block one another. Rewriting the audited
POSIX retention and SQLite algorithms around Windows concepts was rejected in
favor of explicit native branches behind the common contract.
