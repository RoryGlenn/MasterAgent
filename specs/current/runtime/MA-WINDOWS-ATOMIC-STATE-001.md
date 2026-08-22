# MA-WINDOWS-ATOMIC-STATE-001 — Native Windows atomic local state and recovery

## Status

Active

## Requirement

On native Windows 11, MasterAgent MUST advertise
`atomic_publication_recovery` only when it provides retained-handle,
protected-DACL, bounded, serialized local-state transactions. Every temporary,
lock, ledger, and sensitive public file MUST be created exclusively with an
explicit protected private DACL. Writes MUST enforce a caller-supplied bound,
flush and read back the same handle, and capture the exact content digest,
volume/file ID, owner SID, DACL digest, and trust-policy digest before
publication.

Replacement MUST first hold the stable native lock, revalidate the retained
parent and expected destination identity, and flush a bounded protected,
integrity-checked prepare record containing the exact old and new generation.
It MUST rename the
prepared file by its live handle relative to the retained parent, MUST NOT
reopen an unvalidated pathname between authorization and mutation, and MUST
verify that the public destination is the prepared identity with the expected
content and security before recording commit. The backend MUST flush every
file and directory boundary supported by the certified native path. A partial
rename or flush failure MUST leave an explicit recoverable or indeterminate
state; it MUST NOT be presumed to have POSIX rename semantics.

Recovery MUST parse only complete bounded ledger records and accept only the
recorded old or new generation, including a recorded absent generation. It
MUST make the observed old or new state the committed state and fail closed for
an unexpected absence, third identity, uninspectable object, security drift, or
digest mismatch. Exact removal MUST remain bound to retained handles and
recorded identities. Pair deletion and quarantine MUST publish a bounded,
content-free, exact-identity recovery intent before their first irreversible
step, then complete the recorded all-absent or destination-present/source-
absent state before removing that intent. Concurrent writers MUST serialize on
the stable target lock, and stale uncommitted state MUST be reconciled before a
new mutation.

SQLite/audit generations, approval handoff and restricted command output,
retained evidence and repair/quarantine state, explicit configuration
snapshots, supported credential and OAuth token files, advisory state,
capsule/plugin local stores, draft state, and every other protected persistence
caller MUST select the native Windows backend rather than POSIX descriptors,
UIDs, mode bits, `fcntl`, or pathname-only fallbacks. Existing byte limits,
secret-redaction behavior, payload formats, approval rules, and certified POSIX
behavior MUST remain unchanged.

## Rationale

Windows namespace and durability semantics differ from POSIX rename and
directory-FD semantics. Retained handles plus an explicit old/new ledger turn a
possibly interrupted replacement into a deterministic state machine while
owner/DACL and digest verification preserve the authorization boundary.

## Scenarios

### Serialized replacement commits

- GIVEN a private Windows state file and its stable lock
- WHEN a writer prepares and publishes a bounded replacement
- THEN the prepared bytes and ledger are flushed before the handle-relative
  rename
- AND the destination identity, digest, owner, and DACL match before commit
- AND a concurrent writer cannot observe or publish through the same lock

### Interrupted replacement reconciles exactly

- GIVEN a flushed prepare record and an interruption before or after rename
- WHEN the next operation recovers the target
- THEN the exact old public generation produces an abort and the exact new
  generation produces a commit
- AND every third, missing, changed-ACL, or uninspectable state is reported as
  indeterminate without a new mutation

### Protected persistence is native on Windows

- GIVEN a Windows operation using SQLite, approvals, retention, configuration,
  credentials, OAuth, advisory, capsule, plugin, draft, or restricted output
- WHEN it creates, reads, replaces, removes, repairs, or quarantines local state
- THEN it uses the Windows atomic-state and handle/ACL backends
- AND it does not invoke a POSIX descriptor, ownership, mode, or rename fallback

### Race and broad access fail closed

- GIVEN a target identity or DACL is replaced or broadened during a transaction
- WHEN publication or removal reaches its final validation
- THEN the operation fails without accepting the changed object
- AND temporary cleanup targets only the exact identity created by that attempt

## Implementation

- `src/master_agent/platform_runtime/contracts.py`
- `src/master_agent/platform_runtime/factory.py`
- `src/master_agent/platform_runtime/windows/native.py`
- `src/master_agent/platform_runtime/windows/filesystem.py`
- `src/master_agent/platform_runtime/windows/locking.py`
- `src/master_agent/platform_runtime/windows/atomic.py`
- `src/master_agent/platform_runtime/windows/runtime.py`
- `src/master_agent/sqlite_safety.py`
- `src/master_agent/retention.py`
- `src/master_agent/approval_handoff.py`
- `src/master_agent/config_sources.py`
- `src/master_agent/credentials.py`
- `src/master_agent/oauth.py`
- `src/master_agent/advisory_budget.py`
- `src/master_agent/capsules.py`
- `src/master_agent/plugins.py`
- `src/master_agent/connectors/drafts.py`
- `src/master_agent/operating.py`
- `src/master_agent/cli.py`

## Verification

- `tests/test_windows_atomic_state.py`
- `tests/test_windows_platform_runtime.py`
- `tests/test_sqlite_safety.py`
- `tests/test_retention.py`
- `tests/test_approval_handoff.py`
- `tests/test_oauth_readiness.py`
- `tests/test_plugins.py`
- `tests/test_capability_capsules.py`
- `tests/test_platform_runtime.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #100.
