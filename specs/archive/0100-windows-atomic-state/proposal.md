# Proposal

## Problem

MasterAgent can pin Windows files and directories and coordinate native locks,
but it still reports atomic publication and recovery unavailable. Every
security-sensitive persistence caller therefore either fails before use or
contains POSIX-only descriptor, mode-bit, rename, unlink, and directory-fsync
operations. Treating those calls as portable would lose the crash and identity
guarantees that protect approvals, credentials, tokens, audit state, retained
evidence, capsules, and plugins.

## Desired outcome

Advertise a native Windows atomic-publication backend only after protected
state can be created, read, replaced, recovered, and removed through retained
handles with deterministic locking and explicit recovery. Route every existing
protected persistence family through that backend on Windows without changing
the certified POSIX behavior.

## Scope

This change adds protected directory creation, handle-relative atomic file
replacement and deletion, file and directory flushes, a protected bounded
integrity-checked prepare/commit ledger, exact recovery,
identity/digest/owner/DACL verification,
and a platform-neutral state transaction surface. It ports SQLite/audit,
approval and readiness output, retained evidence and quarantine, explicit
configuration snapshots, retained credential files, OAuth token files,
capsule/plugin state, advisory state, and other protected local stores that
currently require POSIX persistence primitives.

## Rationale

A single typed state boundary keeps Windows security semantics out of business
logic and prevents each caller from inventing weaker pathname-based recovery.
Keeping the existing POSIX implementations in place minimizes regression risk
while letting Windows use the native handle and ACL primitives delivered by
#99.

## Alternatives considered

Using ordinary `Path.write_bytes`, `os.replace`, POSIX emulation, or SQLite's
pathname connection directly was rejected because those approaches reopen
unvalidated names and cannot prove destination identity or DACL state.
Treating a successful Windows rename as fully durable without a ledger was
rejected because an interrupted replacement can be indeterminate. Moving the
credential provider, Git sandbox, process supervision, or AppContainer work
into this change was rejected because issues #101–#104 own those contracts.

## Non-goals

This change does not add Credential Manager or DPAPI providers, trusted Git
execution, Job Object supervision, AppContainer isolation, organization SID
policy configuration, packaging certification, or the full Windows adversarial
matrix. It does not weaken existing byte limits, redaction, approval, or
retention rules.

## Risks

The principal risks are replacing a target after identity drift, treating a
partial rename as success, losing a recovery record, accepting inherited broad
access, deadlocking concurrent writers, or leaving a temporary generation
public. Protected exclusive creation, retained handles, pre/post identity and
ACL checks, a flushed integrity-checked prepare/commit ledger, exact old/new
reconciliation,
stable lock files, bounded I/O, interruption tests, and native standard-user
coverage mitigate those risks.
