# Proposal

## Problem

MasterAgent has explicit platform contracts but no Windows implementation for
filesystem trust or cross-process locks. Existing path and approval identities
encode POSIX device, inode, UID, and mode values, while Windows security depends
on retained kernel handles, file IDs, SIDs, DACLs, volume type, and namespace
rules. Marking POSIX-like calls as compatible would make replacement and
untrusted-writer attacks invisible.

## Desired outcome

Provide native Windows 11 filesystem identity, restricted read/create/write,
and locking primitives with the same fail-closed intent as the certified POSIX behavior.
Bind the native identity into approvals, expose truthful partial runtime
readiness, and keep every incomplete state/effect contract unavailable.

## Scope

This change adds the Windows handle/ACL and `LockFileEx` backends, a versioned
platform-object identity, Windows path and volume policy, retained directory and
file pins, bounded restricted reads, exclusive DACL-at-create publication with
bounded write/flush/readback and identity-bound cleanup, execution-context
binding, focused native CI, semantic ownership, and operator/developer
documentation. It preserves the existing POSIX implementation.

## Rationale

Completing the lowest-level security primitive first gives later atomic state,
credentials, process, Git, capsule, and organization-trust changes a single
reviewed Windows boundary. Partial contract reporting makes that incremental
delivery honest without granting stateful capability early.

## Alternatives considered

POSIX emulation, pathname-only `Path.resolve`, shelling out to ACL tools, and
accepting any local filesystem were rejected because none proves stable object
identity and effective write authority. Shipping all Windows work as one large
change was rejected because independently unavailable contracts already allow
safe staged certification.

## Non-goals

This change does not implement atomic replacement/recovery or retention (#100), Windows
credential brokers (#101), Git/process/capsule isolation (#102–#104), full
organization trust configuration (#111), or native release certification
(#106/#107). It does not accept remote or cloud-backed mutable state.

## Risks

The main risks are incomplete ACE parsing, handle/path identity drift, unsafe
Windows namespace aliases, stale trust configuration, and accidentally
enabling state operations when only two contracts are ready. Exact DACL
evaluation, retained no-delete-share handles, versioned bindings, adversarial
native tests, and unchanged fail-closed contract admission mitigate them.
