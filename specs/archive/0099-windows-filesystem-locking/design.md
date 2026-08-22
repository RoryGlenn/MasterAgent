# Design

## Approach

Add a lazily imported native Windows runtime that selects only a handle/ACL
filesystem backend and a `LockFileEx` backend. The filesystem backend validates
the input namespace and every path component, opens objects with Win32 handles
that omit delete sharing, captures stable file and security information, and
retains the full ancestor chain. A versioned platform-neutral identity is added
to runtime-path approval bindings while legacy POSIX fields remain readable.

Read-only callers that need only `secure_filesystem` consume an already pinned
handle through bounded backend operations. Persistent-state callers continue to
request the full filesystem, locking, and atomic-publication set and therefore
remain unavailable until #100. Organization SID configuration is represented
as an explicit immutable policy input, but #111 owns its configuration and
deployment UX.

The filesystem contract also supplies the issue-required create-only
publication primitive. It creates a new immediate child with an explicit
protected DACL in the creation call, writes and flushes within a bound, reads
back and revalidates the same handle and namespace identity, and cleans up only
that exact created identity after failure. It does not replace an existing
name, reconcile an interrupted namespace change, or satisfy the atomic-state
contract; those operations remain #100.

## Affected components

- platform contracts, native Windows selection, and readiness projection
- Win32 path, volume, identity, ACL, restricted read/create/write, and lock
  primitives
- directory pinning and runtime execution/approval identity serialization
- secure-only configuration, credential, token, CA, approval, plugin, capsule,
  and advisory reads where native Windows semantics are required
- Windows CI, semantic routing, behavioral specifications, architecture,
  threat-model, operator, and release documentation

## Data flow

An operation first requests `secure_filesystem`. On Windows the factory loads
the native backend and its immutable trusted-writer policy. The backend rejects
unsafe syntax/namespaces before opening a handle, verifies a fixed NTFS/ReFS
volume, retains each no-delete-share ancestor handle, rejects special objects,
and captures identity/security metadata. A distinct ancestor ACL mode permits
only unrelated child creation commonly present on standard Windows roots;
delete-child, metadata, generic-write, ACL, owner, and replacement authority
remain forbidden, while selected targets retain the full public/private writer
policy. The mode is part of each handle's trust-policy digest. Restricted bytes
are read from the validated final handle within a caller limit, followed by
full-chain revalidation. Approval serialization binds the same platform
identity and policy digest; applied execution reopens and compares every field.
Lock callers translate a Python descriptor to its native handle and lock the
complete 64-bit range.

## Compatibility

POSIX selection, identities, descriptors, locks, and serialized legacy fields
retain their current behavior. Existing POSIX `@2` runtime bindings remain
readable. New bindings include an additive versioned platform-object identity;
Windows bindings require it and never infer trust from POSIX placeholder
fields. Windows package imports remain lazy. The runtime gains two available
contracts while all other Windows contracts keep bounded unavailable status.

## Security

The backend treats paths, ACLs, SIDs, and filesystem metadata as untrusted.
It rejects namespace aliases, reparse and cloud objects, untrusted write/delete
authority, null DACLs, owner or policy drift, and identity changes. Additional
organization SIDs are immutable explicit inputs and are incorporated into the
approval identity. The exact Windows `OWNER RIGHTS` well-known SID is treated
only as an alias for the separately admitted and continuously revalidated
owner, so CPython's private temporary-directory ACLs remain usable without
adding the alias to the configured trusted-SID set. Every other applying
well-known SID remains subject to the ordinary configured-principal and
dangerous-access evaluation. No authorized file can define its own trust
policy. A partial runtime cannot satisfy persistent-state admission.

## Rejected alternatives

A third-party Windows dependency was rejected because the required API surface
is small enough to bind directly and a mandatory package would expand the
supply-chain boundary. Converting native handles to POSIX-style directory FDs
was rejected because Python does not provide equivalent `dir_fd` semantics on
Windows. Trusting a file solely because the current user can open it was
rejected because another principal may still have write/delete authority.
