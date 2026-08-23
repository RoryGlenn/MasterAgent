# MA-WINDOWS-FILESYSTEM-001 — Native Windows filesystem identity and locking

## Status

Active

## Requirement

On native Windows 11, MasterAgent MUST advertise `secure_filesystem` only when
the runtime supplies retained Win32 handle traversal, versioned object
identity, owner-SID and effective-DACL trust evaluation, bounded restricted
reads, and stable revalidation. It MUST advertise `cross_process_locking` only
when whole-file shared and exclusive `LockFileEx` operations are available.
The selected backend identities and unavailability reasons MUST remain stable
and secret-free.

The filesystem backend MUST create a restricted regular file only at a new
immediate child name of a retained directory. It MUST attach an explicit
protected user-private DACL as part of creation, reject an existing name,
enforce the caller's byte limit while writing, flush and bounded-read back the
same handle, revalidate the namespace entry against the handle identity and
security policy, and remove an incomplete file only when its current namespace
identity still equals the identity it created. These primitives MUST NOT be
reported as atomic replacement or crash recovery.

The versioned platform-object identity MUST discriminate POSIX and Windows
payloads. POSIX bindings MUST retain their device, inode, owner, and mode
semantics. Windows bindings MUST include volume serial number, 128-bit file ID,
object kind, owner SID, a canonical DACL or security-policy digest, and the
exact trusted-writer policy digest. Approval capture and execution MUST compare
the complete native identity, and writable roots MUST be distinct by native
volume/object identity rather than display path.

Windows traversal MUST open and retain every existing ancestor and final
object with no delete sharing, inspect reparse and cloud attributes on the
opened handles, and revalidate stable identity and security metadata before and
after use. It MUST reject symlinks, junctions, mount points, unsupported reparse
types, cloud placeholders, ancestor or final-object replacement, owner or DACL
broadening, and case-sensitive directory semantics. Native restricted reads
MUST consume the already validated handle and enforce a caller-supplied byte
limit.

The Windows path policy MUST accept canonical absolute local drive paths and
Unicode/long-path names without lossy normalization. It MUST reject relative,
UNC/SMB, device, NT, volume-GUID, and other remote namespaces; alternate data
streams; reserved device names; control or reserved characters; dot traversal;
and components ending in a space or period. Trusted mutable objects MUST reside
on a fixed local NTFS or ReFS volume until another filesystem is separately
certified. Case-insensitive name and handle-path comparisons MUST use Windows
ordinal uppercase-table semantics rather than linguistic or Unicode full case
folding, so names such as `ß` and `ss` remain distinct when Windows treats them
as distinct.

The DACL policy MUST reject a missing or null DACL. On the selected target or
mutable root it MUST reject any untrusted principal that can write data or
attributes, create or delete children, delete the object, change its DACL, or
change ownership. A retained immutable ancestor MAY permit the directory-only
right to create an unrelated file or subdirectory, because every selected
component already exists and its handle denies delete sharing, but it MUST
still reject untrusted child deletion, object deletion, metadata writes,
DACL/owner changes, generic writes, or any other replacement-capable right.
The ancestor/target/private policy mode MUST be included in the immutable
trust-policy digest and revalidated with the retained handle. The default
user-private policy MUST trust only the effective user plus fixed
operating-system administration principals. The exact Windows `OWNER RIGHTS`
well-known SID MAY carry access only as an alias for an owner that has already
passed that trust policy; it MUST NOT enter the configured trusted-SID set or
bypass owner admission or revalidation. No other applying well-known SID MAY
receive this owner-alias treatment; each MUST remain subject to the ordinary
trusted-SID and dangerous-access evaluation. An organization-managed
read-only configuration policy MUST accept an explicit bounded SID writer set
supplied by an already trusted user-private profile, MUST retain only that set
plus the fixed operating-system administration principals, and MUST exclude
implicit effective-user trust. A configured or fixed writer SID enabled in the
effective token MUST reject managed mode. The file being authorized MUST NOT
be able to authorize its own writers. The policy choice, complete trusted-SID
set, and digest MUST be immutable for the lifetime of a pin.

`LockFileEx` MUST preserve deterministic shared, exclusive, blocking, and
nonblocking intent for Python file descriptors and MUST map lock contention to
`BlockingIOError`. Locks MUST be released explicitly and by handle closure.
Atomic replacement/recovery, persistent state, retention, credential-provider,
process, Git, and capsule contracts that are not completed by this change MUST
remain unavailable, so no existing operation can silently downgrade through
the new partial Windows runtime.

## Rationale

Windows file security is defined by kernel object identity and access-control
lists, not Unix inode ownership and mode bits. Retained native handles and an
approval-bound trust-policy digest prevent pathname replacement and policy
drift while allowing later state and organization-trust work to reuse one
certified primitive.

## Scenarios

### Trusted local directory is pinned and approval-bound

- GIVEN a standard-user directory on a fixed NTFS or ReFS volume whose DACL
  grants write authority only to the user and trusted system principals
- WHEN MasterAgent captures and later reopens the runtime path
- THEN every ancestor and the leaf remain pinned by retained handles
- AND the exact volume/file ID, owner SID, DACL digest, and trust-policy digest
  match the approved platform-object identity

### Replacement or permission broadening fails closed

- GIVEN an approved Windows path or restricted file
- WHEN an ancestor, final object, owner, DACL, reparse status, or cloud status
  changes before or during use
- THEN validation fails before bytes or effects are accepted
- AND no pathname-only retry or weaker fallback occurs

### Owner Rights remains bound to the validated owner

- GIVEN a Windows object owned by an admitted user or system principal
- AND its DACL grants access through the `OWNER RIGHTS` well-known SID
- WHEN MasterAgent admits and later revalidates the object
- THEN that SID is evaluated only as an alias for the separately trusted owner
- AND an untrusted owner or owner change still fails closed
- AND the distinct `CREATOR OWNER` SID remains untrusted

### Ordinary system ancestors do not weaken the selected target

- GIVEN a retained Windows ancestor that permits an untrusted principal only
  to create an unrelated child
- WHEN a private selected descendant is pinned and used
- THEN the ancestor remains identity/DACL-bound without blocking the pin
- AND child deletion, metadata, generic-write, ACL, owner, or target mutation
  authority still fails closed

### Organization-managed configuration excludes the effective user

- GIVEN a private organization profile binds an exact configuration digest
  and approved administrator or support writer SIDs
- WHEN the Windows backend retains and reads that managed configuration
- THEN the current user is excluded from the immutable trusted-writer policy
- AND ordinary inherited access by configured principals remains admissible
- AND an unconfigured write-capable principal or owner fails closed

### Unsafe Windows namespaces and names are rejected

- GIVEN a relative, UNC, device, alternate-stream, reserved-name,
  trailing-dot/space, case-sensitive, remote, unsupported-filesystem, or
  reparse/cloud path
- WHEN the secure-filesystem backend is asked to pin or read it
- THEN the request fails with a bounded non-secret configuration error

### Windows ordinal Unicode names remain lossless

- GIVEN a case-insensitive Windows directory containing Unicode names that are
  distinct under the operating system's ordinal uppercase table
- WHEN the backend lists, pins, or exclusively creates an immediate child
- THEN canonical case aliases still match and fail closed where required
- AND linguistic expansions such as `ß` to `ss` never create a false collision

### Native locks are deterministic under contention

- GIVEN independent Windows processes holding or requesting the same whole-file
  region
- WHEN shared, exclusive, blocking, and nonblocking locks contend
- THEN compatible shared locks succeed, conflicting nonblocking locks raise
  `BlockingIOError`, and a blocking waiter proceeds only after release

### Restricted create-only publication stays identity-bound

- GIVEN a trusted pinned directory and a new immediate child name
- WHEN the backend publishes bounded private bytes
- THEN the file is created exclusively with its protected DACL, flushed,
  read back, and revalidated against the same retained handle
- AND failure removes only the exact identity created by that attempt
- AND replacement or crash-recovery availability is not implied

### Partial runtime does not enable incomplete state

- GIVEN the filesystem and locking backends are available on Windows
- WHEN an operation also requires atomic publication or another incomplete
  contract
- THEN native admission fails before protected state or effects
- AND readiness reports the implemented and unavailable contracts separately

## Implementation

- `src/master_agent/platform_runtime/contracts.py`
- `src/master_agent/platform_runtime/factory.py`
- `src/master_agent/platform_runtime/windows/native.py`
- `src/master_agent/platform_runtime/windows/filesystem.py`
- `src/master_agent/platform_runtime/windows/locking.py`
- `src/master_agent/platform_runtime/windows/runtime.py`
- `src/master_agent/directory_safety.py`
- `src/master_agent/execution_context.py`
- `src/master_agent/models.py`
- `src/master_agent/config_sources.py`
- `src/master_agent/credentials.py`
- `src/master_agent/oauth.py`
- `src/master_agent/trust_store.py`
- `src/master_agent/approval_handoff.py`
- `src/master_agent/capsules.py`
- `src/master_agent/plugins.py`
- `src/master_agent/oauth_config.py`
- `src/master_agent/config.py`
- `src/master_agent/copilot_advisory.py`
- `src/master_agent/sqlite_safety.py`

## Verification

- `tests/test_windows_platform_runtime.py`
- `tests/test_platform_runtime.py`
- `tests/test_directory_safety.py`
- `tests/test_execution_context.py`
- `tests/test_capability_capsules.py`
- `tests/test_plugins.py`
- `tests/test_approval_handoff.py`
- `tests/test_oauth_readiness.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #99.
- Added explicit non-user organization-managed trust in GitHub issue #111.
