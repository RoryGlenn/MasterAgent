# Requirement deltas

## ADDED

### MA-WINDOWS-FILESYSTEM-001 — Native Windows filesystem identity and locking

On native Windows 11, MasterAgent MUST implement `secure_filesystem` with
retained Win32 handles, stable volume/file identity, owner SID and effective
DACL validation, and MUST implement `cross_process_locking` with
`LockFileEx`. Security-sensitive path reads and approval bindings MUST use
those native identities without falling back to pathname-only or POSIX
emulation. The filesystem backend MUST also provide exclusive create-only
private-file publication with an explicit protected DACL at creation, bounded
write/flush/readback, path-to-handle revalidation, and exact-identity cleanup;
it MUST NOT claim atomic replacement or recovery. Unsupported path namespaces,
volumes, filesystems, reparse/cloud objects, case-sensitive directories, unsafe
names, and untrusted writers of selected targets MUST fail closed. Retained
immutable ancestors MAY permit unrelated child creation, but MUST reject
untrusted deletion, replacement, metadata, DACL, owner, and generic-write
authority, with the exact ancestor policy bound into revalidation. The exact
Windows `OWNER RIGHTS` well-known SID MAY carry access only as an alias for an
owner that separately passes admission and revalidation; it MUST NOT enter the
configured trusted-SID set. No other applying well-known SID MAY receive this
owner-alias treatment; each MUST remain subject to the ordinary trusted-SID and
dangerous-access evaluation. Other incomplete Windows contracts MUST remain
unavailable.

## MODIFIED

None.

## REMOVED

None.
