# Requirement deltas

## ADDED

### MA-TRUST-PROFILES-001 — Explicit resource trust classes

MasterAgent MUST keep user-private, organization-managed configuration,
approved installed runtime, credential source, and writable effect-state trust
as distinct classes. An organization-managed configuration MUST be selected by
an already trusted user-private organization profile, bound to an exact SHA-256
digest and explicit platform writer identities, read through retained local
identity, and rejected when the effective user can modify it or when any
untrusted principal can write it. The selected trust class and reason MUST be
reported without paths, principal identifiers, or content.

## MODIFIED

### MA-WINDOWS-FILESYSTEM-001 — Native Windows filesystem identity and locking

The configured additional SID policy MUST be able to exclude the effective
user for organization-managed read-only configuration. The policy choice and
complete SID set MUST remain immutable and identity-bound, while contextual
SIDs, reparse paths, remote namespaces, and untrusted writers remain rejected.

### MA-WINDOWS-INSTALL-001 — Native Windows installation

A bootstrap marker MUST NOT by itself authorize reuse. Before reuse,
bootstrap MUST independently verify the selected interpreter/virtual
environment identity, installed MasterAgent version and distribution/build
identity, and the exact dependency-policy digest. Failure MUST preserve the
existing environment and choose a fresh bounded side-by-side path.

### MA-WINDOWS-CERTIFICATION-001 — Windows release certification

Organization ACL-inheritance and approved support/EDR-principal policy have
hosted-safe software evidence after this change, but MUST remain explicit
certification-only blockers on #106 until an enrolled managed standard-user
Windows 11 x64 host supplies the real ACL evidence. Closed software issue #107
and completed implementation issue #111 MUST NOT be used as live-host evidence.

## REMOVED

None.
