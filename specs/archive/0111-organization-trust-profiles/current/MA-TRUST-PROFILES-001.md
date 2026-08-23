# MA-TRUST-PROFILES-001 — Explicit resource trust classes

## Status

Active

## Requirement

MasterAgent MUST keep user-private resources, organization-managed read-only
configuration, approved installed runtimes, credential sources, and writable
effect state as distinct trust classes. A control admitted for one class MUST
NOT authorize another class.

An organization-managed configuration MUST be selected from an already trusted
user-private organization profile. That profile MUST bind the exact
configuration name, local path, SHA-256 content digest, and bounded platform
writer identities before the managed bytes are opened. The managed file and
its selected parent MUST be retained by native identity, MUST reject links,
reparse/cloud objects, remote namespaces, replacement, and untrusted write
authority, and MUST reject any layout that gives the effective user write
authority. The managed bytes MUST NOT authorize their own digest or writers.

POSIX evaluation MUST accept only configured owner UIDs and MAY accept a
configured writer GID only when the effective process is not a member; other
write access MUST fail. Windows evaluation MUST accept only configured writer
SIDs plus fixed operating-system administration principals and MUST exclude
implicit effective-user writer trust, including an allowed group enabled in the
effective token. User-private configuration MUST retain the current user-owned
non-shared-writable behavior and MUST reject symbolic parent traversal and
extended ACLs that the owner/mode projection cannot safely authorize.

Readiness and setup diagnostics MUST identify `user-private` or
`organization-managed` and the content-bound validation reason without
rendering configured paths, principal identifiers, file content, or secrets.
Credential providers MUST retain deterministic explicit-source precedence and
writable state MUST remain local/private or separately approved external state.

## Rationale

Company configuration is often owned by deployment administrators and only
readable by employees. Exact content and writer binding admits that safe shape
without confusing it with user-editable state, executable provenance, or
secret storage.

## Scenarios

### Organization-managed configuration is content and writer bound

- GIVEN a private profile names a local read-only configuration, its digest,
  and the exact administrator writer identities
- WHEN a standard user loads that configuration
- THEN the retained object identity, effective write authority, and digest all match
- AND the bytes are accepted without granting that trust to state or credentials

### User or untrusted writer access fails closed

- GIVEN managed configuration whose owner, group, DACL, content, or namespace differs
- WHEN the profile-selected source is captured
- THEN capture fails before parsing, approval, credential resolution, or provider access
- AND the diagnostic reveals no path, principal, content, or secret

### User-private behavior remains compatible

- GIVEN an explicit configuration owned by the current user and not shared-writable
- WHEN no managed trust declaration is selected
- THEN the existing descriptor or handle validation and immutable snapshot behavior applies

## Implementation

- `src/master_agent/config_sources.py`
- `src/master_agent/operating.py`
- `src/master_agent/cli.py`
- `src/master_agent/platform_runtime/windows/filesystem.py`
- `scripts/bootstrap_agent.py`

## Verification

- `tests/test_config_sources.py`
- `tests/test_operating.py`
- `tests/test_operating_modes.py`
- `tests/test_agent_bootstrap.py`
- `tests/test_windows_platform_runtime.py`

## History

- Introduced by GitHub issue #111.
