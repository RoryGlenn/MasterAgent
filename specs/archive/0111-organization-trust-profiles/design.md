# Design

## Approach

Add an immutable per-configuration trust declaration to the organization
profile. The declaration contains `class = "organization-managed"`, an exact
content SHA-256, and bounded POSIX UID/GID and Windows SID writer allowlists.
The existing private profile remains the source of that policy, so managed
configuration cannot authorize itself.

`resolve_config_source` accepts the optional immutable declaration. POSIX reads
retain descriptor identity, require an allowed non-user owner, calculate
write-capable owner/group/other access against the effective process groups,
and compare the captured payload digest. Windows reads create a bounded
filesystem policy with the declared additional SIDs and with implicit
current-user writer trust disabled. It also rejects any configured or fixed
writer SID enabled in the effective token, then compares the same digest.

Bootstrap records a versioned JSON attestation only after installation. Reuse
first evaluates every runtime object's POSIX permissions/ACLs or retained
Windows DACL and independently hashes
the environment configuration, interpreter target, launcher, distribution
identities, installed package files, source/install digest, and dependency
policy before comparing the result with the attestation. Only a byte-for-byte
match runs the fixed `-I -S` interpreter probe, so candidate site initialization
and installed code do not run during the probe. An unverifiable candidate is
skipped and never executed as the readiness launcher.

The hosted-safe managed-policy test becomes the exact software evidence for
the ACL-inheritance and support/EDR registry entries. Both remain blocked on
#106 because only the protected enrolled x64 runner can supply managed-host
certification evidence.

## Affected components

- `src/master_agent/config_sources.py`
- `src/master_agent/operating.py`
- `src/master_agent/cli.py`
- `src/master_agent/platform_runtime/windows/filesystem.py`
- `scripts/bootstrap_agent.py`
- focused configuration, operating, bootstrap, and Windows tests
- organization-profile schema examples and operator documentation

## Data flow

1. A private profile is captured and parsed.
2. A selected configuration path is paired with its immutable trust declaration.
3. The platform reader retains the local object identity and evaluates writers.
4. Captured bytes are digest-checked before parsing and approval binding.
5. Readiness reports the class and validation reason without sensitive details.

## Compatibility

Existing profiles without `[configuration_trust]` remain user-private and use
the existing behavior. Existing credential adapters and private state paths do
not consume configuration trust declarations. Existing legacy hexadecimal
bootstrap markers are treated as unverifiable and repaired side by side.

## Security

Managed bytes cannot select their own digest or writers. POSIX other-writable
objects always fail, trusted group write fails when the effective user belongs
to that group, and extended ACLs fail because the declaration cannot bind named
POSIX principals. Windows current-user write fails in managed mode, and all
identity, reparse, local-volume, bounded-read, and approval checks remain.
User-private POSIX inputs also reject symbolic parent traversal and extended
ACLs so their owner/mode checks cannot hide a named writer.

## Rejected alternatives

Global ambient allowlists and environment-variable policies were rejected
because they are not profile-bound. Reusing a marker without an interpreter
probe was rejected because the environment may have changed after installation.
