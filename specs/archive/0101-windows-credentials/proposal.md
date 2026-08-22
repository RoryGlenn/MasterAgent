# Proposal

## Problem

Native Windows can now protect files and publish crash-consistent state, but
connector credentials still come only from the process environment or a
restricted JSON development file. Windows operators need current-user
Credential Manager and DPAPI providers without weakening source selection,
approval binding, redaction, or the existing adapters.

## Desired outcome

Release a native `credential_storage` platform contract backed by Windows
Credential Manager and current-user DPAPI. A connector may explicitly select
one provider through its reviewed configuration, and the runtime will resolve
only its declared credential names before constructing that connector.

## Scope

- add the typed credential-storage platform contract;
- implement bounded Win32 Credential Manager and current-user DPAPI storage;
- keep DPAPI ciphertext beneath the native Windows atomic-state backend;
- implement production credential providers behind the existing broker
  protocol;
- support reviewed connector-level provider selection;
- normalize Windows environment names case-insensitively and keep diagnostics
  secret-free; and
- add native and pure regression coverage plus operator documentation.

## Rationale

The operating system already provides current-user secret services, and the
completed Windows filesystem/atomic backends can protect the DPAPI envelope.
Using those primitives behind the existing typed provider boundary avoids a
new dependency and keeps connector construction unchanged.

## Alternatives considered

- Continue requiring plaintext restricted files on Windows.
- Adopt a cross-platform keyring dependency and its runtime-specific plugins.
- Shell out to PowerShell or `cmdkey` for every credential operation.

## Non-goals

- machine-scoped DPAPI or service-account rollout policy;
- automatic migration or rewriting of restricted JSON files;
- organization-managed ACL/environment trust, which remains issue #111; and
- account provisioning or company distribution, which remains issue #113.

## Compatibility

Environment credentials and restricted JSON files retain their existing
interfaces. Existing configurations select the environment adapter by default.

## Risks

Win32 structure or memory-lifetime mistakes could expose or corrupt a secret;
native tests and bounded wrappers cover those paths. Multi-entry Credential
Manager updates are not inherently transactional, so trusted setup must retain
and restore prior entries on partial failure. DPAPI behavior depends on the
current Windows user profile and fails closed when that profile is unavailable.
