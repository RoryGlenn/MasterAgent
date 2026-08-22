# Requirement deltas

## ADDED

### MA-WINDOWS-CREDENTIALS-001 — Native Windows credential storage and selection

Native Windows MUST provide current-user Credential Manager and DPAPI
credential providers. DPAPI MUST omit machine scope, keep plaintext out of the
filesystem, and publish only a bounded encrypted envelope through the native
atomic-state backend. Resolution MUST admit only declared credential names,
keep all values out of representations and diagnostics, bind non-secret source
identity through reviewed connector configuration, and select explicit sources
deterministically. Windows environment names MUST be compared
case-insensitively so implicit duplicates fail closed; an explicitly configured
provider MUST win over shadowed ambient values while reporting only their
names. Existing environment and restricted-file adapters MUST remain
compatible, and no existing file may be migrated or rewritten automatically.

## MODIFIED

None.

## REMOVED

None.
