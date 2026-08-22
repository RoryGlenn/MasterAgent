# MA-WINDOWS-CREDENTIALS-001 — Native Windows credential storage and selection

## Status

Active

## Requirement

On native Windows 11, MasterAgent MUST provide production-ready current-user
Windows Credential Manager and DPAPI credential providers behind the typed
credential-provider boundary. Credential Manager targets MUST be bounded,
configuration-selected, Generic entries beneath a stable namespace. Each entry
MUST admit only one exact declared credential name and a bounded UTF-8 value.
DPAPI MUST protect a bounded structured credential document in the current-user
context, MUST use UI-forbidden operation, MUST NOT select machine scope, and
MUST bind optional entropy to the exact application/path identity. Only a
versioned, bounded, ciphertext-only envelope MAY reach disk, and it MUST be
published, recovered, and removed through the protected native Windows
atomic-state backend.

Credential resolution MUST admit only credential names declared by the
selected connector configuration and MUST keep every credential value and
ciphertext out of plans, logs, audit records, readiness, diagnostics,
exceptions, evidence, equality, and representations. The reviewed provider
kind, target, and connector configuration identity MUST be the only source
metadata bound into execution context. Production broker adapters MUST resolve
one exact provider, account, and credential name on demand and MUST NOT give
generated code or planning models raw secret values.

Source selection MUST be deterministic across environment, restricted JSON,
Credential Manager, and DPAPI adapters. Existing configurations MUST continue
to select the environment adapter. An explicitly configured provider MUST win
over same-name ambient values and MAY diagnose only the shadowed credential
names. An implicit multi-source selection MUST fail closed. Windows environment
names MUST use case-insensitive comparison so case-variant names cannot evade
duplicate or allowlist checks. Existing environment and restricted JSON
development adapters MUST remain compatible, and MasterAgent MUST NOT
silently migrate, rewrite, or delete an existing credential file.

## Rationale

Windows provides user-bound secret facilities that avoid plaintext credential
files. Explicit source identity and current-user cryptographic scope preserve
deterministic execution and least privilege without weakening the established
connector, approval, or redaction boundaries.

## Scenarios

### Credential Manager satisfies a declared connector

- GIVEN a connector explicitly selects a reviewed Credential Manager namespace
- WHEN the runtime resolves its declared credential names
- THEN it reads only the corresponding Generic current-user entries
- AND connector resolution succeeds without a plaintext file or secret-bearing
  execution-context field

### DPAPI structured state remains user-bound

- GIVEN a connector explicitly selects an absolute DPAPI store path
- WHEN trusted setup publishes credentials and the same user later resolves
  them
- THEN disk contains only the protected envelope and the same user recovers the
  exact declared values
- AND an unprotect failure from another security context is bounded and reveals
  no plaintext, ciphertext, or credential value

### Explicit provider wins without hiding ambiguity

- GIVEN a reviewed provider contains a declared name and the Windows
  environment contains the same name with different casing
- WHEN the configured provider is resolved
- THEN its value wins and diagnostics contain only the shadowed declared name
- AND two case-variant implicit environment sources fail closed

### Legacy adapters do not migrate

- GIVEN an existing restricted JSON development store
- WHEN it is loaded through the existing explicit file option
- THEN its permission, allowlist, collision, and in-memory adaptation behavior
  remains compatible
- AND the file bytes are not rewritten or imported into a Windows provider

## Implementation

- `src/master_agent/platform_runtime/contracts.py`
- `src/master_agent/platform_runtime/windows/credentials.py`
- `src/master_agent/platform_runtime/windows/runtime.py`
- `src/master_agent/config.py`
- `src/master_agent/credentials.py`
- `src/master_agent/credential_broker.py`
- `src/master_agent/cli.py`
- `scripts/semantic_router.py`

## Verification

- `tests/test_windows_credentials.py`
- `tests/test_windows_credential_cli.py`
- `tests/test_config.py`
- `tests/test_credentials.py`
- `tests/test_capsule_broker_and_routing.py`
- `tests/test_windows_platform_runtime.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #101.
