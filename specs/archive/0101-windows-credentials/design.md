# Design

## Approach

Extend the platform runtime with a narrow credential-storage service. The
Windows implementation exposes two exact source kinds:

- Generic Credential Manager entries, one bounded UTF-8 value per declared
  credential name beneath a reviewed namespace; and
- one versioned structured credential document protected with current-user
  DPAPI and path-bound optional entropy, stored as a bounded ciphertext-only
  envelope through the Windows atomic-state transaction.

The platform-neutral credential snapshot remains the adapter used by connector
construction. Reviewed connector configuration selects `environment`,
`windows-credential-manager`, or `windows-dpapi` and supplies a non-secret
target. That configuration already contributes its complete identity and
source digest to the execution context, so values never enter a plan or audit
binding.

Production provider adapters implement the existing `CredentialProvider`
protocol and resolve one exact principal/account/name on demand. Storage APIs
are also available for trusted setup tooling without accepting secrets on
command lines.

## Affected components

- platform contracts and Windows runtime selection;
- Win32 native credential and cryptography bindings;
- credential parsing, selection, and broker adapters;
- connector readiness/discovery/connect/applied-run environment assembly;
- Windows native CI; and
- configuration, architecture, threat-model, and operations guidance.

## Data flow

1. A reviewed connector configuration selects one source kind and target.
2. The runtime verifies Windows credential-storage availability before any
   secret access.
3. Credential Manager reads exact names, or DPAPI reads an exact protected
   ciphertext generation and decrypts it in the current-user context.
4. The parser validates names and bounded string values without rendering
   values.
5. Explicit selected values replace same-name ambient entries using Windows
   case-insensitive name comparison; only shadowed names may be diagnosed.
6. Connector resolution receives the in-memory mapping and execution context
   records only the reviewed connector/configuration identities.

## Failure and recovery

Credential Manager operations fail with bounded messages and roll back a
partially applied multi-entry trusted setup operation where possible. DPAPI
read fails closed on malformed envelopes, wrong scope/description, invalid
ciphertext, another user context, unexpected names, or atomic-state drift.
Atomic-state recovery completes before decrypting or publishing another
generation.

## Compatibility

Connectors without `credential_provider` continue reading the environment.
The explicit `--credentials-file` development path keeps its existing schema,
permission, collision, mapping, and no-rewrite behavior. The new platform
contract is additive; POSIX reports it unavailable without blocking either
legacy adapter.

## Security

- `CRYPTPROTECT_LOCAL_MACHINE` is never used.
- UI prompts are forbidden in unattended runtime access.
- Credential blobs and plaintext documents have strict byte/count bounds.
- DPAPI ciphertext is additionally protected by the current private DACL and
  retained-handle atomic-state contract.
- Credential Manager targets and DPAPI paths are non-secret, bounded, and
  configuration-bound.
- errors, readiness, logs, plans, evidence, and object representations contain
  names/identities only, never values or ciphertext.
- case-variant environment names cannot create two implicit sources.

## Rejected alternatives

- Shelling out to `cmdkey`, PowerShell, or a generic keyring package would add
  subprocess, quoting, dependency, and provider-selection ambiguity.
- Machine-scoped DPAPI would let another account on the host decrypt state and
  violates the current-user default.
- Automatically importing a JSON credential file would mutate an existing
  security boundary without explicit operator intent.
