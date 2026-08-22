# MA-PLATFORM-001 — Platform runtime contracts

## Status

Active

## Requirement

MasterAgent MUST expose deterministic `secure_filesystem`,
`cross_process_locking`, `atomic_publication_recovery`,
`process_supervision`, `trusted_git`, and `capsule_isolation` platform
contracts. Platform-neutral
package and CLI imports MUST NOT load operating-system-specific modules until
an operation selects the relevant backend. Selection MUST expose stable,
secret-free backend identity and availability, MUST preserve the certified
POSIX behavior, and MUST NOT substitute a compatibility shim or weaker fallback
when an equivalent secure backend is unavailable.

`capsule_isolation` availability MUST mean executable OS worker containment,
not owner/group trust for worker artifacts. Linux MAY advertise the certified
bubblewrap implementation only after selecting a trusted executable and MUST
otherwise report this contract unavailable. macOS MUST report this contract
unavailable until a native isolation backend is implemented; owner-private
group validation MUST remain under `secure_filesystem`. A test-only subprocess
selected with
`require_os_sandbox=False` MUST NOT advertise production isolation.

On Windows, `master_agent`, `master_agent.cli`, command help and version,
deployment readiness, and configuration-only progressive diagnostics MUST run
without initializing unavailable stateful backends. An operation that requires
an unavailable backend MUST fail with a stable bounded error before protected
state, credentials, connector construction, provider access, or effects. The
separate native Windows backend and hosted-certification areas MUST remain
planned until each supplies equivalent implementation and evidence.
Progressive doctor MAY report the bounded absent-profile setup state without
opening profile bytes. Reading an existing or explicit profile MUST require
`secure_filesystem` first.

Progressive readiness MUST include the secret-free platform summary and MUST
treat `install_ready` as the platform-neutral package and configuration-only
CLI surface, rather than as a claim that every stateful backend is available.
Draft, effect, and enterprise levels MUST remain false when a required secure
backend is unavailable, with a stable `runtime_defect` explanation that does
not initialize that backend. Capability readiness MUST likewise remain false
for a state-backed read whose required contract is unavailable; an eligible
stateless read MAY remain ready.

## Rationale

Package usability and secure operation are different claims. A user should be
able to inspect an installation without causing native state initialization,
while every operation still receives the exact filesystem, locking, atomicity,
process, Git, or capsule guarantee it requires. Explicit identities prevent a
future port from silently weakening that guarantee.

## Scenarios

### Windows configuration diagnostics stay usable

- GIVEN MasterAgent is installed on Windows before native secure state
  backends are implemented
- WHEN a user imports the package, requests command help or version, or runs
  deployment readiness or configuration-only progressive diagnostics
- THEN the command succeeds without loading a Unix-only module or initializing
  protected state
- AND the report identifies each relevant backend and its availability without
  exposing secrets

### Unavailable native operation fails before protected access

- GIVEN an operation requires a secure backend that is unavailable on the
  selected platform
- WHEN the operation requests that backend
- THEN it fails with the stable platform-unavailable error
- AND it does not inspect protected state, resolve credentials, construct a
  connector, contact a provider, or attempt a weaker fallback

### Native isolation status remains truthful

- GIVEN a Linux or macOS host and a capability-capsule worker request
- WHEN the runtime selects that backend
- THEN Linux reports the certified bubblewrap isolation identity only when a
  trusted executable is selected, and otherwise reports it unavailable
- AND macOS reports capsule isolation unavailable before executable discovery
- AND owner/group artifact validation remains a secure-filesystem operation
- AND the test-only subprocess route never claims production isolation

## Implementation

- `src/master_agent/platform_runtime/contracts.py`
- `src/master_agent/platform_runtime/factory.py`
- `src/master_agent/platform_runtime/posix/runtime.py`
- `src/master_agent/platform_runtime/windows/__init__.py`
- `src/master_agent/cli.py`
- `src/master_agent/operating.py`
- `src/master_agent/readiness.py`

## Verification

- `tests/test_platform_runtime.py`
- `tests/test_operating.py`
- `tests/test_operating_modes.py`
- `tests/test_release_metadata.py`

## History

- Introduced by GitHub issue #98.
