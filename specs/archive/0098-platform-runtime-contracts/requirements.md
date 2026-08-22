# Requirement deltas

## ADDED

### MA-PLATFORM-001 — Platform runtime contracts

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

## MODIFIED

None.

## REMOVED

None.
