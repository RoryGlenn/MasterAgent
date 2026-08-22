# Design

## Approach

Add one platform-runtime package whose public data is limited to normalized
platform family, stable backend identifiers, availability, and bounded reasons.
It exposes the exact `secure_filesystem`, `cross_process_locking`,
`atomic_publication_recovery`, `process_supervision`, `trusted_git`, and
`capsule_isolation` contracts.
Backend selection is deterministic and side-effect free. Platform-neutral
modules depend on this contract instead of importing Unix-only primitives at
module load. An operation asks for its exact backend immediately before use;
an unavailable selection raises the typed fail-closed error rather than
returning a partial implementation.

The initial Windows contract advertises the backend areas that are not yet
implemented. The import and configuration-only surfaces consume status only,
so they remain usable. Stateful setup and reads, draft/effect execution,
retention, process, Git, and capsule paths continue only when their exact
secure backend is available. Eligible stateless reads need no state contract.
Existing POSIX filesystem, locking, atomic-state, process, and Git
implementations remain selected and retain their current semantics. Linux
selects its bubblewrap worker-isolation implementation only when a trusted
executable is available. Linux otherwise reports capsule isolation unavailable,
and macOS reports capsule
isolation unavailable: account/group artifact trust remains part of the secure-
filesystem backend and cannot satisfy executable OS containment.

Readiness serializes the same status contract for both human and JSON output.
The progressive report keeps local package usability separate from stateful
capability readiness: unavailable state backends do not make the neutral
installation surface disappear, but they do block every readiness level and
operation that depends on those guarantees.

## Affected components

- the platform-runtime contract and its integration with package and CLI
  imports
- progressive `doctor`, deployment `readiness`, command help, and version
- filesystem/locking, atomic state, process, Git, and capsule backend callers
- Windows import/configuration smoke coverage and POSIX regression coverage
- the platform-runtime behavioral requirement and operating-mode modification
- semantic route ownership and generated documentation
- architecture, threat model, roadmap, CLI, release, README, and changelog
  documentation

## Data flow

At import time, platform-neutral package and CLI modules load no native backend.
Help, version, and offline readiness ask the platform registry for descriptive
status only. When a stateful operation begins, it requests the exact backend
area, validates availability, and either receives the certified implementation
or raises the typed unavailable error before any protected input or external
resource is resolved. Readiness projects the same immutable status into a
secret-free report.

## Compatibility

Supported POSIX systems select the existing non-isolation implementations and
preserve their current security and user-visible behavior. The Linux capsule
worker retains bubblewrap isolation when its trusted executable is available
and otherwise fails closed; the macOS worker continues to fail closed,
now through the truthful unavailable contract instead of a later generic
bubblewrap error. `require_os_sandbox=False` remains a deterministic test-only
subprocess route and never reports production isolation. Existing JSON reports
gain one additive platform-runtime object. The top-level `--version` option is
additive. Windows gains package import, help/version, and bounded absent-profile
readiness; operations whose native guarantees are not implemented remain
explicitly unavailable.

## Security

Backend identity is a fixed code-owned identifier, never an environment-
selected plugin name. Platform detection cannot grant authority or enable a
capability. Availability checks are descriptive and must not touch protected
state, load credentials, construct connectors, or contact providers. Failure
does not retry through another backend or downgrade required guarantees.
Reasons are bounded and secret-free. Native Windows areas remain independently
planned and cannot become released merely because the common contract exists.

## Rejected alternatives

Eagerly importing every backend was rejected because one unavailable native
dependency would break safe neutral commands. A generic best-effort backend
was rejected because filesystem identity, locking, persistence, containment,
and process control are security properties rather than convenience APIs.
Treating backend availability as one global boolean was rejected because the
native work is deliberately split into independently reviewable areas.
