# Proposal

## Problem

Windows currently reports `capsule_isolation` unavailable. Pure promoted
capsules therefore cannot validate or execute natively even though Windows now
has secure filesystem, process, credential, state, and Git backends.

## Desired outcome

Standard-user Windows 11 validates and executes dependency-free pure capsules
inside a no-capability AppContainer with Job Object quotas, a minimal
environment, an explicit read-only runtime projection, one ephemeral writable
directory, bounded protocol pipes, and identity evidence that invalidates when
the backend, runtime, interpreter, or worker changes.

## Scope

- add a native AppContainer capsule-isolation backend and injectable Win32 API;
- make the shared capsule worker portable while preserving its restricted
  language and protocol;
- route production capsule execution through the selected native isolation
  backend;
- bind backend/runtime/worker identity into validation and promotion evidence;
- add portable adversarial tests and standard-user native Windows evidence;
- update platform readiness, semantic ownership, release metadata, and current
  documentation; and
- preserve Linux bubblewrap behavior and the test-only subprocess boundary.

## Rationale

AppContainer supplies the Windows-native low-privilege token and capability
boundary. Job Objects already provide the required process-tree and resource
limits. Keeping profile, ACL, process, and pipe setup in one narrow native
adapter avoids making the capsule program or general runtime responsible for
Win32 authority.

## Alternatives considered

- WSL is not native Windows containment.
- A Job Object alone limits resources but does not remove filesystem or network
  authority.
- A restricted token without an AppContainer package identity does not provide
  the same default resource isolation.
- An ambient subprocess fallback would falsely advertise production isolation.

## Non-goals

- provider access, credentials, network capabilities, or side-effect capsules;
- raw Python plugins or third-party runtime dependencies;
- macOS capsule isolation; and
- weakening the existing Linux bubblewrap launch.

## Risks

AppContainer filesystem grants, inherited handles, runtime projection, process
startup attributes, and cleanup are security-sensitive. Any incomplete native
symbol set, unsafe path, mutable runtime projection, profile failure, output
overflow, or identity drift must leave the contract unavailable or fail the
worker before capsule code runs.
