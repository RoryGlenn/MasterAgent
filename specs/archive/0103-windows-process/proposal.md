# Proposal

## Problem

Native Windows exposes the platform process-supervision contract as unavailable.
Callers therefore cannot launch a fixed executable with the same bounded tree,
resource, environment, handle, timeout, and output guarantees used by secure
runtime paths on POSIX.

## Desired outcome

Add a platform-neutral supervised-command result and a Windows backend that
creates each child suspended, assigns it to a configured Job Object, and only
then resumes it. Keep caller secrets out of the child environment and keep
untrusted child diagnostics out of typed failure reasons.

## Scope

- explicit executable, arguments, working directory, environment, and inherited
  handle selection;
- Job Object CPU-time, memory, active-process, and kill-on-close limits;
- bounded stdout/stderr capture and whole-tree timeout termination;
- native Windows standard-user evidence and unchanged established POSIX limit
  behavior; and
- readiness, architecture, operations, threat-model, roadmap, and semantic
  ownership updates.

## Rationale

Job Objects are the Windows-native primitive that can bound and terminate a
complete descendant tree. Suspended creation prevents child code from racing
Job Object assignment, and explicit startup attributes prevent ambient handle
inheritance.

## Alternatives considered

- Ordinary `subprocess.Popen` followed by Job Object assignment leaves a race
  before assignment.
- `taskkill`, PowerShell, and shell wrappers add executable discovery, parsing,
  and incomplete authority boundaries.
- Killing only the root PID does not terminate descendants.

## Non-goals

This change does not add the Windows Git execution sandbox, capsule isolation,
an arbitrary command capability, shell execution, or provider effects.

## Risks

Incorrect native structure layouts, handle ownership, or failure cleanup could
leak processes or handles. Native standard-user CI therefore exercises real
launch, inheritance, timeout, memory, process-count, and output behavior in
addition to portable validation tests.
