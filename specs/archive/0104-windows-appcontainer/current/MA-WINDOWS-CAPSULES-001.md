# MA-WINDOWS-CAPSULES-001 — Native Windows capability capsule isolation

## Status

Active

## Requirement

MasterAgent MUST execute dependency-free pure capability capsules natively on
Windows 11 inside a zero-capability AppContainer. The worker MUST receive no
ambient credentials or secret environment values, no network capability, no
arbitrary host filesystem access, no undeclared inherited handle, and no
subprocess escape. It MUST receive read/execute access only to the exact
interpreter/runtime/worker projection and write access only to one private
ephemeral working directory.

The backend MUST create the process suspended, bind an explicit stdin/stdout/
stderr handle list and AppContainer security capabilities, attach the complete
process tree to a kill-on-close Job Object, configure process-count, CPU,
memory, time, input, combined-output, and diagnostic bounds, and resume only
after every control succeeds. Timeout, truncation, malformed protocol, native
failure, cleanup failure, and identity or ACL drift MUST fail with bounded
content-free reasons.

Promotion and activation MUST bind the exact Windows isolation backend and the
SHA-256 identities of the security-relevant native adapter, process boundary,
runtime projection, interpreter, and restricted worker. Signed validation and
sandbox evidence MUST expose those component digests. Any changed component or
tampered runtime/worker artifact MUST invalidate the combined worker identity
before capsule execution.

Provider, credentialed, network, side-effect, dependent, and raw-plugin
capsules MUST remain fail closed. Linux bubblewrap behavior MUST remain
unchanged, macOS MUST remain unavailable, and the explicit test subprocess MUST
remain non-production.

## Rationale

Job Objects bound resource use in Windows but do not remove authority.
AppContainer adds a native low-privilege package identity and default-denied
resource boundary. A content-addressed, read-only runtime projection avoids
granting that identity access to the host installation and makes the exact
execution boundary reviewable and promotion-bound.

## Scenarios

### Pure capsule executes under native isolation

- GIVEN a dependency-free pure capsule and standard-user Windows 11
- WHEN validation or governed execution launches the capsule worker
- THEN the worker runs in the selected zero-capability AppContainer
- AND only a typed bounded worker response is returned

### Ambient authority probes are denied

- GIVEN probes for a host file, ambient secret, IPv4, IPv6, localhost, child
  process, and private introspection
- WHEN the native sandbox validator runs them
- THEN every probe is denied without exposing content or credentials

### Quotas terminate the complete worker tree

- GIVEN a worker request that exceeds process, CPU, memory, timeout, input,
  output, or diagnostic limits
- WHEN the AppContainer backend supervises it
- THEN the complete Job Object is terminated or rejected
- AND only the stable bounded failure reason crosses the protocol boundary

### Identity drift invalidates promotion

- GIVEN signed evidence for one backend/runtime/interpreter/worker identity
- WHEN any component or runtime projection byte changes before activation
- THEN activation fails before capsule code runs
- AND no promoted lifecycle state or provider path is widened

## Implementation

- `src/master_agent/platform_runtime/windows/capsules.py`
- `src/master_agent/platform_runtime/windows/process.py`
- `src/master_agent/platform_runtime/windows/runtime.py`
- `src/master_agent/platform_runtime/windows/capsule_worker.py`
- `src/master_agent/capsule_runtime.py`

## Verification

- `tests/test_windows_capsules.py`
- `tests/test_windows_process.py`
- `tests/test_platform_runtime.py`
- `tests/test_capability_capsules.py`

## History

- Introduced by GitHub issue #104.
