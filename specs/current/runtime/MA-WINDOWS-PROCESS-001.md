# MA-WINDOWS-PROCESS-001 — Native Windows process supervision

## Status

Active

## Requirement

On native Windows 11, MasterAgent MUST provide Job Object based process
supervision behind the platform-neutral `process_supervision` contract. A
supervised command MUST use an explicit absolute executable, a distinct bounded
argument vector, an absolute working directory, and `shell=False` semantics.
The backend MUST create the process suspended, restrict inherited handles to a
validated explicit allowlist containing only its private standard handles plus
caller-selected handles, assign the process to its Job Object, and only then
resume its primary thread.

The Job Object MUST enforce kill-on-close, process CPU-time, process/job memory,
and active-process limits. A timeout or protocol/control failure after creation
MUST terminate the complete process tree and reap the root process. Environment
construction MUST begin with only the Windows directory baseline obtained from
the operating system and MUST NOT inherit arbitrary caller variables. Explicit
environment names MUST be bounded and compared case-insensitively, and they
MUST NOT shadow the baseline.

Standard output and standard error MUST be drained concurrently, MUST share one
exact byte-retention budget, and MUST continue draining after truncation so an
attacker cannot deadlock the parent through full pipes. A completed command
MUST return a typed `exited` or `nonzero_exit` reason and bounded output. A
timeout MUST return `timed_out` without an exit code. Native-control failures
MUST use bounded stable reasons and MUST NOT include child output, arguments,
paths, environment values, secrets, or native error text.

The backend MUST NOT expose a shell, executable search, generic command
capability, provider authority, or compatibility fallback. Established POSIX
`apply_capsule_limits` behavior MUST remain compatible.

## Rationale

Windows Job Objects are the native boundary for applying limits to a complete
child process tree. Suspended launch closes the race in which a child could
create descendants before assignment, while exact handle and environment lists
prevent unrelated parent authority from leaking into the child.

## Scenarios

### Fixed command receives only selected authority

- GIVEN an absolute executable and explicit environment and handle selections
- WHEN the Windows process backend launches it
- THEN the child begins only after Job Object assignment
- AND it cannot observe an ambient secret variable or an unselected inheritable
  handle

### Timeout kills descendants

- GIVEN a supervised child creates a descendant and then exceeds its timeout
- WHEN the supervisor terminates the Job Object
- THEN the root and descendant stop
- AND the result is `timed_out` without child-controlled diagnostic text

### Resource and output pressure stays bounded

- GIVEN a child attempts excess allocation, process creation, or output
- WHEN the configured Job Object and pipe budgets are reached
- THEN memory and process limits are enforced for the job
- AND retained stdout plus stderr never exceeds the configured byte budget

## Implementation

- `src/master_agent/platform_runtime/contracts.py`
- `src/master_agent/platform_runtime/windows/process.py`
- `src/master_agent/platform_runtime/windows/runtime.py`
- `src/master_agent/platform_runtime/posix/process.py`
- `.ai/semantic-router.toml`

## Verification

- `tests/test_windows_process.py`
- `tests/test_platform_runtime.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #103.
