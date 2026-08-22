# Design

## Approach

Extend `ProcessSupervisionBackend` with one platform-neutral fixed-command
operation and a bounded result type. The Windows implementation uses direct
`kernel32` bindings rather than a shell or helper program.

`CreateProcessW` receives an absolute application path, a separately encoded
argument vector, `CREATE_SUSPENDED`, `CREATE_UNICODE_ENVIRONMENT`, and an
extended startup attribute list. That list contains only a private null-input
handle, the two bounded output pipe handles, and caller-selected inheritable
handles. The parent assigns the suspended process to a new Job Object with
process CPU-time, process/job memory, active-process, unhandled-exception, and
kill-on-close limits before calling `ResumeThread`.

## Affected components

- platform-neutral process contracts and public exports;
- native Windows process APIs and runtime selection;
- the additive POSIX fixed-command adapter;
- semantic ownership and Windows hosted CI; and
- architecture, operations, threat-model, and roadmap documentation.

## Data flow

1. A platform-neutral caller provides an absolute executable, arguments,
   working directory, explicit environment additions, handle allowlist, and
   resource budgets.
2. The backend validates and bounds every field, obtains the Windows directory
   through the native API, and builds the minimal environment.
3. The native adapter creates private standard handles and an exact process
   attribute handle list.
4. `CreateProcessW` creates the root suspended; the backend configures and
   assigns its Job Object before resuming the primary thread.
5. Drain threads share one retention budget while the parent waits.
6. Completion returns a bounded typed result; timeout or control failure
   terminates the Job Object and reaps the root.

## Environment and output

The environment begins with `SystemRoot` and `WINDIR` obtained from
`GetWindowsDirectoryW`, not `os.environ`. Callers may add a bounded mapping but
cannot shadow the baseline or create case-variant duplicates. `PATH`, credential
variables, and other ambient values are absent unless deliberately supplied.

Two drain threads consume stdout and stderr concurrently into one locked shared
byte budget. Bytes beyond that budget are discarded while pipes continue to be
drained, preventing both unbounded retention and pipe deadlock. The result says
whether truncation occurred; its terminal reason contains no child-controlled
text.

## Failure and recovery

Every native-control failure maps to a stable reason. After process creation,
any incomplete control path terminates the child and closes the Job Object. A
timeout terminates the Job Object, waits for the root process, drains closed
pipes, and returns `timed_out` without an exit code. Job close is the final
whole-tree cleanup boundary.

## Compatibility

The existing POSIX `apply_capsule_limits` behavior is unchanged. Its additive
fixed-command method applies the same existing `rlimit` set in a new session.
Windows cannot safely attach after arbitrary code has begun running, so its
legacy apply-only method returns a typed `supervised_launch_required` error and
callers use the new suspended-launch method.

## Security

- executable discovery and shell parsing are excluded;
- no ambient handle or environment inheritance is permitted;
- active-process and job-memory limits cover descendants;
- control errors never embed `GetLastError` text or child diagnostics;
- shared output retention is bounded independently of how much a child writes;
  and
- process creation remains a platform backend, not a general runtime
  capability or authority source.

## Rejected alternatives

- Launch-then-assign with `subprocess.Popen` permits a pre-assignment child race.
- Root-only termination leaves descendants alive.
- Inheriting the caller environment or all inheritable handles leaks ambient
  authority.
- Shell or PowerShell wrappers add parsing and executable-selection ambiguity.
