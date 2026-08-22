# Requirement deltas

## ADDED

### MA-WINDOWS-PROCESS-001 — Native Windows process supervision

Native Windows MUST execute only an explicit executable and argument vector
without a shell, create the process suspended, restrict inherited handles to an
explicit allowlist, assign the process to a Job Object before resuming it, and
terminate the complete Job Object on timeout or control failure. The Job Object
MUST enforce bounded CPU time, memory, and active-process count, including
descendants, and MUST use kill-on-close behavior. Environment construction MUST
start from the native Windows directory baseline rather than the caller's
ambient environment. Standard output and error MUST share an exact byte budget.
Terminal results and control failures MUST use bounded typed reasons that do not
incorporate child output, arguments, paths, environment values, or native error
text. Established POSIX resource-limit behavior MUST remain compatible.

## MODIFIED

None.

## REMOVED

None.
