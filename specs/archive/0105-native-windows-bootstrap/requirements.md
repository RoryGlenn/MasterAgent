# Requirement deltas

## ADDED

### MA-WINDOWS-INSTALL-001 — Native Windows installation

Bootstrap MUST use native virtual-environment interpreter and console-launcher
paths, MUST apply POSIX permission operations only on POSIX, and MUST NOT
execute or rewrite an unverified existing environment. A collision MUST select
a fresh bounded side-by-side managed environment. Source, wheel, source archive,
and explicit local offline package directories MUST be supported without
requiring activation or placing index credentials on the command line.

Native default configuration and runtime state MUST use an absolute
current-user platform directory and MUST NOT derive authority from the current
working directory. Release construction MUST exclude environment, runtime,
credential, audit-database, cache, and build artifacts. Hosted native Windows
evidence MUST cover standard-user source bootstrap idempotency, a built-wheel
console launcher, and spaces, Unicode, and long local paths while preserving
the POSIX installation path.

## MODIFIED

None.

## REMOVED

None.
