# Proposal

## Problem

Native Windows reports the trusted-Git contract as unavailable. Repository
inspection therefore cannot use the released Windows filesystem and Job Object
boundaries, and any direct `git.exe` fallback would inherit unsafe executable
discovery, configuration, credentials, helpers, filters, process lifetime, and
pathname races.

## Desired outcome

Add a read-only native Windows Git backend that pins a validated Git for
Windows executable and repository metadata, executes fixed inspection commands
through the Windows process supervisor, and returns bounded secret-free
results. Make generated patches byte-stable across POSIX and Windows checkouts.

## Scope

- explicit or bounded Git for Windows executable discovery;
- executable file identity, access-control, and content-digest binding;
- repository, `.git`, config, index, object, and ref pinning and revalidation;
- complete fixed read-only Git command admission, isolated configuration, minimal
  environment, Job Object execution, and bounded output/time;
- deterministic LF patch generation and repository line-ending policy; and
- portable adversarial tests plus real standard-user Windows evidence.

## Rationale

The filesystem backend can retain handles that deny replacement while checking
file IDs and access-control lists. The process backend can launch the exact
executable suspended under Job Object limits. Composing those released
boundaries gives Git inspection native Windows guarantees without inventing a
weaker subprocess or shell fallback.

## Alternatives considered

- Resolving `git` from ambient `PATH` does not bind which executable runs.
- Calling PowerShell, `cmd.exe`, or `where.exe` adds shell parsing and another
  executable-discovery boundary.
- Copying the POSIX descriptor/reflog mutation transaction to Windows would not
  preserve Windows file-sharing, identity, or atomicity semantics.

## Non-goals

This change does not enable branch creation, patch application, commit
publication, push, remote fetch, credentials, hooks, filters, arbitrary Git
subcommands, or the deferred Windows capsule-isolation route.

## Risks

Git for Windows installation layouts vary, and Git configuration can indirectly
execute helpers. Discovery therefore stays bounded and every selected file is
pinned and validated. Command and configuration allowlists remain read-only,
and native standard-user CI verifies the installed runner rather than treating
portable mocks as Windows evidence.
