# Design

## Approach

Extend the trusted-Git platform contract with one bounded read-only execution
operation and an immutable executable binding. The POSIX backend preserves its
existing fixed-path behavior. The Windows backend discovers a finite candidate
set, pins the selected `git.exe` with the native filesystem backend, hashes the
bytes from that retained handle, and keeps the handle open for the backend
lifetime so the executable cannot be replaced.

For each command, the Windows backend pins the approved repository and its
local `.git` directory. It rejects a file-form `.git`, linked-worktree and
alternate-object-database redirection, unsafe case collisions, and
`config.lock` or `index.lock`, then recursively pins a bounded local object and
reference tree plus the config and index when present. Those retained handles
deny replacement and concurrent writes while Git reads them. All pins are
revalidated before and after the supervised process. A shared contract parser
admits complete command forms rather than trusting a read-only subcommand name;
backend safety options are inserted before the literal-pathspec separator so a
caller cannot reinterpret them as paths.

## Affected components

- platform-neutral trusted-Git contract, backend accessor, and POSIX adapter;
- native Windows Git discovery, identity binding, repository admission, and
  Job Object execution;
- advisory repository Git reads and deterministic repository patch generation;
- Windows hosted CI, semantic ownership, and current architecture, operations,
  threat-model, release, and roadmap documentation; and
- portable and native Windows adversarial tests.

## Data flow

1. Runtime construction chooses an explicit executable or enumerates bounded
   registry and fixed Git for Windows installation candidates.
2. The filesystem backend opens the candidate without following reparse points,
   validates native identity and DACL policy, reads bounded executable bytes,
   and records their SHA-256 digest.
3. A caller supplies an absolute repository and a fixed read-only Git argument
   vector.
4. The backend pins the repository, `.git`, config, index, local objects, and
   refs and rejects redirects, collisions, or lock contention.
5. Forced Git options and a minimal environment disable ambient or executable
   behavior. The process backend launches the pinned executable path under its
   Job Object and shared output budget.
6. Every retained object is revalidated. Success returns only bounded stdout;
   timeout, truncation, nonzero exit, or control failure maps to a stable reason.

## Compatibility

Existing POSIX Git connector behavior and mutation transactions remain
unchanged. The platform-neutral advisory Git reader uses the new backend but
preserves its existing command results and error contract. Windows gains only
read-only inspection. The pure local patch generator normalizes input newlines
to LF, and `.gitattributes` keeps source files LF while explicitly selecting
CRLF for Windows command files.

## Security

- no shell, PATH lookup, remote transport, credential helper, prompt, hook,
  filter, textconv, pager, editor, replacement object, or lazy fetch is allowed;
- retained handles and exact identities prevent executable, repository, `.git`,
  config, index, object, and ref replacement during execution;
- linked-worktree and alternate-object redirection is rejected before launch,
  and all backends enforce one complete read-only argument grammar;
- a pre-existing Git lock or case-insensitive collision fails closed;
- the Job Object bounds the complete process tree, memory, CPU, time, and
  retained output; and
- failures never incorporate Git diagnostics, paths, arguments, registry text,
  or environment values.

## Rejected alternatives

- Ambient PATH and shell discovery are not stable executable identities.
- Validating only path text leaves executable and repository replacement races.
- Sanitizing stderr after capture still risks persisting hostile or
  credential-bearing text.
- Enabling Windows Git writes without a Windows-native compare-and-swap and
  recovery design would silently weaken the existing POSIX transaction.
