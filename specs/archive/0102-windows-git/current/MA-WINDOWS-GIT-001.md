# MA-WINDOWS-GIT-001 — Native Windows trusted Git execution

## Status

Active

## Requirement

Native Windows MUST select `git.exe` only from an explicit absolute path or a
bounded Git for Windows installation candidate and MUST pin and validate its
native file identity, owner, DACL, non-reparse attributes, and content digest.
Every operation MUST pin and revalidate the repository root, local `.git`
directory, configuration, local object database and references, and index where
present; MUST reject reparse points, case-insensitive collisions, active
config/index lock contention, linked-worktree redirection, or alternate object
databases; and MUST execute only a complete backend-owned grammar of fixed
read-only inspection commands through the native process supervisor with
bounded time, resources, descendants, and output. The child
MUST receive a minimal environment and forced configuration that disables
system/global configuration, includes, hooks, prompts, credential helpers,
external diff/text-conversion/filter execution, replacement objects, lazy
fetch, optional locks, and every transport protocol. Failures MUST expose only
stable secret-free reasons. Generated patch bytes and repository checkout
attributes MUST define deterministic LF/CRLF behavior. Windows Git mutation and
publication MUST remain unavailable.

## Rationale

Git configuration and executable discovery can invoke code or credentials even
during apparently read-only operations. Native retained handles plus the
released Job Object supervisor provide a Windows boundary equivalent in
strength to the established fixed Git inspection path without copying POSIX
mutation mechanics.

## Scenarios

### Read-only inspection stays isolated

- GIVEN a validated Git for Windows installation and a trusted local repository
- WHEN MasterAgent reads status, diff, index, or immutable object state
- THEN the exact pinned executable runs through the Job Object supervisor
- AND no ambient configuration, credential, prompt, hook, filter, transport, or
  child output can escape the declared boundary

### Repository or executable substitution fails closed

- GIVEN the executable, repository, `.git`, config, object database, refs, or
  index changes identity, access policy, attributes, case topology, or lock
  state, or metadata redirects outside the admitted repository
- WHEN a Git inspection is admitted or completes
- THEN the operation returns a bounded failure
- AND no weaker executable, shell, PATH, or unpinned repository fallback runs

### Windows mutation remains unavailable

- GIVEN native Windows trusted Git inspection is available
- WHEN a local branch, patch-apply, commit, push, or remote operation is
  requested
- THEN the existing mutation route remains unavailable
- AND the POSIX reflog and hard-link transaction is not copied to Windows

## Implementation

- `src/master_agent/platform_runtime/windows/git.py`
- `src/master_agent/platform_runtime/contracts.py`
- `src/master_agent/copilot_advisory.py`
- `src/master_agent/connectors/drafts.py`
- `.gitattributes`

## Verification

- `tests/test_windows_git.py`
- `tests/test_copilot_advisory.py`
- `tests/test_draft_package.py`

## History

- Introduced by GitHub issue #102.
