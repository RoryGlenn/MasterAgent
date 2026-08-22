# Requirement deltas

## ADDED

### MA-WINDOWS-GIT-001 — Native Windows trusted Git execution

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

## MODIFIED

None.

## REMOVED

None.
