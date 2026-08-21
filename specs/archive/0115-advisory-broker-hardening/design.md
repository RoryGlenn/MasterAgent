# Design

## Approach

Keep `AdvisoryBroker` as the parent authority boundary while making its budget
backend replaceable. The live runner supplies a durable backend; hermetic uses
retain an in-memory session budget. Normalize the CLI path route before any
reservation, then pass the same immutable scope to SDK tools, state binding,
the task prompt, and parent citation revalidation.

## Affected components

- `src/master_agent/advisory.py`
- `src/master_agent/advisory_budget.py`
- `src/master_agent/copilot_advisory.py`
- `scripts/advisory_subagent.py`
- `tests/test_advisory_budget.py`
- `tests/test_advisory_runner.py`
- `tests/test_copilot_advisory.py`
- advisory policy, profile, architecture, operator, and semantic-index docs

## Architecture

```text
selected MasterAgent parent + opaque goal ID
        ↓
private HMAC-authenticated SQLite budget reservation
        ↓
sanitize payload + bind normalized route scope
        ↓
bounded stable Git snapshot (including untracked bytes)
        ↓
one isolated Copilot SDK session
        ↓
repository-owned scoped read/search tools only
        ↓
narrow untrusted AdvisoryReport
        ↓
same state/scope recheck + scope-aware parent citation reread
```

## Durable goal budget

`AdvisoryBudgetStore` stores only a SHA-256 goal identifier, a repository
identity digest, two non-negative counters, and an HMAC tag. A random 32-byte
key and the database live in a mode-`0700` ignored runtime directory; state
files use mode `0600`. `PinnedSQLiteDatabase` supplies cross-process locking,
generation identity, atomic replacement, and crash reconciliation. One SQL
transaction verifies the existing tag, enforces the global record bound, and
reserves an attempt before SDK creation. All adapter failures and retries
therefore consume the same goal budget.

The selected parent creates one opaque goal ID and reuses it for every advisory
attempt in that operator goal. A different identifier represents a different
goal; changing it mid-goal violates the parent contract. Local HMAC state is a
development-host integrity boundary, not protection from an attacker who owns
the same OS account and can replace both the key and all state while the runner
is stopped.

## Repository state snapshot

Each repository digest takes two complete bounded snapshots and requires them
to match. A snapshot includes bounded Git output for HEAD, porcelain status,
tracked worktree diff, staged diff, and the NUL-delimited untracked file list.
Every untracked regular file is opened no-follow, read under per-file and total
byte limits, hashed, and checked for descriptor/path identity and metadata races
before its path and content digest enter the snapshot. Special, unreadable,
oversized, excessive, truncated, or changing input rejects delegation.

## Route-scoped SDK tools

`AdvisoryPathScope` resolves a non-empty set of repository-relative existing
files or directories, rejects traversal and symlink route entries, removes
redundant descendants, and produces a deterministic digest. The SDK receives
only repository-owned custom tools for bounded reads, literal content search,
and file listing. Each handler enumerates or opens only descendants of the
bound scope and does not follow symlinks. The pre-tool hook repeats the tool and
argument gate as defense in depth; no SDK filesystem built-in is exposed.

The runner requires at least one `--path`. Citations are accepted only when the
same route scope contains the cited regular UTF-8 file.

## SDK lifecycle

Every specialist call still receives a fresh isolated session. A runner process
uses one SDK client for its goal work and closes it deterministically. The
one-call CLI has no safe cross-process client object to reuse; durable state,
not a process-local client, is shared between invocations.

## Failure behavior

Invalid scope, unavailable or corrupt budget state, scan failure, SDK failure,
malformed output, stale state, or citation failure returns content-minimized
JSON instructing the selected parent to complete equivalent work directly.
None of those states grants another tool, host route, credential, provider, or
approval authority.

## Data flow

1. The selected parent chooses one opaque goal ID and a minimum set of existing
   repository-relative paths.
2. The runner normalizes and inventories the path scope before touching the
   goal budget.
3. The broker sanitizes the task and atomically reserves one authenticated role
   attempt before SDK startup.
4. The worker takes a stable bounded repository snapshot and binds its digest
   with the exact task, profile, and route inventory.
5. One isolated SDK session receives exactly one role and the repository-owned
   scoped read/search tools.
6. The worker recomputes every binding and rejects a stale or incomplete result.
7. The parent rereads each citation through the same scope and either accepts
   narrow advisory evidence or completes equivalent work directly.

## Compatibility

The base package still has no SDK dependency. Installing `.[subagents]` enables
the optional adapter. Existing in-process broker callers retain their local
session counters unless they explicitly supply a durable budget backend. The
live runner now requires `--goal-id` and at least one `--path`; this intentional
fail-closed CLI change prevents the previously unenforceable implicit goal and
repository-wide scope. macOS and Ubuntu use the existing no-follow, ownership,
mode, `fcntl`, Git, and SQLite primitives.

## Security

- Goal rows contain only digests, counters, and an HMAC; task and file contents
  are never stored in budget state or reflected in failure diagnostics.
- The private state directory and every key/database generation are
  permission-checked, descriptor-pinned, generation-bound, and process-locked.
- Git commands have bounded output, time limits, disabled hooks/fsmonitor/
  external diffs, and a sanitized `GIT_*` environment.
- Untracked files and scoped reads use no-follow opens, file identity/race
  checks, and strict file/count/byte limits.
- Ignored files, private runtime paths, symlinks, repository-root scope, SDK
  filesystem built-ins, extension discovery, effects, and nested agents remain
  unavailable.
- Output is untrusted until the same scope and repository state survive parent
  citation revalidation. Every unsafe state returns direct-parent fallback.

## Rejected alternatives

### Process-local counters

Rejected because independent runner commands reset them.

### A pathname-only untracked binding

Rejected because editing an existing untracked file does not alter its status
pathname.

### SDK built-in file tools plus a prompt rule

Rejected because pathless or schema-drifted searches are not technically
confined. Repository-owned custom tools make the scope the implementation.

### Sharing a client across runner processes

Rejected because an SDK client is a process-local live object. Same-process
goal work may reuse one client with isolated sessions; cross-process state
sharing is limited to the authenticated budget.
