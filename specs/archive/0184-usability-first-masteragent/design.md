# Design

## Approach

Add a standalone package under `simple/` using Python 3.12 and standard-library
HTTP, JSON, subprocess, filesystem, and SQLite facilities. One conversational
host selects ordinary typed tool functions. Explicit CLI workflows persist
their inputs and step results so another process can continue unfinished work.
The Simple runtime does not import or call the governed runtime.

The host interprets prose, edits code in the prepared worktree, reviews the
diff, commits the requested change, and runs checks on that clean commit. The CLI prepares the
worktree and performs explicitly requested publication. This distinction is
part of the product contract, not a temporary implementation detail.

## Affected components

- Standalone package, launcher, packaging, and focused tests in `simple/`.
- `MasterAgent-Simple.agent.md` host profile and `simple/AGENTS.md` guidance.
- Usage and architecture documentation, repository entry-point navigation,
  and the current requirement introduced by this change.
- Existing release validation remains applicable; the legacy runtime is not
  rewritten or automatically migrated.

## Data flow

Setup writes provider URLs, credential environment-variable names, project
repository mappings, documentation links, and check argument arrays. Context
is editable Markdown. The default state root is `~/.masteragent`, overridden
by `MASTERAGENT_HOME` or `--home`.

Review fetches selected issue and linked evidence through native providers and
records task artifacts. Develop creates an isolated worktree plus a host
handoff. Checks run configured argument arrays in that worktree. Publish pushes
the branch, requests a draft Bitbucket pull request, and adds a Jira comment.
The host reports the provider's actual draft flag, including when unreported;
older server versions may ignore the request. Status derives a local draft
from stored task progress.

Each workflow step stores a confirmed result. Resume reuses completed steps.
After a confirmed branch push, remaining provider writes use its saved result
without requiring the worktree again. Provider destinations are checkpointed
on first use while credential refresh remains possible. Publication settings
can change before its first external write starts and remain fixed afterward.
Read requests have bounded retries; a transport failure during a write leaves
the result uncertain. `resolve` accepts an explicitly confirmed result or an
explicit finding that no remote effect happened before resume. Only confirmed
absence allows a later write retry. Cancellation changes task state without
undoing completed remote work.

## Compatibility

`masteragent` selects Simple; `master-agent` remains the governed entry point.
Configuration and state are separate. Existing legacy requirements continue to
apply to that runtime. Neither runtime silently falls back to the other.
Repository development continues to maintain specifications and test evidence.

## Security

This user-authorized profile removes legacy runtime approval artifacts and
governance machinery. It retains ordinary account permissions, host and
employer controls, credential isolation, source-content instruction boundaries,
process timeouts, isolated worktrees, cancellation, and duplicate prevention.
Configuration stores only names of environment variables, never secret values.
Provider content remains task data and cannot grant authorization.

## Rejected alternatives

An immutable plan engine, dynamic capability admission, approval artifact
pipeline, append-only integrity ledger, and a second model runtime would add
friction and duplicate responsibilities that are unnecessary for the first
personal workflows. A distributed scheduler, broad communications layer,
and provider-independent draft guarantees are deferred rather than simulated.
