# Proposal

## Problem

The optional broker-owned Copilot SDK runner creates a fresh in-memory advisory
session for every command. That lets repeated processes reset the documented
three-research/one-review limit for one operator goal. Its repository digest
records untracked paths but not untracked bytes, and its SDK hook confines file
arguments only to the repository rather than to the requested `--path` route.
Some policy and profile prose also still describes the implemented adapter as
future-only.

## Desired outcome

Every live advisory attempt is reserved against one durable authenticated goal
record before SDK startup. The exact task, profile, technical route scope, and
complete bounded Git state—including untracked file contents—remain identical
until the parent accepts the report. Specialists can use only repository-owned,
scope-enforcing read/search tools, and all current documentation describes the
same optional broker-owned path.

## Scope

This change adds private HMAC-authenticated SQLite advisory budget state, an
explicit CLI goal identifier and path route, race-detecting repository-state
hashing, repository-owned scoped SDK read/search tools, scope-aware citation
revalidation, multi-process and mutation regressions, and aligned policy,
profile, architecture, operator, and semantic-index documentation.

## Rationale

Budgets, stale-result checks, and route limits are security controls. They must
be enforced by deterministic code at the real runner boundary and survive
ordinary retries, failures, concurrency, and process restart. Prompt text and
one process's counters cannot provide those properties.

## Alternatives considered

### Keep the in-memory broker counters

Rejected because the public runner constructs a new broker for every command.

### Treat `git status` as untracked-content identity

Rejected because status identifies an untracked path but not later byte changes
at that path.

### Retain SDK built-ins and rely on path instructions

Rejected because a pathless search or a differently shaped SDK argument can
escape the requested route even when a prompt says not to do so.

## Non-goals

This change does not enable the generic host `agent` tool, child recursion,
writer tools, provider access, credentials, approval, runtime `ChangePlan`
authority, or authoritative advisory output.

## Risks

Cross-process state can be replaced by a same-account attacker when no process
is running, large or hostile worktrees can exhaust scanners, and SDK interfaces
can change. The implementation documents the same-account limit, authenticates
content-minimized rows with a private key, uses the repository's pinned SQLite
storage, applies strict file/count/byte limits, detects scan races, exposes only
repository-owned tools, and falls back to direct-parent work on every unsafe or
incompatible condition.
