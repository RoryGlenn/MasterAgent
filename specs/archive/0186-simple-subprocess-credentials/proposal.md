# Proposal

## Problem

PR #185 review found that Git hooks and configured project checks inherit
provider API credentials from the parent process.

## Desired outcome

Repository subprocesses receive normal build and Git settings but no configured
Jira, Bitbucket, or Confluence credential variables. Provider clients in the
parent process keep working.

## Scope

Correct the Simple subprocess boundary, cover real checks and hooks, and
clarify account setup documentation. Do not change the governed runtime.

## Rationale

Provider credentials belong to the native API clients, not arbitrary project
commands. Filtering names is sufficient for this environment boundary.

## Alternatives considered

Clearing the parent environment would break provider calls and concurrent work.
Filtering only check commands would still expose credentials through Git hooks.

## Non-goals

No OS sandbox, changed account permissions, or new runtime approval flow.

## Risks

Custom names must be propagated to every workspace operation. Same-user code
can still access files and other process resources; this is not full isolation.
