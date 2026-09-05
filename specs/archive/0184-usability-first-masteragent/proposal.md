# Proposal

## Problem

The current MasterAgent runtime combines ordinary personal work with extensive
planning, approval, verification, extension, and memory machinery. The operator
explicitly requested implementing a rebuild that prioritizes usability, fewer
interruptions, and ease of use with substantially less governance.

## Desired outcome

An operator selects MasterAgent Simple in the existing coding assistant,
connects the relevant project once, and completes useful work through native
tools with durable task continuity. The CLI supports a credential-free demo,
issue review, development preparation/publication, and a local status draft.
The host assistant supplies reasoning and application code edits.

Success means useful tasks complete with few repeated setup questions, clear
progress, meaningful checks, and recovery that avoids repeating successful
writes. The change must be reviewable without accessing workplace systems.

## Scope

- A standalone Python 3.12 standard-library package and `masteragent` entry
  point under `simple/`, with Windows and POSIX launch commands.
- An explicitly selected Copilot profile and concise local setup.
- Native Jira, Bitbucket, and Confluence Cloud/Server adapters.
- Editable project context, environment-variable credential references,
  reusable provider clients, and SQLite task state.
- Issue review, isolated worktree handoff, configured checks, explicit branch
  push/pull-request creation/Jira update, and local status drafts.
- Cancellation, cached successful steps, and explicit reconciliation for an
  uncertain write result.
- Deterministic workflow tests, documentation, and a current requirement.

## Rationale

A separate profile makes the user's requested design concrete while keeping
the governed runtime available to existing users. Predictable tool sequences
belong in ordinary Python; the existing assistant can own conversation,
judgment, and code edits without a second LLM backend.

## Alternatives considered

- Relax the existing runtime in place. Rejected because the large inherited
  architecture and compatibility surface would remain.
- Add a desktop application and generic workflow builder immediately. Deferred
  until actual workflow use demonstrates their value.
- Merely simplify the command wrapper around signed plans. Rejected because
  it preserves the machinery the operator asked to remove from this profile.

## Non-goals

This change does not merge open work, rewrite the legacy runtime, remove host
or employer controls, send Outlook/Teams messages, merge pull requests, supply
a portable draft-pull-request state, schedule recurring work, or introduce
dynamic plugins, a UI, or a separate model API.

## Risks

Provider versions, credentials, and account permissions vary. Local fixture
tests cannot certify a live organization deployment. Native Windows execution
must be exercised on a Windows runner. Issue context and task artifacts can
contain private content; state must remain local and outside source control.
Ambiguous writes can duplicate remote work if retried blindly, so they pause
for explicit reconciliation. The governed runtime must never fall back to the
Simple profile after a policy denial.
