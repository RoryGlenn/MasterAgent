# Proposal

## Problem

MasterAgent has native Jira, Bitbucket, and Confluence reads, independent
verification, citations, private artifact publication, and bounded performance
evidence, but no high-level employee workflow combines them into one exact
engineering work-item review. The existing weekly-status shortcut is not
manifest-bound and its Jira result omits acceptance criteria and governed
provider relations.

## Desired outcome

One high-level command accepts an exact Jira key and profile-selected workflow
configuration, executes the fixed `T1-EWIR-001` read plan through the normal
approval-bound runtime, and creates exactly one private JSON review, Markdown
review, and digest manifest. Jira review context, the configured Bitbucket
repository and pull request, build state, optional diffstat, and zero to three
configured Confluence pages are independently re-read and verified.

## Scope

- Add one narrowly typed Jira review-context read with allowlisted custom fields,
  bounded text, issue links, and approved exact Bitbucket/Confluence relations.
- Let Bitbucket build-status reads resolve and reverify the head commit of one
  exact configured pull request while preserving commit-based compatibility.
- Add one immutable registered-workflow planner and create-only renderer.
- Route the command through organization profile admission, runtime binding,
  native connector identity, provider-data policy, audit, retention, citations,
  and performance instrumentation.
- Update tests, configuration examples, behavioral requirements, semantic
  routing, and operator/developer documentation.

## Rationale

The existing plan/orchestrator remains the authority and execution boundary.
The first protected pilot already owns exact provider IDs, so the executable
plan can bind those identifiers before provider access. Jira relations are
normalized and checked as evidence but cannot dynamically broaden or rewrite
the immutable plan.

## Alternatives considered

- Re-enabling the legacy weekly-status execution shortcut was rejected because
  it bypasses the profile-owned manifest and path binding.
- A generic report or staged dynamic-action framework was rejected as broader
  than the first exact fixture case.
- Jira UI scraping, arbitrary HTTP, provider CLIs, and MCP fallback were rejected
  because they bypass the typed connector and native implementation boundary.

## Non-goals

- Provider writes, comments, transitions, merges, sends, or publication.
- Repository-wide or tenant-wide relationship search.
- PowerPoint, Outlook, Teams, browser automation, or third-party MCP.
- Managed-workstation certification, which remains owned by issue #172.

## Risks

- Retrieved relation prose could attempt to broaden scope; only exact trusted
  IDs and allowlisted URL shapes may be normalized or acted upon.
- Optional sources could be mistaken for complete evidence; bundle status must
  distinguish complete, partial, failed, stale, and ambiguous outcomes.
- Provider content could leak through audit or metrics; only the private bundle
  may retain bounded normalized content.
