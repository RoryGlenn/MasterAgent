# Governed Reddit connector

## Problem

MasterAgent cannot currently search or read Reddit through a typed provider
boundary, and it cannot prepare or execute a Reddit post, comment, reply, edit,
or deletion through the approval-bound applied runtime. Ad hoc HTTP or browser
automation would bypass provider identity, endpoint, response-budget, approval,
verification, and audit controls.

## Desired outcome

Add an official-API Reddit connector that supports bounded reads and local
drafts, refreshes purpose-separated delegated OAuth access tokens without
persistence, rejects missing or out-of-profile provider scope reports, and
sends only the exact approved externally visible mutation. Every mutation is
independently re-read or deletion-checked and never automatically retried.

## Scope

- Purpose-separated OAuth refresh-token acquisition plus provider-backed
  identity and scope attestation.
- Search, post/comment, subreddit-rule, authenticated-history, and inbox reads.
- Local post and comment/reply drafts.
- Approved post, comment/reply, edit, and own-content delete operations.
- Fixed provider origins, bounded pagination and responses, rate-limit errors,
  prompt-injection marking, semantic routing, configuration, and documentation.

## Rationale

A repository-owned typed adapter preserves the same identity, egress,
approval, and verification boundaries as other providers while supporting the
official Reddit API and its OAuth lifecycle.

## Alternatives considered

- Browser automation: rejected because it is brittle and bypasses typed API,
  identity, response-budget, and poststate contracts.
- A generic HTTP connector: rejected because it would expose arbitrary origins,
  methods, fields, and authorization-header forwarding.
- Enabling edit/delete after a local pre-read: rejected because Reddit has no
  atomic provider precondition and a concurrent change could race the mutation.

## Non-goals

- Password-grant authentication, moderation, voting, awards, chat, or subreddit
  administration.
- Automated engagement, bulk posting, or approval-free recurring publication.
- Storing access tokens, refresh tokens, or client secrets in repository files,
  output artifacts, audit events, or model-visible error messages.

## Risks

Reddit content is untrusted and may contain prompt injection or malicious links.
Posting is externally visible and a lost response can leave an indeterminate
provider outcome. Fixed origins, exact approvals, zero write retries, bounded
normalization, and independent re-reads reduce those risks without claiming
delivery, readership, or atomicity that Reddit does not provide.
