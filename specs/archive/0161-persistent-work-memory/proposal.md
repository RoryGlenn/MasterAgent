# Proposal

## Problem

MasterAgent can execute and audit governed actions, but it does not retain a
small, durable account of development work across separate CLI invocations.
Issue context, decisions, checkpoints, references, and lifecycle progress are
therefore easy to lose between planning, implementation, review, verification,
and merge.

## Desired outcome

An operator can keep one bounded local work record from issue through merge,
inspect it after restarting the process, and verify that its append-only event
history has not been deleted, reordered, or edited.

## Scope

Add an owner-private SQLite work journal, an append-only hash-chained event
model, strict lifecycle validation, deterministic inspection and verification,
and `work-memory start`, `record`, `show`, and `verify` CLI commands. Document
the feature as local terminal functionality that requires no website, server,
poller, hook, or provider credential.

## Rationale

The smallest useful memory is a local event journal, not a general knowledge
base. Explicit bounded records preserve continuity while keeping authority,
credentials, provider content, and background network activity outside the
feature.

## Alternatives considered

- A hosted cockpit would require infrastructure the operator cannot provide.
- A local web server would add another service and attack surface without
  improving the core persistence contract.
- Free-form notes would not provide lifecycle validation or tamper evidence.
- GitHub synchronization would introduce credentials, network failure modes,
  and provider authority into a local memory boundary.

## Non-goals

The feature will not host a UI, access GitHub or another provider, poll or run
in the background, store issue or pull-request bodies, index embeddings, act as
an approval artifact, or grant execution authority.

## Risks

Remembered summaries and references may be incorrect or malicious, so they
remain untrusted metadata. A cryptographic hash chain detects modification; it
does not prove the truth or authorship of an entry. Local deletion of the whole
database cannot be detected without an external anchor, so callers must treat a
missing database as unavailable memory rather than a valid empty history.
