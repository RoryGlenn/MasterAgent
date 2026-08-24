# Proposal

## Problem

The production `T1-EWIR-001` Engineering Work Item Review is implemented, but
the protected live connector workflow cannot select and execute that exact case.
The existing read matrix also starts on effect and administration dispatches,
so adding the case without an explicit selector would expose overlapping live
paths and unrelated provider credentials. Without a repository-owned protected
path, issue #94 cannot produce the initial live fixture evidence needed before
the managed-workstation work in issue #172.

## Desired outcome

Add one default-disabled, manual selector to the existing protected workflow.
The selector runs `T1-EWIR-001` only from reviewed default-branch code, through
the read environment, with exactly the Jira, Bitbucket, and Confluence
credential surface. It must validate the narrow one-page, no-diffstat fixture
before provider access and accept only one complete, digest-verified run whose
content-free performance evidence stays within the 14-call initial bound.

## Scope

This change updates the existing GitHub Actions workflow, extends its local
credentialed harness with create-only case preparation and post-run evidence
validation, adds adversarial and static tests, and updates the protected-live
and Tier-1 operational documentation. Existing broad read, effect, and
administration modes remain available but become mutually exclusive with the
new case.

## Rationale

One selector in the existing manual workflow reuses its reviewed branch,
environment, action-pinning, and secret boundaries. A fixed generated employee
profile and strict before/after validation keep fixture data private while
proving that only the three native connectors were selected. The initial
one-page, no-diffstat shape is intentionally narrower than the general
production workflow because it is the proven 14-provider-call fixture.

## Alternatives considered

A separate workflow was rejected because it would duplicate the same protected
environment and workflow boundary. Extending the broad read matrix was rejected
because it requires unrelated GitHub and Microsoft credentials and does not run
the high-level production command. Generating fixture TOML from many repository
variables was rejected because the exact private workflow configuration is one
reviewable protected object and must not be reconstructed from loosely related
inputs.

## Non-goals

This change does not provision provider fixtures or credentials, enable the
repository gate, execute a credentialed run, establish a Windows 11
managed-workstation baseline, complete issue #172, change the general
zero-to-three-page workflow contract, or enable diffstat for the initial
protected case.

## Risks

The main risks are accidental mixed dispatch, unselected credentials reaching a
job, mutable or unsafe private configuration, a partial or ambiguous result
being counted as success, and provider content entering retained CI evidence.
Exact selector validation, create-only mode-restricted files, pre-provider
configuration checks, strict run/artifact/performance readback, and a
content-free job summary mitigate those risks.
