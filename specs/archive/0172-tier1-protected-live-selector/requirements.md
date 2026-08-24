# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-LIVE-INTEGRATION-001 — Protected credentialed integration evidence

The existing manual credentialed workflow MUST expose a default-disabled exact
case selector. `T1-EWIR-001` MUST be mutually exclusive with the broad read,
effect, and administration paths and MUST run only from reviewed default-branch
code in `connector-integration-read` while the existing read enablement variable
is the literal string `true`. The case job MUST expose only Jira, Bitbucket, and
Confluence credentials plus its explicitly selected proxy or enterprise-CA
inputs; it MUST NOT expose GitHub or Microsoft credentials or use artifact
upload/download actions.

Before provider access, the case harness MUST create and validate one fixed
employee/live/no-write/no-communication profile, the protected integrations
file, and the protected workflow file as distinct create-only regular
mode-`0600` files beneath a private runner-temporary directory. It MUST require
exactly one Confluence page, Bitbucket Cloud with diffstat disabled, internal-or-
stricter classification, the five exact read capabilities, and enabled
credentialed first-party `native` Jira, Bitbucket, and Confluence routes. Missing,
malformed, stale, foreign, ambiguous, or over-broad input MUST fail before any
provider request.

The case MUST invoke the installed production
`engineering-work-item-review` command for the exact protected Jira key and
capture its ordinary output only in ephemeral private state. Success MUST
require one exit-zero complete run; exactly three create-only regular
mode-`0600` review artifacts with valid manifest/readback digests; a valid
baseline-ineligible `T1-EWIR-001` performance snapshot; exactly three selected,
initialized, and credential-resolved `native`/bound connector implementations;
exactly six principal attestations, two for each selected provider across
immutable bind and applied execution; zero governance or approval interactions;
at most 14 provider content calls and always fewer than 20; and zero credential,
initialization, principal, transport, or verification activity for every
unselected provider. The high-level bind/apply attestation count is distinct
from deterministic benchmark setup, which performs one attestation per selected
provider and records exactly three. Retained workflow evidence MUST be content-
free and MUST NOT include provider payloads, fixture identifiers, URLs, local
paths, credentials, or exception text.

The GitHub-hosted Ubuntu selector is repository-side protected fixture evidence
for issue #94. It is baseline-ineligible and MUST NOT be described as the
Windows 11 standard-user managed-workstation baseline or as completing issue
#172.

## REMOVED

None.
