# Provider-data model-context egress policy

## Problem

Typed provider connectors normalize and verify data without calling a model,
but their returned payloads can still enter the surrounding agent or model
context. The existing external-model check depends on a static capability flag,
and no checked-in provider-read capability sets that flag. Direct reads,
repository-list shortcuts, and connection probes also have separate return
paths, so they can bypass a capability-local model declaration entirely.

## Desired outcome

Every provider read is bound to an organization-approved data classification,
provider account, requested projection, output limit, destination, model
tenancy, handling rule, and audit requirement before provider content is
requested. The same immutable binding is revalidated before sanitized content
is returned. Approved public and internal direct reads remain approval-free and
stateless; sensitive or unknown data fails closed unless a configured governed
route can satisfy its audit and redaction requirements.

## Scope

- Add typed organization model-context configuration and egress rules.
- Add an immutable, content-free provider-data egress binding and deterministic
  output sanitization/size enforcement.
- Enforce the boundary in direct reads, applied workflows, live discovery and
  connection probes, and GitHub/Bitbucket repository shortcuts.
- Require explicit classification in serialized provider-read plans.
- Add optional offline readiness checks for a selected provider/classification.
- Record content-free egress metadata in governed audit state without retaining
  provider content.

## Rationale

The relevant security boundary is where provider data is returned to a caller,
not whether the connector implementation directly invokes a model. A shared
return-boundary policy therefore covers both current and future connector
routes while preserving the low-friction read-only execution model.

## Alternatives considered

- Mark every read capability as using an external model: rejected because it
  still does not bind provider account, requested projection, destination,
  tenancy, output handling, or audit requirements, and it misses probes.
- Require effect approval for every provider read: rejected because an approved
  public/internal egress is not a provider mutation and needs no effect grant.
- Let retrieved content declare its own classification or destination: rejected
  because untrusted content, including prompt injection, is never authority.

## Non-goals

- Cryptographically attest the surrounding Copilot or model tenancy from this
  Python process; the configured tenancy remains a reviewed deployment fact.
- Claim generic redaction declassifies content.
- Persist provider bodies solely to create an audit trail.
- Add provider writes or relax any existing effect boundary.

## Risks

Organization rules can be misconfigured to approve an inappropriate tenancy or
projection. Strict typed parsing, fail-closed rule matching, readiness output,
configuration digests, bounded results, and deployment documentation reduce
that risk. Generic secret-key and configured-field redaction is deliberately
treated as handling within the original classification, not declassification.
