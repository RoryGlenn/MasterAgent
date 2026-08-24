# Proposal

## Problem

Applied execution binds the provider system, configuration, destination,
credentials, principal, trust store, proxy, and network profile, but it does not
name the reviewed connector implementation authorized to execute. Performance
evidence therefore still emits the temporary `unbound_pending_170` value. A
future second implementation for the same provider could otherwise be
substituted without an implementation-specific approval boundary.

## Desired outcome

Trusted integration configuration selects the exact `native` implementation for
every live connector before credentials or connector construction. The identity
is approval-bound, compared on apply and resume, and exposed only through
content-free execution, audit, readiness, support, and performance metadata.
Native failure propagates as the original typed failure and never falls back.

## Scope

- Add the closed `implementation = "native"` connector setting, with `native`
  as the compatibility default for existing first-party configurations.
- Bind implementation identity into connector configuration and versioned
  execution-context fingerprints.
- Reject missing, unsupported, or drifted identities before credential or
  connector work.
- Route factory construction only through the selected native implementation.
- Attribute native identity in bounded audit, readiness, support-bundle, and
  performance evidence.
- Add adversarial selection, drift, fallback, privacy, and selected-only tests.
- Update configuration, architecture, execution, operations, threat, and
  integration documentation.

## Rationale

One closed configuration enum and one required execution-binding field extend
the existing typed connector path without replacing `Connector`,
`ConnectorRegistry`, or the provider-specific constructors. Capability-specific
connector objects for one provider remain facets of the same selected native
implementation.

## Alternatives considered

- A generic backend abstraction was rejected because there is only one reviewed
  implementation and the existing registry already owns capability routing.
- Inferring identity from Python class names was rejected because classes are
  implementation detail rather than trusted organization configuration.
- Allowing action metadata or runtime user selection was rejected because both
  are untrusted inputs outside the organization configuration boundary.

## Non-goals

- Adding an MCP client, dynamic tool discovery, or arbitrary MCP schemas.
- Replacing provider identity, configuration, principal, policy, approval,
  verification, idempotency, compensation, retention, or audit binding.
- Adding automatic fallback for reads or effects.
- Asking users to select implementations at runtime.

## Risks

- Compatibility defaults could be mistaken for untrusted selection; only the
  already trusted integration parser applies the default.
- Historical execution contexts did not bind implementation identity; they must
  not be accepted as effect authorization under the new schema.
- Diagnostic propagation could become a content channel; serialized identity is
  restricted to the fixed `native` value and bounded provider system names.
