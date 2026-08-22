# Proposal

## Problem

Imported quarantines can cross promotion environments, and validation evidence
can describe a different worker from the enabled manifest. Either mismatch
breaks the claim that production readiness and sandbox validation apply to the
exact capability execution boundary.

## Desired outcome

Promotion fails before lifecycle mutation unless the signed quarantine,
promotion service, validator, validation evidence, sandbox evidence, and future
execution manifest all bind the same canonical environment and worker identity.

## Scope

Tighten the existing capsule promotion service, expose the validator's worker
identity, add adversarial regressions, and clarify the maintained capsule-import
requirement and developer documentation.

## Rationale

The promotion service is the narrow shared boundary that already owns every
quarantine-to-enable transition. Enforcing identity there closes both imported
and direct promotion paths without weakening later runtime verification.

## Alternatives considered

Changing only the import function would leave other signed quarantines able to
reach the same vulnerable promotion path. Trusting evidence digests without
checking their worker fields would preserve sandbox substitution.

## Non-goals

This change does not add a production credential provider, approval service,
external audit sink, or a new capsule execution backend.

## Risks

Callers using the undocumented `test` environment label or custom validators
without an explicit worker identity will now fail closed. There are no shipping
non-test callers, and maintained callers are migrated to the canonical
`non_production` environment.
