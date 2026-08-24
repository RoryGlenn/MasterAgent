# Design

## Approach

Add a closed `ConnectorImplementation` enum to integration configuration. The
only supported value is `native`; omitted values default to `native` so existing
first-party configurations retain their behavior. The field participates in the
secret-free connector configuration digest.

During selected connector capture, read the implementation after system
selection and before credential resolution or principal attestation. Store it
as a required field on `ConnectorExecutionBinding` and advance the execution
context schema. Applied capture compares the configured and approved identities
before resolving credentials. Factory validation repeats the comparison for
supplied immutable captures and dispatches only the `native` branch. Exceptions
propagate; there is no alternate branch or retry through another implementation.

Performance records one selected and initialized implementation per selected
provider configuration, even when the native implementation exposes several
capability-specific connector objects. Audit rows, deployment readiness,
capability doctor output, and support bundles receive only the fixed identity.

## Affected components

- Configuration and binding: `config.py`, `models.py`, and
  `execution_context.py`.
- Construction and execution: connector factory, registry-facing orchestration,
  direct reads, CLI bind/apply/resume, and deterministic benchmark setup.
- Evidence: performance, audit, deployment readiness, operating doctor, and
  support bundles.
- Tests for configuration, binding/drift, factory selection, approval, audit,
  diagnostics, performance, and fallback behavior.
- Current behavioral requirements and maintainer/operator documentation.

## Data flow

1. A trusted integration snapshot parses `implementation`, defaulting to the
   closed `native` enum.
2. Capability routing selects the provider system.
3. Capture selects the provider's implementation and destination.
4. If applying or resuming, implementation drift is rejected before any
   credential resolution, principal attestation, provider I/O, connector
   construction, or registry registration.
5. The exact identity is serialized in the execution context, changing its
   fingerprint and therefore the plan and approval fingerprint.
6. The factory constructs the native capability facets only and registers no
   alternate implementation.
7. Audit and diagnostics expose only `{system, implementation}` or the fixed
   implementation field; performance emits `native` with `bound = true`.

## Compatibility

Existing trusted integration files that omit `implementation` select `native`
without changing capabilities. New execution contexts use the advanced schema
and require implementation identity. Historical contexts that did not bind an
implementation cannot authorize applied execution and must be rebound and
reapproved. Report schemas otherwise retain their existing shapes except for
the corrected implementation values and additive readiness fields.

## Security

Project files, prompts, retrieved content, action parameters, provider output,
and arbitrary connector attributes are never consulted for implementation
selection. Unsupported configuration values fail parsing. Structurally valid
but mismatched approved identities fail before secret or provider access. Audit,
readiness, support, and performance serializers admit only bounded identity
values and no provider content, credentials, endpoints, or exception text.

## Rejected alternatives

- Generic `backend` fields or a `CapabilityBackend` layer: unnecessary and
  broader than the connector-specific requirement.
- Class-name inference: not organization-owned and unstable across refactors.
- Silent native-to-MCP or native-to-plugin fallback: unsafe for duplicate
  effects, semantic equivalence, data policy, and observability.
- Treating the whole integrations digest as sufficient: it detects file drift
  but does not make the selected implementation reviewable in plans or evidence.
