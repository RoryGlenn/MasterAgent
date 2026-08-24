# MA-CONNECTOR-IMPLEMENTATION-001 — Exact connector implementation binding

## Status

Active

## Requirement

Every live connector execution MUST select exactly one stable connector
implementation identity from trusted integration or organization configuration
after capability and system selection but before credential resolution,
principal attestation, provider access, connector construction, or registry
registration. The initial and compatibility-default identity MUST be `native`.
Unsupported values MUST fail closed. Project configuration, prompts, retrieved
content, connector output, action parameters, and runtime user input MUST NOT
select or alter the implementation.

The identity MUST participate in the connector configuration identity, the
versioned connector execution binding, the execution-context fingerprint, the
plan fingerprint, and effect approval. Bind, apply, and resume MUST compare the
exact identity before credential or connector work. A historical context that
did not bind implementation identity MUST NOT authorize applied execution.

The connector factory MUST construct and register only the selected native
implementation for the selected system and capability set. Several
capability-specific connector objects MAY expose facets of that one native
implementation. A construction or execution failure MUST propagate through the
existing typed failure path and MUST NOT retry through, fall back to, or silently
substitute another implementation for reads or effects.

Audit, deployment readiness, capability doctor output, support bundles, and
performance evidence MUST identify the implementation using only bounded,
content-free metadata. Ordinary user output SHOULD remain
implementation-neutral unless the identity is needed to diagnose a failure.
Implementation identity MUST NOT replace or weaken provider, configuration,
origin, CA, credential, principal, scope, policy, approval, verification,
idempotency, compensation, retention, or audit controls.

## Rationale

The provider name alone cannot distinguish two reviewed implementations for the
same system. Exact trusted selection prevents post-review substitution while
preserving the existing connector protocol and capability registry.

## Scenarios

### An existing first-party connector selects native

- GIVEN a trusted integrations file omits the new setting
- WHEN a selected live connector is captured
- THEN its configuration and execution binding explicitly identify `native`

### Implementation drift fails before secrets or construction

- GIVEN a plan approved one implementation identity
- WHEN applied trusted configuration or a supplied capture names another identity
- THEN execution fails before credentials, provider access, construction, or registration

### Untrusted data cannot select an implementation

- GIVEN project content, a prompt, an action parameter, or provider output names an implementation
- WHEN the runtime selects and constructs the connector
- THEN only trusted integration configuration determines the implementation

### Native failure does not fall back

- GIVEN the selected native connector raises a typed construction or execution failure
- WHEN the action runs
- THEN the failure is reported and no alternate implementation is initialized or invoked

### Diagnostics remain content-free

- GIVEN connector configuration and provider data contain sensitive canaries
- WHEN audit, readiness, support, and performance evidence is serialized
- THEN the evidence identifies only the bounded system and `native` implementation

## Implementation

- `src/master_agent/config.py`
- `src/master_agent/models.py`
- `src/master_agent/execution_context.py`
- `src/master_agent/cli.py`
- `src/master_agent/connectors/factory.py`
- `src/master_agent/capabilities.py`
- `src/master_agent/direct_read.py`
- `src/master_agent/orchestrator.py`
- `src/master_agent/readiness.py`
- `src/master_agent/operating.py`
- `src/master_agent/performance.py`

## Verification

- `tests/test_config.py`
- `tests/test_config_and_discovery.py`
- `tests/test_execution_context.py`
- `tests/test_factory_and_catalog.py`
- `tests/test_approval_handoff.py`
- `tests/test_cli.py`
- `tests/test_orchestrator.py`
- `tests/test_audit_safety.py`
- `tests/test_oauth_readiness.py`
- `tests/test_operating.py`
- `tests/test_performance.py`

## History

- Introduced by GitHub issue #170.
