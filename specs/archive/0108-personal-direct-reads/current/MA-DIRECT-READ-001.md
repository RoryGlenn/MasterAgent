# MA-DIRECT-READ-001 — Direct read-only provider session

## Status

Active

## Requirement

The runtime MUST provide an explicit direct-read route for a plan containing
only direct-user, `read_only` actions for exactly one built-in typed provider.
The route MUST validate each action through the capability catalog,
governance, policy, source-of-truth, authenticated connector identity/scope,
fixed provider endpoint, bounded transport, prompt-injection marking, and an
independent provider re-read. It MUST not require a persisted audit database,
artifact directory, approval artifact, or pre-bound runtime context.

The route MUST reject a plan that contains a non-read risk, non-direct
authority, more than one provider, plugin or capsule binding, persisted output,
or a connector that is not a typed `ReadOnlyConnector`, before it dispatches a
provider request. Provider effects, communications, administration, deletes,
merges, raw plugins, capsules, and recurring execution MUST continue to use
their existing governed boundaries.

## Rationale

Read-only provider access should be practical for a direct user request, while
effect-bearing operations retain their stronger bound and auditable runtime.

## Scenarios

### Direct GitHub read

- GIVEN a direct-user GitHub read-only plan and configured credentials
- WHEN the user runs `master-agent run PLAN --direct-read`
- THEN only GitHub is contacted, the result is independently re-read, and no
  persistent runtime state is created.

### Rejected effect

- GIVEN a plan containing a provider write or message send
- WHEN the user requests direct-read execution
- THEN the command rejects it before it resolves a provider connector.

## Implementation

- `src/master_agent/direct_read.py`
- `src/master_agent/cli.py`
- `src/master_agent/connectors/read_only.py`

## Verification

- `tests/test_direct_read.py`
- `tests/test_cli.py`

## History

- Introduced by GitHub issue #108.
