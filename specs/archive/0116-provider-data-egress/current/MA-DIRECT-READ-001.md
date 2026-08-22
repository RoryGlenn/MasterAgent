# MA-DIRECT-READ-001 — Direct read-only provider session

## Status

Active

## Requirement

The runtime MUST provide an explicit direct-read route for a plan containing
only direct-user, `read_only` actions for exactly one built-in typed provider.
Before credentials or principal attestation, the route MUST statically approve
provider-data egress for its stateless destination and model tenancy and bind
the exact field, schema, item, and byte shape. After authenticated control-plane
attestation and before provider content dispatch, it MUST construct the complete
account-bound egress binding. It MUST reject missing or denied classification,
unapproved destination or tenancy, and any policy rule that requires persistent
audit or unavailable handling before provider content access.

The route MUST otherwise validate each action through the capability catalog,
governance, policy, source-of-truth, authenticated connector identity/scope,
fixed provider endpoint, bounded transport, prompt-injection marking, and an
independent provider re-read. Before returning content it MUST revalidate the
egress binding, apply its deterministic minimization/redaction and byte limit,
and return the content-free binding metadata. It MUST not require a persisted
audit database, artifact directory, approval artifact, or pre-bound runtime
context for an approved public/internal read.

The route MUST reject a plan that contains a non-read risk, non-direct
authority, more than one provider, plugin or capsule binding, persisted output,
or a connector that is not an exact built-in typed `ReadOnlyConnector`, before
it dispatches a provider request. Provider effects, communications,
administration, deletes, merges, raw plugins, capsules, and recurring execution
MUST continue to use their existing governed boundaries.

## Rationale

Read-only provider access should be practical for approved low-sensitivity
data, while the model-context boundary prevents an unaudited or unapproved data
egress and provider effects retain their stronger runtime.

## Scenarios

### Approved direct GitHub read

- GIVEN a direct-user GitHub read-only plan with an explicit approved
  classification, configured credentials, destination, and model tenancy
- WHEN the user runs `master-agent run PLAN --direct-read`
- THEN static egress checks run before GitHub account attestation, only GitHub
  is contacted, the complete binding is constructed before repository content,
  the result is independently re-read and sanitized, and no persistent runtime
  state is created.

### Rejected confidential direct read

- GIVEN a confidential read whose organization rule requires durable audit
- WHEN the user requests direct-read execution
- THEN the command rejects it before it resolves provider content.

### Rejected effect

- GIVEN a plan containing a provider write or message send
- WHEN the user requests direct-read execution
- THEN the command rejects it before it resolves a provider connector.

## Implementation

- `src/master_agent/direct_read.py`
- `src/master_agent/provider_egress.py`
- `src/master_agent/cli.py`
- `src/master_agent/connectors/read_only.py`

## Verification

- `tests/test_direct_read.py`
- `tests/test_provider_egress.py`
- `tests/test_cli.py`

## History

- Introduced by GitHub issue #108.
- Extended by GitHub issue #116 with provider-data model-context policy.
