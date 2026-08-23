# Design

## Approach

Map `MASTER_AGENT_LIVE_READ_PROXY_USERNAME` and
`MASTER_AGENT_LIVE_READ_PROXY_PASSWORD` from the protected read environment to
the runtime's fixed `MASTER_AGENT_PROXY_USERNAME` and
`MASTER_AGENT_PROXY_PASSWORD` references on the single live-read test step.

## Affected components

- `.github/workflows/live-connector-integration.yml`
- `tests/test_live_connector_workflow.py`
- `docs/live-connector-integration-tests.md`
- `specs/current/security/MA-LIVE-INTEGRATION-001.md`

## Data flow

GitHub resolves the two environment secrets only after read-environment review.
The live test process exposes them under the already approved broker names.
Configuration captures only the secret-free proxy profile; credential
resolution obtains the values in memory when the connector is constructed.

## Compatibility

Direct profiles ignore the optional values. Existing live jobs remain disabled
until their repository variables and protected environments are complete.

## Security

The mapping exists only on the read harness step, uses no credential-bearing
URL or file, and is statically excluded from effect and administration job
sources. Logs and artifacts remain subject to the existing no-secret and
no-upload boundaries.

## Rejected alternatives

Global job variables, repository secrets, plaintext TOML fields, and mappings
shared with effect or administration jobs were rejected because they would
broaden credential visibility or create a second credential contract.
