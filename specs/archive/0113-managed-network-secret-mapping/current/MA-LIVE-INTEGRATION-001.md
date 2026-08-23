# MA-LIVE-INTEGRATION-001 — Protected credentialed integration evidence

## Status

Active

## Requirement

MasterAgent MUST count a provider integration as verified only when reviewed
default-branch code executes a non-skipped live test with real protected
credentials and stable dedicated fixtures. The complete multi-provider matrix
MUST be manual-dispatch only and MUST NOT expose credentials to pull-request,
fork, or unreviewed branch code. Read, reversible effect/communication, and
administration credentials MUST remain in separately gated protected
environments and use privilege-specific secret names. Repository enablement
variables MUST remain absent or false until the corresponding environment,
least-privilege credentials, fixtures, default-branch restriction, and reviewer
rules are complete.

Delegated-only Microsoft coverage MUST use a restricted delegated token file.
Before any provider effect, the live harness MUST verify delegated identity,
the exact required provider scopes, and enough remaining token lifetime to
cover the job timeout plus cleanup margin. Application credentials MUST NOT be
treated as equivalent evidence for delegated OneNote reads or normal Teams
sends, and a static stored delegated token MUST NOT be assumed renewable for a
scheduled run.

Every compensatable live mutation MUST write one bounded mode-`0600` recovery
entry immediately after the connector returns its provider result. Normal
execution MUST attempt and independently verify compensation in `finally`; a
separate same-job `always()` step MUST replay any remaining entries after an
ordinary failure. Recovery entries MUST use an exact schema, current run
binding, approved reversible capabilities, bounded counts, private directories,
and no credential values. They MUST remain runner-temporary and MUST NOT be
uploaded. Non-reversible communications MUST use explicitly dedicated
nonproduction destinations that expect test traffic.

The repository MUST statically verify workflow triggers, exact default-branch
binding, protected environment names, opt-in gates, privilege-specific secret
mapping, private materialization, pinned actions, recovery execution, and the
absence of artifact upload. Missing credentials, provider consent, fixtures,
or environment setup MUST be a visible incomplete-integration result and MUST
NOT be silently replaced with anonymous, mock, or application-mode coverage.

When the protected read matrix selects an authenticated managed-network
profile, the workflow MUST map its fixed `MASTER_AGENT_PROXY_USERNAME` and
`MASTER_AGENT_PROXY_PASSWORD` broker references from dedicated
`connector-integration-read` environment secrets only for the live read
harness. Those privilege-specific secrets MUST NOT be available to effect or
administration jobs, and missing proxy setup MUST remain a visible incomplete-
integration result rather than falling back to direct or ambient networking.
The repository MUST statically verify the exact mapping and its absence from
other privilege zones.

Credentialed connectors that use a shared tenant gateway MUST bind the exact
product and tenant or cloud identifier in their API base path before credential
resolution. Relative, absolute, redirected, response, and pagination URLs MUST
NOT escape that path even when they remain on the same origin. A distinct
provider browser/UI root MAY be used only for sanitized user-facing references;
it MUST be independently allowlisted, approval-bound, and MUST never receive
connector credentials.

## Rationale

Live tests are evidence only when their code, credential, target, and cleanup
boundaries are real and explicit. A skipped job or a broad credential is not
proof that a protected provider workflow is ready.

## Scenarios

### Expiring delegated token blocks before mutation

- GIVEN the effects environment has a delegated Microsoft token that expires
  before the job timeout and cleanup margin
- WHEN the protected effects matrix starts
- THEN it fails before the first provider mutation and reports only a
  secret-free authentication readiness error.

### Ordinary failure still recovers a reversible effect

- GIVEN a connector returned a successful reversible mutation and the test
  failed before its normal compensation completed
- WHEN the workflow reaches its independent cleanup step
- THEN the exact private recovery entry is replayed, compensation is
  independently verified, and the workflow remains failed for the original
  test error.

### Missing external setup is not evidence

- GIVEN one protected environment lacks its provider secret, fixture, consent,
  reviewer, or enablement variable
- WHEN the repository workflow is evaluated
- THEN the corresponding live job does not claim success and offline tests do
  not substitute a mock provider result.

### Managed-network credentials stay in the read privilege zone

- GIVEN the protected read environment contains the dedicated proxy username
  and password secrets
- WHEN the reviewed live read harness selects an authenticated proxy profile
- THEN the runtime receives them only through its fixed broker references
- AND neither the effect nor administration job can access those read secrets.

### Shared gateway cannot escape its tenant path

- GIVEN an Atlassian credential is bound to an exact product and cloud-ID API
  gateway root
- WHEN a request, redirect, response, or pagination link remains on the shared
  origin but leaves that root
- THEN the connector rejects it before accepting provider data or reusing the
  credential outside the approved path.

## Implementation

- `.github/workflows/live-connector-integration.yml`
- `tests/test_connector_integration_matrix.py`
- `src/master_agent/config.py`
- `src/master_agent/http.py`

## Verification

- `tests/test_live_connector_workflow.py`
- `tests/test_connector_integration_matrix.py`
- `tests/test_http.py`
- `tests/test_config.py`
- `tests/test_atlassian_connectors.py`

## History

- Introduced by GitHub issue #94 with protected live-evidence and shared-gateway
  path-confinement requirements.
- Clarified for company rollout by GitHub issue #113 to bind authenticated
  proxy credentials only inside the protected read integration job.
