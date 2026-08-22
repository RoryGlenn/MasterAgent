# Design

## Approach

Treat the configured provider API root as an origin-and-path boundary. The HTTP
client retains the normalized base-path prefix and rejects relative traversal,
same-origin absolute URLs, redirects, and pagination links that leave it.
Jira and Confluence Cloud accept either a tenant API root or the exact
`api.atlassian.com/ex/{product}/{cloudId}` gateway form. A separate validated
`web_base_url` supplies browser links and is never used for authenticated API
requests.

The full credentialed matrix becomes manual-dispatch only. Its read, effect,
and administration jobs map distinct protected secrets into the runtime's
fixed credential names. Microsoft read/effect jobs require a delegated
restricted token file, the exact operation scopes, and enough remaining token
lifetime for the job plus cleanup margin before any live effect begins.
Application credentials cannot stand in for OneNote or normal Teams delegated
coverage.

Every compensatable test writes one bounded, mode-`0600` recovery entry
immediately after the connector returns its result and removes it only after
independent compensation verification. A separate `always()` workflow step
replays any remaining entries through the same connector compensation API.
Recovery state remains inside `RUNNER_TEMP`, is never uploaded, and cannot
contain credentials. Non-reversible Outlook and Teams tests remain limited to
explicit dedicated destinations.

## Affected components

- `src/master_agent/config.py`, `src/master_agent/http.py`, and Atlassian
  connector normalization
- `config/integrations.toml`, `config/oauth.toml`, and packaged copies
- `.github/workflows/live-connector-integration.yml`
- `tests/test_http.py`, connector/config tests, live integration guards and
  recovery tests, and a static workflow contract test
- credentialed-integration, configuration, deployment, security, and release
  documentation
- semantic ownership and this behavioral change

## Data flow

1. A reviewed default-branch manual dispatch selects read, effects, or admin.
2. The protected environment releases only that job's configuration and
   credentials after its reviewer and branch rules pass.
3. Preflight validates every required gate, fixture, provider scope, token
   lifetime, and endpoint before connector effects begin.
4. Each reversible connector result is recorded in the private recovery
   journal, independently compensated, and removed only after verification.
5. A same-job `always()` step replays any entry left by an ordinary failure;
   the runner-temporary journal is never published as an artifact.
6. Provider results and browser references remain subject to distinct API-path
   and credential-free UI-root boundaries.

## Compatibility

Existing tenant-host Jira and Confluence roots remain valid. Existing provider
runtime environment-variable names remain accepted. The packaged Bitbucket
profile now names the Atlassian account email explicitly while private legacy
app-password profiles may retain the username name. Protected workflow secret
names become privilege-specific before being mapped into fixed runtime names.
Existing low-level and mock connector paths remain unchanged.

## Security

The browser root is an allowlisted, credential-free output base and cannot
alter the API destination. Gateway configuration requires the exact Jira or
Confluence product segment and one bounded cloud ID. HTTP resolution compares
the decoded canonical request path with the captured base prefix before header
construction or transport. Recovery readers accept only private regular files,
an exact schema, the current workflow run label, approved reversible
capabilities, and bounded entry counts.

## Rejected alternatives

Keeping the weekly full-matrix schedule was rejected because the shipped
delegated token format has no CI refresh path. Treating client credentials as
equivalent was rejected because OneNote reads and normal Teams sends require a
delegated user. Uploading recovery state as an artifact was rejected because
provider pre/post state can be sensitive. Reusing one GitHub token name across
all environments was rejected because it obscures privilege separation.
