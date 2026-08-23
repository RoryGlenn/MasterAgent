# Credentialed Live Connector Integration Tests

## Purpose

The protected live suite answers one question: can reviewed MasterAgent code
authenticate to the real providers, execute its production connector contract,
and independently verify the result against stable test resources?

It is intentionally separate from offline coverage:

- `tests/test_connector_contract_matrix.py` checks factory wiring, capability
  routing, disabled surfaces, and local artifact generation without credentials
  or network access.
- `tests/test_connector_integration_matrix.py` requires real provider
  credentials and stable fixtures, rejects anonymous configuration, and makes
  external requests.
- `tests/test_live_connector_workflow.py` statically checks the GitHub Actions
  trigger, branch, environment, credential, preflight, recovery, pinning, and
  no-artifact boundaries without opening a provider connection.

A skipped live job or missing credential, consent grant, fixture, target, or
enablement variable is incomplete setup—not successful integration evidence.
Only a non-skipped protected run of reviewed default-branch code counts.

## Live coverage

### Credentialed reads

The read job probes and then executes one stable typed read for Jira,
Confluence, Bitbucket, GitHub, Microsoft identity, SharePoint, Outlook, Teams,
and OneNote. Each result is independently re-read with `verify()` rather than
trusted from the first response.

Microsoft coverage is delegated. The token must have exactly these effective
scopes:

- `User.Read`
- `Mail.Read`
- `Chat.Read`
- `Sites.Read.All`
- `Notes.Read`

The 25-minute job requires at least 30 minutes of remaining token lifetime,
including its cleanup margin.

### Protected effects and communications

The effects job uses dedicated nonproduction targets to:

- create, verify, and delete a Jira comment;
- create, verify, and delete a Confluence page;
- create, verify, and decline a Bitbucket pull request;
- create, verify, and close a GitHub issue; and
- replace, byte-verify, and restore a SharePoint DriveItem.

Only after the reversible stage and its recovery pass succeed does the job send
one Outlook message and one Teams chat message to dedicated destinations that
expect automated test traffic. Sends are non-reversible.

The Microsoft effects token must have exactly these effective scopes:

- `User.Read`
- `Sites.ReadWrite.All`
- `Mail.ReadWrite`
- `Mail.Send`
- `Chat.Read`
- `ChatMessage.Send`

The 35-minute job requires at least 45 minutes of remaining token lifetime,
including its cleanup margin. Application credentials are not equivalent
evidence for delegated OneNote reads or normal Teams sends.

Before the first mutation, the harness validates the nonproduction gate, every
credentialed connector, every read/effect/communication fixture, delegated
identity, exact scopes, and token lifetime. A later fixture failure therefore
cannot be discovered only after an earlier provider mutation.

### Recovery boundary

Each compensatable effect writes a bounded mode-`0600` recovery entry under a
mode-`0700` directory in `RUNNER_TEMP` immediately after the connector returns
its provider result. Normal execution attempts compensation in `finally` and
independently verifies the restored state. A separate same-job `always()` step
replays any residual entries after an ordinary failure.

Recovery state uses an exact schema and current-run binding, contains no
credential values, and is never uploaded as an artifact. This covers returned
effects and ordinary same-job failures. It cannot prove whether a provider
committed a request whose success response was lost before a recovery entry
could be written; that provider state remains indeterminate and must be
reconciled directly.

### GitHub administration

A mutually exclusive administration job tests `GitHubAdminConnector`. It
toggles one allowlisted benign setting in a dedicated sandbox repository,
verifies the provider state, restores the exact prior value, and uses the same
private journal and independent recovery pattern. It does not share the
ordinary GitHub job credential or configuration.

### Repository-scoped GitHub Actions credential

The read and effect jobs map the job-scoped `${{ github.token }}` into the
runtime's `MASTER_AGENT_GITHUB_TOKEN` name. Read grants only `contents: read`;
effects add `issues: write`. No stored personal access token is available to
those jobs.

Because `github.token` is an installation credential rather than a user bearer
token, those jobs set `MASTER_AGENT_LIVE_GITHUB_ACTIONS_TOKEN=true` and do not
claim user-token `/user` attestation evidence. The administration job alone
receives `MASTER_AGENT_LIVE_GITHUB_ADMIN_TOKEN`, mapped to the runtime name only
inside that job and preflighted against GitHub `/user` before administration.

`.github/workflows/github-actions-live-integration.yml` remains the separate
GitHub-only lifecycle for routine repository-scoped coverage.

## Protected GitHub Actions execution

`.github/workflows/live-connector-integration.yml` has only
`workflow_dispatch`. It has no pull-request, push, or schedule trigger, and
every provider job checks that it is running from the repository's current
default branch. `run_effects` and `run_github_admin` are mutually exclusive.

The jobs use three protected environments:

1. `connector-integration-read` — credentialed reads.
2. `connector-integration-effects` — reversible effects and dedicated test
   communications, selected with `run_effects`.
3. `connector-integration-admin` — GitHub administration, selected with
   `run_github_admin`.

Repository variables gate them independently:

- `MASTER_AGENT_LIVE_CONNECTOR_TESTS_ENABLED`
- `MASTER_AGENT_LIVE_EFFECT_TESTS_ENABLED`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_TESTS_ENABLED`

Set a gate to the literal string `true` only after its environment,
least-privilege credentials, consent, fixtures, dedicated targets, default-
branch restriction, and reviewer rules are complete.

### Current repository setup

All three environments currently require reviewer `RoryGlenn` and allow only
the exact `main` branch through a custom deployment policy. Self-review
prevention is off because `RoryGlenn` is the sole eligible collaborator. No
environment secrets, repository enablement variables, or fixture variables are
configured, so every provider job remains disabled. No full credentialed run
has therefore been counted as evidence.

This keeps the reviewer gate usable with one collaborator; it is not
independent reviewer separation. Add a second eligible reviewer and enable
self-review prevention when organization policy requires that separation.
GitHub currently also reports administrator bypass as enabled for these
environments.

## Privilege-specific secrets

Each private TOML starts from `config/integrations.toml`, contains real test
origins and only the gates needed for its job, and stores environment-variable
names rather than credential values. The workflow materializes it with mode
`0600` under `RUNNER_TEMP` and exposes only
`MASTER_AGENT_LIVE_INTEGRATIONS_FILE` to the test process. Every secret listed
for the selected environment is mandatory except the explicitly optional CA
bundle.

### Read environment

- `MASTER_AGENT_LIVE_READ_INTEGRATIONS_TOML`
- `MASTER_AGENT_LIVE_READ_GRAPH_TOKEN_FILE_JSON`
- `MASTER_AGENT_LIVE_READ_JIRA_USERNAME`
- `MASTER_AGENT_LIVE_READ_JIRA_TOKEN`
- `MASTER_AGENT_LIVE_READ_CONFLUENCE_USERNAME`
- `MASTER_AGENT_LIVE_READ_CONFLUENCE_TOKEN`
- `MASTER_AGENT_LIVE_READ_BITBUCKET_EMAIL`
- `MASTER_AGENT_LIVE_READ_BITBUCKET_TOKEN`

The read TOML keeps every write, send, branch-push, and administration flag
false.

### Effects environment

- `MASTER_AGENT_LIVE_EFFECT_INTEGRATIONS_TOML`
- `MASTER_AGENT_LIVE_EFFECT_GRAPH_TOKEN_FILE_JSON`
- `MASTER_AGENT_LIVE_EFFECT_JIRA_USERNAME`
- `MASTER_AGENT_LIVE_EFFECT_JIRA_TOKEN`
- `MASTER_AGENT_LIVE_EFFECT_CONFLUENCE_USERNAME`
- `MASTER_AGENT_LIVE_EFFECT_CONFLUENCE_TOKEN`
- `MASTER_AGENT_LIVE_EFFECT_BITBUCKET_EMAIL`
- `MASTER_AGENT_LIVE_EFFECT_BITBUCKET_TOKEN`

The effects TOML enables only the tested Jira/Confluence writes, Bitbucket pull
request creation, GitHub issue creation, SharePoint replacement, Outlook send,
and Teams send gates. Bitbucket branch push and GitHub administration remain
false.

### Administration environment

- `MASTER_AGENT_LIVE_GITHUB_ADMIN_INTEGRATIONS_TOML`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_TOKEN`

The administration TOML enables the GitHub master write and administration
gates while leaving ordinary GitHub issue/pull-request writes false.

`MASTER_AGENT_ENTERPRISE_CA_BUNDLE_PEM` is an optional environment-local file
secret in any job that needs an approved private certificate authority. Do not
reuse the read/effect TOML or token secrets across environments merely because
their provider fields look similar.

## Managed-network profile evidence

Authenticated proxy and enterprise-CA evidence is opt-in and must run only from
reviewed default-branch code in the protected `connector-integration-read`
environment. It must never run for a pull request or fork. Before enabling it:

1. add a dedicated company proxy test account to the environment secret store
   as `MASTER_AGENT_LIVE_READ_PROXY_USERNAME` and
   `MASTER_AGENT_LIVE_READ_PROXY_PASSWORD`;
2. add the inspection CA as `MASTER_AGENT_ENTERPRISE_CA_BUNDLE_PEM`;
3. place a `network_profiles` entry in
   `MASTER_AGENT_LIVE_READ_INTEGRATIONS_TOML` using the fixed proxy authority,
   `MASTER_AGENT_PROXY_USERNAME`, `MASTER_AGENT_PROXY_PASSWORD`, and
   `MASTER_AGENT_ENTERPRISE_CA_BUNDLE` references;
4. confirm the workflow maps those two read-environment secrets only to the
   fixed `MASTER_AGENT_PROXY_USERNAME` and `MASTER_AGENT_PROXY_PASSWORD` broker
   references on the protected read harness step;
5. confirm the proxy permits CONNECT only to the fixed provider origins in the
   read matrix; and
6. manually dispatch the read matrix from the current default branch.

Count the run as evidence only when at least one typed credentialed provider
read completes through the tunnel and its ordinary `verify()` re-read also
succeeds. A direct-network fallback, skipped test, missing proxy secret, missing
CA, or disabled inspection policy is incomplete evidence. The job log and
artifacts must contain none of the proxy username, password, authorization
header, CA body, provider tokens, or credential-bearing URLs.

Run the corresponding offline regressions before dispatch:

```bash
python -m unittest -q tests.test_http tests.test_config \
  tests.test_execution_context tests.test_oauth_readiness
```

Those tests cover CONNECT authentication placement, provider hostname and CA
validation, ambient proxy suppression, redirect and origin confinement,
private-address pivots, immutable binding, readiness, and redaction without
opening an external connection.

Jira and Confluence scoped-token TOML uses the exact gateway roots
`https://api.atlassian.com/ex/jira/{cloudId}` and
`https://api.atlassian.com/ex/confluence/{cloudId}` plus a distinct exact tenant
`web_base_url`. Their scoped tokens are product-specific; only the Atlassian
account email may be shared in memory. Bitbucket Cloud API tokens use the
Atlassian account email. A private legacy app-password configuration may retain
`MASTER_AGENT_BITBUCKET_USERNAME` explicitly.

## Stable fixture variables

The read environment defines stable resources that are not edited during a run:

- `MASTER_AGENT_LIVE_JIRA_ISSUE_ID`
- `MASTER_AGENT_LIVE_CONFLUENCE_PAGE_ID`
- `MASTER_AGENT_LIVE_BITBUCKET_WORKSPACE`
- `MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY`
- `MASTER_AGENT_LIVE_GITHUB_OWNER`
- `MASTER_AGENT_LIVE_GITHUB_REPOSITORY`
- `MASTER_AGENT_LIVE_MICROSOFT_IDENTITY`
- `MASTER_AGENT_LIVE_SHAREPOINT_SITE_ID`
- `MASTER_AGENT_LIVE_OUTLOOK_MESSAGE_ID`
- `MASTER_AGENT_LIVE_TEAMS_CHAT_ID`
- `MASTER_AGENT_LIVE_TEAMS_MESSAGE_ID`
- `MASTER_AGENT_LIVE_ONENOTE_PAGE_ID`

The effects environment defines its own target variables:

- `MASTER_AGENT_LIVE_NON_PRODUCTION=true`
- `MASTER_AGENT_LIVE_JIRA_ISSUE_ID`
- `MASTER_AGENT_LIVE_CONFLUENCE_SPACE_ID`
- `MASTER_AGENT_LIVE_CONFLUENCE_PARENT_ID` when required
- `MASTER_AGENT_LIVE_BITBUCKET_WORKSPACE`
- `MASTER_AGENT_LIVE_BITBUCKET_REPOSITORY`
- `MASTER_AGENT_LIVE_BITBUCKET_SOURCE_BRANCH`
- `MASTER_AGENT_LIVE_BITBUCKET_DESTINATION_BRANCH`
- `MASTER_AGENT_LIVE_GITHUB_OWNER`
- `MASTER_AGENT_LIVE_GITHUB_REPOSITORY`
- `MASTER_AGENT_LIVE_MICROSOFT_IDENTITY`
- `MASTER_AGENT_LIVE_SHAREPOINT_DRIVE_ID`
- `MASTER_AGENT_LIVE_SHAREPOINT_ITEM_ID`
- `MASTER_AGENT_LIVE_OUTLOOK_RECIPIENT`
- `MASTER_AGENT_LIVE_TEAMS_CHAT_ID`

The existing SharePoint item must be disposable and have provider version
history. The Bitbucket source branch must already differ from the destination.
The Outlook recipient and Teams chat must be dedicated test destinations.

The administration environment defines:

- `MASTER_AGENT_LIVE_GITHUB_ADMIN_NON_PRODUCTION=true`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_OWNER`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_REPOSITORY`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_SETTING`

## Microsoft token preparation

Acquire fresh restricted token files with the disabled-by-default
`microsoft_integration_read` and `microsoft_integration_effects` OAuth profiles
after the tenant administrator grants the exact delegated scopes. The token
files must be mode `0600` before they are stored as the corresponding protected
JSON secrets. Both Graph token-file JSON secrets are required; each job fails
materialization when its selected secret is empty. The workflow has no refresh-
token path and intentionally cannot be scheduled around a static delegated
access token.

## Running locally

Local execution is for controlled provider troubleshooting, not a substitute
for protected default-branch evidence. Supply every secret and fixture listed
for the selected mode, use a mode-`0600` integrations/token file, and set the
same timeout plus cleanup margin checked by GitHub Actions:

```bash
export MASTER_AGENT_RUN_LIVE_CONNECTOR_TESTS=1
export MASTER_AGENT_LIVE_INTEGRATIONS_FILE=/absolute/private/live-read.toml
export MASTER_AGENT_GRAPH_TOKEN_FILE=/absolute/private/microsoft-read.json
export MASTER_AGENT_LIVE_JOB_TIMEOUT_SECONDS=1500
export MASTER_AGENT_LIVE_CLEANUP_MARGIN_SECONDS=300
python -m unittest \
  tests.test_connector_integration_matrix.CredentialedReadConnectorIntegrationTests \
  -v
```

Effects additionally require a mode-`0700` recovery directory, the 35-minute
timeout plus 10-minute cleanup margin, and every communication fixture before
the reversible test begins:

```bash
mkdir -p /absolute/private/live-recovery
chmod 700 /absolute/private/live-recovery
export MASTER_AGENT_RUN_LIVE_EFFECT_TESTS=1
export MASTER_AGENT_LIVE_NON_PRODUCTION=true
export MASTER_AGENT_LIVE_RUN_ID=local-manual-run-001
export MASTER_AGENT_LIVE_INTEGRATIONS_FILE=/absolute/private/live-effects.toml
export MASTER_AGENT_GRAPH_TOKEN_FILE=/absolute/private/microsoft-effects.json
export MASTER_AGENT_LIVE_RECOVERY_ROOT=/absolute/private/live-recovery
export MASTER_AGENT_LIVE_JOB_TIMEOUT_SECONDS=2100
export MASTER_AGENT_LIVE_CLEANUP_MARGIN_SECONDS=600
python -m unittest \
  tests.test_connector_integration_matrix.CredentialedEffectConnectorIntegrationTests \
  -v
```

The normal `unittest discover` run discovers these classes but skips them until
their explicit opt-in variables are set. Once selected, missing setup is a
failure rather than a silent skip.
