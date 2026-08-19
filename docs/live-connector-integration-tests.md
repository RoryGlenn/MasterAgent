# Credentialed Live Connector Integration Tests

## Purpose

The live integration suite proves that MasterAgent can authenticate to the real
providers, issue real external requests through its production connector code,
normalize provider responses, and independently verify what the provider
returned.

It is intentionally separate from the offline connector contract suite:

- `tests/test_connector_contract_matrix.py` checks factory wiring, capability
  routing, connector inventory, disabled surfaces, and local artifact
  generation without credentials or network access.
- `tests/test_connector_integration_matrix.py` requires real credentials,
  rejects `auth_mode = "none"`, and talks to the configured external systems.

Calling the offline suite an integration suite would be misleading. Both are
useful, but they prove different things.

## Live coverage

### Credentialed reads

The read job exercises all active external read connectors:

- Jira
- Confluence
- Bitbucket
- GitHub
- Microsoft identity
- SharePoint
- Outlook
- Teams
- OneNote

For each connector, the test performs its fixed provider probe and then runs one
stable typed read through `execute()`. It calls `verify()` afterward, which
forces an independent provider re-read rather than trusting the first response.
The test fails when a provider configuration is absent, disabled, anonymous, or
missing a required credential or stable fixture target.

### Protected effects

The effects job performs actual operations in dedicated non-production
sandboxes:

- create, verify, and delete a Jira comment;
- create, verify, and delete a Confluence page;
- create, verify, and decline a Bitbucket pull request;
- create, verify, and close a GitHub issue;
- replace, byte-verify, and restore a SharePoint DriveItem;
- send one Outlook message to a dedicated test recipient; and
- post one Teams message to a dedicated test chat and re-read its content.

The reversible tests call the connector's compensation method in `finally`
cleanup. Outlook and Teams messages are non-reversible, so their targets must be
dedicated test destinations whose users expect automated test traffic.

### GitHub administration

A separate, manually selected job tests `GitHubAdminConnector`. It toggles one
benign setting in a dedicated sandbox repository, verifies the provider state,
and restores the exact prior value. The job requires its own protected GitHub
environment and explicit non-production marker.

### Intentionally non-live surfaces

Local draft connectors, `MockConnector`, and `IdentityMapConnector` have no
external provider boundary, so the offline contract suite is the correct test
for them. Quarantined local Git mutation connectors and the disabled OneNote
write connector are also contract-tested as unavailable. A test must not enable
a prohibited runtime surface merely to make a network call.

## GitHub Actions execution

`.github/workflows/live-connector-integration.yml` never runs on pull requests,
which prevents unreviewed branch code from receiving provider credentials.

The workflow uses three protected environments:

1. `connector-integration-read` runs credentialed reads on the default branch by
   schedule or manual dispatch.
2. `connector-integration-effects` runs only after manual selection of
   `run_effects` and requires `MASTER_AGENT_LIVE_NON_PRODUCTION = true`.
3. `connector-integration-admin` runs only after manual selection of
   `run_github_admin` and requires
   `MASTER_AGENT_LIVE_GITHUB_ADMIN_NON_PRODUCTION = true`.

Repository variables gate each job:

- `MASTER_AGENT_LIVE_CONNECTOR_TESTS_ENABLED`
- `MASTER_AGENT_LIVE_EFFECT_TESTS_ENABLED`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_TESTS_ENABLED`

Set a gate to the literal string `true` only after its protected environment,
credentials, targets, and reviewer rules are ready.

## Private connector configuration

Each protected environment supplies a secret named
`MASTER_AGENT_LIVE_INTEGRATIONS_TOML`. The workflow writes it to a private file
under `RUNNER_TEMP` and exports only that path as
`MASTER_AGENT_LIVE_INTEGRATIONS_FILE`.

The TOML should start from `config/integrations.toml`, but it must use real test
provider origins and authenticated modes. It must keep credential values out of
TOML and reference the environment names already used by MasterAgent, such as:

- `MASTER_AGENT_JIRA_USERNAME` and `MASTER_AGENT_JIRA_TOKEN`
- `MASTER_AGENT_CONFLUENCE_USERNAME` and
  `MASTER_AGENT_CONFLUENCE_TOKEN`
- `MASTER_AGENT_BITBUCKET_USERNAME` and `MASTER_AGENT_BITBUCKET_TOKEN`
- `MASTER_AGENT_GITHUB_TOKEN`
- the declared Microsoft Graph token-file, access-token, or client-credential
  environment names

The read environment should keep write and send flags disabled. The protected
effects environment may enable only the granular sandbox capabilities exercised
by the effects job. The protected admin environment should contain only the
GitHub administration configuration it needs.

Optional private file secrets are materialized in the same runner-temporary
boundary:

- `MASTER_AGENT_GRAPH_TOKEN_FILE_JSON`
- `MASTER_AGENT_ENTERPRISE_CA_BUNDLE_PEM`

## Stable read fixtures

The read environment must define stable provider targets as GitHub environment
variables:

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

These resources should be dedicated fixtures that are not edited while the
suite is running. Verification deliberately fails when the resource changes
between the initial read and independent re-read.

## Effect targets

The effects environment additionally defines:

- `MASTER_AGENT_LIVE_CONFLUENCE_SPACE_ID`
- `MASTER_AGENT_LIVE_CONFLUENCE_PARENT_ID` when a parent is required
- `MASTER_AGENT_LIVE_BITBUCKET_SOURCE_BRANCH`
- `MASTER_AGENT_LIVE_BITBUCKET_DESTINATION_BRANCH`
- `MASTER_AGENT_LIVE_SHAREPOINT_DRIVE_ID`
- `MASTER_AGENT_LIVE_SHAREPOINT_ITEM_ID`
- `MASTER_AGENT_LIVE_OUTLOOK_RECIPIENT`

The Bitbucket source branch must already exist and contain a change relative to
the destination branch. The SharePoint item must be an existing disposable file
with provider version history so the connector can restore it. The Outlook
recipient and Teams chat must be dedicated test destinations.

The GitHub administration environment defines:

- `MASTER_AGENT_LIVE_GITHUB_ADMIN_OWNER`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_REPOSITORY`
- `MASTER_AGENT_LIVE_GITHUB_ADMIN_SETTING`

## Running locally

Run credentialed reads only after exporting the real credential variables and
fixture targets referenced by the private integrations file:

```bash
export MASTER_AGENT_RUN_LIVE_CONNECTOR_TESTS=1
export MASTER_AGENT_LIVE_INTEGRATIONS_FILE=/absolute/private/live-integrations.toml
python -m unittest \
  tests.test_connector_integration_matrix.CredentialedReadConnectorIntegrationTests \
  -v
```

Run effects only against dedicated non-production targets:

```bash
export MASTER_AGENT_RUN_LIVE_EFFECT_TESTS=1
export MASTER_AGENT_LIVE_NON_PRODUCTION=true
export MASTER_AGENT_LIVE_INTEGRATIONS_FILE=/absolute/private/live-effects.toml
python -m unittest \
  tests.test_connector_integration_matrix.CredentialedEffectConnectorIntegrationTests \
  -v
```

The normal `unittest discover` CI job discovers these classes but skips them
unless the relevant opt-in flag is set. Once opted in, missing credentials,
configuration, or fixture variables are failures rather than silent skips.
