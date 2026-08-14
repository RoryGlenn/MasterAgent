# Configuration

## Resolution order

Each CLI configuration option resolves in this order:

1. explicit path supplied to the command;
2. same-named file under the current project's `config/` directory;
3. the wheel-packaged safe default.

Packaged defaults are intended for installation verification. They enable no live connector, write, send, or recurring schedule.

## Files

| File | Responsibility |
|---|---|
| `capabilities.toml` | public typed capability surface |
| `governance.toml` | organization owners, environments, classifications, approval tiers |
| `policy.toml` | risk defaults and hard prohibitions |
| `integrations.toml` | endpoints, environment-variable references, provider gates |
| `oauth.toml` | token acquisition profiles and requested scopes |
| `sources_of_truth.toml` | canonical resources and projection direction |
| `identities.toml` | names, aliases, and provider IDs |
| `retention.toml` | evidence persistence and expiry |
| workflow TOML files | exact registered task inputs |
| `recurring.toml` | disabled schedules and workflow allowlists |

## Credentials

TOML contains environment-variable **names**, never secret values. The runtime rejects credentials embedded in URLs and redacts query strings from errors.

Development variables are documented in [`.env.example`](../.env.example). Persistent deployments should inject short-lived credentials through an organization-approved secret manager.

## Live connector gates

The following do different jobs:

```text
capability enabled
    + governance permits environment/action
    + runtime --enable-writes or --enable-communications
    + connector enabled
    + generic connector write_enabled/send_enabled
    + granular provider flag
    + valid credentials
    + exact approval
    = connector can be constructed and action can execute
```

Examples of granular flags:

- Jira/Confluence: `writes_enabled`;
- Bitbucket: `pull_request_writes_enabled`, `branch_push_enabled`;
- Microsoft: `sharepoint_writes_enabled`, `onenote_read_enabled`, `onenote_writes_enabled`, `outlook_send_enabled`, `teams_send_enabled`.

The broad generic flag is retained as a compatibility gate, not as permission to enable every mutation.

## Atlassian deployment type

Select `cloud` or `data_center` independently for Jira, Confluence, and Bitbucket. Cloud and Data Center endpoints and payloads are implemented by separate connector branches rather than pretending the APIs are identical.

## Microsoft identity mode

- `delegated` represents the signed-in user and is required by this runtime for OneNote and normal Teams sends.
- `application` is supported only by capabilities and organization policy that explicitly permit it. The built-in Teams Graph send connector never accepts application identity; bot-based Teams communication must use a separate connector.
- `default_identity = "me"` is valid only for delegated access.

## OAuth profiles

`config/oauth.toml` separates read-only, reversible-write, communication, application, and existing-token profiles. Enable only a reviewed profile.

The device-code command writes a restricted JSON token file. It does not manage tenant consent, register applications, or persist a refresh token in a general-purpose database.

## Governance

Replace placeholder owners such as `unassigned` and `example-organization` before non-development deployment. Production readiness additionally requires:

- `production_approved = true`;
- a non-local audit sink;
- an approved secret manager;
- explicit external-model policy;
- rules covering every enabled capability.

## Recurring workflows

A recurring workflow must be enabled explicitly and may execute only capabilities, recipients, and canonical sources in its registration. `--force` changes due-time evaluation only; it cannot enable a disabled registration.

## Safe validation

```bash
master-agent readiness
master-agent discover
master-agent recurring-status
master-agent plugins
```

These commands do not import plugin code, publish content, or send communication. `discover --probe` is the explicit network-read step.
