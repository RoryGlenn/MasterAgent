# Configuration

## Resolution order

Each CLI configuration option resolves in this order:

1. explicit path supplied to the command;
2. the wheel-packaged safe default.

The current working directory is never an implicit configuration authority.

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

GitHub Cloud uses `MASTER_AGENT_GITHUB_TOKEN` as a bearer token. The cloud
origin is fixed to `api.github.com`; alternate cloud hosts are rejected, and
GitHub Enterprise Server is not part of the current connector contract. At
context binding and applied execution, the typed GitHub adapter calls
`GET /user` and binds the provider-returned numeric user ID. It does not trust a
configured identity label or persist the token or mutable login.

Exact-plan binding records a flow-enforced or provider-verified non-secret
credential identity, not the token or password. Basic usernames and Entra
client-credential tenant/client IDs are derived from their configured
environment variables. GitHub bearer tokens are verified by GitHub at bind and
apply time and resolve to `github:user:<numeric-id>`. Secrets may rotate without
changing the binding when the verified principal remains the same. Other opaque
bearer, delegated, token-file, and application-environment tokens cannot prove
their principal to this runtime. Both `bind-context --connector-mode live` and
live `run --apply` reject those flows even if configuration supplies a claimed
identity label. Another provider-verified principal or trusted credential-broker
attestation adapter is required before those flows can be used for applied
execution.

## Applied-run manifest

`bind-context` must receive the same execution arguments later supplied to
`run --apply`. Its plan fingerprint covers connector mode and write/send gates,
canonical workspace and artifact roots, configured Bitbucket publication roots,
the audit database, optional result path and evidence type, and SHA-256 digests
of policy, source-of-truth, capability, governance, identity, retention, and
approval-authority snapshots. A missing legacy binding or any mismatch is
rejected before connector construction.

All runtime directories (the audit database parent, artifact root, optional
workspace root, optional result parent, and any configured publication root)
must preexist, be owned by the current account, and not be writable by group or
world. Create reviewed boundaries explicitly before binding, for example with
`mkdir -m 700 PATH`. Binding and apply never create runtime directories.
The audit parent, artifact root, and result parent must be pairwise distinct by
both canonical path and filesystem identity; use dedicated directories for
each writer.
Draft and retained-evidence publication is create-only, so each run must bind
fresh output filenames or a fresh private output directory. Existing and
concurrently created files are preserved and cause the run to fail closed.

An unbound policy dry run remains free of live connector credential resolution
and is non-persistent: its audit chain exists only in a temporary directory
that is removed before the command returns, and `--result-json` is rejected
unless `--apply` is selected. Durable audit and retained evidence therefore use
only manifest-bound paths.

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
- Bitbucket: `pull_request_writes_enabled`; `branch_push_enabled` is retained
  only to reject attempted local-Git publication explicitly;
- Microsoft: `sharepoint_writes_enabled`, `onenote_read_enabled`, `outlook_send_enabled`, `teams_send_enabled`.

OneNote write flags are intentionally not part of the runtime surface. Legacy
`onenote_writes_enabled` values are ignored; page create/update remain disabled
in the catalog, governance profile, connector capabilities, and live registry.

Local Git patch, branch, commit, and push capabilities are likewise disabled in
the catalog and governance profile and are not registered by the live factory.
They remain unavailable until repository metadata, ref, reflog, index, lock,
and publication transactions share one descriptor-bound repository identity.

The broad generic flag is retained as a compatibility gate, not as permission to enable every mutation.

## Atlassian deployment type

Select `cloud` or `data_center` independently for Jira, Confluence, and Bitbucket. Cloud and Data Center endpoints and payloads are implemented by separate connector branches rather than pretending the APIs are identical.

## GitHub Cloud

The GitHub connector is read-only and disabled by default. It exposes only
repository metadata, pull-request search/read, and commit check-run reads.
`discover --systems github --probe` calls the fixed `/user` endpoint to verify
the configured bearer token. `bind-context` and `run --apply` also call that
endpoint to bind and re-verify the numeric GitHub user ID before governed live
reads. No GitHub mutation gate exists.

## Microsoft identity mode

- `delegated` represents the signed-in user and is required by this runtime for OneNote reads and normal Teams sends.
- `application` is supported only by capabilities and organization policy that explicitly permit it. The built-in Teams Graph send connector never accepts application identity; bot-based Teams communication must use a separate connector.
- `default_identity = "me"` is valid only for delegated access.

## OAuth profiles

`config/oauth.toml` separates read-only, reversible-write, communication, application, and existing-token profiles. Enable only a reviewed profile.

The device-code command writes a restricted JSON token file. It does not manage tenant consent, register applications, or persist a refresh token in a general-purpose database.

## Governance

Replace placeholder owners such as `unassigned` and `example-organization` before non-development deployment. Production readiness additionally requires:

- `production_approved = true`;
- an implemented typed adapter for an external, tamper-resistant audit sink;
- an approved secret manager;
- explicit external-model policy;
- rules covering every enabled capability.

## Canonical-source extractors

Each entry in `sources_of_truth.toml` maps every allowed canonical and
projection capability to one or more reviewed parameter selectors. The runtime
derives typed SHA-256 values from those exact immutable action parameters and
requires a dependent canonical write with a matching value. A capability with
no built-in selector verifier, or a configured selector that the verifier does
not recognize for that capability, makes configuration loading fail closed.

The packaged rules currently verify these mappings:

| Governed field | Capability | Selected parameters |
|---|---|---|
| project status narrative | `confluence.page.update` | `body` |
| project status narrative | `teams.message.draft` | `body` |
| project status narrative | `outlook.email.draft` | `body` |

The exact `powerpoint:weekly-status` target is governed but deliberately has no
allowed projection capability. Generic slides do not provide a unique typed
location for each canonical field, so that target fails closed until the
PowerPoint connector accepts and renders a complete field-addressed schema.
PowerPoint previews under other resource IDs remain available as local output.

`source_bindings` values supplied in an action are not authorization evidence
and cannot influence this comparison. Governed local-generation targets are
checked too; their lower risk does not exempt them from canonical integrity.
The built-in static sample uses distinct `*-preview` resource IDs because it
reads canonical systems but does not propose a canonical write; those harmless
preview artifacts must not masquerade as the exact governed projections above.

## Recurring workflows

Recurring definitions and due-state reporting remain available, but
`recurring-run` is disabled. The prior capability-only scope check did not bind
exact targets, canonical sources, delivery mode, and configuration snapshots to
one execution manifest. `weekly-status` and `communication-context` execution
are disabled for the same reason; their plan-generation commands remain
available.

## Safe validation

```bash
master-agent readiness
master-agent discover
master-agent recurring-status
master-agent plugins
```

These commands do not import plugin code, publish content, or send communication. `discover --probe` is the explicit network-read step.

The v1 runtime currently implements only the local SQLite development audit
sink. Naming an external product in `audit_sink` does not make it operational;
production readiness therefore fails closed until an actual typed external
sink adapter is installed and registered by the runtime.
