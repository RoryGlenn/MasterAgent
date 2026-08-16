# Configuration

## Resolution order

Each CLI configuration option resolves in this order:

1. explicit path supplied to the command;
2. the wheel-packaged safe default.

The current working directory is never an implicit configuration authority.

Packaged defaults make every supported read connector available. A connector is
resolved only when selected for an operation, so availability alone neither
requires credentials nor opens a provider connection. Mutation, administration,
send, and recurring-schedule gates remain disabled.

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

Authenticated GitHub Cloud capabilities use `MASTER_AGENT_GITHUB_TOKEN` as a
bearer token. The separate `github.public_repository.list` capability is
anonymous and never resolves or sends that token, even when it is present in
the environment. The cloud origin is fixed to `api.github.com`; alternate
cloud hosts are rejected, and GitHub Enterprise Server is not part of the
current connector contract. At context binding and applied execution for an
authenticated capability, the typed GitHub adapter calls `GET /user` and binds
the provider-returned numeric user ID. It does not trust a configured identity
label or persist the token or mutable login.

Authenticated Bitbucket capabilities use the configured username/token pair.
The separate `bitbucket.public_repository.list` capability constructs an
anonymous connector from the fixed `api.bitbucket.org` Cloud root and never
resolves or sends ambient Bitbucket credentials.

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

If policy or governance requires human approval, `bind-context` requires an
explicit `--approval-authorities` path. The snapshot digest becomes part of the
plan before anyone reviews it; the signing secret is not loaded at bind time.
Every enabled authority explicitly declares its issuer, tenant, subject, and
non-empty role list. Approval artifacts authenticate those claims together with
the exact plan/actions and bounded validity window. Optional `revoked_before`
and `revoked_approval_ids` entries in the trusted snapshot invalidate issued
artifacts without trusting fields supplied by those artifacts. Identity
distinctness uses the canonical issuer/tenant/subject tuple, including Unicode
compatibility normalization and case folding.
An approval-required apply writes its secret-free resumable request beneath the
bound artifact root. `resume-approval` restores only the captured invocation,
so there is no supported path for adding or replacing a trust configuration,
provider URL, credential mapping, runtime path, or gate after review.

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
- GitHub: `writes_enabled` for issue/PR creation; `admin_enabled` only exposes
  implemented adapters that remain catalog/governance-prohibited pending CAS;
- Microsoft: `sharepoint_writes_enabled` only constructs the disabled
  SharePoint adapter; `onenote_read_enabled`, `outlook_send_enabled`, and
  `teams_send_enabled` govern active typed routes.

OneNote write flags are intentionally not part of the runtime surface. Legacy
`onenote_writes_enabled` values are ignored; page create/update remain disabled
in the catalog, governance profile, connector capabilities, and live registry.

Local Git patch, branch, commit, and push capabilities are likewise disabled in
the catalog and governance profile and are not registered by the live factory.
They remain unavailable until repository metadata, ref, reflog, index, lock,
and publication transactions share one descriptor-bound repository identity.

The broad generic flag is retained as a compatibility gate, not as permission to enable every mutation.

## Ephemeral operator-requested connections

The checked-in and packaged read connectors are available at rest. For an
explicit operator-requested connection, `connect` selects only the requested
read systems and runs their fixed bounded probes:

```bash
master-agent connect \
  --systems jira,confluence,bitbucket,github,microsoft,sharepoint,outlook,teams,onenote \
  --credentials-file /absolute/path/to/private-credentials.json \
  --output /absolute/path/to/private-connection-report.json
```

This does not edit `integrations.toml`, the credential file, or any mutation or
communication gate. Explicit credential-file values win over ambient values for the names in
that file. The optional report is mode `0600` and contains only redacted
discovery metadata. Jira and Confluence packaged URLs are deliberate
placeholders. For an operator-requested Atlassian Cloud connection, pass the
Jira or Confluence page/site URL without editing configuration:

```bash
master-agent connect \
  --systems confluence \
  --connector-url confluence=https://tenant.atlassian.net/wiki/spaces \
  --credentials-file /absolute/path/to/private-credentials.json
```

`connect` normalizes the URL to `https://tenant.atlassian.net`, rejects any
non-HTTPS, credential-bearing, non-Atlassian, duplicate, or unselected target,
and uses the override only in memory. `bind-context` and applied `run` accept
the same repeatable `--connector-url SYSTEM=URL` argument; the normalized
destination and connector identity are approval-bound. Data Center context
roots still require the organization's permission-checked integrations file.

`connect`, `bind-context`, and applied `run` accept
`--credential-map FILE_KEY=DECLARED_NAME` to select and rename fields from a
canonical multi-provider store for one invocation. This supports, for example,
explicitly reusing one Atlassian email and API token for both Jira and
Confluence without loading unrelated credentials or rewriting the store.
For selected Jira and Confluence Cloud connectors using Basic authentication,
that same-account fallback is automatic when the selected connector's own
names are absent. Explicit selected-connector credentials always win. The
related connector is not activated, and only the provider probe determines
whether that Atlassian account has access to the target product and site.

Microsoft runtime systems share one connector configuration. `connect` selects
delegated token-file, delegated environment-token, or application
client-credentials authentication from the available declared values in that
order. OneNote read access is enabled only in the in-memory overlay when
OneNote is explicitly selected.

## Atlassian deployment type

Select `cloud` or `data_center` independently for Jira, Confluence, and Bitbucket. Cloud and Data Center endpoints and payloads are implemented by separate connector branches rather than pretending the APIs are identical.

## GitHub Cloud

The GitHub connector is available by default. Its read surface exposes an
anonymous public-user repository list, an authenticated-user repository list,
repository metadata, pull-request search/read, and commit check-run reads.
`discover --systems github --probe` calls the fixed `/user` endpoint to verify
the configured bearer token. `bind-context` and `run --apply` also call that
endpoint to bind and re-verify the numeric GitHub user ID before governed live
reads.

Mutation construction requires `--enable-writes`, `write_enabled = true`, and
one of two independent granular gates. `writes_enabled = true` permits only
`github.issue.create` and `github.pull_request.create`; both are independently
re-read and emit manual re-read/close recovery descriptors. They are not
closed automatically because the adapter cannot make its conflict check and
close one atomic provider operation. The typed `github.repository.settings.update` and
`github.collaborator.access.update` adapters remain behind `admin_enabled`, but
the capability catalog and governance profile prohibit them. GitHub does not
document conditional unsafe-method support for these endpoints, so a local
read-check-write sequence cannot prevent a concurrent overwrite. They must not
be re-enabled until an adapter can prove a provider-side compare-and-swap.

Use a fine-grained token whose repository permissions cover only the selected
operation. GitHub documents the endpoint-specific permissions for
[issues](https://docs.github.com/en/rest/issues/issues#create-an-issue),
[pull requests](https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request),
[repository updates](https://docs.github.com/en/rest/repos/repos#update-a-repository),
and [collaborator access](https://docs.github.com/en/rest/collaborators/collaborators#add-a-repository-collaborator).

For a specified user's public repositories, the convenience command constructs
an anonymous in-memory connector, evaluates `github.public_repository.list`,
calls only `/users/{username}/repos`, and independently verifies the result. It
does not load an ambient token and rejects a credential file:

```bash
master-agent github-repositories --username USERNAME
```

For a specified Bitbucket Cloud workspace's public repositories, the separate
convenience command constructs an anonymous in-memory connector, evaluates
`bitbucket.public_repository.list`, calls only
`/repositories/{workspace}`, rejects any repository not explicitly marked
public, and independently verifies the bounded result:

```bash
master-agent bitbucket-repositories --workspace WORKSPACE
```

For repositories visible to the authenticated account, the same command keeps
the persistent connector disabled, attests the user, evaluates
`github.repository.list`, and independently verifies the result:

```bash
master-agent github-repositories \
  --credentials-file /absolute/path/to/private-token.json
```

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

Each entry in `sources_of_truth.toml` declares canonical and projection
resources as exact `{system, resource_type, resource_id}` identities and maps every allowed canonical and
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

The exact `powerpoint:presentation:weekly-status` target is governed but deliberately has no
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

## Executable capability contracts

Every enabled non-read capability declares `target_resource_types` and a
`parameter_schema`. Unknown top-level parameters, missing required parameters,
wrong types, target-system substitutions, and target-resource substitutions are
rejected before policy evaluation. At live execution the runtime also enforces
the catalog authentication class, approval-bound effective principal, granted
`required_scopes`, and the compensation interface promised by `reversible`.

Modifying capabilities additionally require an approved `expected_version` and
a declared `provider_precondition` backed by a provider-side conditional write.
Confluence supplies version-number compare-and-swap (`version`). SharePoint
small-file replacement, Jira update/transition/compensation, and GitHub
administration are disabled because their current adapters cannot provide an
equivalent atomic precondition.
This boundary follows the providers' documented contracts: Confluence page
updates carry a version number; Microsoft Graph's exact small-file content
endpoint does not list `If-Match` (although other DriveItem and upload-session
operations do); GitHub's unsafe-method guidance and the Jira issue mutation API
do not document an equivalent conditional input for these adapters. See the
[Confluence page API](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/),
[Microsoft small-file content API](https://learn.microsoft.com/en-us/graph/api/driveitem-put-content?view=graph-rest-1.0),
[GitHub REST best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api),
and [Jira issue API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/).

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
With no path arguments they inspect the packaged safe defaults. To validate a
deployment, pass every reviewed configuration file explicitly from its private
trusted directory; the current working directory is never consulted
implicitly.

The v1 runtime currently implements only the local SQLite development audit
sink. Naming an external product in `audit_sink` does not make it operational;
production readiness therefore fails closed until an actual typed external
sink adapter is installed and registered by the runtime.
# Restricted local credential files

Development environments may supply connector-declared credential variables from
one explicitly selected JSON file instead of exporting each variable. The file is
opt-in and is never loaded by a policy-only dry run:

```json
{
  "schema": "master-agent/credential-store@1",
  "credentials": {
    "MASTER_AGENT_GITHUB_TOKEN": "replace-with-a-real-token"
  }
}
```

Store it outside the repository in a private (`0700`) directory and set the file
mode to `0600`. Pass its absolute path with `--credentials-file` to `readiness`,
`discover`, `bind-context`, and `run --apply`. Only names already referenced by
the selected `integrations.toml` are accepted. A name present in both the file and
the ambient environment is rejected. Applied execution binds the canonical file
path (but not its contents or digest), so bind and apply must select the same file.

This plaintext format is a local-development convenience, not a production secret
manager. Non-development governance profiles reject it.

For `connect` and authenticated `github-repositories` calls without
`--username`, an existing restricted provider-keyed file is also accepted and
adapted in memory. The anonymous public-user route rejects a credential file.
A provider may contain a token
string or an object using only applicable fields from `token`, `username`,
`token_file`, `token_expires_at`, `tenant_id`, `client_id`, and
`client_secret`, for example:

```json
{
  "jira": {
    "username": "operator@example.com",
    "token": "replace-with-a-real-token"
  },
  "github": "replace-with-a-real-token"
}
```

For compatibility with common local token files, the same restricted JSON file
may instead use the exact environment-variable names declared by the selected
integration, without the schema wrapper:

```json
{
  "MASTER_AGENT_JIRA_USERNAME": "operator@example.com",
  "MASTER_AGENT_JIRA_TOKEN": "replace-with-a-real-token"
}
```

Exact declared names are accepted first. For flat key/value files, MasterAgent
also examines key names—not secret values—for recognizable provider and field
hints. Names such as `myJiraApiToken`, `jiraLoginEmail`, or `jira.com` can be
mapped automatically when only one interpretation is possible. When a name is
unclear or matches several selected providers, the command stops with the
possible declared destinations. After the operator identifies the meaning, the
agent can retry `connect` with
`--credential-map FILE_KEY=DECLARED_NAME` without rewriting the token file.

Only providers selected by `--systems`, plus the related Jira/Confluence Cloud
credential labels described above, are accepted. Related labels supply only
the selected connector and never activate their own connector. Unknown or
duplicate mappings, loose permissions, symlinks, and ambiguous shapes fail
closed. The file is never rewritten.
