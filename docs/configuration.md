# Configuration

## Resolution order

Each CLI configuration option resolves in this order:

1. explicit path supplied to the command;
2. the wheel-packaged safe default.

The current working directory is never an implicit configuration authority.

Profile-aware commands resolve an explicit `--profile` first and otherwise use
the dedicated private path under `~/.master-agent/MasterAgent/`. `setup` uses
the packaged safe profile when the selected installed path does not yet exist;
an existing selected profile is validated in place. It never discovers a
profile from the current directory.

Packaged defaults make every supported read connector available. A connector is
resolved only when selected for an operation, so availability alone neither
requires credentials nor opens a provider connection. Mutation, administration,
send, and recurring-schedule gates remain disabled.

## Files

| File | Responsibility |
|---|---|
| `organization-profile.toml` | user mode, private state root, normal configuration locations, connector/write/send gates, and installed capability allowlist |
| `capabilities.toml` | public typed capability surface and exact read-result contracts |
| `governance.toml` | organization owners, environments, classifications, approval tiers, and model-context egress policy |
| `policy.toml` | risk defaults and hard prohibitions |
| `integrations.toml` | endpoints, environment-variable references, provider gates |
| `oauth.toml` | token acquisition profiles and requested scopes |
| `sources_of_truth.toml` | canonical resources and projection direction |
| `identities.toml` | names, aliases, and provider IDs |
| `retention.toml` | evidence persistence and expiry |
| `dependency-licenses.toml` | admitted/denied SPDX identifiers and third-party notice requirements |
| workflow TOML files | exact registered task inputs |
| `recurring.toml` | disabled schedules and workflow allowlists |

## Organization profile

The organization profile is the normal user-workflow entry point. It removes
repeated path and gate flags, but it is not permission: every listed action
must still be installed in `capabilities.toml` and pass governance, policy,
source-of-truth, provider, credential, approval, verification, compensation,
retention, and audit checks.

The packaged `local-default` profile is `employee`/`live`, keeps writes and
communications off, and lists only anonymous public repository reads and
reviewed local-generation capabilities. Its empty `[configuration]` table uses
the wheel-packaged safe defaults. Install it and the minimum private state with:

```bash
master-agent setup --non-interactive
```

The default installed path is
`~/.master-agent/MasterAgent/organization-profile.toml`. Its `state_root = "."`
resolves relative to that installed profile, so setup creates only the private
product directory and its `runs/` child. It creates no plan, workspace, audit
database, artifact, result, credential, provider connection, or approval. An
existing identical profile is reusable; a conflicting or unsafe destination
fails closed instead of being overwritten.

The schema is exact:

| Key | Contract |
|---|---|
| `schema` | must be `master-agent/organization-profile@1` |
| `organization` | bounded non-secret organization/profile label |
| `mode` | `employee` or `developer` |
| `state_root` | absolute path or path relative to the profile file; user-owned private state boundary |
| `connector_mode` | `live` for real typed connectors or `mock` for explicit developer testing; employee provider capabilities cannot use mock |
| `writes_enabled` | profile-level reversible-write gate; still subordinate to all runtime gates |
| `communications_enabled` | separate profile-level send gate; still subordinate to exact approval and provider gates |
| `capabilities` | unique bounded dotted names forming the installed capability allowlist |
| `[configuration]` | optional reviewed paths keyed by the supported names below |

`[configuration]` accepts only `approval_authorities`, `capabilities`,
`communication_context`, `draft_package`, `governance`, `identities`,
`integrations`, `oauth`, `policy`, `recurring`, `retention`,
`sources_of_truth`, and `weekly_status`. Paths may be absolute or relative to
the organization-profile file. A deployed profile should use reviewed absolute
paths so relocating the profile cannot silently select a different file. The
configuration directory and files must be owned by the MasterAgent service
account and must not be group- or other-writable; a mode-`0700` directory with
mode-`0600` files is the recommended deployment shape:

```toml
schema = "master-agent/organization-profile@1"
organization = "example-organization"
mode = "employee"
state_root = "/var/lib/master-agent/employee"
connector_mode = "live"
writes_enabled = false
communications_enabled = false
capabilities = ["github.repository.read"]

[configuration]
integrations = "/var/lib/master-agent/private-config/integrations.toml"
capabilities = "/var/lib/master-agent/private-config/capabilities.toml"
governance = "/var/lib/master-agent/private-config/governance.toml"
policy = "/var/lib/master-agent/private-config/policy.toml"
sources_of_truth = "/var/lib/master-agent/private-config/sources_of_truth.toml"
approval_authorities = "/var/lib/master-agent/private-config/approval-authorities.toml"
```

The profile contains paths and gates, never credential or signing-secret
values. Employee mode rejects a missing or unlisted capability before it loads
plugins, constructs connectors, resolves credentials, or creates runtime
state. Developer mode does not widen provider authority; generated effect code
remains quarantined until independent review, tests, specification archival,
signing, deployment, and normal runtime admission.

## Retention and expiry

`retention.toml` determines the persistence mode and time to live (TTL) when
evidence is first written. The selected creation time, expiration time,
persistence decision, digest, and sibling evidence filename are stored in the
mode-`0600` retention sidecar. Changing `retention.toml` later does not
silently recalculate or shorten an existing record's expiration.

`evidence-prune` therefore accepts an evidence root, not a retention
configuration path. It validates the complete persisted sidecar and deletes a
pair only when that recorded expiration is at or before the current time.
Preview is the default. On POSIX, explicit `--apply` uses the pinned root,
an exclusive selected-root retention lock, shared existing owner-controlled
ancestor retention locks, the discovered evidence-parent publication locks, an
exact descriptor rescan, and a bounded same-filesystem recoverable transaction.
Retained writers expose and exclusively lock their exact parent before sharing
existing ancestor retention locks, so publication under a nested parent cannot
begin during ancestor maintenance. All Windows execution remains gated pending
equivalent native filesystem guarantees.

`evidence-repair --apply` uses the same selected-root and ancestor handshake,
locks every discovered descendant record parent, and rescans before
classification or quarantine. It refuses an active child publication even
when the manifest is already visible but its evidence sibling is not.

The selected-root publication controls are also referred to as the root and discovered evidence-parent locks.

Interrupted transaction recovery is scoped to the exact root that created the
transaction. An ancestor scan reports a nonempty nested `.retention-prune`
directory and performs no new deletion; recover the child root first, then
repeat the ancestor operation.

Use an owner-controlled root containing retained evidence pairs and their
MasterAgent maintenance state. Any discovered sidecar with a missing or
malformed referenced evidence member, unsafe identity, scan truncation, or
concurrent change makes apply fail closed. Other unreferenced regular files are
not classified as prune candidates. Retention configuration does not encode or
adjudicate legal holds; deployments must keep held evidence outside an
apply-eligible boundary or otherwise prevent the operation under their approved
policy.

## Credentials

TOML contains environment-variable **names**, never secret values. The runtime rejects credentials embedded in URLs and redacts query strings from errors.

Development variables are documented in [`.env.example`](../.env.example). Persistent deployments should inject short-lived credentials through an organization-approved secret manager.

Capability capsules use a separate typed broker boundary. The existing
restricted JSON snapshot is a development adapter only. Production capsule
readiness requires an organization-provided credential/OAuth adapter that
attests its provider/account/principal binding and is explicitly marked
production-ready. A capsule declares credential names and scopes but never
contains values. Opaque handles are short-lived, single-use, and bound to the
complete plan-selected capsule and destination. The shipped runtime does not
include a production secret-manager adapter.

Authenticated GitHub Cloud capabilities use `MASTER_AGENT_GITHUB_TOKEN` as a
bearer token. The separate `github.public_repository.list` capability is
anonymous and never resolves or sends that token, even when it is present in
the environment. The cloud origin is fixed to `api.github.com`; alternate
cloud hosts are rejected, and GitHub Enterprise Server is not part of the
current connector contract. At context binding and applied execution for an
authenticated capability, the typed GitHub adapter calls `GET /user` and binds
the provider-returned numeric user ID. It does not trust a configured identity
label or persist the token or mutable login.

Authenticated Bitbucket Cloud capabilities use an Atlassian account email and
API-token pair. The packaged configuration therefore references
`MASTER_AGENT_BITBUCKET_EMAIL`; an existing private app-password deployment may
keep `MASTER_AGENT_BITBUCKET_USERNAME` explicitly for compatibility. The
separate `bitbucket.public_repository.list` capability constructs an anonymous
connector from the fixed `api.bitbucket.org` Cloud root.
It never resolves or sends ambient Bitbucket credentials.

Exact-plan binding records a flow-enforced or provider-verified non-secret
credential identity, not the token or password. Basic usernames and Entra
client-credential tenant/client IDs are derived from their configured
environment variables. GitHub bearer tokens are verified by GitHub at bind and
apply time and resolve to `github:user:<numeric-id>`. Microsoft delegated
environment and restricted-token-file flows are verified through Microsoft
Graph and bind the provider-returned user ID. Secrets may rotate without
changing the binding when the verified principal remains the same. Other
opaque bearer, delegated, token-file, and application-environment tokens cannot
prove their principal to this runtime. Both `bind-context --connector-mode
live` and live `run --apply` reject those flows even if configuration supplies
a claimed identity label. Another provider-verified principal or trusted
credential-broker attestation adapter is required before those flows can be
used for applied execution.

## License and SBOM policy

The repository and packaged copy of `dependency-licenses.toml` must match.
Unknown license identifiers are denied by default, selected strong-copyleft and
source-available licenses are explicitly denied, and dependency notices are
required. Runtime inventory lives in
[`supply-chain/runtime-dependencies.toml`](../supply-chain/runtime-dependencies.toml);
the generated exact lock, CycloneDX SBOM, and notices live at the repository
root.

Run this after any runtime dependency or license change:

```bash
python3 scripts/generate_sbom.py --check --verify-installed
```

The generator rejects a non-exact `pyproject.toml` requirement, an incomplete
or unreachable dependency graph, installed version/license drift, an unknown
or denied license, missing notices, or generated-file drift. Capsule-specific
locks/SBOMs use the same fail-closed policy. The current pure capsule worker
validates but then rejects nonempty third-party runtime dependency closures.

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
All CLI JSON output, draft, and retained-evidence publication is create-only,
so each invocation must use fresh output filenames or a fresh private output
directory. The final name is created as a mode-`0600` regular file beneath a
pinned, preexisting private parent. Symlinks, existing or concurrently created
files, and parent-identity changes are preserved and cause publication to fail
closed.

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
  --data-classification internal \
  --credentials-file /absolute/path/to/private-credentials.json \
  --output /absolute/path/to/private-connection-report.json
```

This does not edit `integrations.toml`, the credential file, or any mutation or
communication gate. Explicit credential-file values win over ambient values for the names in
that file. The optional report is mode `0600` and contains only redacted
discovery metadata. Jira and Confluence packaged URLs are deliberate
placeholders. A Cloud connector may use either its exact tenant root or an
Atlassian scoped-token gateway root as its authenticated API boundary:

- Jira: `https://api.atlassian.com/ex/jira/{cloudId}`
- Confluence: `https://api.atlassian.com/ex/confluence/{cloudId}`

A gateway configuration must also set `web_base_url` to the exact
`https://tenant.atlassian.net` browser root. Connector credentials go only to
the API root; `web_base_url` is used only for sanitized user-facing links. For
an operator-requested Atlassian Cloud connection, pass the Jira or Confluence
page/site URL without editing configuration:

```bash
master-agent connect \
  --systems confluence \
  --data-classification internal \
  --connector-url confluence=https://tenant.atlassian.net/wiki/spaces \
  --credentials-file /absolute/path/to/private-credentials.json
```

`connect` normalizes the URL to `https://tenant.atlassian.net`, rejects any
non-HTTPS, credential-bearing, non-Atlassian, nondefault-port, duplicate, or
unselected target, normalizes an explicit default `:443` away, and uses the
override only in memory. For a tenant-root connector, it becomes the API and
browser root. For a scoped gateway connector, it changes only `web_base_url`;
the exact product/cloud-ID API root is preserved.
`bind-context`, direct-read `run`, and applied `run` accept the same repeatable
`--connector-url SYSTEM=URL` argument; both roots are approval-bound for an
applied run. Data Center context roots still require the organization's
permission-checked integrations file.

`connect`, `bind-context`, direct-read `run`, and applied `run` accept
`--credential-map FILE_KEY=DECLARED_NAME` to select and rename fields from a
canonical multi-provider store for one invocation. For selected Jira and
Confluence Cloud connectors using Basic authentication, same-account
compatibility is deliberately narrower for scoped tokens:

- the configured Atlassian account email may be reused in memory;
- a Jira scoped token is never copied into the Confluence token field, or vice
  versa; and
- legacy tenant-root configurations retain automatic email/API-token pair
  compatibility for existing unscoped tokens.

Explicit selected-connector credentials always win. The related connector is
not activated, and only the provider probe determines whether the account has
access to the target product and site.

Microsoft runtime systems share one connector configuration. `connect` selects
delegated token-file, delegated environment-token, or application
client-credentials authentication from the available declared values in that
order. OneNote read access is enabled only in the in-memory overlay when
OneNote is explicitly selected.

`connect` and `discover --probe` authorize probe output through the provider-data
model-context policy before principal attestation or connector construction.
Pass `--data-classification public|internal|confidential|restricted`. Only the
development profile may omit it, and only when `[model_context]` declares a
default while `source_data_environment = "nonproduction"`. Non-development
profiles reject an omitted classification. Successful probe output is reduced
to `master-agent/provider-probe@1` with only `reachable` and `result_sha256`,
plus a separate content-free egress binding.

## Direct read-only sessions

Use `master-agent run PLAN --direct-read` when a direct user request already
has a plan containing only typed read-only actions for exactly one built-in
provider. It is an execution route for a read, not a replacement for the
manifest-bound applied runtime. The packaged development profile permits it
with this organization setting:

```toml
[organization]
allow_ephemeral_direct_reads = true
```

A custom governance profile must opt in with the same Boolean setting. Before
loading credentials or constructing a connector, the command rejects plans
that are not direct-user, single-provider, read-only, approval-free, and
unbound to a workflow, execution context, plugin, or capsule. It then resolves
one selected typed `ReadOnlyConnector`, validates its identity, scope, and
fixed endpoint, executes the bounded read, and independently re-reads it. Every
serialized read action must state `data_classification`; the command authorizes
that classification, destination, tenancy, field/schema contract, and limits
before credentials or provider access, then revalidates the same immutable
binding before returning a sanitized copy.

An optional `--credentials-file`, `--credential-map`, or supported
`--connector-url` is used only for that session. Direct reads print a bounded
terminal result and content-free egress metadata. Results are projected through
the catalog's exact versioned schema, recursively stripped of secret-key and
configured redacted fields, and rejected if they exceed the bound size. Direct
reads do not create a runtime directory, audit or idempotency
record, approval artifact, draft artifact, or result file. Effects—including
writes, sends, administration, deletion, merge, and recurring work—must use
the normal bound `run --apply` path and retain its approval and state checks.

## Provider deployment type

Select `cloud` or `data_center` independently for Jira, Confluence, and
Bitbucket. Cloud and Data Center endpoints and payloads are implemented by
separate connector branches rather than pretending the APIs are identical.
Jira and Confluence Cloud accept an exact single-label tenant root or the
product-specific `api.atlassian.com/ex/{product}/{cloudId}` form. A scoped
gateway binds its product, UUID cloud ID, and decoded path prefix: relative
traversal, same-origin absolute URLs, redirects, and pagination links cannot
escape it. Extra paths and explicit ports are rejected on configured Cloud API
roots. GitHub and Microsoft operating/runtime connectors are Cloud-only.
Microsoft Graph targets are additionally restricted to the supported fixed
cloud origin; an arbitrary or Data Center origin is rejected before credential
resolution or any bearer request.

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

`config/oauth.toml` separates read-only, reversible-write, communication,
application, existing-token, and credentialed-integration profiles. Enable only
one exact reviewed profile. The disabled integration profiles request:

- `microsoft_integration_read`: `User.Read`, `Mail.Read`, `Chat.Read`,
  `Sites.Read.All`, and `Notes.Read`;
- `microsoft_integration_effects`: `User.Read`, `Sites.ReadWrite.All`,
  `Mail.ReadWrite`, `Mail.Send`, `Chat.Read`, and `ChatMessage.Send`.

The general `microsoft_communication` profile pairs each send permission with
the read permission used for independent verification: `Mail.ReadWrite` plus
`Mail.Send`, `Chat.Read` plus `ChatMessage.Send`, and
`ChannelMessage.Read.All` plus `ChannelMessage.Send`.

The corresponding live jobs require a delegated restricted token file. Before
provider work, the harness verifies the delegated identity, the exact effective
scope set, and enough remaining lifetime for the job timeout plus cleanup
margin. Application credentials do not substitute for delegated OneNote reads
or normal Teams sends.

The device-code command writes a restricted JSON token file. It does not manage tenant consent, register applications, or persist a refresh token in a general-purpose database.

## Governance

Replace placeholder owners such as `unassigned` and `example-organization` before non-development deployment. Production readiness additionally requires:

- `production_approved = true`;
- an implemented typed adapter for an external, tamper-resistant audit sink;
- an approved secret manager;
- explicit external-model policy;
- reviewed model-context destination, tenancy, source-data environment, and
  provider-data classification rules;
- rules covering every enabled capability.

### Provider-data model-context policy

`[model_context]` governs provider data crossing from a connector into an
agent, user, or model context. It is independent of
`[organization].external_model_policy`: the latter applies to capabilities that
invoke an external model themselves, while `[model_context]` applies to every
provider-read return path whether or not the connector calls a model.

The top-level table is strict. It requires `destination`, `model_tenancy`,
`source_data_environment` (`nonproduction` or `production`), `dlp_adapter`, and
one or more `[[model_context.rules]]`. The optional
`development_default_classification` is used only for trusted probes in a
development profile backed by explicitly nonproduction source data. Unknown or
misspelled keys fail configuration loading.

Every rule must declare all of these fields:

| Field | Meaning |
|---|---|
| `name` | Unique operator-facing rule name |
| `providers`, `capabilities` | Exact names or glob patterns to match |
| `data_classifications` | `public`, `internal`, `confidential`, or `restricted` |
| `destinations`, `model_tenancies` | Allowed active return destination and tenancy |
| `routes` | `ephemeral`, `audited`, or both |
| `handling` | `allow`, `redact`, or `deny` |
| `audit_required`, `dlp_required` | Required executable controls, not declarations of intent |
| `redacted_fields`, `allowed_fields` | Recursive removals and allowed resource projection; `*` must stand alone |
| `max_items`, `max_output_bytes` | Positive result ceilings |

The uniquely most-specific matching rule wins; an equally specific tie, no
match, `deny`, missing required audit, or unavailable DLP fails closed.
`ephemeral` routes never satisfy `audit_required`. Any allowed confidential or
restricted rule must use only `audited`, require audit, and enumerate fields
instead of using `*`. The shipped runtime has no centralized DLP adapter, so a
rule with `dlp_required = true` is currently denied. Collection capabilities
also require an explicit positive action `limit` no greater than the rule's
`max_items`.

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

Every `read_only` capability has a matching top-level
`[read_result_contracts."CAPABILITY"]` entry with an exact `schema`, resource
field descriptors (`object`, `object_list`, or scalar `value`), and fixed
non-content `metadata`. Provider query envelopes are intentionally omitted at
the return boundary. Unknown fields, wrong schemas or resource shapes, and
missing bound resource fields fail closed before data is returned.

Every `local_generation` capability must also declare positive
`max_input_bytes` and `max_output_bytes` values. Input quotas may not exceed
4 MiB, and output quotas may not exceed 16 MiB. Live capabilities may not
declare these local-artifact fields. The packaged catalog currently uses those
hard ceilings for each local generator; deployments may lower them.

Plan ingestion has independent hard ceilings:

| Resource | Ceiling |
|---|---:|
| serialized plan file | 8 MiB before JSON parsing |
| actions per plan | 256 |
| dependencies per action | 256 |
| JSON nesting | 32 levels |
| items in one JSON object or array | 1,024 |
| JSON nodes | 65,536 |
| one string | 1,048,576 characters |
| parameters for one action | 4 MiB of bounded scalar content |
| parameters across one plan | 8 MiB of bounded scalar content |

Local publication additionally uses a single 64 MiB artifact budget shared by
all draft connectors and the final package summary/manifest in one run.
Per-capability and aggregate budgets are reserved before final-name creation.

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
`discover`, `bind-context`, `run --direct-read`, and `run --apply`. Only names
already referenced by the selected `integrations.toml` are accepted. A name
present in both the file and the ambient environment is rejected. Applied
execution binds the canonical file path (but not its contents or digest), so
bind and apply must select the same file. A direct-read session uses its selected
credential only in memory and does not persist the path or contents.

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
account-email label and legacy tenant-root compatibility labels described
above, are accepted. Related labels supply only the selected connector and
never activate their own connector. A product-specific scoped token is not a
cross-product compatibility label. Unknown or duplicate mappings, loose
permissions, symlinks, and ambiguous shapes fail closed. The file is never
rewritten.
