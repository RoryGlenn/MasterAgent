# CLI Reference

`master-agent COMMAND --help` is the exact argument reference. The table below
documents every public command and, critically, whether it can perform network
or filesystem side effects.

Every JSON `--output` is published through the same restricted-artifact
primitive. Its parent directory must already exist, be owned by the current
account, and not be writable by group or world. Publication pins that directory,
creates the final name with mode `0600`, refuses symlinks and every existing
destination, verifies the opened identity, writes and reads back the exact
bytes, and fsyncs both the file and directory. Use a fresh output filename for
each invocation; commands never create the parent or overwrite prior output.

| Command | Purpose | Side-effect boundary |
|---|---|---|
| `demo` | Run the credential-free Phase 3 demonstration | Creates a fresh private local workspace; no provider access |
| `sample-plan` | Write a synthetic weekly-status plan | Writes only the selected local JSON output |
| `inspect` | Validate and display a plan and fingerprint | Read-only local inspection |
| `bind-context` | Bind reviewed config, paths, connector identities, and gates into a plan | Writes the bound plan; live GitHub binding performs `GET /user`, while other supported identities are derived without provider mutation |
| `approve` | Sign selected action IDs for an exact plan fingerprint | Writes a local approval artifact; performs no provider request |
| `inspect-approval-request` | Review the exact actions, runtime context, and fingerprint in a private approval request | Read-only local inspection; requires a mode-`0600` request beneath a private directory |
| `approve-request` | Sign every pending action in an inspected approval request | Creates one mode-`0600` approval artifact; performs no provider request and never overwrites an existing file |
| `resume-approval` | Retry the captured bound run with one or more authenticated approvals | Can perform the exact provider effects in the original plan; accepts no replacement connector, target, credential, path, or gate arguments |
| `run` | Evaluate a plan or execute an approved, manifest-bound plan | No provider side effect without `--apply`; live apply is governed by every catalog, policy, approval, connector, and runtime gate |
| `plugins` | Inventory connector entry-point metadata without importing plugin code | Optional local JSON output; never executes plugin code |
| `readiness` | Validate governance, configuration, OAuth, permissions, implemented production adapters, and optional provider/classification egress readiness | Offline; optional local JSON output; `--egress-check` performs no network request |
| `oauth-device-code` | Run an enabled Microsoft delegated device-code flow | Performs Microsoft authentication requests and writes a mode-`0600` token file |
| `draft-package` | Generate the Phase 3 review package | Local create-only artifacts and audit state; no provider access |
| `compensation-plan` | Build a separately reviewable compensation plan from an original plan and run report | Writes only the selected local plan |
| `recurring-status` | Inspect registered schedules and due state | No provider access; may mark expired claims in an existing configured SQLite state database and can write optional local JSON output |
| `recurring-run` | Reserved recurring execution entry point | Disabled before config, credentials, connectors, or audit access |
| `discover` | Inspect connector configuration | Offline unless `--probe`; live probes require a model-context classification or the configured development/nonproduction default |
| `connect` | Enable selected supported read connectors in memory and verify access | Fixed, classified, bounded provider probes; never edits credentials or persistent configuration; optional output is mode `0600` |
| `github-repositories` | List a named user's public repositories anonymously with `--username`, or verify GitHub and list repositories visible to the authenticated user | Explicit schema-bound GitHub read returned only to the terminal; persisted `--output` is rejected |
| `bitbucket-repositories` | List a Bitbucket Cloud workspace's public repositories anonymously with `--workspace` | Explicit schema-bound Bitbucket read returned only to the terminal; persisted `--output` is rejected |
| `weekly-status-plan` | Build a read-only weekly-status plan | Writes only the selected local plan |
| `weekly-status` | Reserved direct weekly-status package entry point | Disabled before config, credentials, connectors, or audit access |
| `identity-resolve` | Resolve a configured person or provider identifier | Local identity-map read; optional local JSON output |
| `retain-evidence` | Persist evidence under the selected retention rule | Local create-only evidence and sidecar output; never contacts a provider |
| `evidence-prune` | Preview expired evidence | Read-only preview; `--apply` is disabled before traversal or deletion |
| `evidence-repair` | Detect or quarantine orphaned evidence | Preview by default; `--apply` recoverably moves exact descriptor-validated identities into a private same-filesystem quarantine |
| `citations` | Extract resource citations from a result JSON file | Read-only local extraction; optional local JSON output |
| `communication-context-plan` | Build a read-only Outlook/Teams context plan | Writes only the selected local plan |
| `communication-context` | Reserved direct communication-context package entry point | Disabled before config, credentials, connectors, or audit access |
| `scan` | Scan supplied text or a local file for prompt-injection indicators | Local read/analysis only; displayed excerpts are terminal-safe and bounded while raw input is not printed |
| `audit-verify` | Verify an existing SQLite audit hash chain | Read-only verification; missing or malformed state is rejected without creation |

Connector-aware `readiness`, `discover`, `bind-context`, direct-read `run`,
and applied `run` commands accept
`--credentials-file /absolute/path/credentials.json` in a development
governance profile. Policy-only `run` commands do not read secrets. The selected
canonical path is part of the bound execution context only for applied runs;
direct reads keep their credential selection in memory for the session.

`connect`, `bind-context`, direct-read `run`, and applied `run` also accept repeatable
`--credential-map FILE_KEY=DECLARED_NAME` arguments. This keeps an explicit
cross-connector credential selection in memory and lets bind/apply use the
same mapping without rewriting a canonical multi-provider store.

The same commands accept repeatable `--connector-url SYSTEM=URL` arguments for
operator-supplied Jira and Confluence Cloud URLs. UI paths such as
`/wiki/spaces` are normalized to the HTTPS `atlassian.net` tenant origin. Only
selected connectors may be overridden; unsafe origins, embedded credentials,
duplicates, nondefault ports, and Data Center targets fail before credential
loading or network access. Bind and apply must receive the same override
because the normalized target is part of the execution context.

## Direct read sessions

`master-agent run PLAN --direct-read` is the low-friction route for a direct
user request that is limited to one built-in provider and typed read-only
actions. It always builds a live `ReadOnlyConnector`, even though ordinary
`run` defaults to mock mode. Before credentials, connector construction, or a
provider request, it validates the catalog, governance, policy,
source-of-truth rules, plan origin, and direct-read shape. It then attests the
selected connector identity and scope, retains one transport budget across the
read and independent verification, revalidates the immutable provider-data
binding, and renders a schema-bound, policy-sanitized, terminal-safe result.

The route accepts an explicit integrations path, credential file or mapping,
and supported connector URL override for its one selected provider. It never
creates audit, idempotency, approval, artifact, or result-file state, and it
rejects `--apply`, approval options, write or communication flags, result and
retention options, identity/workspace paths, plugins, and non-default state
paths. A plan with a non-read action, non-direct authority, registered workflow,
persisted execution context, multiple providers, or an approval requirement is
rejected before provider dispatch. Use the applied route for every effect.

Every serialized read action must include `data_classification`. The direct
route binds that value together with provider/account/configuration digests,
request parameters, exact requested fields or catalog output schema, item and
byte limits, model destination, tenancy, handling, audit, and DLP requirements.
It returns content-free egress metadata, not a second verification body.

## Provider-data egress controls

Use a selected offline readiness check before enabling workplace reads:

```bash
master-agent readiness \
  --integrations /trusted/config/integrations.toml \
  --capabilities /trusted/config/capabilities.toml \
  --governance /trusted/config/governance.toml \
  --credentials-file /absolute/path/to/private-credentials.json \
  --egress-check jira:internal
```

`--egress-check PROVIDER:CLASSIFICATION` may be repeated. It performs no network
request, but the selected check passes only when the connector is configured
and enabled, required credential names are available, principal attestation and
provider feature gates are usable, and at least one matching `ephemeral` or
`audited` policy route is permitted for the active destination and tenancy.

`discover --probe` and `connect` accept
`--data-classification public|internal|confidential|restricted`. Omitting it is
valid only for a development profile whose model-context policy explicitly
sets a default for nonproduction source data. A successful probe returns the
fixed `master-agent/provider-probe@1` envelope containing `reachable` and
`result_sha256`; provider-specific identity, version, URL, and response fields
do not cross the return boundary.

All direct, applied, probe, and repository-shortcut reads are authorized before
provider content access and rebound before return. The runtime removes query
envelopes, recursively redacts secret-key and configured fields, minimizes raw
prompt-injection details and references, enforces exact catalog result fields,
item limits, and serialized byte limits, and emits only content-free audit and
egress facts. The GitHub and Bitbucket repository shortcuts deliberately reject
`--output`; use the manifest-bound audited route when approved persistence is
required.

An approval-required plan must include `--approval-authorities` during
`bind-context`; adding a trust configuration after review would change the
bound runtime and cannot produce a usable approval. An applied `run` that stops
at `approval_required` writes a deterministic, create-only approval request in
the already approved `--draft-output-dir`. The mode-`0600` request includes the
exact pending action manifests and every non-secret argument needed to resume,
but contains no credential or approval-secret values and grants no authority.
When `--result-json` is bound, its create-only output remains uncommitted while
approval is pending and is written by the approval-complete resume.

Use the request fingerprint printed by `run` for the handoff:

```bash
master-agent inspect-approval-request /private/drafts/approval-request-....json

# Run by a trusted operator with access to the configured approval authority.
master-agent approve-request /private/drafts/approval-request-....json \
  --key-id rory \
  --expected-fingerprint REQUEST_FINGERPRINT \
  --output /private/approvals/approval-rory.json

# MasterAgent can resume without reconstructing the original apply arguments.
master-agent resume-approval /private/drafts/approval-request-....json \
  --expected-fingerprint REQUEST_FINGERPRINT \
  --approval /private/approvals/approval-rory.json
```

For dual approval, repeat `approve-request` with a distinct configured human
identity. Distinctness is based on the normalized issuer, tenant, and subject;
case or Unicode-compatibility aliases cannot count twice. The signed artifact
also binds the authority's roles and validity window, while trusted
`revoked_before` and `revoked_approval_ids` configuration can invalidate it. If
only one valid approval is supplied, `resume-approval` creates a new request
that carries the first approval path forward; supply the second artifact to
that new request. Changed request bytes, a changed referenced plan or authority
configuration, unsafe permissions, symlinks, or an apply-time context mismatch
fail before the pending provider action executes.

`connect` accepts a comma-separated `--systems` selection from Jira,
Confluence, Bitbucket, GitHub, Microsoft identity, SharePoint, Outlook, Teams,
and OneNote. It activates only the selected connector configurations for that
probe and performs each connector's fixed read-only check. An Atlassian Cloud
URL supplied through `--connector-url` replaces the packaged placeholder only
in memory; Data Center still requires an explicit reviewed integrations file.
This command verifies connectivity; the agent must continue with a typed
feature command to complete the requested outcome.

`bitbucket-repositories --workspace WORKSPACE` is also credential-free. It
constructs an anonymous Bitbucket Cloud connector, ignores ambient Bitbucket
credentials, accepts no credential-file option, returns only repositories
explicitly marked public, and independently verifies the bounded result.

`github-repositories --username USERNAME` is credential-free and accepts only
public visibility. It ignores ambient GitHub tokens by constructing an
anonymous connector, and it rejects `--credentials-file` rather than loading an
unneeded secret. Without `--username`, `github-repositories` and `connect`
accept the canonical store or a strict
provider-keyed wrapper. A provider may be a token string, such as
`{"github":"<token>"}`, or an object using only these applicable named fields:
`token`, `username`, `token_file`, `token_expires_at`, `tenant_id`, `client_id`,
and `client_secret`. A restricted file may also use exact integration-declared
environment names directly, for example
`{"MASTER_AGENT_JIRA_TOKEN":"<token>"}`. Clear provider/field hints in flat key
names, such as `myJiraApiToken`, are inferred without inspecting values. An
ambiguous key stops with candidate declared names; after clarification,
`connect --credential-map FILE_KEY=DECLARED_NAME` supplies a one-run mapping
without rewriting the file. For selected Jira or Confluence Cloud Basic-auth
connectors, a missing selected-product name automatically falls back to the
other connector's Atlassian email/API-token pair in memory. Explicit selected-
product credentials win, the other connector remains inactive, and a fixed
probe decides access. Unknown fields and duplicate destinations fail closed.
An explicit credential file wins over ambient values for the names it contains;
no value is printed or persisted. Selected output is written mode `0600`.

## Configuration behavior

Commands that accept configuration paths use an explicit path first and the
wheel-packaged safe default otherwise. They never load configuration from the
current working directory implicitly. Explicit configuration and runtime paths
must satisfy the ownership, permission, and identity checks described in
[`configuration.md`](configuration.md).

Provider mutation is available only through an exact, manifest-bound
`run --apply`. The direct workflow commands retained for compatibility do not
offer an alternate execution path.
