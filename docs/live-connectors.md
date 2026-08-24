# Live Connector Contracts

## Shared HTTP boundary

All HTTP connectors use a constrained client that enforces:

- HTTPS base URLs;
- no embedded URL credentials;
- same-origin API requests and pagination, plus exact decoded base-path
  confinement when a provider shares one gateway origin;
- cross-origin authenticated redirect rejection;
- bounded response bytes, pages, items, and timeouts;
- method allowlists per connector;
- controlled retries for transient failures;
- query-free and secret-free errors;
- no credential forwarding to temporary SharePoint download URLs.

## Implementation identity

Every live provider route selects its implementation from trusted
`integrations.toml` after capability/system routing and before credentials or
construction. The initial and only supported identity is `native`, including
when one provider configuration exposes several capability-specific connector
objects. That identity is configuration-, execution-context-, plan-, and
approval-bound. Unsupported, missing legacy, or drifted identities fail closed;
a native construction or execution failure never falls back to another
implementation. See [Connector registry](architecture.md#connector-registry)
and [Connector implementation selection](configuration.md#connector-implementation-selection).

## Read connectors

Read results are normalized into stable schemas, marked as untrusted content,
scanned for prompt-injection indicators, and independently re-read for
verification where practical. The GitHub Cloud connector constructs fixed
public-user and authenticated-user repository-list, repository, pull-request,
check-run, and identity endpoints internally and uses bounded numbered
pagination. Separately constructed GitHub mutation connectors implement
issue/PR creation plus typed administration adapters; catalog and governance
permit only issue/PR creation because the administration endpoints lack a
documented provider compare-and-swap. No connector exposes an arbitrary-request surface.
`github.public_repository.list` uses the public-user endpoint anonymously and
does not resolve or forward an ambient credential. Authenticated GitHub reads
bind the provider-returned numeric principal during context review and
re-verify that principal before applied reads. Communication bodies and
document content remain in memory unless explicit evidence output and
retention rules permit persistence.

`bitbucket.public_repository.list` similarly constructs only the fixed
Bitbucket Cloud workspace-repositories endpoint, ignores ambient Bitbucket
credentials, rejects repositories not explicitly marked public, and uses the
shared same-origin pagination boundary. Authenticated Cloud API-token
configuration uses the Atlassian account email; a private legacy app-password
configuration may retain its explicit username.

The registered `T1-EWIR-001` route adds a separate
`jira.issue.review_context.read` projection so existing Jira issue callers keep
their schema. Only reviewed `customfield_<digits>` acceptance/relation fields
join the fixed standard projection; plain text and ADF are bounded, and exact
links are evidence rather than selectors. Its Bitbucket build read first
re-reads the exact pull request, extracts the current head, and reads statuses
from that commit endpoint. Malformed/oversized status evidence, repository or PR
identity mismatch, head drift, and Confluence page/space mismatch fail closed
instead of being normalized from the request or silently truncated.

The Reddit connector sends refresh-token exchanges only to Reddit's fixed token
origin and bearer requests only to the fixed OAuth API origin. It attests the
immutable account ID through `/api/v1/me`, binds granted scopes, and exposes
typed search, content, rules, history, and inbox reads. The packaged read
credential profile contains only `identity`, `read`, `history`, and
`privatemessages`. Its separate communication credential profile contains only
`identity`, `read`, and `submit`; missing or out-of-profile provider scope
reports fail closed. The effect adapter requires exact approval for every active
visible mutation, performs no write retry, and independently re-reads created
content. Typed edit and deletion adapters enforce authenticated-user ownership,
expected version, and poststate checks in tests but remain catalog-disabled
because Reddit has no atomic provider precondition.

`master-agent connect --systems ...` is the provider-neutral readiness path
when operator-requested access requires authentication. It enables only the
selected supported read connectors in memory, accepts canonical or strictly
mapped provider-keyed local credentials, runs each connector's fixed probe,
and persists no connector or credential changes. Selected Jira/Confluence
Cloud Basic-auth connectors may reuse the other product's configured account
email in memory. Product-specific scoped tokens are never copied across Jira
and Confluence; legacy tenant-root configurations retain unscoped email/token
pair compatibility. `--connector-url` normalizes an operator-supplied Atlassian
UI URL to the selected tenant origin. It sets both roots for a tenant-root
connector, but only the credential-free `web_base_url` for a scoped gateway, so
the exact `api.atlassian.com/ex/{product}/{cloudId}` API boundary cannot be
replaced by a browser URL. Jira constructs browse links from that approved web
root. Confluence accepts `_links.webui` only when it resolves to the same
scheme, host, and port, then canonicalizes the link onto the configured web
authority. Bind/apply include both roots in the execution context. It is not a
prerequisite for the anonymous GitHub public-user or Bitbucket public-workspace
repository lists. It is not a generic HTTP surface and does not execute a
feature action; the agent continues through the typed capability that produces
the requested outcome.

### Provider-data return boundary

Connector normalization and independent verification establish what a provider
returned; they do not by themselves authorize that data to enter an agent,
human, or model context. One shared boundary covers stateless direct reads,
audited orchestrator reads, `discover`/`connect` probes, and the GitHub and
Bitbucket repository shortcuts.

Before provider content is requested, the boundary approves the trusted data
classification against the configured destination, model tenancy, route,
handling, audit, and DLP rule. It binds that decision to the action, request
parameters, provider origin/account/configuration digests, requested fields or
versioned catalog output contract, item limit, and byte limit. Principal
attestation may supply the account digest only after a no-I/O policy/shape
preflight has passed. Attestation and content requests reuse the same captured
credential snapshot, and the exact endpoint, origin, and CA identity are
checked before content access and before return.

After the connector independently re-reads the provider result, the runtime
recomputes the same binding. Only then does it project the exact schema and
resource fields, omit query envelopes and duplicate verification content,
recursively redact standard secret keys and configured field names, minimize
prompt-injection findings and references using one separator-insensitive field
identity, and enforce the bound item and byte
ceilings. Applied reads record only binding facts, digests, counts, and outcomes
in audit state. Ephemeral routes persist no provider result. A missing or changed
binding, unavailable required audit/DLP adapter, wrong schema, extra or missing
resource field, or oversized result fails closed.

## Mutation connectors

Mutation connectors are not extensions of the read connector's arbitrary request surface. They expose narrowly typed capability names and validate required fields, risk, approval intent, effective principal/scopes, identity mode, resource path, size, branch prefix, expected version, or expected commit before network or Git side effects. A modifying provider route is enabled only when its write carries a provider-side conditional precondition.

Local Git mutation internals are quarantined. Their capability definitions are
disabled, governance marks them prohibited, and the live factory does not
register either workspace or local-Git publication connectors. Descriptor-pinned
subprocess working directories alone do not prove that every ref, reflog, index,
lock, object, and temporary metadata helper stayed on the same repository
identity. Patch, branch, commit, and push remain unavailable until that entire
metadata boundary is descriptor-backed and adversarially verified.

## Compensation

Compensation is connector-specific:

- Jira comment creation emits manual deletion recovery; issue mutation and restoration remain disabled pending provider CAS;
- Confluence restores a captured prior page state atomically and independently
  re-reads every restored content and placement field; created page/space
  deletion is manual, and page deletion verification requires provider
  not-found or the documented trash state;
- Bitbucket PR creation emits manual re-read/decline recovery;
- GitHub issue/PR creation emits manual re-read/close recovery;
- Reddit creation emits manual recovery after a fresh ownership review; the
  edit adapter remains catalog-quarantined, and deletion remains a
  catalog-quarantined high-impact action with no compensation because Reddit
  does not expose a provider-side atomic precondition;
- the non-routable SharePoint replacement adapter can restore a captured prior
  version after byte proofs only as a manually reviewed operation, and remains
  disabled until its write is atomic;
- Git mutation and compensation are not exposed by the live registry.

Every reversible result carries a typed descriptor. Automatic compensation is
independently verified and audited, and runs only where the adapter has an
atomic precondition. Manual recovery and failures are reported, never hidden.

The disabled SharePoint adapter's byte verification uses the bounded Graph content endpoint and never
forwards credentials across an origin change. Tenants that return a cross-origin
download redirect therefore remain fail-closed until a destination-attested,
no-auth download broker is implemented. The full upload/verify/restore lifecycle
requires at least 12 requests; packaged Microsoft defaults reserve 16 and cap
approved uploads at 1,000,000 bytes so repeated byte proofs remain inside the
shared response budget. Those checks do not substitute for provider CAS.

## Communication connectors

Outlook and Teams sends are separate from local draft generation. They require `external_communication` risk, `requires_approval = true`, the runtime communication flag, a granular provider flag, and valid exact-plan approval. The built-in Teams Graph send connector is delegated-only. Outlook delegated sending is the default; application sending additionally requires an explicit private connector gate and organization policy.

A provider acceptance response proves submission, not human delivery or readership. The runtime therefore reports provider acceptance and content verification, not guaranteed delivery.

## Connector testing

The connector tests are intentionally divided by what they prove:

- `tests/test_connector_contract_matrix.py` is the offline contract suite. It
  checks factory wiring, registry routing, connector inventory, local artifact
  generation, and disabled connector surfaces without credentials or network
  access.
- `tests/test_connector_integration_matrix.py` is the credentialed live suite.
  It rejects anonymous provider configuration, uses real credentials, makes
  real external requests, and independently re-reads provider state. Protected
  opt-in jobs also exercise sandbox writes, compensation, communications, and
  GitHub administration.

The normal CI matrix runs the offline contracts and discovers the live classes
in skipped state. The complete multi-provider workflow is manual-dispatch only,
runs only from the reviewed default branch, and separates read, effect, and
administration credentials across protected GitHub environments. Ordinary
GitHub read/effect coverage uses the job-scoped `github.token`; only the admin
job receives its separate personal access token and configuration.

Before an effect begins, the harness checks every fixture and gate plus the
delegated Microsoft token's exact scopes and remaining lifetime. Reversible
tests record private runner-temporary recovery entries, verify in-process
compensation, and have a same-job `always()` recovery step. This reduces
ordinary cleanup gaps but cannot prove that a provider did not commit a request
whose success response was lost; such indeterminate provider state still needs
provider-side reconciliation.

See [Credentialed Live Connector Integration Tests](live-connector-integration-tests.md)
for the covered provider operations, required fixtures, protected environments,
and local execution commands.

## Plugins

Connector plugins are Python entry points. Discovery, locking, and plan binding
read metadata and artifact bytes without importing entry modules. CLI execution
is disabled: `run --apply --plugin` fails closed before import until an isolated
worker can verify the complete dependency closure.
