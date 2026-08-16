# Live Connector Contracts

## Shared HTTP boundary

All HTTP connectors use a constrained client that enforces:

- HTTPS base URLs;
- no embedded URL credentials;
- same-origin API requests and pagination;
- cross-origin authenticated redirect rejection;
- bounded response bytes, pages, items, and timeouts;
- method allowlists per connector;
- controlled retries for transient failures;
- query-free and secret-free errors;
- no credential forwarding to temporary SharePoint download URLs.

## Read connectors

Read results are normalized into stable schemas, marked as untrusted content,
scanned for prompt-injection indicators, and independently re-read for
verification where practical. The GitHub Cloud connector constructs fixed
public-user and authenticated-user repository-list, repository, pull-request,
check-run, and identity endpoints internally and uses bounded numbered
pagination. Separately constructed GitHub mutation connectors expose only
issue/PR creation, allowlisted repository settings, and existing-collaborator
built-in-role updates; no connector exposes an arbitrary-request surface.
`github.public_repository.list` uses the public-user endpoint anonymously and
does not resolve or forward an ambient credential. Authenticated GitHub reads
bind the provider-returned numeric principal during context review and
re-verify that principal before applied reads. Communication bodies and
document content remain in memory unless explicit evidence output and
retention rules permit persistence.

`bitbucket.public_repository.list` similarly constructs only the fixed
Bitbucket Cloud workspace-repositories endpoint, ignores ambient Bitbucket
credentials, rejects repositories not explicitly marked public, and uses the
shared same-origin pagination boundary.

`master-agent connect --systems ...` is the provider-neutral readiness path
when operator-requested access requires authentication. It enables only the
selected supported read connectors in memory, accepts canonical or strictly
mapped provider-keyed local credentials, runs each connector's fixed probe,
and persists no connector or credential changes. Selected Jira/Confluence
Cloud Basic-auth connectors may reuse the other product's configured Atlassian
account pair in memory when their own names are absent. `--connector-url`
normalizes an operator-supplied Atlassian UI URL to the selected tenant origin;
bind/apply include that origin in the execution context. It is not a
prerequisite for the anonymous GitHub public-user or Bitbucket public-workspace
repository lists. It is not a generic HTTP surface and does not execute a
feature action; the agent continues through the typed capability that produces
the requested outcome.

## Mutation connectors

Mutation connectors are not extensions of the read connector's arbitrary request surface. They expose narrowly typed capability names and validate required fields, risk, approval intent, identity mode, resource path, size, branch prefix, expected version, or expected commit before network or Git side effects.

Local Git mutation internals are quarantined. Their capability definitions are
disabled, governance marks them prohibited, and the live factory does not
register either workspace or local-Git publication connectors. Descriptor-pinned
subprocess working directories alone do not prove that every ref, reflog, index,
lock, object, and temporary metadata helper stayed on the same repository
identity. Patch, branch, commit, and push remain unavailable until that entire
metadata boundary is descriptor-backed and adversarially verified.

## Compensation

Compensation is connector-specific:

- Jira restores captured fields, removes the comment created by the workflow, or applies a configured reverse transition;
- Confluence restores the captured prior page version/body or removes the exact page created by the workflow;
- Bitbucket declines the exact PR created by the workflow;
- SharePoint restores the captured prior version only after hashing the prior, uploaded, and restored provider bytes;
- Git mutation and compensation are not exposed by the live registry.

A compensation operation is independently verified and audited. Failure to compensate is reported, never hidden.

SharePoint byte verification uses the bounded Graph content endpoint and never
forwards credentials across an origin change. Tenants that return a cross-origin
download redirect therefore remain fail-closed until a destination-attested,
no-auth download broker is implemented. The full upload/verify/restore lifecycle
requires at least 12 requests; packaged Microsoft defaults reserve 16 and cap
approved uploads at 1,000,000 bytes so repeated byte proofs remain inside the
shared response budget.

## Communication connectors

Outlook and Teams sends are separate from local draft generation. They require `external_communication` risk, `requires_approval = true`, the runtime communication flag, a granular provider flag, and valid exact-plan approval. The built-in Teams Graph send connector is delegated-only. Outlook delegated sending is the default; application sending additionally requires an explicit private connector gate and organization policy.

A provider acceptance response proves submission, not human delivery or readership. The runtime therefore reports provider acceptance and content verification, not guaranteed delivery.

## Plugins

Connector plugins are Python entry points. Discovery, locking, and plan binding
read metadata and artifact bytes without importing entry modules. CLI execution
is disabled: `run --apply --plugin` fails closed before import until an isolated
worker can verify the complete dependency closure.
