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

Read results are normalized into stable schemas, marked as untrusted content, scanned for prompt-injection indicators, and independently re-read for verification where practical. Communication bodies and document content remain in memory unless explicit evidence output and retention rules permit persistence.

## Mutation connectors

Mutation connectors are not extensions of the read connector's arbitrary request surface. They expose narrowly typed capability names and validate required fields, risk, approval intent, identity mode, resource path, size, branch prefix, expected version, or expected commit before network or Git side effects.

Local Git commits are assembled in a private alternate index while the standard
index lock is held. The reviewed diff becomes an immutable tree, the branch ref
is updated by compare-and-swap, and the reviewed index is installed atomically;
worktree edits made after the snapshot remain unstaged and are not discarded.
Branch publication uses the exact approved commit object ID as the push source,
so a concurrently advanced local branch cannot change the published content.

## Compensation

Compensation is connector-specific:

- Jira restores captured fields, removes the comment created by the workflow, or applies a configured reverse transition;
- Confluence restores the captured prior page version/body or removes the exact page created by the workflow;
- Bitbucket declines the exact PR and may delete only the exact unchanged branch created by the workflow;
- SharePoint restores the captured prior version only after hashing the prior, uploaded, and restored provider bytes;
- Git compensates only inside the verified connector flow: patches are reversed,
  commit refs use compare-and-swap plus a mixed index reset, and an exact unchanged
  new branch may be removed. Concurrent worktree content is preserved and causes
  compensation to refuse or report a conflict. No separately approved destructive
  worktree-restore action is exposed. A remote push reports manual recovery because
  automatically rewriting or deleting a published ref could destroy concurrent work.

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
