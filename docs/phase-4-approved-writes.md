# Phase 4 — Approved Reversible Writes

## Execution contract

A reversible write requires:

- an enabled typed capability;
- an organization rule permitting it in the current environment;
- direct-user, organization-policy, or registered-workflow authority;
- exact-plan human approval;
- live connector runtime enablement;
- generic and granular provider gates;
- valid credentials;
- approval-bound effective identity and required scopes;
- resource/commit preconditions enforced atomically by the provider;
- independent verification.

The orchestrator reserves each side-effecting idempotency key atomically and
binds it to the action-effect digest. Durable outcomes distinguish pending,
completed, certified pre-effect failure, and indeterminate execution. Failed
claims may be atomically retried by an explicit later run. Indeterminate claims
remain blocked unless a typed connector can independently reconcile the exact
provider resource from bounded content-free metadata.

The Microsoft Graph v1.0 [sendMail](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0)
and [chat message](https://learn.microsoft.com/en-us/graph/api/chatmessage-post?view=graph-rest-1.0)
contracts do not declare an idempotency-key header. Graph's documented
`client-request-id` is for diagnostics, so MasterAgent never treats it as
duplicate suppression. Teams messages that already returned an exact provider
message ID can be re-read and reconciled; uncertain Outlook acceptance remains
blocked for operator investigation rather than automatically resent.

The approval-authority configuration is part of the bound plan before review.
If approval is absent or incomplete, the applied run emits a private,
create-only request beneath its approved artifact root and leaves the pending
write untouched. A trusted operator signs that exact request; MasterAgent then
uses `resume-approval` to retry the captured invocation through every normal
gate. Partial dual approvals are carried into the next request. The request and
chat conversation never constitute authority.

## Supported writes

### Jira

- comment creation with a manual deletion descriptor;

Issue update, transition, and compensation adapters remain implemented but are
disabled in catalog and governance. Their current Jira endpoints do not provide
an adapter-usable conditional precondition, so the former read-check-write
sequence could race. Generic Jira `update` operators and transition-side field
mutations are also rejected because their complete poststate and rollback
cannot be derived exactly.

### Confluence

- Cloud space creation with exact key/name verification and manual deletion recovery;
- page creation with manual deletion recovery;
- version-checked page update;
- atomic version-checked prior-version/body restoration.

### Bitbucket and Git

- create a pull request with a manual re-read/decline recovery descriptor;

Local Git patch, branch, commit, push, and compensation definitions are
disabled and absent from the live registry. They remain quarantined internals
until every repository metadata/ref/reflog/index/object/lock transaction is
descriptor-bound to one approved repository identity.

### GitHub

- create an issue with a manual re-read/close recovery descriptor;
- create a pull request with a manual re-read/close recovery descriptor;

Repository-settings and existing-collaborator adapters remain separately gated
from ordinary writes but are prohibited by catalog and governance. GitHub does
not document a provider-side conditional precondition for those unsafe methods.
Collaborator invitations, removals, custom roles, repository deletion, secrets,
branch protection, and merge are not exposed.

### SharePoint (disabled)

The byte-verifying replacement adapter remains implemented, but its capability
and governance routes are disabled. The exact Graph small-file `PUT /content`
contract does not document `If-Match`; checking an eTag immediately before that
write would still be a race. Re-enable only after using a provider-documented
atomic commit path and preserving the existing prior/uploaded/restored byte
proofs.

### OneNote

Delegated reads remain available. Page create/update definitions and governance
routes are explicitly disabled until provider-normalized HTML and generic PATCH
commands have an exact, target-aware DOM poststate contract.

## Compensation modes

Every reversible `ExecutionResult` carries the one typed, versioned
`master-agent/compensation@1` descriptor. The runtime persists a
content-free `side_effect_may_have_occurred` event immediately after `execute`
returns and before verification. A failed or raised verification retains the
result, records `indeterminate`, and blocks retry.

`compensate_on_failure = true` processes results in reverse order. Mode
`in_process` is allowed only in the originating connector flow; mode `plan`
can also be reconstructed from a persisted run report into a new
approval-bound plan; mode `manual` is never invoked automatically. The runtime
rejects unversioned legacy descriptor shapes and incomplete/partial recovery
plans.

Before automatic compensation, the connector re-reads the exact agent
post-state and the mutation itself must enforce an atomic provider or local
compare-and-swap precondition. Confluence page versions and Git ref leases meet
that bar. A read followed by an unconditional close, decline, delete, or
restore does not, so those adapters emit `manual`. Concurrent edits, provider
retention, permission changes, or external deletion become explicit terminal
audit states rather than being overwritten.
