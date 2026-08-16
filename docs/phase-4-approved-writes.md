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

- comment creation;

Issue update, transition, and compensation adapters remain implemented but are
disabled in catalog and governance. Their current Jira endpoints do not provide
an adapter-usable conditional precondition, so the former read-check-write
sequence could race. Generic Jira `update` operators and transition-side field
mutations are also rejected because their complete poststate and rollback
cannot be derived exactly.

### Confluence

- Cloud space creation with exact key/name verification and created-space removal;
- page creation;
- version-checked page update;
- prior-version/body restoration.

### Bitbucket and Git

- create a pull request;
- decline the exact pull request created by the workflow under exact
  preconditions.

Local Git patch, branch, commit, push, and compensation definitions are
disabled and absent from the live registry. They remain quarantined internals
until every repository metadata/ref/reflog/index/object/lock transaction is
descriptor-bound to one approved repository identity.

### GitHub

- create an issue and close the exact created issue during compensation;
- create a pull request and close the exact created pull request during
  compensation;

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

`compensate_on_failure = true` instructs the orchestrator to compensate previously verified reversible actions in reverse order after a later action fails. Alternatively, persist the run report and create a separate compensation plan for human approval.

Compensation is not guaranteed. Concurrent edits, provider retention, permission changes, or external deletion can prevent restoration. Such failures are terminal audit states.
