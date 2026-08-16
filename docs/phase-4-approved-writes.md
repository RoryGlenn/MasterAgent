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
- resource/commit preconditions;
- independent verification.

The approval-authority configuration is part of the bound plan before review.
If approval is absent or incomplete, the applied run emits a private,
create-only request beneath its approved artifact root and leaves the pending
write untouched. A trusted operator signs that exact request; MasterAgent then
uses `resume-approval` to retry the captured invocation through every normal
gate. Partial dual approvals are carried into the next request. The request and
chat conversation never constitute authority.

## Supported writes

### Jira

- explicit field update;
- comment creation;
- transition with an explicit target status and required reverse transition;
- compensation.

Generic Jira `update` operators and transition-side field mutations are rejected
because their complete poststate and rollback cannot yet be derived exactly.

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
- update an allowlisted set of boolean repository settings with an expected
  version, independent re-read, and exact prior-value restoration;
- change the built-in role of an existing collaborator with dual approval and
  independent re-read.

GitHub administration is separately gated from ordinary writes. Collaborator
invitations, removals, custom roles, repository deletion, secrets, branch
protection, and merge are not exposed. Existing-collaborator role changes do
not have automatic compensation because the provider's permission endpoint
reports the highest effective role across direct and inherited grants, not the
specific grant that would need to be restored. A race that makes the provider
return a new invitation is handled by cancelling the invitation and failing the
action.

### SharePoint

- upload or replace a bounded file from an approved artifact root;
- hash bounded provider bytes before and after replacement;
- restore the previous version and independently hash the restored bytes.

### OneNote

Delegated reads remain available. Page create/update definitions and governance
routes are explicitly disabled until provider-normalized HTML and generic PATCH
commands have an exact, target-aware DOM poststate contract.

## Compensation modes

`compensate_on_failure = true` instructs the orchestrator to compensate previously verified reversible actions in reverse order after a later action fails. Alternatively, persist the run report and create a separate compensation plan for human approval.

Compensation is not guaranteed. Concurrent edits, provider retention, permission changes, or external deletion can prevent restoration. Such failures are terminal audit states.
