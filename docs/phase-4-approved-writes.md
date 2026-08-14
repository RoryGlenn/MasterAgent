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

## Supported writes

### Jira

- explicit field update;
- comment creation;
- transition with optional reverse transition;
- compensation.

### Confluence

- page creation;
- version-checked page update;
- prior-version/body restoration.

### Bitbucket and Git

- apply a bounded patch in an approved workspace;
- create a non-protected branch;
- create a commit from explicit paths;
- push a new approved branch without force;
- create a pull request;
- restore or decline/delete only resources created by the workflow under exact preconditions.

### SharePoint

- upload or replace a bounded file from an approved artifact root;
- verify resulting item metadata;
- restore the previous version when supported.

### OneNote

- delegated page create;
- delegated page patch;
- delete exact created page or restore retained prior HTML.

## Compensation modes

`compensate_on_failure = true` instructs the orchestrator to compensate previously verified reversible actions in reverse order after a later action fails. Alternatively, persist the run report and create a separate compensation plan for human approval.

Compensation is not guaranteed. Concurrent edits, provider retention, permission changes, or external deletion can prevent restoration. Such failures are terminal audit states.
