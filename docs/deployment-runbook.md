# Deployment Runbook

## 1. Establish ownership

Replace the example organization, security owner, retention owner, system owners, and communications owner in `config/governance.toml`.

## 2. Classify the environment

Start with `development`, then `non_production`. Do not set `production_approved = true` before non-production contract validation and security review.

## 3. Select provider deployments

For each Atlassian connector choose Cloud or Data Center and set the exact HTTPS API root. For Microsoft, select the correct Graph national-cloud root and capability-specific identity mode. The built-in Teams send connector is delegated-only; any Teams bot must be implemented and approved as a separate connector.

## 4. Register applications and credentials

Request only the scopes needed for the first workflow. Prefer separate credentials for read, reversible write, and communication. Store persistent secrets in the approved secret manager.

## 5. Run offline readiness

```bash
master-agent readiness --output .master-agent/readiness.json
```

Resolve every error and review every warning.

## 6. Validate read-only access

Enable one read connector at a time and run:

```bash
master-agent discover --systems jira --probe
```

Then run the relevant read-only package workflow. Review normalized evidence, citations, retention, and audit output.

## 7. Validate draft-only output

Run `master-agent draft-package`. Review the generated `.eml`, Teams draft, deck, proposals, patch, and manifest.

## 8. Validate reversible writes in non-production

Use disposable Jira issues, Confluence pages, branches, SharePoint files, and OneNote pages. Capture expected versions. Obtain exact approvals. Enable only one granular provider flag. Execute, verify, and test compensation.

## 9. Validate communication

Use designated test recipients/chats/channels. Approve exact content. Verify provider identity and tenant restrictions. Confirm the runtime reports provider acceptance rather than claiming delivery/read receipt.

## 10. Enable one recurring workflow

Keep delivery local/draft-only. Set strict capability and canonical-source allowlists. Run manually, inspect scheduler state, then install the scheduler invocation. Do not enable overlapping broad workflows.

## 11. Production controls

Before production:

- use a non-local audit sink or export process;
- use an approved secret manager;
- define incident response and token revocation;
- define evidence retention/legal hold;
- keep plugin execution disabled; inventory and pin artifacts only for review;
- review every enabled capability and connector gate;
- preserve a tested rollback procedure;
- monitor provider throttling and authentication failures.
