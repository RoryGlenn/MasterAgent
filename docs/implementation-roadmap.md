# Implementation Roadmap and Completion Status

## Overall status

The v1 governed core and provider connectors are implemented. Release-hardening
gates keep incomplete local-Git metadata mutation, non-manifest package
execution, recurring execution, and destructive retention maintenance
non-routable.

| Phase | Software status | Operational status |
|---|---|---|
| 0 — environment/governance | Complete | Replace example governance and run readiness in the target organization |
| 1 — local governed runtime | Complete | Ready |
| 2A — Jira/Confluence/Bitbucket/SharePoint reads | Complete | Contract-tested; target deployment requires approved credentials |
| 2B — Outlook/Teams/identity/citations/retention | Complete | Contract-tested; target deployment requires approved credentials |
| 2C — authentication/readiness | Complete | App registration, consent, Conditional Access, and token issuance are organization tasks |
| 3 — draft-only output | Complete | Usable locally without provider credentials |
| 4 — approved reversible writes | Provider contracts implemented; CAS and persisted-compensation gaps tracked; local Git disabled | Provider-specific gates and approvals required |
| 5 — external communication | Complete | Disabled until exact-content approval and provider send gates are configured |
| 6 — recurring autonomy | Registration/status only | Execution disabled pending exact target/config/runtime binding |

## Phase acceptance criteria

### Phase 0

- capability owners and approval tiers are machine-readable;
- production configuration fails closed without explicit approval;
- secret-free readiness output identifies missing variable names and permissions;
- no network call occurs during readiness.

### Phase 1

- immutable plans and exact-plan approvals;
- policy and canonical-source enforcement;
- idempotency, dependency handling, audit hash chain, prompt-injection scanning;
- independent verification.

### Phase 2

- read-only connectors for all target systems;
- bounded retrieval and safe authentication boundaries;
- normalized evidence, citations, and retention;
- real provider probes are explicit rather than automatic.

### Phase 3

- complete local review package across Jira, Confluence, Outlook, Teams, PowerPoint, and repository patch;
- integrity manifest;
- no external side effects.

### Phase 4

- separate write connectors;
- expected-version or commit preconditions;
- exact approvals and idempotency;
- provider-side compare-and-swap and reconstructable compensation remain
  required before production write enablement;
- protected branches, force pushes, merge, permissions, and broad deletion prohibited.

### Phase 5

- exact recipient/destination and content are inside the approved plan;
- Outlook provider draft is re-read before sending;
- Teams response is re-read after posting;
- sends are labeled non-reversible and correction is a new approved action.

### Phase 6 release boundary

- registered built-in workflows and due state can be inspected;
- timezone-aware due calculation and maximum lateness;
- execution is disabled before config, credentials, connectors, or audit access;
- reactivation requires exact target, source, delivery, config, and runtime
  manifest binding rather than capability-name-only scope checks.

## Deployment work that cannot be completed generically

The following are intentionally outside a source-code release and must be performed in the target organization:

1. choose Cloud or Data Center endpoints;
2. register Microsoft Entra and/or Atlassian applications;
3. obtain administrator consent and assign least-privilege scopes;
4. satisfy Conditional Access and device/network requirements;
5. provision a secret manager and production audit sink;
6. define data classification, retention, legal hold, and external-model policy;
7. replace sample identities, project keys, sites, repositories, recipients, and canonical resources;
8. validate read-only probes in non-production;
9. validate reversible writes using disposable resources;
10. approve a narrow production rollout.

The runtime reports this distinction rather than representing simulated API-contract tests as a successful company deployment.
