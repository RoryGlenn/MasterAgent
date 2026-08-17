# Changelog

- Harden advisory sub-agent boundaries end to end. Direct GitHub-host child
  invocation is now disabled, the researcher no longer has generic execution,
  both child profiles are read/search-only and non-invocable, and a deterministic
  repository-owned harness enforces exact-parent routing, depth/call budgets,
  context minimization, pre-dispatch denial, untrusted-output validation, and
  citation re-read under adversarial prompt-injection tests.

- Add two depth-one GitHub Copilot advisory sub-agents for bounded read-only
  research and independent plan review. The user-selected MasterAgent caps
  delegation, treats every result as untrusted data, keeps simple work direct,
  and retains sole ownership of typed plans and governed runtime execution.

- Add an immutable signed capability-capsule lifecycle for dependency-free pure
  generated capabilities: descriptor-pinned quarantine storage, separate
  promotion roles, Linux bubblewrap isolation, strict source language and
  resource limits, exact catalog/plan/approval binding, normal orchestrator
  execution, deterministic readback, immediate deprecation/revocation, and
  adversarial escape/substitution/exhaustion tests. Provider, side-effect,
  dependent, raw-plugin, and production capsule execution remains fail closed.

- Add complete-binding single-use credential handles, authenticated runtime
  principal/account constraints, policy-first intent cards and bounded active
  sessions, contextual resource/classification/budget/time policy, durable
  exact-run checkpoints, signed content-free execution receipts, and external
  audit/telemetry interfaces. Production readiness now requires the isolated
  worker, a production credential provider, authenticated approvals, and a
  healthy external tamper-resistant sink together.

- Record the repository's current proprietary license status and add an exact
  runtime dependency closure, deny-by-default dependency-license policy,
  deterministic CycloneDX SBOM generation, third-party notices, packaged
  evidence, and CI/release drift checks.

- Add a default-branch-only Confluence Cloud sandbox workflow that exercises
  the normal connection probe, private authenticated-approval resume, exact
  page create/read/versioned-update verification, always-run fresh cleanup,
  bounded HMAC-owned stale-page recovery, and a separately gated disposable
  space lifecycle without exposing secrets or retrieved page bodies.

- Persist explicit pending, completed, failed, and indeterminate idempotency
  outcomes; retry only certified pre-effect failures; independently reconcile
  provider-addressable Teams messages; and keep uncertain sends blocked rather
  than treating a diagnostic request ID as duplicate suppression.

- Authenticate approval issuer, tenant, subject, and role claims; compare dual
  approvers by a Unicode-normalized canonical principal; and support trusted
  timestamp and approval-ID revocation without weakening exact-plan binding.

- Automatically reuse a related Jira/Confluence Cloud account email and API
  token when the selected connector's dedicated names are absent, without
  rewriting the credential store or activating the related connector. Add
  approval-bound `--connector-url SYSTEM=URL` overrides that normalize supplied
  Atlassian Cloud UI URLs to their validated tenant origins.

- Add governed Confluence Cloud space creation with exact provider re-read,
  created-space compensation, and page creation by approved space key.

- Allow explicit one-run credential mappings to select fields from canonical
  multi-provider stores, enabling safe in-memory Atlassian credential reuse
  across Jira and Confluence through connection probes and governed bind/apply
  runs without rewriting private token files.

- Add a resumable authenticated-approval handoff. Approval-required plans now
  bind their trust configuration up front, emit private create-only review
  requests, support exact-request signing with `approve-request`, carry partial
  dual approvals forward, and continue through `resume-approval` without
  reconstructing provider targets, credentials, paths, or gates.

## 1.0.0 — Governed enterprise-agent runtime

### Added

- Phase 2C deployment-readiness assessment, OAuth profile configuration, Microsoft delegated device-code acquisition, restricted token files, token/scope inspection, and safe connector probes;
- organization governance profiles with capability ownership, environment constraints, data classifications, and automatic/single/dual/prohibited approval tiers;
- an 82-capability catalog spanning read, local generation, reversible writes, external communication, and high-impact operations;
- a bounded GitHub Cloud read connector for authenticated-user repository
  listing, repository metadata, pull-request search/read, and commit check-run
  reads;
- separately gated GitHub issue and pull-request creation with verified close
  compensation, plus dual-approved repository-setting and existing-collaborator
  role administration;
- a credential-free `github.public_repository.list` path for bounded,
  independently verified public repositories owned by a specified GitHub user;
- a credential-free `bitbucket.public_repository.list` path for bounded,
  independently verified public repositories in a specified Bitbucket Cloud
  workspace;
- Phase 3 complete local draft packages containing Jira and Confluence proposals, Outlook `.eml`, Teams draft, PowerPoint, repository patch, summary, and integrity manifest;
- approved Jira field updates, comments, transitions, version checks, and compensation;
- approved Confluence page creation/update and compensation for Cloud and Data Center contracts;
- quarantined Git mutation internals; patch, branch, commit, push, and local
  Bitbucket branch publication are disabled and absent from the live registry;
- Bitbucket pull-request creation with exact decline compensation;
- SharePoint bounded file upload with previous-version restoration;
- delegated OneNote notebook/section/page reads; page writes remain disabled until exact DOM-aware post-state verification is available;
- exact-plan Outlook send with provider-draft content verification;
- exact-plan Teams chat/channel message send and channel reply with provider re-read verification;
- compensation-plan generation bound to the original immutable plan and run report;
- recurring workflow registration and due-state inspection; execution is
  disabled pending exact target/config/source and runtime-manifest binding;
- metadata-only connector plugin discovery, locking, and plan binding through the `master_agent.connectors` entry-point group; in-process apply remains disabled pending an isolated dependency-closure worker;
- command-level and factory-gate tests proving broad runtime flags cannot bypass provider-specific gates.
- provider-verified GitHub bearer-token principal attestation that binds the
  immutable numeric user ID at review time and re-verifies it before applied
  connector execution.
- a repository-scoped GitHub Copilot custom-agent profile that exposes
  MasterAgent in the agent picker, performs an idempotent bounded local setup on
  the first ordinary prompt, reports a stable nontechnical outcome, and
  preserves the governed runtime boundary; repository-inspection and explicit
  no-local-change prompts remain non-mutating.
- a force-multiplier default-to-action contract that owns setup, connection,
  in-scope capability implementation, repair, tests, and end-to-end
  verification, while batching any truly operator-only input into one final
  request;
- a provider-neutral `connect` command for Jira, Confluence, Bitbucket, GitHub,
  Microsoft identity, SharePoint, Outlook, Teams, and OneNote that enables only
  selected read connectors in memory, adapts strict provider-keyed credentials
  without rewriting them, and produces optional mode-`0600` reports;
- a `github-repositories` convenience path that accepts canonical or exact
  legacy GitHub token wrappers without rewriting them, verifies the provider
  identity, evaluates the typed read, and independently verifies the result;

### Changed

- capability gaps now trigger immediate governed runtime implementation and a
  same-run return to the operator's original goal; a read-only connector or
  missing typed capability is explicitly forbidden as a final response;
- the implement-validate-resume contract applies uniformly to every existing,
  future, and plugin-provided connector;
- the same contract now covers every missing capability and repository code-path
  barrier, while preserving external credential, permission, policy, and
  authenticated-approval boundaries;
- packaged read connectors are available by default and lazily resolve only the
  provider selected by the current operation; credentials for unrelated
  providers are never required, while write, admin, send, and schedule gates
  remain disabled;
- live read, write, and communication connectors are constructed independently;
- configuration now requires granular provider gates in addition to runtime flags;
- policy evaluation now combines the capability catalog, organization governance, source-of-truth rules, immutable approvals, and risk rules;
- the CLI exposes the one-command credential-free `demo`, plus `readiness`,
  `oauth-device-code`, `draft-package`, `compensation-plan`, `recurring-status`,
  and `plugins`; `recurring-run`,
  `weekly-status`, and `communication-context` are retained as fail-closed
  command names but do not execute;
- readiness output states the live connector count, and an empty citation
  lookup reports `no citations found` instead of producing blank output;
- direct provider goals now authorize their minimum in-memory read connector,
  fixed safe probe, and implied network access for that one goal without
  persistently enabling live access or prompting again;
- applied result names are reserved before connector/audit effects and committed
  create-only before human-readable output; audit, artifact, and result
  directories must be pairwise distinct;
- evidence expiry/orphan maintenance is preview-only; destructive pruning and
  quarantine are disabled pending descriptor-relative recursive traversal;
- packaged defaults include every v1 configuration file while keeping provider
  access inactive until selected and all mutation, send, and schedule gates disabled;
- HTTP user agent and package version are now `1.0.0`.

### Security

- retrieved content cannot authorize mutations or external communication;
- dual approvals require distinct approvers;
- communication approvals bind to exact recipients/destinations and exact content;
- plugin discovery never imports plugin code, and CLI plugin apply fails closed before import;
- provider mutation connectors require runtime, generic, and granular provider gates;
- PR merge, generic permission changes, invitations, custom roles,
  protected-branch writes, arbitrary HTTP, arbitrary shell, and broad deletion
  remain prohibited; an existing GitHub collaborator's built-in role is the
  only typed, dual-approved access-management exception.
- all local Git mutation definitions are catalog-disabled,
  governance-prohibited, and non-routable because descriptor-pinning a Git child
  working directory does not bind every ref, reflog, index, object, and lock
  helper to one repository identity;
- direct weekly-status, communication-context, and recurring execution reject
  before config, credentials, connectors, or audit access;
- draft package summaries/manifests and retained results use pinned,
  create-only final names with transaction-owned rollback.
- GitHub token rotation is accepted only when `GET /user` proves the same
  numeric principal; a token for another user fails before connector actions.

## 0.3.0 — Read-only communication context

- Added read-only Outlook and Teams context, cross-system identities, citations, retention, and communication-context packaging.

## 0.2.0 — Read-only enterprise context

- Added Jira, Confluence, Bitbucket, Microsoft identity, SharePoint/OneDrive, and weekly-status package generation.

## 0.1.0 — Governed local runtime

- Added immutable plans, approvals, policy, audit, verification, prompt-injection controls, and mock connectors.
