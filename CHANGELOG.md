# Changelog

## 1.0.0 — Governed enterprise-agent runtime

### Added

- Phase 2C deployment-readiness assessment, OAuth profile configuration, Microsoft delegated device-code acquisition, restricted token files, token/scope inspection, and safe connector probes;
- organization governance profiles with capability ownership, environment constraints, data classifications, and automatic/single/dual/prohibited approval tiers;
- a 75-capability catalog spanning read, local generation, reversible writes, external communication, and prohibited high-impact operations;
- a bounded, read-only GitHub Cloud connector for authenticated-user repository
  listing, repository metadata, pull-request search/read, and commit check-run
  reads;
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
- a one-request goal-completion contract that batches necessary reversible
  read-only prerequisites, uses ephemeral least-privilege connector overlays,
  and reserves questions for real missing authority or operator-only input;
- a `github-repositories` convenience path that accepts canonical or exact
  legacy GitHub token wrappers without rewriting them, verifies the provider
  identity, evaluates the typed read, and independently verifies the result;

### Changed

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
- direct provider-read goals now authorize their minimum in-memory read
  connector for that one goal without persistently enabling live access;
- applied result names are reserved before connector/audit effects and committed
  create-only before human-readable output; audit, artifact, and result
  directories must be pairwise distinct;
- evidence expiry/orphan maintenance is preview-only; destructive pruning and
  quarantine are disabled pending descriptor-relative recursive traversal;
- packaged defaults include every v1 configuration file while keeping all live access, mutations, sends, and schedules disabled;
- HTTP user agent and package version are now `1.0.0`.

### Security

- retrieved content cannot authorize mutations or external communication;
- dual approvals require distinct approvers;
- communication approvals bind to exact recipients/destinations and exact content;
- plugin discovery never imports plugin code, and CLI plugin apply fails closed before import;
- provider mutation connectors require runtime, generic, and granular provider gates;
- PR merge, permissions, protected-branch writes, arbitrary HTTP, arbitrary shell, and broad deletion remain prohibited.
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
