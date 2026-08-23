# Changelog

- Add immutable enterprise network profiles for direct, fixed authenticated
  HTTP CONNECT, and explicitly selected ambient-proxy routing. Proxy
  credentials now resolve through the governed broker and remain CONNECT-only;
  provider DNS, origin/path redirects, Server Name Indication, captured
  enterprise-CA validation, request/response budgets, and execution bindings
  remain enforced through the tunnel. Offline readiness reports the selected
  network mode without secrets, and protected managed-network evidence is
  documented as an opt-in default-branch integration gate.

- Add explicit `user-private` and `organization-managed` configuration trust.
  A private organization profile can bind exact managed bytes to bounded POSIX
  UID/GID or Windows SID writer policies; effective-user or untrusted write,
  replacement, links/reparse paths, and digest drift fail closed. Trust-class
  reporting omits digests and principals, while credentials and writable state
  remain separate. Bootstrap now replaces marker-only reuse with a versioned
  source/dependency/version/runtime attestation, an isolated `-I -S`
  interpreter check, and independent installed-file hashing; legacy, broken,
  or changed environments are preserved and repaired side by side.

- Add a machine-checked 52-invariant Windows adversarial registry with exact
  hosted-safe and protected-certification test groups. Required test skips,
  missing or renamed IDs, expected-reason mismatches, and unresolved managed-
  workstation dependencies now fail the gate. Native AppContainer evidence
  additionally probes named-pipe and parent-handle access; real Defender/CFA,
  AppLocker/WDAC, and organization-trust managed-host evidence remains blocked
  on #106, while enterprise-network evidence remains blocked on #112 rather
  than being treated as optional.

- Add a required Windows 11 ARM Python 3.12–3.14 pull-request matrix and a
  protected Windows 11 x64 release-certification workflow. The x64 gate checks
  the current protected default-branch SHA before checkout, rejects server,
  non-x64, administrator, long-path-disabled, or production-credential-bearing
  hosts, installs wheel and source distributions outside the checkout, and
  runs the full native, specification, and release suite. Live x64
  certification remains gated on a reviewed ephemeral standard-user runner;
  workflow presence or a skipped job is not certification evidence.

- Add native Windows bootstrap, packaging, and current-user paths. First run
  uses `Scripts\python.exe` and `Scripts\master-agent.exe`, applies umask only
  on POSIX, leaves unverified environments untouched in favor of a managed
  side-by-side venv, and supports explicit local wheel/source archives plus
  offline wheelhouses. Windows defaults use `%LOCALAPPDATA%\MasterAgent` rather
  than the checkout. Bootstrap markers must be ordinary single-link files and
  are published by atomic replacement, so linked markers cannot authorize an
  environment or redirect marker writes. Hosted standard-user evidence now covers source and wheel
  installs, console entry points, idempotency, spaces, Unicode, and long paths;
  release validation excludes environment, state, credential, audit, cache,
  and build artifacts.

- Add native Windows atomic local-state and retention persistence. Protected
  state now uses stable handle locks, explicit private DACLs, bounded
  write/flush/readback, handle-relative replacement, an integrity-checked
  old/new recovery ledger, destination identity/content/security verification,
  and retained-directory durability. SQLite/audit and recurring state,
  approvals and restricted output, configuration and OAuth token files,
  advisory budgets, capsule/plugin stores, retained evidence, and local draft
  packages select the native backend instead of POSIX fallbacks. Retention pair
  deletion and quarantine publish a content-free exact-identity intent before
  the first irreversible step so interrupted work completes deterministically.
  Native standard-user CI exercises restricted readiness output plus atomic,
  SQLite, and retention lifecycles; Credential Manager/DPAPI, Job Objects,
  trusted Git, AppContainer isolation, and full certification remain separate
  tranches.

- Add the native Windows filesystem and locking tranche. On native Windows 11,
  `windows-native-partial` now binds trusted paths to retained Win32 handles,
  volume/file IDs, owner SIDs, DACL and trust-policy digests; performs bounded
  restricted reads and exclusive protected create-only publication; and
  provides shared/exclusive `LockFileEx` locking. Unicode name checks use
  Windows ordinal comparison rather than lossy linguistic case folding. Unsafe
  namespaces, reparse/cloud objects, unsupported volumes, permission drift, and
  replacement fail closed. A separately digested ancestor policy permits only
  unrelated child creation on retained system roots while continuing to reject
  deletion, metadata, ACL, owner, generic-write, and target mutation authority.
  Approval bindings now carry a versioned POSIX or Windows object identity
  without breaking existing POSIX payloads. Atomic state and retention were
  subsequently released above; process, Git, capsule isolation, organization
  trust-profile integration, and full hosted certification remain separately
  gated.

- Add deterministic cross-platform runtime contracts for secure filesystem,
  cross-process locking, atomic publication/recovery, process supervision,
  trusted Git, and capsule isolation. Platform-neutral package and CLI imports
  no longer require Unix-only modules at startup; Windows can run help,
  version, deployment readiness, and configuration-only install diagnostics.
  Readiness exposes secret-free backend identity and per-contract availability,
  while operations that need an unavailable native backend fail before state,
  credentials, connectors, or provider access. Existing POSIX filesystem,
  locking, atomic-state, process, and Git semantics remain unchanged; Linux
  reports bubblewrap capsule isolation only when a trusted executable is
  selected and otherwise reports that contract unavailable, as does macOS.
  The Windows filesystem route is released; the Windows atomic-state route was
  subsequently released above, while hosted Windows certification remains
  planned until the protected runner produces successful evidence.

- Harden credentialed connector evidence behind a manual-only, reviewed-
  default-branch workflow with separate protected read, effect, and GitHub
  administration credentials; exact delegated Microsoft scope/lifetime and
  all-fixture preflight; private same-job recovery; and a static workflow
  contract. Add scoped Atlassian Jira/Confluence gateway roots with exact path
  confinement and separate credential-free browser roots, keep scoped tokens
  product-specific while sharing only the account email, and use the Atlassian
  account email for Bitbucket API tokens. Provider credentials, tenant consent,
  stable fixtures, dedicated communication targets, enablement variables, and
  the final approved live run remain deployment work.

- Add progressive employee and trusted developer operating modes, strict
  organization profiles, capability-scoped `doctor` results, safe local
  `setup`, stable employee-facing error categories, and one `execute` front
  door over the existing stateless-read and exact-plan applied runtime.
  Employee mode cannot scaffold or promote code; developer-generated effects
  remain quarantined through review, tests, specification archival, signing,
  deployment, and normal runtime admission.

- Generate the compact semantic router and hub-and-spoke agent topology from one
  exact ownership manifest. Release validation now rejects unmapped or stale
  modules, tests, requirements, configurations, CLI commands, capabilities,
  connectors, profiles, and platform routes; specialists receive only their
  selected route and local contract. Live advisory dispatch now requires one
  fully validated parent-selected route ID, binds its selected-only navigation
  slice into task and state identity, and excludes global policy, router data,
  and peer profiles from child-readable scopes. Native Windows areas remain
  distinctly routed until their own implementation and certification.

- Enable descriptor-safe expiration deletion for retained evidence on POSIX.
  `evidence-prune` now derives preview and explicit apply from the same bounded,
  validated record plan, coordinates ancestor and descendant roots through
  owner-private ancestor retention locks, holds the selected-root and discovered
  evidence-parent publication locks, descriptor-rescans before mutation, and
  removes each expired evidence and sidecar pair through a recoverable
  content-free transaction with a durable source-parent commit barrier. A
  pending nested-root transaction is reported for exact-root recovery, and
  apply can repair crash-stricter owner-only internal modes. Orphan repair now
  takes the same descendant-parent locks and rescans before quarantine, so a
  partial child publication fails closed. Malformed, unsafe, truncated,
  substituted, or concurrently changing trees fail closed. Native Windows
  retention was subsequently released with retained-handle identity and
  recovery-intent semantics above.

- Make the optional broker-owned Copilot SDK adapter enforce its documented
  controls at the real runner boundary: HMAC-authenticated cross-process goal
  budgets, bounded tracked/staged/untracked-content state binding,
  repository-owned path-scoped read/search tools, isolated-session client
  reuse, scope-aware citation revalidation, and content-minimized fallback.

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

- Automatically reuse a related Jira/Confluence Cloud account email when the
  selected connector's dedicated name is absent; legacy tenant-root
  configurations also retain unscoped API-token pair compatibility, while
  product-specific scoped tokens never cross products. Add approval-bound
  `--connector-url SYSTEM=URL` overrides that normalize supplied Atlassian
  Cloud UI URLs to their validated tenant origins.

- Add governed Confluence Cloud space creation with exact provider re-read,
  created-space compensation, and page creation by approved space key.

- Allow explicit one-run credential mappings to select fields from canonical
  multi-provider stores, enabling safe in-memory Atlassian account-email and
  legacy unscoped-token reuse across Jira and Confluence through connection
  probes and governed bind/apply runs without rewriting private token files.

- Add a resumable authenticated-approval handoff. Approval-required plans now
  bind their trust configuration up front, emit private create-only review
  requests, support exact-request signing with `approve-request`, carry partial
  dual approvals forward, and continue through `resume-approval` without
  reconstructing provider targets, credentials, paths, or gates.

## 1.0.0 — Governed enterprise-agent runtime

### Added

- Phase 2C deployment-readiness assessment, OAuth profile configuration, Microsoft delegated device-code acquisition, restricted token files, token/scope inspection, and safe connector probes;
- organization governance profiles with capability ownership, environment constraints, data classifications, and automatic/single/dual/prohibited approval tiers;
- a 96-capability catalog spanning read, local generation, reversible writes, external communication, and high-impact operations;
- a governed Reddit OAuth connector with purpose-separated read and communication credentials, provider-reported scope enforcement, bounded reads, local drafts, exact approved post/comment/reply operations, zero write retries, and catalog-quarantined non-atomic edit/delete adapters;
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
