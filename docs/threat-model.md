# Threat Model

## Protected assets

- provider credentials and OAuth tokens;
- source code and repository history;
- Jira/Confluence/OneNote/SharePoint content;
- email and Teams communications;
- employee identity mappings;
- approval authority;
- canonical source integrity;
- audit/evidence integrity;
- capability capsule signing authorities, immutable artifacts, and receipts;
- recurring workflow scope.

## Trust boundaries

- planner output is untrusted until schema, catalog, governance, policy, and approval validation;
- advisory sub-agent output is untrusted until the parent re-checks its evidence;
- retrieved provider content is always data, never authority;
- connector code is trusted application code and must be reviewed;
- generated capsule source and installed plugins remain untrusted data; raw
  plugin CLI execution is disabled, and a capsule becomes executable only
  after its complete signed promotion chain verifies;
- provider responses are untrusted until normalized and verified;
- local artifact/workspace roots are explicit security boundaries.

The operating-system service account, installed Master Agent runtime, and
private runtime directories are part of the trusted computing base. Descriptor
pins, restrictive ownership/modes, create-only publication, and transaction
locks guard common pathname-substitution and concurrency attacks. A local,
unkeyed SQLite database cannot authenticate a malicious same-UID process that
replaces the complete database, ledger, and lock state with a different
self-consistent set. Production readiness therefore still requires an external
tamper-resistant audit sink and isolated or broker-attested credentials; local
SQLite is a development boundary, not protection from a compromised service
account.

## Threats and controls

### Prompt injection and instruction laundering

An email, message, issue, page, note, source file, PR comment, or attachment may attempt to override policy or cause tool use.

Controls:

- authority-source field on every action;
- retrieved content cannot authorize writes or communications;
- prompt-injection scanning and untrusted-content metadata;
- one bounded terminal renderer for untrusted findings and provider
  diagnostics: C0/C1, escape sequences, carriage return, backspace, Unicode
  line separators, and bidirectional formatting controls are visible inert
  text rather than terminal instructions;
- exact capability catalog and parameter validation;
- recipient/target cannot be introduced solely by retrieved content.

### Delegation laundering or authority confusion

A delegated researcher or reviewer may follow retrieved instructions, invent a
target, claim approval, disclose sensitive context, recursively delegate, or
attempt to execute work that belongs to the parent and governed runtime.

Controls:

- direct GitHub-host advisory invocation is disabled because the host cannot
  prove the selected-parent allowlist, depth-one routing, or per-goal counters;
- the parent profile omits `agent`, and both children are non-user- and
  non-model-invocable with only `read` and `search`;
- the repository-owned advisory integration harness loads the exact checked-in
  profiles, binds every session to MasterAgent, denies nested delegation, and
  atomically enforces at most three research attempts and one plan review in
  private HMAC-authenticated state shared across runner processes;
- payload minimization rejects credentials, approval/signing artifacts,
  targets, recipients, connectors, tenants, unrelated private context, and
  `ChangePlan` data before worker invocation;
- the profile-derived dispatcher denies execute, edit, agent, MCP, HTTP,
  environment, credential, provider, approval, audit, and mutation categories
  before dispatch;
- the optional SDK adapter exposes only repository-owned scoped read/search
  tools, excludes ignored/private/symlink paths, and binds the task, profile,
  route inventory, HEAD, index, tracked/staged diffs, and bounded untracked file
  contents before and after each isolated session;
- repository and provider-content prompt injections remain inert test data;
- child reports cannot select targets, claim approval, propose plans, return
  secret-like content, or become evidence without parent citation re-read;
- unavailable, failed, unsafe, nested, or over-budget delegation falls back to the parent without changing filesystem, environment, network, provider,
  credential, approval, audit, or plan state; and
- the deterministic policy, approval, connector, verification, compensation,
  retention, and audit runtime remains the only provider-effect path.

### Excessive permissions

A single broad token may expose unrelated data or actions.

Controls:

- separate OAuth profiles by read/write/send purpose;
- disabled defaults;
- development-only JSON credential stores accept only integration-declared names,
  require an owner-controlled `0700` parent and `0600` regular file, reject
  ambient-variable collisions, and bind only the canonical path into applied
  execution; non-development environments require an approved secret manager;
- Jira/Confluence credential fallback is limited to selected Cloud connectors
  using Basic authentication and copies only the configured Atlassian account
  email/API-token pair in memory. Explicit target-product names win, the source
  connector is not activated, and the fixed provider probe remains authoritative
  for actual product/site access;
- capability authentication is authoritative: a typed anonymous public-data
  route never resolves or forwards an ambient credential and cannot be silently
  upgraded to a broader authenticated route;
- GitHub bearer credentials are provider-attested through `GET /user` at bind
  and apply time, with the immutable numeric user ID and reported OAuth scopes
  approval-bound;
- Microsoft delegated credentials are provider-attested through Graph `/me` at
  bind and apply time, with the immutable user object ID and token-file or
  configured effective scopes approval-bound;
- other opaque bearer/application credentials fail closed for live applied
  execution until a provider-verified principal or trusted broker attestation
  is available;
- runtime + provider master + granular gates;
- capability catalog required scopes;
- delegated/application identity checks;
- non-production rollout capability by capability.

### Confused deputy

A legitimate user request may be combined with untrusted content to act on the wrong target or recipient.

Controls:

- explicit `ResourceRef` and identity mapping;
- exact target system, resource type, and identifiers in plans;
- source-of-truth rules whose identity includes the typed resource, governed
  field, and capability-specific immutable-value extractors;
- caller-supplied source-binding hashes are ignored as authority;
- exact recipient/body approval;
- no implicit external recipients.

### Approval substitution or mutation

An old approval may be reused after changing content, target, order, dependency, or parameters.

Controls:

- SHA-256 fingerprint of the complete immutable plan;
- approval bound to fingerprint and explicit action IDs;
- expiry and distinct approver requirements;
- signature-bound issuer, tenant, subject, and role claims;
- canonical principal comparison plus authority-side timestamp and artifact-ID
  revocation;
- approval invalidation after any plan mutation.
- approval-authority configuration bound before review;
- mode-`0600`, create-only resumable requests beneath the pinned artifact root;
- request fingerprint plus exact plan/action/context validation before signing;
- captured non-secret invocation replayed through the unchanged apply gates,
  with symlink, permission, plan, authority, and context drift rejected.

The resumable request is review data, not approval. Conversational assent, an
edited request, or possession of the request cannot authenticate an approver.

### Lost update

A resource may change between planning and execution.

Controls:

- expected version/eTag/commit preconditions;
- local Git patch/branch/commit/push definitions remain disabled and
  non-routable until every metadata transaction is descriptor-bound;
- independent provider re-read whose capability-specific contract includes
  every effect-bearing field; Confluence page writes prove content,
  representation, version, publication status, space, and direct parent;
- fail closed when a provider omits required poststate fields;
- fail-closed conflict states;
- no automatic overwrite/rebase after conflict.

### Duplicate irreversible action

A retry may send duplicate email/message or repeat a write.

Controls:

- atomic action-digest-bound reservations with explicit pending, completed,
  failed, and indeterminate outcomes;
- retries only for durable certified pre-effect failures;
- independent provider reconciliation before an indeterminate Teams message can
  be reused; other uncertain sends remain blocked;
- unsafe POST/PUT retry disabled;
- provider draft/content preflight for Outlook;
- recurring execution disabled pending exact target/config/runtime binding;
- explicit correction instead of automatic resend.

### Partial multi-system failure

One action may succeed before a later action fails.

Controls:

- dependency-aware state machine;
- `compensate_on_failure` for atomic plans;
- reverse-order provider-specific compensation;
- a typed descriptor that distinguishes plan, in-process, and manual recovery;
- independent compensation verification;
- `compensation_failed` state and manual escalation;
- no claim of distributed transactions.

### Unsafe rollback

A rollback may destroy human changes made after the agent action.

Controls:

- record the returned result as `side_effect_may_have_occurred` before
  verification and preserve it in an explicit indeterminate incident;
- restore captured versions only through an atomic version/ref precondition;
- mark close, decline, delete, or restore paths manual when the adapter has
  only a raceable read-check-mutate sequence;
- keep local Git mutation and compensation unavailable until all metadata access
  is descriptor-bound;
- refuse rollback with a version conflict when current state advanced;
- require a fresh provider observation after compensation and retain completed
  idempotency state until that observation proves the complete captured
  prestate (or a documented terminal deletion state);
- reject unversioned legacy compensation metadata and partial reconstructed
  plans;
- sent communications never use fake rollback.

### Secret leakage

Tokens may leak through configuration, URLs, logs, errors, plans, evidence, or generated artifacts.

Controls:

- environment/secret-store references only in TOML;
- secrets excluded from `repr`;
- restricted token files and no refresh-token persistence;
- URL credentials prohibited;
- queries/fragments stripped from evidence/error URLs;
- audit content minimization;
- release secret scanning and exclusion rules.

### SSRF and credential forwarding

A provider response may redirect to an attacker-controlled host or temporary download URL.

Controls:

- HTTPS and same-origin authenticated requests;
- operator-supplied Jira/Confluence Cloud URLs are reduced to an HTTPS
  `atlassian.net` tenant origin; embedded credentials, nondefault ports, and
  unselected connectors are rejected, and the result is approval-bound for
  live execution;
- authenticated cross-origin redirects blocked;
- SharePoint download host suffix allowlist;
- no Graph Authorization header on temporary download URLs;
- IP literals, localhost, URL credentials, and fragments rejected.

### Arbitrary code or shell execution

A planner may attempt to turn a connector into a general execution environment.

Controls:

- no generic HTTP connector;
- no generic shell connector;
- no routable local Git mutation or generic repository command surface;
- raw CLI plugin execution remains disabled;
- promoted pure capsules use an AST-restricted language in Linux bubblewrap
  with no network, no ambient environment, no import/file/process authority,
  and bounded resources; and
- provider destinations, credentials, side effects, and capsule dependencies
  are rejected before connector construction in the demonstrated runtime;
- each credential lease binds the exact plan fingerprint, action ID, normalized
  origin, method, and path, then rechecks that immutable operation before a
  trusted adapter can receive credential material; and
- routing negation crosses bounded intervening modifiers to the operation term,
  preventing phrases such as `do not ever delete` from admitting the delete
  capability.

### Generated capability substitution or self-promotion

Generated source may alter its declared contract, replace validation evidence,
escape quarantine, select its own reviewer, or reuse an approval for another
version.

Controls:

- owner-private descriptor-pinned capsule store with no-follow, single-link,
  bounded regular-file reads and create-only writes;
- complete source/artifact/dependency/SBOM/test/contract/policy/worker digests;
- deterministic package modes plus a restrictive install umask, with a
  shared-group- or world-writable capsule worker rejected before execution;
- ordered signed manifests with distinct generator, validator, sandbox,
  reviewer, publisher, and revoker roles;
- publisher/reviewer separation, monotonic timestamps, append-only states, and
  exact latest-enabled resolution;
- dependency-license allow/deny policy, complete exact lock, CycloneDX SBOM,
  and required third-party notices;
- activation verifies the signature chain and all artifacts before connector
  construction;
- the complete capsule identity is inside `ExecutionContext`, the plan and
  approval fingerprint, audit events, active session, and signed receipt;
- deprecation/revocation becomes the latest state and blocks resolution; and
- generated code has no signing, approval, credential, routing, or promotion
  authority.

The complete demonstrated boundary and explicit production exclusions are in
[`capability-capsules.md`](capability-capsules.md).

### Malicious connector plugin

An installed plugin may execute code, leak data, or claim broad capabilities.

Controls:

- discovery reads entry-point metadata without importing;
- distribution inventories are validated in full before lookup, and bounded
  owner-checked regular artifacts are read only descriptor-relatively beneath
  one pinned root without following symlinks or accepting hardlinks;
- installation grants no authority;
- exact plugin name, distribution, version, entry point, and artifact digest are
  operator-locked and approval-bound;
- binding imports no plugin code;
- CLI apply rejects plugins before importing the entry module or factory;
- the capsule worker is not a raw plugin loader and accepts only a separately
  reviewed dependency-free pure capsule;
- a future dependency filesystem must seal the complete transitive closure and
  isolate it from already-cached host modules before dependent capsules can run;
- package publisher and code review remain operator responsibilities.

### Recurring autonomy expansion

A scheduled workflow may gain capabilities, recipients, or destinations over time.

Controls:

- only built-in workflow kinds;
- fixed registration fingerprint/configuration;
- capability and recipient allowlists;
- canonical-source and output-root restrictions;
- disabled defaults;
- local-only/draft-only delivery modes;
- no arbitrary plan generation from retrieved content.

### Audit/evidence tampering

An operator or process may alter records or retained content.

Controls:

- serialized hash-chained audit events with a durable count/head checkpoint;
- verification that refuses missing, empty, malformed, or tail-truncated audit
  databases without creating them;
- evidence SHA-256 digests and manifests;
- one restricted-artifact primitive for every CLI JSON output: pinned private
  parent, no-follow exclusive mode-`0600` creation, descriptor-identity checks,
  exact-byte readback, file and directory fsync, and identity-bound rollback;
- mode-`0600` same-directory staging, fsync, create-only manifest-first
  publication, and transaction-owned rollback;
- descriptor-relative, no-follow orphan detection and recoverable quarantine;
- expiry deletion remains preview-only;
- production readiness that requires an implemented typed external,
  tamper-resistant audit sink rather than trusting a configured product name.

The local checkpoint detects accidental corruption and simple event deletion,
but an administrator able to rewrite the entire SQLite database can rewrite the
checkpoint too. Local SQLite is therefore a development sink, not an immutable
external compliance record.

### Resource exhaustion

An attacker-controlled or accidentally enormous plan, generated draft, or
artifact set may exhaust memory, CPU, or local storage before policy can make a
decision.

Controls:

- reject plan files over 8 MiB before JSON parsing;
- iteratively bound JSON nesting, collection fan-out, node count, string size,
  per-action parameters, aggregate plan parameters, actions, and dependencies
  before recursive model construction;
- require every local-generation capability to declare input and output byte
  quotas beneath hard runtime ceilings;
- reserve one 64 MiB aggregate budget across all artifacts in a complete local
  run and reject over-budget bundles before any final artifact name is created;
- stream artifact readback and verification in bounded chunks instead of
  holding a duplicate whole-file buffer;
- cap capsule source, manifest chain, dependency count, test cases, AST nodes,
  process count, address space, CPU, wall time, request/output bytes, active
  credential handles, and active-session calls/bytes.

## Packaged prohibitions

- protected-branch write;
- force push;
- pull-request merge;
- arbitrary permission changes, invitations, custom roles, and GitHub
  administration without provider compare-and-swap;
- arbitrary deletion;
- arbitrary HTTP;
- arbitrary shell execution;
- provider/network or side-effect capsule execution;
- capsule self-promotion or generated approval;
- capsule third-party runtime dependencies in the current pure worker;
- local Git patch, branch, commit, and push execution;
- non-manifest weekly-status, communication-context, and recurring execution;
- destructive recursive evidence pruning;
- automatic Teams attachment download;
- autonomous external communication from recurring workflows;
- automatic refresh-token persistence.

## Residual risks

- provider APIs and permissions differ by tenant/version;
- exact HTML normalization may cause safe false negatives;
- local SQLite is not sufficient for every production threat model;
- HMAC capsule/receipt signing assumes externally protected authority keys;
- local advisory-budget HMAC state protects ordinary corruption and
  cross-process races, not a same-account attacker who can replace both its
  private key and all state while every runner is stopped;
- the bundled pure capsule worker is intentionally too small for many useful
  provider capabilities; production brokerage and external audit adapters are
  deployment work, not demonstrated guarantees;
- expiry deletion is preview-only; quarantine intentionally retains orphaned
  bytes until an operator reviews and removes them;
- a reviewed connector or plugin may still contain defects;
- a legitimate human approval may authorize a harmful plan;
- provider acceptance does not guarantee human receipt or downstream interpretation;
- compensation cannot reverse external observers, notifications, or all provider side effects.
