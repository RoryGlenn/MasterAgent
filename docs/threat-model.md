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
- approved provider-data destination, model tenancy, and classification;
- organization-profile mode, capability allowlist, and configuration binding;
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
- organization model-context configuration is trusted deployment policy;
  provider content cannot select its own classification, destination, tenancy,
  fields, handling, audit, or DLP requirements;
- the organization profile is reviewed workflow input, not capability,
  credential, approval, signing, or code-promotion authority;
- local artifact/workspace roots are explicit security boundaries.

The operating-system service account, installed Master Agent runtime, and
private runtime directories are part of the trusted computing base. Descriptor
or retained-handle pins, restrictive POSIX modes or Windows DACLs, create-only
publication, and transaction locks guard common pathname-substitution and
concurrency attacks. Local integrity digests are not an independent
authentication secret: a malicious same-UID process or same-SID process that
can replace the complete database, ledger, lock, and private-key state while
the runtime is stopped can construct a different self-consistent set.
Production readiness therefore still requires an external
tamper-resistant audit sink and isolated or broker-attested credentials; local
SQLite is a development boundary, not protection from a compromised service
account.

Retention hierarchy locks provide cooperative concurrency for MasterAgent
processes within that service-account boundary. They use only restricted
retention lock files in eligible owner-controlled directories, not raw public
ancestor directory locks, and remain subject to the same trusted-service-
account availability assumption as the other local lock state.

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

### Unapproved provider-data model-context egress

A correctly authenticated and verified provider read may still disclose data to
an unapproved agent, user, model destination, or model tenancy. Retrieved data
may also try to broaden its own classification or field scope.

Controls:

- trusted action or probe classification is evaluated before provider content
  access and is never inferred from the response;
- an immutable binding covers provider/account/configuration digests, request
  digest, requested fields or exact versioned output contract, item and byte
  limits, destination, tenancy, handling, audit, and DLP requirements;
- attestation and content access reuse one captured credential snapshot, while
  the endpoint, origin, and CA identity are checked before access and return;
- the policy and binding are recomputed immediately before return;
- schema projection, separator-insensitive recursive secret/configured-field
  redaction, minimized prompt-injection findings and references, and byte/item
  ceilings are enforced on a private copy after independent verification;
- missing classification, ambiguous or denied rules, changed bindings, and
  unavailable required audit or DLP adapters fail closed before content crosses
  the boundary; and
- durable audit stores only binding facts, digests, counts, and outcomes—not
  provider bodies, query values, raw account identities, secrets, or raw
  injection excerpts.

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
  route inventory, HEAD, raw index entries, descriptor-read tracked bytes, and
  bounded untracked file contents before and after each isolated session;
- semantic-route authorization is parsed from the immutable HEAD revision
  carried by a complete repository-state binding, requires identical worktree
  manifest and profile bytes, rehashes commit/tree/prompt-bearing blob objects,
  disables content conversion, replacement refs, worktree redirection, lazy
  fetch, and transport protocols, and requires the same digest before SDK client
  creation;
- object-address verification follows the repository object format: SHA-256
  repositories receive SHA-256 binding, while legacy SHA-1 repositories use
  standard SHA-1 content-address checks and do not claim Git's separate SHA1DC
  collision-detection property;
- repository and provider-content prompt injections remain inert test data;
- child reports cannot select targets, claim approval, propose plans, return
  secret-like content, or become evidence without parent citation re-read;
- unavailable, failed, unsafe, nested, or over-budget delegation falls back to the parent without changing filesystem, environment, network, provider,
  credential, approval, audit, or plan state; and
- the deterministic policy, approval, connector, verification, compensation,
  retention, and audit runtime remains the only provider-effect path.

### Organization-profile widening or mode confusion

A modified profile may list an unreviewed capability, redirect trusted
configuration, select developer mode, or change between review and approval
resume in an attempt to widen employee authority.

Controls:

- bounded exact-schema parsing rejects unknown fields, modes, malformed or
  duplicate capability names, and unsafe paths;
- pre-runtime validation rejects catalog-missing or profile-unlisted
  capabilities, while employee risk checks and the existing effect gates keep
  high-impact work disabled, before connector, credential, audit, artifact,
  plugin, capsule, or provider access;
- setup and doctor are offline and cannot create credentials, approvals, audit
  sinks, provider connections, or code-promotion state;
- every effect-bearing execution binds both the exact canonical profile path
  and its bytes, then revalidates both with the captured plan and invocation
  during approval resume, so an identical profile substituted at another path
  is rejected;
- developer mode does not add runtime capabilities, and generated effect code
  remains quarantined through independent review, tests, specification
  archival, signing, deployment, and normal admission; and
- capability, governance, policy, source-of-truth, provider, credential,
  approval, verification, idempotency, compensation, and audit gates remain
  independently mandatory after profile admission.

### Platform backend downgrade or eager native loading

An unsupported host, missing native primitive, or platform-specific import may
either break harmless package inspection or tempt a caller to continue through
a compatibility layer that does not preserve MasterAgent's security
guarantees.

Controls:

- platform family and backend identities are selected by fixed runtime code,
  not an organization profile, environment variable, retrieved instruction, or
  plugin;
- platform-neutral package and CLI imports do not initialize Unix-only or other
  native backends;
- `secure_filesystem`, `cross_process_locking`,
  `atomic_publication_recovery`, `credential_storage`, `process_supervision`,
  `trusted_git`, and `capsule_isolation` report independent stable availability and secret-free
  reasons;
- capsule isolation means executable OS containment: Linux selects the
  bubblewrap backend only when a trusted executable is available and otherwise
  reports the contract unavailable; macOS reports the contract unavailable
  rather than treating owner-private group membership as a sandbox;
- native Windows filesystem trust retains every opened ancestor and leaf
  handle without delete sharing, binds volume/file identity plus owner/DACL and
  trust-policy digests, rejects unsafe namespaces, reparse/cloud objects and
  unsupported volumes, compares Unicode components and handle paths with the
  operating system's non-linguistic ordinal uppercase table, and revalidates
  before and after bounded reads. Its
  ancestor policy permits only unrelated child creation while rejecting
  delete-child, metadata, generic-write, ACL, owner, and replacement rights;
  the exact `OWNER RIGHTS` SID aliases only a separately admitted and
  revalidated owner and never enters the configured trusted-SID set;
- Windows create-only publication attaches a protected DACL during exclusive
  creation, bounds and flushes the write, reads back and revalidates the same
  identity, and cleans up only the exact file created by the failed attempt;
- Windows whole-file shared and exclusive locks use `LockFileEx`; atomic
  publication uses stable handle locks, protected exclusive temporary and
  ledger files, same-parent handle-relative replacement, exact old/new
  identity and digest reconciliation, post-publication owner/DACL checks, and
  retained-directory flushes;
- Windows retained pair deletion and quarantine publish a bounded content-free
  intent before the first irreversible step, then accept only recorded source
  identities while completing the recorded final state;
- Windows credential storage reads only configuration-declared names from
  exact Generic Credential Manager targets or a versioned DPAPI document;
  DPAPI omits machine scope, forbids UI, binds optional entropy to the canonical
  path, and publishes ciphertext only through protected atomic state;
- explicit native sources remove same-name ambient values using Windows
  case-insensitive comparison and diagnose names only, while duplicate implicit
  sources and case variants fail closed;
- Windows supervised commands use an explicit executable and argument vector,
  create the root process suspended, admit only selected inheritable handles,
  assign a kill-on-close Job Object before resume, and apply process CPU-time,
  process/job memory, and active-process limits across descendants. The child
  starts from a Windows-directory baseline instead of caller environment,
  stdout and stderr share one retention budget, and timeouts terminate the
  complete job;
- Windows trusted Git accepts only a pinned Git for Windows executable and a
  bounded retained local metadata tree, rejects reparse points, case
  collisions, lock contention, linked-worktree redirection, and alternate
  object databases, disables ambient configuration, credentials, hooks,
  filters, helpers, prompts, and transports, and admits only complete fixed
  read-only command forms through the Job Object supervisor;
- help, version, and configuration-only readiness consume descriptive status
  only and cannot turn availability into authority;
- a stateful operation requires its exact contract before protected state,
  credentials, connector construction, provider access, or effects;
- unavailable selection raises one typed bounded error and never retries
  through a POSIX shim, another platform, or a weaker fallback; and
- Windows native filesystem, locking, atomic-state, credential-storage,
  process supervision, trusted Git, AppContainer isolation, and existing POSIX
  behavior receive separate regression coverage. Hosted matrix and protected
  x64 workflow controls are implemented, while live certification remains
  separately planned until an enrolled clean standard-user runner supplies
  evidence.

### Excessive permissions

A single broad token may expose unrelated data or actions.

Controls:

- separate OAuth profiles by read/write/send purpose;
- disabled defaults;
- development-only JSON credential stores accept only integration-declared names,
  require an owner-controlled `0700` parent and `0600` regular file, reject
  ambient-variable collisions, and bind only the canonical path into applied
  execution; non-development environments require an approved secret manager;
- native Windows deployments may instead select current-user Credential Manager
  for individual named values or current-user DPAPI for one structured set;
  connector identity binds only the provider and target, and neither mode
  migrates or rewrites an existing JSON file;
- Jira/Confluence credential fallback is limited to selected Cloud connectors
  using Basic authentication. A scoped gateway may reuse only the configured
  Atlassian account email in memory; product-specific scoped tokens never cross
  between Jira and Confluence. Legacy tenant-root configurations retain the
  unscoped email/API-token pair compatibility. Explicit target-product names
  win, the source connector is not activated, and the fixed provider probe
  remains authoritative for actual product/site access;
- credentialed integration jobs separate read, effect, and administration
  secrets across protected environments; ordinary GitHub coverage uses the
  job-scoped token while only the administration job receives its distinct
  personal access token and configuration;
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

The manual credentialed integration workflow adds a test-harness recovery
layer: every compensatable provider result is written immediately to a bounded
mode-`0600` journal under `RUNNER_TEMP`, normal `finally` cleanup verifies the
compensation independently, and a same-job `always()` step replays residual
entries. The journal is never uploaded. This catches ordinary test failures;
it cannot prove whether a provider committed an operation when the success
response was lost before a recovery entry existed. That state remains
indeterminate and requires provider-side reconciliation.

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
- privilege-specific protected-environment secrets for credentialed live jobs;
- bounded runner-temporary recovery journals with mode `0600`, no credential
  values, and no artifact upload;
- URL credentials prohibited;
- queries/fragments stripped from evidence/error URLs;
- audit content minimization;
- release secret scanning and exclusion rules.

### SSRF and credential forwarding

A provider response may redirect to an attacker-controlled host or temporary download URL.

Controls:

- HTTPS and same-origin authenticated requests;
- operator-supplied Jira/Confluence Cloud URLs are reduced to an exact HTTPS
  single-label `atlassian.net` tenant origin; embedded credentials, explicit
  default `:443` is normalized away, while nondefault ports and unselected
  connectors are rejected, and the result is approval-bound for live
  execution;
- Jira and Confluence scoped-token API roots require the exact
  `api.atlassian.com/ex/{product}/{cloudId}` form plus a separately allowlisted,
  credential-free tenant `web_base_url`; decoded request, response, redirect,
  and pagination paths cannot leave the captured product/cloud-ID prefix even
  when the origin is unchanged;
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
- promoted pure capsules use an AST-restricted language in Linux bubblewrap or
  a native Windows zero-capability AppContainer with no network, no ambient
  environment, no undeclared host-file/process authority, and bounded
  resources; Windows must return signed OS-level denial evidence for host-file,
  IPv4, IPv6, localhost, named-pipe, parent-handle, ambient-secret, and child-
  process probes; and
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

### Malicious custom-agent capability import

A foreign agent export may contain prompt injection, hidden code, substituted
dependencies, recursive agents, or claims to the source agent's credentials,
identity, approval, and trust.

Controls:

- accept only one owner-controlled, regular, bounded, self-contained versioned
  JSON snapshot and reject symlinks, unsafe permissions, duplicate keys,
  unknown fields, malformed identifiers, controls, and unbounded structures;
- treat descriptions, constraints, requirements, and embedded source as data
  and never run a prompt, program, hook, plugin, shell command, network call, or
  original agent during inspection;
- compare exact dependency declarations with the embedded lock, SBOM, notices,
  and license policy and statically reject forbidden source constructs;
- classify existing-name shadowing, unsupported surfaces, imported authority,
  recursion, and inconsistencies before selection;
- require exactly one explicit safely importable ability and the previewed
  source SHA-256, then re-snapshot and reclassify before any write;
- bind the exact source digest and declared publisher into the derived capsule
  policy identity, while treating the publisher as unverified until the normal
  independent publisher authority signs promotion;
- load capsule signing identities only from an explicit owner-controlled TOML
  ring whose secrets are environment-backed, whose enabled entries own one role
  each, and whose required key IDs, case-folded subjects, environment references,
  and resolved signing key values are distinct;
- install only the signed quarantine state; catalog and routing construction
  still require the final independently signed enabled state;
- authenticate the complete latest state chain, then apply governance and
  policy before lexical intent routing; execute only an exact enabled binding
  through the typed orchestrator and a worker environment that omits signing
  secrets; and
- use append-only deprecation or revocation to remove future routing without
  erasing promotion history.

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

The complete credentialed provider matrix is not recurring automation. It has
only a manual-dispatch trigger, is bound to reviewed default-branch code, and
keeps repository enablement variables absent or false until every protected
environment, credential, fixture, reviewer, and restriction is ready. A static
workflow contract test guards that boundary.

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
- bounded descriptor-relative expiration planning beneath one pinned root;
- an exclusive exact-parent publication lock followed by shared existing
  owner-controlled ancestor retention locks, paired with the same
  selected-root/ancestor maintenance handshake;
- deterministic acquisition of the selected-root and every discovered evidence-parent
  retention lock, followed by an exact identity-bound rescan;
- the same descendant-parent lock discovery and rescan before orphan
  classification or quarantine, including partial child-first publication;
- exact schema, timestamp, persistence, sibling, digest, owner, mode, file type,
  single-link, and bounded-size validation before new expiration deletion;
- create-only hard-link staging of each pair in a bounded content-free
  same-filesystem transaction, with descriptor-bound completion or rollback
  after interruption, an absent-source-parent fsync barrier before staged-link
  cleanup, exact-root reporting for pending nested transactions, and apply-only
  normalization of stricter owner-only internal directory/lock/marker modes;
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
- broad, path-based, or unvalidated recursive evidence deletion;
- automatic Teams attachment download;
- autonomous external communication from recurring workflows;
- automatic refresh-token persistence.

## Residual risks

- provider APIs and permissions differ by tenant/version;
- the Python CLI cannot cryptographically attest which surrounding model
  tenancy receives its output; the configured destination and tenancy remain a
  reviewed deployment assertion until a host-attestation adapter exists;
- exact HTML normalization may cause safe false negatives;
- local SQLite is not sufficient for every production threat model;
- HMAC capsule/receipt signing assumes externally protected authority keys;
- local advisory-budget HMAC state protects ordinary corruption and
  cross-process races, not a same-account attacker who can replace both its
  private key and all state while every runner is stopped;
- the bundled pure capsule worker is intentionally too small for many useful
  provider capabilities; production brokerage and external audit adapters are
  deployment work, not demonstrated guarantees;
- native Windows implementation and hosted matrix evidence are not live x64
  release certification: the skip-intolerant adversarial registry also keeps
  organization-trust and enterprise-network cases explicitly blocked on #111
  and #112, and the protected workflow remains unproven until those cases and
  an enrolled clean standard-user Windows 11 x64 runner complete it. Operations
  also remain unavailable where another required runtime or credential-broker
  contract is absent. Expiration
  quarantine intentionally retains orphaned bytes until an
  operator reviews and removes them;
- a reviewed connector or plugin may still contain defects;
- a legitimate human approval may authorize a harmful plan;
- provider acceptance does not guarantee human receipt or downstream interpretation;
- compensation cannot reverse external observers, notifications, or all provider side effects.
