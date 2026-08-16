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
- recurring workflow scope.

## Trust boundaries

- planner output is untrusted until schema, catalog, governance, policy, and approval validation;
- retrieved provider content is always data, never authority;
- connector code is trusted application code and must be reviewed;
- installed plugins remain untrusted executable code and CLI execution is disabled;
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
- exact capability catalog and parameter validation;
- recipient/target cannot be introduced solely by retrieved content.

### Excessive permissions

A single broad token may expose unrelated data or actions.

Controls:

- separate OAuth profiles by read/write/send purpose;
- disabled defaults;
- development-only JSON credential stores accept only integration-declared names,
  require an owner-controlled `0700` parent and `0600` regular file, reject
  ambient-variable collisions, and bind only the canonical path into applied
  execution; non-development environments require an approved secret manager;
- capability authentication is authoritative: a typed anonymous public-data
  route never resolves or forwards an ambient credential and cannot be silently
  upgraded to a broader authenticated route;
- GitHub bearer credentials are provider-attested through `GET /user` at bind
  and apply time, with only the immutable numeric user ID approval-bound;
- other opaque bearer/delegated credentials fail closed for live applied
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
- exact target identifiers in plans;
- source-of-truth rules with capability-specific immutable-value extractors;
- caller-supplied source-binding hashes are ignored as authority;
- exact recipient/body approval;
- no implicit external recipients.

### Approval substitution or mutation

An old approval may be reused after changing content, target, order, dependency, or parameters.

Controls:

- SHA-256 fingerprint of the complete immutable plan;
- approval bound to fingerprint and explicit action IDs;
- expiry and distinct approver requirements;
- approval invalidation after any plan mutation.

### Lost update

A resource may change between planning and execution.

Controls:

- expected version/eTag/commit preconditions;
- local Git patch/branch/commit/push definitions remain disabled and
  non-routable until every metadata transaction is descriptor-bound;
- independent provider re-read;
- fail-closed conflict states;
- no automatic overwrite/rebase after conflict.

### Duplicate irreversible action

A retry may send duplicate email/message or repeat a write.

Controls:

- idempotency records for side effects;
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
- independent compensation verification;
- `compensation_failed` state and manual escalation;
- no claim of distributed transactions.

### Unsafe rollback

A rollback may destroy human changes made after the agent action.

Controls:

- restore captured versions where the provider supports them;
- delete only resources created by the exact action;
- keep local Git mutation and compensation unavailable until all metadata access
  is descriptor-bound;
- refuse rollback when current state advanced;
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
- CLI plugin execution is disabled pending an isolated worker.

### Malicious connector plugin

An installed plugin may execute code, leak data, or claim broad capabilities.

Controls:

- discovery reads entry-point metadata without importing;
- installation grants no authority;
- exact plugin name, distribution, version, entry point, and artifact digest are
  operator-locked and approval-bound;
- binding imports no plugin code;
- CLI apply rejects plugins before importing the entry module or factory;
- a future worker must lock the complete transitive dependency closure and
  isolate it from already-cached host modules before activation;
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
- mode-`0600` retained files where supported;
- read-only expiry/orphan previews; destructive recursive maintenance remains
  disabled until every traversal and deletion is descriptor-relative;
- production readiness that requires an implemented typed external,
  tamper-resistant audit sink rather than trusting a configured product name.

The local checkpoint detects accidental corruption and simple event deletion,
but an administrator able to rewrite the entire SQLite database can rewrite the
checkpoint too. Local SQLite is therefore a development sink, not an immutable
external compliance record.

## Packaged prohibitions

- protected-branch write;
- force push;
- pull-request merge;
- arbitrary permission changes, invitations, and custom roles; the separately
  gated existing-GitHub-collaborator role update requires dual approval;
- arbitrary deletion;
- arbitrary HTTP;
- arbitrary shell execution;
- local Git patch, branch, commit, and push execution;
- non-manifest weekly-status, communication-context, and recurring execution;
- destructive recursive evidence pruning or quarantine;
- automatic Teams attachment download;
- autonomous external communication from recurring workflows;
- automatic refresh-token persistence.

## Residual risks

- provider APIs and permissions differ by tenant/version;
- exact HTML normalization may cause safe false negatives;
- local SQLite is not sufficient for every production threat model;
- expiry/orphan maintenance is preview-only pending descriptor-relative
  recursive traversal;
- a reviewed connector or plugin may still contain defects;
- a legitimate human approval may authorize a harmful plan;
- provider acceptance does not guarantee human receipt or downstream interpretation;
- compensation cannot reverse external observers, notifications, or all provider side effects.
