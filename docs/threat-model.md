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
- installed plugins are untrusted executable code until explicitly reviewed and enabled;
- provider responses are untrusted until normalized and verified;
- local artifact/workspace roots are explicit security boundaries.

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
- runtime + provider master + granular gates;
- capability catalog required scopes;
- delegated/application identity checks;
- non-production rollout capability by capability.

### Confused deputy

A legitimate user request may be combined with untrusted content to act on the wrong target or recipient.

Controls:

- explicit `ResourceRef` and identity mapping;
- exact target identifiers in plans;
- source-of-truth rules;
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
- independent provider re-read;
- fail-closed conflict states;
- no automatic overwrite/rebase after conflict.

### Duplicate irreversible action

A retry may send duplicate email/message or repeat a write.

Controls:

- idempotency records for side effects;
- unsafe POST/PUT retry disabled;
- provider draft/content preflight for Outlook;
- recurring completion state and exclusive locks;
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
- delete remote Git branches only when still pointing to the exact created commit;
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
- fixed Git executable and argument templates;
- approved workspace/repository roots;
- patch and path validation;
- plugins load only by exact operator request.

### Malicious connector plugin

An installed plugin may execute code, leak data, or claim broad capabilities.

Controls:

- discovery reads entry-point metadata without importing;
- installation grants no authority;
- exact plugin name required on applied run;
- connector contract and non-empty dotted capabilities validated;
- registry rejects overlapping capability implementations;
- catalog/governance/policy still apply;
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

- hash-chained audit events;
- evidence SHA-256 digests and manifests;
- mode-`0600` retained files where supported;
- path-safe expiry cleanup;
- production recommendation for immutable external audit storage.

## Packaged prohibitions

- protected-branch write;
- force push;
- pull-request merge;
- permission changes;
- arbitrary deletion;
- arbitrary HTTP;
- arbitrary shell execution;
- automatic Teams attachment download;
- autonomous external communication from recurring workflows;
- automatic refresh-token persistence.

## Residual risks

- provider APIs and permissions differ by tenant/version;
- exact HTML normalization may cause safe false negatives;
- local SQLite is not sufficient for every production threat model;
- a reviewed connector or plugin may still contain defects;
- a legitimate human approval may authorize a harmful plan;
- provider acceptance does not guarantee human receipt or downstream interpretation;
- compensation cannot reverse external observers, notifications, or all provider side effects.
