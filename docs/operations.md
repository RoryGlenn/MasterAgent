# Operations Guide

Use this guide after local setup to run reviewed plans, resume approval, handle
incidents, rotate state, and monitor MasterAgent. For the first local result,
start with the [quickstart](quickstart.md); for symptom-first recovery, use
[troubleshooting](troubleshooting.md).

## Employee workflow

The organization profile is the normal employee entry point. It selects one
reviewed mode, configuration locations, a dedicated private state root, and an
exact installed-capability allowlist. It never contains credentials, approval
secrets, or provider content and does not grant authority by itself.

On native Windows, package import, help/version, deployment readiness, and
`doctor --require-level install` use the partial native runtime. Existing or
explicit profiles are read only after retained-handle, local-volume,
object-identity, owner-SID, and DACL validation. The native atomic-state
backend now satisfies `setup` and protected local persistence with explicit
private DACLs, stable handle locks, bounded replacement, and restart recovery.
The native `credential_storage` contract is also available: a connector may
select current-user Credential Manager or a current-user DPAPI document through
reviewed, non-secret configuration. DPAPI state contains only a bounded
ciphertext envelope and uses the atomic backend. Same-name ambient variables
are reported by name and ignored for that explicit source; ambiguous implicit
case variants fail closed. The native `process_supervision` contract is
available through `windows-job-object`: it runs only a fixed absolute
executable, starts from a minimal environment, inherits selected handles, and
applies whole-tree CPU-time, memory, process-count, timeout, and output bounds.
It is not a shell or general command capability.
The native `trusted_git` contract is available through `windows-trusted-git`.
It selects only an explicit or bounded Git for Windows `git.exe`, binds its
identity and digest, pins a bounded local repository metadata tree, rejects
linked-worktree and alternate-object redirection, and permits only complete
bounded local status, diff, index, revision, and object command forms with
ambient Git configuration, credentials, helpers, hooks, filters, and transports disabled.
It does not enable commit, branch, fetch, push, or any other Git mutation.
An `execute` plan should proceed only when every contract its route needs is
available in the report's `platform_runtime` section; capsule isolation remains
a separate fail-closed gate.

1. Run `master-agent setup` once for the selected profile. This prepares only
   owner-private local paths and does not contact a provider.
2. Run `master-agent doctor`. Treat `install_ready`, `read_ready`,
   `draft_ready`, `effect_ready`, and `enterprise_ready` as separate answers; a
   missing optional account does not mean the local installation is broken.
3. Run `master-agent execute PLAN`. The command keeps an eligible read
   stateless or provisions a fresh private run boundary for draft/effect work.
4. If policy requires approval, inspect the returned request. A trusted
   operator supplies the authenticated artifact; resume with `master-agent
   execute --resume REQUEST --approval ARTIFACT`.
5. Review the verified result. High-impact work retains the same exact-plan
   approval, idempotency, recovery, and disabled-at-rest controls as the
   low-level runtime.

The high-level command is orchestration convenience, not a second execution
engine. It still uses typed plans and connectors, selected-provider-only
credential resolution, catalog and governance checks, policy, exact runtime
binding, independent verification, compensation or reconciliation, and
secret-free audit.

Employee failures are categorized for a useful next action:

- `unsupported_capability`: the requested action is not an installed, reviewed
  capability on this profile;
- `missing_organization_setup`: a required reviewed profile or configuration
  location is absent;
- `missing_user_authentication`: the selected provider needs a user credential
  that is not available;
- `blocked_policy`: catalog, governance, policy, source-of-truth, approval, or
  an effect gate denied the request; and
- `runtime_defect`: a required secure platform backend is unavailable, or
  installed code or local runtime state failed unexpectedly.

Do not repair `unsupported_capability` from employee mode. Capability work
belongs in a separate trusted developer change. Generated effects stay
quarantined until independent review, tests, specification archival, signing,
deployment, and normal runtime admission complete.

## Persistent work memory

Use persistent work memory when work needs to survive separate terminal or
agent sessions but hosting a cockpit is unavailable. It is an explicit local
journal, not a service:

```bash
master-agent work-memory start \
  --database /private/master-agent/work-memory.sqlite3 \
  --work-id issue-161 \
  --issue https://github.com/RoryGlenn/MasterAgent/issues/161 \
  --summary "Add bounded persistent work memory."

master-agent work-memory record \
  --database /private/master-agent/work-memory.sqlite3 \
  --work-id issue-161 \
  --kind checkpoint \
  --stage planned \
  --summary "Implementation scope and safety boundaries are fixed."

master-agent work-memory show \
  --database /private/master-agent/work-memory.sqlite3 \
  --work-id issue-161

master-agent work-memory verify \
  --database /private/master-agent/work-memory.sqlite3
```

Start at `issue`, then advance exactly one step at a time through `planned`,
`implementing`, `reviewing`, `verified`, and `merged`. Keep decisions and
same-stage notes with `--kind decision` or `checkpoint`; use a reference event
with `--kind reference --reference VALUE` for a compact issue, commit,
pull-request, check, or release reference. The database parent must be owned by
the current account and must not be writable by group or world. On Windows it
must satisfy the equivalent private-DACL and retained-handle checks.

Every append verifies the existing global event chain and updates its durable
count and head in one serialized transaction. `show` and `verify` are
non-mutating and never create missing state. Treat a verification failure as a
corrupt or unsafe journal: preserve it for diagnosis and start no new record in
that file. Do not repair rows with SQLite tools. Restoring the exact known-good
database plus its private MasterAgent lock/ledger state is safer than editing
the history.

For mutating commands that use `--output`, choose a fresh file outside the
journal's database and bookkeeping names. MasterAgent rejects occupied or
aliased output paths before opening the journal and validates the prospective
JSON size inside the append transaction so an oversized export rolls back.
The create-only output reservation remains held until journal commit and JSON
publication finish, closing the concurrent-name race. `record` opens existing
state only; use `start` to initialize a new journal.

The chain detects ordinary row edits, deletion, reordering, complete table
definition or constraint drift, and checkpoint mismatch. It does not
authenticate the person who typed a summary,
prove a remembered claim true, or protect against a same-account administrator
replacing every database and bookkeeping file while MasterAgent is stopped.
It also cannot detect deletion of the entire journal without an external
anchor. Missing state fails closed. Remembered content never supplies identity,
authority, capability, or approval.

## Helpdesk support bundles

When an employee needs help, create one fresh diagnostic artifact instead of
copying terminal output, logs, configuration, or environment values into a
ticket. The destination directory must already be current-user-owned and not
writable by group or world:

```bash
master-agent support-bundle \
  --profile /trusted/config/organization-profile.toml \
  --output /private/helpdesk/master-agent-support-001.json
```

The command is offline and succeeds even when the profile is missing or a
readiness level is false. It prints the same support ID stored in the artifact.
The JSON contains only bounded MasterAgent/Python version facts, the redacted
doctor assessment, and canonical byte counts and SHA-256 digests for its two
embedded sections. It omits the profile path and does not collect credentials,
provider content, environment values, hostnames, usernames, logs, or command
history. Parser-controlled error text is replaced with fixed category guidance,
and any remaining path-bearing string is redacted as a whole. It performs no
automatic upload.

Before attaching the artifact, confirm that the ticket's access and retention
match the organization's support policy. Do not post it to public issues,
general chat, or an unapproved email list. Helpdesk should use the failure
category and support ID to correlate the case, then:

- route `missing_organization_setup` to the managed-install/configuration owner;
- route `missing_user_authentication` to the identity or credential owner;
- route `blocked_policy` to the named governance approver without asking the
  employee to bypass the gate;
- route `unsupported_capability` to the reviewed product backlog; and
- escalate `runtime_defect` to the MasterAgent runtime owner with the artifact
  unchanged.

The section digests detect an edited diagnostic section; they do not
authenticate the employee or grant runtime authority. If the artifact was
edited or the case needs a later snapshot, generate a new filename and support
ID. Any request for additional logs, provider data, or configuration is a
separate organization-approved collection step. The deployment owner must
define the support queue, accountable owner, response-time objective, evidence
access, retention, and secure deletion procedure before a pilot begins.

## Low-level run lifecycle

1. Generate or receive a plan.
2. For live execution, bind the trusted integrations bundle, resolved
   destinations/CA identities, and any flow-enforced or provider-verified
   credential principals required by the selected capabilities into the plan.
   A capability whose authentication class is `none` has no credential
   principal and must not resolve one. Plugin identities may be bound for
   review, but raw plugin execution remains disabled. An enabled pure capsule
   must contribute its complete signed identity to the same execution context.
   Before any provider-read attestation or content request, also preflight the
   action's explicit classification against the reviewed model-context
   destination, tenancy, output contract, limits, audit, and DLP rule.
3. Bind the explicit approval-authority configuration before any plan whose
   policy or governance tier requires human approval. Binding does not read its
   secret.
4. Inspect the bound plan and fingerprint.
5. Run policy-only dry run, then apply using only required connector classes.
6. If the run returns `approval_required`, inspect the private request written
   under the approved artifact root. A trusted operator signs it with
   `approve-request`; the agent then uses `resume-approval` instead of
   reconstructing apply arguments.
7. Review per-action state and verification.
8. Verify the audit chain.
9. Retain full evidence only when policy requires it.

Approval requests are create-only, secret-free, and private: mode `0600` on
POSIX or an explicit protected current-user DACL on Windows. They bind no
new authority: the referenced plan, action manifests, execution context,
authority configuration digest, and request fingerprint are revalidated before
signing and again before resume. A partial dual approval produces a new request
that carries the first artifact path forward. Never treat a chat response or
the request JSON as approval.

## Action states

- `planned`: permitted dry run;
- `verified`: provider/local state re-read matched expectations;
- `reused`: an equivalent completed or formerly indeterminate effect was
  independently reverified without repeating the side effect;
- `skipped`: dependency, idempotency, or prior stop prevented execution;
- `approval_required`: immutable approval absent or insufficient; applied runs
  emit a resumable private approval request when the authority was bound;
- `prohibited`: policy, catalog, governance, or source-of-truth denial;
- `conflicted`: version or remote state changed;
- `failed`: a certified pre-effect or local connector failure occurred;
- `indeterminate`: a side effect may have occurred but exact poststate could not
  be established, so automatic retry is blocked;
- `compensated`: reversible side effect was rolled back and verified;
- `compensation_failed`: automatic rollback was unavailable, refused because
  of drift, or could not be proven; inspect the descriptor's manual reason.

## Incident handling

- Stop the scheduled workflow or disable the connector gate.
- Preserve the occurrence artifact, fingerprint, claim generation, exact
  approval request, result reservation, and registration configuration.
- Preserve plan, approval, audit database/export, and explicit retained evidence.
- Verify the audit chain.
- Re-read affected provider resources independently.
- Never retry an indeterminate write or send unless its typed connector can
  reconcile the exact provider resource. A Microsoft Graph `client-request-id`
  is diagnostic correlation, not an idempotency guarantee.
- Use automatic compensation only when the descriptor permits it and the
  connector enforces the exact post-state as an atomic mutation precondition.
  A separate read followed by an unconditional write/delete is not sufficient.
- For sent communications, create a separate correction plan.
- For a provider-data egress denial, preserve the content-free rule/binding
  metadata and compare the classification, destination, tenancy, policy
  fingerprint, limits, audit sink, and DLP adapter. Do not retain or paste the
  denied provider body while diagnosing it.
- For advanced branches or edited resources, do not force rollback; escalate to the system owner.

## Rotation and expiry

- Access tokens should be short-lived.
- Token-file mode rejects group/world-readable files and expired tokens.
- Approval TTLs should be minutes, not days.
- Recurring registrations are disabled by default. When operating an explicitly
  reviewed registration, use one scheduler host and the pinned roots from the
  occurrence. Never copy the claim database to a second active host.
- Use `recurring-recover` only for a recorded certified pre-effect failure. Use
  `recurring-reconcile` for an expired running lease; status `indeterminate`
  requires connector-specific reconciliation and must not be force-retried.
- Use `recurring-cancel` with the inspected exact fingerprint for pending work.
  An active attempt is fenced off and becomes indeterminate; investigate it as
  a possible in-flight provider effect.

Preview an owner-controlled retained-evidence root before explicitly applying
expiration. On POSIX, for example:

```bash
master-agent evidence-prune --root /private/retained-evidence
master-agent evidence-prune --root /private/retained-evidence --apply
```

The root must already exist, be owned by the current account, and not be
writable by group or world. Preview is non-mutating. Both modes enumerate a
bounded descriptor-relative record set and validate every evidence/sidecar
pair, including owner, mode, link count, sidecar schema, canonical timestamps,
sibling name, and content digest. Apply acquires the pinned-root lock and every
discovered evidence-parent lock. It also shared-locks existing retention locks
in owner-controlled pinned ancestors. Retained writers first expose and
exclusively lock their exact parent, then share existing ancestor retention
locks; a parent maintenance scan therefore either already excludes the writer
or discovers its visible leaf lock. Apply repeats the scan and starts no new deletion when a
sidecar or its referenced evidence is malformed, unsafe, substituted, missing,
conflicting, oversized, or omitted by a scan limit. Unreferenced regular files
are outside prune classification and remain available to `evidence-repair`.

Repair apply uses the same selected-root and ancestor coordination, discovers
and locks every descendant record parent, and rescans before classifying or
quarantining an orphan. If a child publication is active—even after its
manifest appears—repair fails closed and moves neither file.

On POSIX, each expired pair is removed through a private `.retention-prune`
transaction.
If an interruption leaves a transaction, preview reports that apply recovery
is required; repeat the apply command under the same root. The recovery path is
bounded and uses the same evidence-parent locks. Apply can normalize an exact
owner-owned internal directory or known lock/marker file left with permissions
stricter than `0700` or `0600` by a crash between creation and mode
normalization; preview never changes it. Internal state with group/world or
special permission bits remains unsafe. Recovery fsyncs the common source
parent while both public names are absent before discarding the staged recovery
links. If an ancestor scan reports pending nested prune state, run apply on the
reported exact child root first; an empty recovered child stage is harmless.
Do not delete or edit staging state manually. A completed repeated apply is an
honest successful no-op, and result records contain paths and status rather
than retained evidence bytes.

On Windows 11, the same commands use retained Win32 directory/file handles,
owner-SID and protected-DACL validation, `LockFileEx` coordination, and the
native atomic-state ledger. Before pair deletion or orphan quarantine starts,
apply writes one bounded, content-free
`.master-agent-retention.transaction` intent containing the exact source
identities and required final state. If interrupted, preview reports that
recovery is pending and remains non-mutating; repeat the matching command with
`--apply` to complete only the recorded all-absent or
destination-present/source-absent state. Do not edit the marker or its private
atomic bookkeeping files manually.
Pruning enforces the expiration already recorded in each sidecar; it does not
make or change legal-hold decisions. Confirm that the selected root is eligible
under the organization's retention and legal-hold policy before apply.

Orphan checks remain a separate operation. `evidence-repair` previews by
default; `--apply` moves exact descriptor-validated files or symlinks into
`.retention-quarantine` without deleting their content.

## Monitoring

Track:

- failed/conflicted/prohibited action counts;
- compensation attempts and failures;
- token expiry and provider authorization failures;
- provider throttling and retry exhaustion;
- evidence nearing expiry;
- audit-chain verification;
- recurring registration and due-state drift;
- plugin inventory changes, while keeping raw plugin execution disabled;
- capsule promotion/deprecation/revocation transitions, worker identity drift,
  run checkpoints, signed-receipt export failures, and readiness-gate changes;
- capability/governance configuration changes.
- provider-data egress denials and binding/policy-fingerprint changes;
- model destination or tenancy drift, exceeded item/byte limits, redaction or
  exact-schema failures, and unavailable required audit/DLP adapters.
