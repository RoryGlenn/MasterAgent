# Operations Guide

## Normal run lifecycle

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

Approval requests are mode `0600`, create-only, and secret-free. They bind no
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
- Recurring execution is disabled; do not install or repair scheduler locks.

On POSIX, preview an owner-controlled retained-evidence root before explicitly
applying expiration:

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

Each expired pair is removed through a private `.retention-prune` transaction.
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

All `evidence-prune` execution remains unavailable on Windows until native
filesystem identity, locking, and atomic-state guarantees are implemented.
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
