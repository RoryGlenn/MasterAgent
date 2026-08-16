# Operations Guide

## Normal run lifecycle

1. Generate or receive a plan.
2. For live execution, bind the trusted integrations bundle, resolved
   destinations/CA identities, and any flow-enforced or provider-verified
   credential principals required by the selected capabilities into the plan.
   A capability whose authentication class is `none` has no credential
   principal and must not resolve one. Plugin identities may be bound for
   review, but plugin execution remains disabled.
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
- `compensation_failed`: rollback could not be proven.

## Incident handling

- Stop the scheduled workflow or disable the connector gate.
- Preserve plan, approval, audit database/export, and explicit retained evidence.
- Verify the audit chain.
- Re-read affected provider resources independently.
- Never retry an indeterminate write or send unless its typed connector can
  reconcile the exact provider resource. A Microsoft Graph `client-request-id`
  is diagnostic correlation, not an idempotency guarantee.
- Use automatic compensation only when the exact connector supports it and the target remains unchanged.
- For sent communications, create a separate correction plan.
- For advanced branches or edited resources, do not force rollback; escalate to the system owner.

## Rotation and expiry

- Access tokens should be short-lived.
- Token-file mode rejects group/world-readable files and expired tokens.
- Approval TTLs should be minutes, not days.
- Evidence expiry and orphan checks are preview-only. Destructive pruning and
  quarantine are disabled pending descriptor-relative recursive maintenance.
- Recurring execution is disabled; do not install or repair scheduler locks.

## Monitoring

Track:

- failed/conflicted/prohibited action counts;
- compensation attempts and failures;
- token expiry and provider authorization failures;
- provider throttling and retry exhaustion;
- evidence nearing expiry;
- audit-chain verification;
- recurring registration and due-state drift;
- plugin inventory changes, while keeping plugin execution disabled;
- capability/governance configuration changes.
