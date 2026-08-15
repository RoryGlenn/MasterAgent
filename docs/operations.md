# Operations Guide

## Normal run lifecycle

1. Generate or receive a plan.
2. For live execution, bind the trusted integrations bundle, resolved
   destinations/CA identities, and any flow-enforced or provider-verified
   credential principals required by the selected capabilities into the plan.
   A capability whose authentication class is `none` has no credential
   principal and must not resolve one. Plugin identities may be bound for
   review, but plugin execution remains disabled.
3. Inspect the bound plan and fingerprint.
4. Create exact action approvals with an explicit trusted approval-authority
   key ring and the fingerprint printed by `master-agent inspect`.
5. Run policy-only dry run.
6. Apply using only required connector classes.
7. Review per-action state and verification.
8. Verify the audit chain.
9. Retain full evidence only when policy requires it.

## Action states

- `planned`: permitted dry run;
- `verified`: provider/local state re-read matched expectations;
- `skipped`: dependency, idempotency, or prior stop prevented execution;
- `approval_required`: immutable approval absent or insufficient;
- `prohibited`: policy, catalog, governance, or source-of-truth denial;
- `conflicted`: version or remote state changed;
- `failed`: connector or verification failure;
- `compensated`: reversible side effect was rolled back and verified;
- `compensation_failed`: rollback could not be proven.

## Incident handling

- Stop the scheduled workflow or disable the connector gate.
- Preserve plan, approval, audit database/export, and explicit retained evidence.
- Verify the audit chain.
- Re-read affected provider resources independently.
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
