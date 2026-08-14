# Operations Guide

## Normal run lifecycle

1. Generate or receive a plan.
2. Inspect the plan and fingerprint.
3. Create exact action approvals with an explicit trusted approval-authority
   key ring and the fingerprint printed by `master-agent inspect`.
4. Run policy-only dry run.
5. Apply using only required connector classes.
6. Review per-action state and verification.
7. Verify the audit chain.
8. Retain full evidence only when policy requires it.

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
- Evidence cleanup should run independently of workflow execution.
- Recurring locks left after a crash require operator investigation before removal.

## Monitoring

Track:

- failed/conflicted/prohibited action counts;
- compensation attempts and failures;
- token expiry and provider authorization failures;
- provider throttling and retry exhaustion;
- evidence nearing expiry;
- audit-chain verification;
- recurring lateness and duplicate-run prevention;
- plugin inventory changes;
- capability/governance configuration changes.
