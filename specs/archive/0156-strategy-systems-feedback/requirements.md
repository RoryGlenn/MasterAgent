# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-SYSTEMS-GOVERNANCE-001 — Systems-governed planning and intervention

A non-trivial assessment MUST include a strategy kernel containing a diagnosis,
guiding policy, proximate objective, explicit tradeoffs, and bounded coherent
action intents. Every plan action on the gated route MUST trace exactly once to
a known coherent-action intent, and every declared intent MUST be used. The
kernel MUST be covered by the assessment fingerprint and the traces MUST be
covered by the plan fingerprint. Missing, unknown, duplicate, stale, or forged
strategy evidence MUST fail closed.

MasterAgent MUST provide a concrete systems assessor that accepts explicit typed
planning evidence and MUST NOT infer or fabricate missing evidence. Static
registered workflows MUST construct their assessments through explicit static
constructors.

After execution, the runtime MAY accept bounded outcome evidence from an
explicit observer only when it matches the admitted assessment, decision, and
success metric fingerprints. The review MUST record metric movement, stop-
condition status, unintended effects, observed complexity when available, and
removal candidates. Missing, malformed, mismatched, dry-run, or otherwise
unprovable evidence MUST produce the conservative unobserved review and require
reassessment. Outcome observation occurs after execution and MUST NOT grant or
weaken any authority.

## REMOVED

None.
