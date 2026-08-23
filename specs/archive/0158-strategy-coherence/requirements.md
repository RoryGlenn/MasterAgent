# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-SYSTEMS-GOVERNANCE-001 — Systems-governed planning and intervention

Every gated plan MUST contain an immutable strategy-coherence review bound to
the exact systems-assessment and strategy-kernel fingerprints. The review MUST
contain strict findings that the diagnosis addresses the constraint, the
guiding policy targets the leverage point, the proximate objective advances the
desired outcome, the coherent-action effects support the success metric, and
the tradeoffs cover relevant considered alternatives. Every positive finding
MUST have bounded evidence reason codes. Missing, false, malformed, mismatched,
stale, or forged coherence evidence MUST fail closed.

A concrete reviewer MUST return only explicitly supplied coherence evidence for
the exact assessment and kernel and MUST NOT infer agreement. Static registered
interventions MAY use an explicit code-owned review constructor. The fast path
MUST remain compatible without a strategy kernel or coherence review. Coherence
evidence MUST be covered by the immutable plan fingerprint and MUST NOT grant or
weaken execution authority. Public fingerprints MUST NOT authenticate reviewer
provenance: applied gated execution MUST require either provenance from the
trusted in-process binder that admitted the exact plan or an authenticated
whole-plan review. Serialized self-attestation MUST fail closed.

### MA-DOCS-001 — Documentation review is a completion gate

When systems assessment, strategy, or outcome evidence exists for a non-trivial
change, Docs Agent maintenance MUST compare the affected documentation with the
same desired outcome, constraint, guiding policy, tradeoffs, success metric,
and observed result. A material disagreement MUST return `needs_review` rather
than documenting the mismatch as intended behavior.

## REMOVED

None.
