# Design

## Approach

`StrategyCoherenceReview` is a content-free immutable attestation carrying the
exact systems-assessment and strategy-kernel fingerprints, five strict boolean
findings, and one required reason code for each positive finding. Its complete
serialization is part of the `ChangePlan` fingerprint.

The systems gate requires the review only on the gated route. It recomputes the
assessment and kernel fingerprints, rejects every false finding, and continues
to validate exact action-to-intent coverage. The fast path rejects unexpected
strategy or coherence artifacts and otherwise remains unchanged.

`EvidenceBackedStrategyCoherenceReviewer` returns a caller-supplied review only
when both fingerprints match. `GovernedPlanner` accepts that reviewer as the
separate trusted planning boundary and does not allow the plan-producing object
to review itself. `bind_static_intervention_governance` creates the same review
at the explicit code-owned static workflow boundary.

Fingerprint agreement is not reviewer authentication. The two trusted binders
therefore attach non-serialized process-local provenance to the exact admitted
plan. Execution snapshots preserve that marker, but JSON cannot supply it. A
deserialized gated plan may be inspected in a dry run; applied execution
requires a current authenticated approval covering the exact plan and every
action. This supports approval handoff/resume without trusting self-described
review fields.

## Affected components

- `src/master_agent/models.py`: immutable coherence review and plan
  serialization.
- `src/master_agent/planners/base.py`: evidence-backed reviewer and gate
  enforcement.
- `src/master_agent/planners/__init__.py`: public planning contract exports.
- `tests/test_strict_types.py`: valid, missing, false, type-confused,
  mismatched, stale, forged, planner-boundary, and compatibility tests.
- `.ai/AUTONOMY.md` and `.ai/DOCS_AGENT.md`: shared-scope development handoffs.
- Current requirements, architecture, developer guide, semantic routing, and
  release validation.

## Data flow

```text
systems assessment + strategy kernel
  -> trusted coherence reviewer
  -> fingerprint-bound StrategyCoherenceReview
  -> systems gate + exact action traces
  -> immutable ChangePlan fingerprint
  -> ordinary authority and execution gates
  -> observed systems outcome
  -> Docs Agent reviews the same outcome and tradeoffs
```

## Compatibility

Fast-path plans remain loadable without strategy or coherence artifacts. Older
gated plans without a coherence review are deliberately rejected and must be
replanned. Static registered workflows receive the review and process-local
provenance through their existing static binder. Serialized gated plans require
authenticated whole-plan review before applied execution.

## Security

The review is planning evidence, not approval or authority. Fingerprints prevent
substitution but do not authenticate authorship; process-local binder provenance
or an authenticated whole-plan review closes that boundary before execution.
Strict booleans prevent truthiness confusion, and bounded reason codes avoid
retained content. The runtime does not use semantic heuristics or a model inside
the deterministic gate. A trusted caller that lies remains a caller validation
failure, not a capability escalation.

## Rejected alternatives

- Natural-language similarity thresholds create false confidence and unstable
  admission decisions.
- Letting the planner self-supply its review collapses independent planning
  boundaries.
- Requiring the review on the fast path would add process without reducing
  risk for low-risk reversible work.
