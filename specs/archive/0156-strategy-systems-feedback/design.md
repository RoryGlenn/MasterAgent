# Design

## Approach

`StrategyKernel` owns the diagnosis, guiding policy, proximate objective,
tradeoffs, and unique `StrategyActionIntent` records. `StrategyActionTrace`
binds every non-trivial `ChangePlan` action to exactly one intent. The systems
gate validates the complete bipartite coverage before admission.

`EvidenceBackedSystemsAssessor` returns one immutable assessment supplied by a
trusted caller and rejects a goal mismatch. `SystemsAssessment.for_fast_path`
and `SystemsAssessment.for_static_intervention` make canned workflow provenance
explicit.

`EvidenceBackedSystemsOutcomeObserver` adapts a bounded evidence provider to the
runtime. Evidence is accepted only after action execution and only when its
assessment, decision, and success-metric fingerprints match. The default path
continues to return a content-free unobserved review.

## Affected components

- `src/master_agent/models.py`: immutable strategy, trace, and outcome records.
- `src/master_agent/planners/base.py`: assessor, gate checks, observer boundary,
  static binders, and conservative review builder.
- `src/master_agent/orchestrator.py` and `src/master_agent/direct_read.py`:
  optional post-execution observer wiring.
- Built-in effect workflow constructors: explicit static strategy binding.
- Focused model, gate, orchestrator, direct-read, and recurring tests.
- Current requirement, architecture, semantic route, and generated index.

## Data flow

```text
explicit planning evidence
  -> EvidenceBackedSystemsAssessor
  -> SystemsAssessment + StrategyKernel fingerprint
  -> SystemsAwarePlanner + action traces
  -> systems gate
  -> immutable plan fingerprint
  -> ordinary runtime authority and execution gates
  -> optional fingerprint-bound outcome observer
  -> content-free review or conservative unobserved fallback
```

## Compatibility

Fast-path assessments and plans may omit a strategy kernel and traces. Existing
serialized fast-path plans continue to load. Non-trivial plans without complete
strategy evidence are deliberately rejected and must be replanned. The outcome
observer is optional, so existing callers retain their conservative result.

## Security

Strategy and systems data remain non-authoritative. Free text is bounded and
control characters are rejected. Outcome evidence is content-free, runs only
after execution, is fingerprint-bound, and cannot change action states or
admission decisions. Invalid observer output degrades to conservative evidence
rather than authorizing or claiming success.

## Rejected alternatives

- Embedding strategy prose in action justifications loses whole-plan structure.
- Passing untyped callbacks arbitrary connector bodies expands the data boundary.
- Making observer evidence mandatory would break workflows whose outcomes
  cannot be independently measured during the run.
