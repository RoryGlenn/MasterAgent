# Design

## Approach

The change is introduced in four bounded layers:

1. **Assessment contract:** `SystemsAssessment` records the diagnosis and
   computes a stable fingerprint. `ComplexityItem` applies the issue's weighted
   budget to durable additions.
2. **Admission gate:** `SystemsGovernanceGate` selects either the explicit fast
   path or the full gated path, accumulates every blocking reason, and fails
   closed through `enforce`.
3. **Planning sequence:** `GovernedPlanner` invokes a `SystemsAssessor` before a
   `SystemsAwarePlanner`, passes the exact assessment into planning, and returns
   a `GovernedPlan` bound to the gate decision.
4. **Runtime binding:** the assessment and decision live inside the immutable
   plan, are re-evaluated by both execution entry points, produce content-free
   audit evidence, and yield a conservative post-execution systems review.

The implementation extends the existing planner contract and runtime rather
than creating a new agent or service. It adds no dependency, connector, state
store, persistent process, or independent configuration surface.

## Affected components

- `src/master_agent/planners/base.py` — typed assessment, complexity budget,
  gate, decision, protocols, and governed wrapper.
- `src/master_agent/planners/__init__.py` — public exports.
- `tests/test_strict_types.py` — fail-closed and sequencing regression tests.
- `src/master_agent/models.py` and `src/master_agent/orchestrator.py` — immutable
  plan binding, runtime enforcement, audit metadata, and post-execution review.
- `src/master_agent/direct_read.py` — fail-closed enforcement for the stateless
  provider-read path.
- `docs/architecture.md` — runtime and operator-facing governance guidance.

## Data flow

```text
User goal
    -> SystemsAssessor.assess(goal)
    -> SystemsAssessment
    -> SystemsAwarePlanner.plan(goal, systems_assessment=assessment)
    -> ChangePlan
    -> SystemsGovernanceGate.enforce(plan, assessment)
    -> GovernedPlan(immutable ChangePlan with assessment and bound decision)
    -> ordinary policy, approval, execution, verification, and audit gates
```

The assessment is development and planning evidence. It never grants execution
authority. Its fingerprint prevents a decision for one assessment from being
reused with another assessment.

## Compatibility

The existing `Planner` protocol remains available for planning-only callers.
Executable plans require the new optional serialized fields, while older plans
still deserialize for inspection and fail closed only when submitted to an
execution entry point. Registered workflows and provider shortcuts now bind an
explicit assessment. The systems records are part of the existing plan
fingerprint, so approvals automatically cover them without a second authority
mechanism.

## Security

- The gate fails closed and reports all missing evidence.
- Fast-path admission is based on both explicit assessment predicates and the
  actual risks in the generated plan.
- Complexity above the automatic budget requires review rather than silently
  increasing the threshold.
- The systems decision cannot authorize a capability, approval, credential,
  target, provider, or side effect.
- Free-form systems text must remain subject to existing size, retention,
  sanitization, and audit rules when it reaches the runtime binding.
- Post-execution review must not retain provider bodies or sensitive content
  where only metadata is permitted.

## Rejected alternatives

- A separate `systems-thinking-agent` was rejected because it would introduce
  another agent and remain bypassable.
- Adding the checklist only to `.ai` instructions was rejected because runtime
  callers and registered workflows would not be deterministically governed.
- Treating action count as the complexity score was rejected because one
  persistent service or state store can be more costly than several local
  actions.
- Automatically approving an over-budget proposal when its prose is complete
  was rejected because complexity review is a distinct decision boundary.
