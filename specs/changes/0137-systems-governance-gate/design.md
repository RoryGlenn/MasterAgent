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
4. **Runtime migration:** a later slice will place the assessment and decision
   in the immutable plan/execution binding, enforce them in orchestration, audit
   content-free governance evidence, and perform the post-execution review.

The initial implementation lives in the existing planner-contract module rather
than creating a new agent or service. It adds no dependency, connector, state
store, persistent process, or independent configuration surface.

## Affected components

- `src/master_agent/planners/base.py` — typed assessment, complexity budget,
  gate, decision, protocols, and governed wrapper.
- `src/master_agent/planners/__init__.py` — public exports.
- `tests/test_strict_types.py` — fail-closed and sequencing regression tests.
- `src/master_agent/models.py` and `src/master_agent/orchestrator.py` — planned
  follow-up integration for immutable plan binding and runtime enforcement.
- `docs/architecture.md` — planned documentation update after the runtime path
  is complete.

## Data flow

```text
User goal
    -> SystemsAssessor.assess(goal)
    -> SystemsAssessment
    -> SystemsAwarePlanner.plan(goal, systems_assessment=assessment)
    -> ChangePlan
    -> SystemsGovernanceGate.enforce(plan, assessment)
    -> GovernedPlan(plan, assessment, bound decision)
    -> future immutable ChangePlan/runtime binding
    -> ordinary policy, approval, execution, verification, and audit gates
```

The assessment is development and planning evidence. It never grants execution
authority. Its fingerprint prevents a decision for one assessment from being
reused with another assessment.

## Compatibility

The existing `Planner` protocol and current static workflows remain unchanged in
the first slice. New planners can adopt `GovernedPlanner` immediately. Runtime
migration will be explicit and tested before the gate becomes mandatory for all
non-trivial entry points. Serialized plan compatibility and approval
fingerprints must be preserved or versioned when the assessment is added to
`ChangePlan`.

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
