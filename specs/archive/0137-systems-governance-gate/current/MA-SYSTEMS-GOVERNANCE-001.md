# MA-SYSTEMS-GOVERNANCE-001 — Systems-governed planning and intervention

## Status

Active

## Requirement

Before a non-trivial goal can produce an actionable plan, MasterAgent MUST
complete a structured systems assessment that identifies the observable outcome,
current behavior, constraint, stocks, flows, feedback loops, delays, leverage
point, smallest intervention, success metric, failure condition, unintended
consequences, and removable complexity. The planner MUST consume the completed
assessment, and the admission decision MUST remain bound to its exact
fingerprint.

An explicit fast path MAY admit only low-risk, reversible, well-understood plans
containing `read_only` or `local_generation` actions and no durable complexity.
Every added dependency, service, agent, configuration surface, authoritative
document, state store, connector, or user workflow MUST contribute to a weighted
complexity budget. Added complexity MUST include simpler alternatives, evidence
that existing mechanisms are insufficient, and a removal or reversibility
strategy. Over-budget work MUST require human review and MUST NOT be
automatically admitted. The runtime MUST consume a current authenticated human
approval bound to the exact plan and covering every action before executing an
otherwise valid over-budget plan.

The runtime MUST enforce the admitted assessment before non-trivial execution
and MUST review success metrics, unintended effects, complexity growth, removal
candidates, and stop conditions afterward. Systems governance MUST NOT grant or
weaken capability, policy, credential, approval, provider, target, retention,
audit, verification, or execution authority.

## Rationale

MasterAgent's existing runtime controls determine whether a proposed action may
execute, but they do not ensure that the proposal targets the actual system
constraint or avoids unnecessary complexity. A mandatory pre-planning diagnosis
and post-execution review closes that gap without replacing existing safety
boundaries.

## Scenarios

### Safe routine work uses the explicit fast path

- GIVEN a low-risk, reversible, well-understood request
- WHEN the generated plan contains only read-only or local-generation actions
  and introduces no durable complexity
- THEN the systems gate admits the plan through the explicit fast path

### A claimed fast path contains a write

- GIVEN an assessment that claims the fast path
- WHEN the generated plan contains a reversible write, communication,
  high-impact, or destructive action
- THEN the systems gate rejects the plan before execution

### A non-trivial intervention lacks system evidence

- GIVEN a non-trivial request
- WHEN stocks, flows, feedback loops, delays, or unintended consequences are
  missing
- THEN the systems gate fails closed and reports each missing requirement

### Added complexity is not justified

- GIVEN a proposal that adds a dependency, service, agent, configuration,
  authoritative document, state store, connector, or user workflow
- WHEN simpler alternatives, insufficiency evidence, or a removal strategy are
  missing, or the score exceeds the automatic budget
- THEN the gate rejects automatic admission and identifies the required review

### Human review admits an otherwise valid over-budget plan

- GIVEN an otherwise valid assessment whose complexity score exceeds the
  automatic budget
- WHEN one current authenticated human approval covers the exact plan and every
  action
- THEN runtime admission may continue without weakening any ordinary policy or
  execution control

### Systems governance cannot grant authority

- GIVEN a complete systems assessment and permitted gate decision
- WHEN ordinary capability, policy, approval, credential, provider, or execution
  validation denies an action
- THEN the action remains denied

## Implementation

- `src/master_agent/planners/base.py`
- `src/master_agent/planners/__init__.py`
- `src/master_agent/models.py`
- `src/master_agent/orchestrator.py`
- `src/master_agent/direct_read.py`

## Verification

- `tests/test_strict_types.py`
- `tests/test_orchestrator.py`
- `tests/test_direct_read.py`

## History

- Introduced by GitHub issue #137.
