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

The assessment MUST include a strategy kernel containing a diagnosis, guiding
policy, proximate objective, explicit tradeoffs, and bounded coherent-action
intents. Every action on the gated route MUST trace exactly once to a known
intent, and every declared intent MUST be used. The kernel MUST be covered by
the assessment fingerprint and the traces MUST be covered by the immutable plan
fingerprint. Missing, unknown, duplicate, stale, or forged strategy evidence
MUST fail closed. A concrete assessor MUST accept explicit typed planning
evidence and MUST NOT invent missing evidence. Static registered workflows MUST
use explicit static assessment constructors.

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
candidates, and stop conditions afterward. It MAY accept bounded observer
evidence only after execution and only when that evidence matches the admitted
assessment, decision, and success-metric fingerprints. Missing, malformed,
mismatched, dry-run, or unprovable evidence MUST produce a conservative
unobserved review and require reassessment. Systems governance and outcome
observation MUST NOT grant or weaken capability, policy, credential, approval,
provider, target, retention, audit, verification, or execution authority.

## Rationale

MasterAgent's runtime controls determine whether a proposed action may execute,
but they do not ensure that the proposal follows a coherent response to the
actual constraint or learns from measured outcomes. A mandatory pre-planning
diagnosis, strategy kernel, action trace, and conservative post-execution review
close that gap without replacing existing safety boundaries.

## Scenarios

### Safe routine work uses the explicit fast path

- GIVEN a low-risk, reversible, well-understood request
- WHEN the generated plan contains only read-only or local-generation actions
  and introduces no durable complexity
- THEN the systems gate admits the plan through the explicit fast path

### A non-trivial intervention lacks coherent strategy

- GIVEN a non-trivial plan
- WHEN its strategy kernel or exact action-to-intent coverage is missing,
  unknown, duplicated, stale, or forged
- THEN the systems gate rejects the plan before execution

### Added complexity is not justified

- GIVEN a proposal that adds durable complexity
- WHEN simpler alternatives, insufficiency evidence, or a removal strategy are
  missing, or the score exceeds the automatic budget
- THEN the gate rejects automatic admission and identifies the required review

### Bound evidence closes the feedback loop

- GIVEN an executed governed plan and independently observed outcome evidence
- WHEN the evidence matches the assessment, decision, and success metric
- THEN the review records metric movement, stop status, unintended effects,
  observed complexity, and removal candidates without changing authority

### Unprovable evidence stays conservative

- GIVEN absent, malformed, mismatched, or dry-run outcome evidence
- WHEN the post-execution review is built
- THEN the metric remains unobserved and reassessment remains required

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
- `tests/test_recurring_occurrence.py`

## History

- Introduced by GitHub issue #137.
- Strengthened with strategy traceability and observable feedback by GitHub
  issue #156.
