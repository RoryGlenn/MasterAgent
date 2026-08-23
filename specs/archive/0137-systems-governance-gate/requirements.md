# Requirement deltas

## ADDED

### MA-SYSTEMS-GOVERNANCE-001 — Systems-governed planning and intervention

Before a non-trivial goal can produce an actionable plan, MasterAgent MUST
complete a structured systems assessment that states the desired observable
outcome, current system behavior, constraint, stocks, flows, feedback loops,
delays, leverage point, smallest intervention, success metric, failure or
reassessment condition, likely unintended consequences, and removable
complexity. The planner MUST consume that assessment rather than plan directly
from the raw goal, and the admission decision MUST be bound to the exact
assessment fingerprint.

A task MAY use an explicit fast path only when it is low risk, reversible, and
well understood; its plan contains only `read_only` or `local_generation`
actions; and it introduces no durable complexity. A claimed fast path that
contains a write, external communication, high-impact action, destructive
action, or complexity item MUST fail closed.

Every added dependency, persistent service, agent, configuration surface,
authoritative document, state store, connector, or user workflow MUST contribute
to a weighted complexity score. When complexity is added, the assessment MUST
identify simpler alternatives considered, explain why existing mechanisms are
insufficient, and include an explicit removal or reversibility strategy. A score
above the configured automatic budget MUST require human review and MUST NOT be
automatically admitted. An otherwise valid over-budget plan MAY proceed only
when the runtime authenticates one current human approval bound to the exact
plan fingerprint and covering every action.

The runtime MUST require the admitted assessment and decision before
executing non-trivial work, preserve their integrity through immutable plan
binding, and perform a post-execution systems review covering metric movement,
unintended effects, complexity growth, removal candidates, and stop or
reassessment conditions. Both applied orchestration and direct-read execution
MUST return that review. Systems governance MUST NOT grant capability,
credential, target, approval, provider, policy, or execution authority that the
ordinary governed runtime does not independently permit.

## MODIFIED

None.

## REMOVED

None.
