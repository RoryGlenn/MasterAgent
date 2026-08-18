# MA-ADVISORY-005 — Broker-owned live specialist adapter

## Status

Active

## Requirement

A live advisory model adapter MUST execute only through the repository-owned
advisory broker. It MUST preselect exactly one reviewed read-only specialist,
MUST disable ambient host inference and extension discovery, MUST technically
deny non-read tool use, and MUST NOT expose edit, shell, provider, credential,
approval, MCP, or nested-agent capabilities.

Delegated input MUST pass the existing sensitive-context sanitizer before SDK
startup. The adapter MUST bind each invocation to the exact sanitized task,
selected profile, and repository state and MUST reject a result if that state
changes during execution. Returned specialist data MUST be converted to the
existing narrow `AdvisoryReport` schema and MUST still pass independent parent
re-validation before it can be accepted as evidence.

The adapter MUST be optional and fail closed. An unavailable, unauthenticated,
incompatible, stale, or failed SDK path MUST return to equivalent direct-parent
work rather than blocking the operator or widening authority.

## Rationale

Host-native automatic agent inference can bypass the deterministic MasterAgent
broker. A broker-owned SDK adapter permits real isolated reasoning while keeping
parent identity, role budgets, context minimization, tool restrictions, and
report validation inside the repository-owned control plane.

## Scenarios

### The Researcher is invoked safely

- GIVEN MasterAgent selects a bounded research task
- WHEN the broker invokes the live SDK adapter
- THEN exactly one Researcher session is preselected with read-only tools and no ambient extension discovery
- AND the result remains untrusted until parent re-validation

### A specialist attempts to widen its tool surface

- GIVEN a specialist requests shell, edit, provider, MCP, or an outside-repository file path
- WHEN the SDK pre-tool policy evaluates the request
- THEN the call MUST be denied before the effect occurs

### The repository changes during delegation

- GIVEN a live advisory call is in progress
- WHEN HEAD, the worktree, the index, or the selected profile changes before completion
- THEN the specialist result MUST be rejected and work MUST fall back to the parent

### The optional SDK is unavailable

- GIVEN the base MasterAgent runtime is otherwise ready
- WHEN the Copilot SDK cannot be imported or started
- THEN the advisory call MUST return an explicit parent fallback
- AND ordinary MasterAgent operation MUST remain available

## Implementation

- `src/master_agent/advisory.py`
- `src/master_agent/copilot_advisory.py`
- `.github/agents/MasterAgent.agent.md`
- `.github/agents/MasterAgent-Read-Researcher.agent.md`
- `.github/agents/MasterAgent-Plan-Reviewer.agent.md`

## Verification

- `tests/test_advisory_integration.py`
- `tests/test_copilot_advisory.py`

## History

- Introduced by GitHub issue #90.
