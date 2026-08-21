# MA-ADVISORY-005 — Broker-owned live specialist adapter

## Status

Active

## Requirement

A live advisory model adapter MUST execute only through the repository-owned
advisory broker. It MUST preselect exactly one reviewed read-only specialist,
MUST disable ambient host inference and extension discovery, MUST technically
deny non-read tool use, and MUST NOT expose edit, shell, provider, credential,
approval, MCP, or nested-agent capabilities.

Delegated input MUST pass the sensitive-context sanitizer before SDK startup.
The adapter MUST bind each invocation to the exact sanitized task, selected
profile, normalized allowed path scope, HEAD, index, tracked worktree state,
staged state, untracked paths, and untracked file contents. Bounded state scans
MUST fail closed on truncation, excess, unreadable or special files, or races,
and a result MUST be rejected if any bound state changes during execution.

The SDK session MUST expose only repository-owned bounded read/search tools
whose handlers technically enforce the allowed path scope. Tool calls and the
independent parent citation re-read MUST reject access outside that same scope.
Returned specialist data MUST use the narrow `AdvisoryReport` schema and MUST
remain untrusted until parent re-validation succeeds.

The adapter MUST be optional and fail closed. An unavailable, unauthenticated,
incompatible, stale, failed, over-budget, or out-of-scope SDK path MUST return to
equivalent direct-parent work rather than blocking the operator or widening
authority.

## Rationale

Host-native automatic agent inference can bypass the deterministic MasterAgent
broker. A broker-owned SDK adapter permits isolated reasoning only when parent
identity, durable role budgets, context minimization, exact repository/scope
binding, technical tool restrictions, and report validation remain inside the
repository-owned control plane.

## Scenarios

### The Researcher is invoked safely

- GIVEN MasterAgent selects a bounded research task, opaque goal identity, and
  repository-relative route scope
- WHEN the broker invokes the live SDK adapter
- THEN exactly one Researcher session is preselected with only repository-owned
  scoped read/search tools and no ambient extension discovery
- AND the result remains untrusted until parent re-validation

### A specialist attempts to widen its scope

- GIVEN a specialist requests shell, edit, provider, MCP, or a path outside its
  bound route scope
- WHEN the SDK tool policy or repository-owned handler evaluates the request
- THEN the call MUST be denied before file access or another effect occurs

### An untracked file changes during delegation

- GIVEN a live advisory call is bound to an already-untracked file's content
- WHEN that file is edited before completion
- THEN the specialist result MUST be rejected and work MUST fall back to the
  parent

### A repository scan is incomplete

- GIVEN Git output or an untracked path/file exceeds a scan bound, cannot be
  read safely, or changes during hashing
- WHEN the adapter attempts to bind repository state
- THEN the SDK MUST NOT produce an accepted result
- AND work MUST fall back to the parent

### The optional SDK is unavailable

- GIVEN the base MasterAgent runtime is otherwise ready
- WHEN the Copilot SDK cannot be imported or started
- THEN the advisory call MUST return an explicit parent fallback
- AND ordinary MasterAgent operation MUST remain available

## Implementation

- `src/master_agent/advisory.py`
- `src/master_agent/advisory_budget.py`
- `src/master_agent/copilot_advisory.py`
- `scripts/advisory_subagent.py`
- `.github/agents/MasterAgent.agent.md`
- `.github/agents/MasterAgent-Read-Researcher.agent.md`
- `.github/agents/MasterAgent-Plan-Reviewer.agent.md`

## Verification

- `tests/test_advisory_integration.py`
- `tests/test_advisory_budget.py`
- `tests/test_advisory_runner.py`
- `tests/test_copilot_advisory.py`

## History

- Introduced by GitHub issue #90.
- Hardened for durable budgets, exact untracked state, and route scope by GitHub
  issue #115.
