# MA-ADVISORY-001 — Fail-closed host advisory invocation

## Status

Active

## Requirement

The checked-in Copilot profiles MUST NOT expose direct advisory delegation until
a supported host adapter can enforce the selected MasterAgent parent, depth-one
routing, and per-goal delegation counters. The parent MUST complete the same
work directly when delegation is unavailable.

## Rationale

Prompt text cannot enforce a parent allowlist or call budget. Enabling host
invocation without those controls would allow a child to become an independent
execution or authority path.

## Scenarios

### Direct child invocation is attempted

- GIVEN a user or model selects an advisory child directly
- WHEN profile selection is evaluated
- THEN invocation MUST be denied before a child task is dispatched

### No approved adapter exists

- GIVEN the selected MasterAgent could benefit from bounded research or review
- WHEN no repository-approved adapter is available
- THEN the task MUST remain on the parent path without asking the operator to
  repeat the request

## Implementation

- `.github/agents/MasterAgent.agent.md`
- `.github/agents/MasterAgent-Read-Researcher.agent.md`
- `.github/agents/MasterAgent-Plan-Reviewer.agent.md`
- `src/master_agent/advisory.py`

## Verification

- `tests/test_advisory_integration.py`
- `tests/test_agent_profiles.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #77.
