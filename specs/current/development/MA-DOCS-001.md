# MA-DOCS-001 — Documentation review is a completion gate

## Status

Active

## Requirement

For every non-trivial repository change, MasterAgent MUST apply the authoritative
Docs Agent contract to the final implementation and test evidence before it
declares the task complete. The result MUST be `updated`, `no_change`, or
`needs_review`; a `needs_review` result MUST return to the relevant planning or
implementation path.

While direct GitHub-host child invocation is disabled, the selected MasterAgent
parent MUST complete the same documentation review directly rather than
creating or implying an unsupported host delegation path.

## Rationale

Documentation drifts when its review depends on the operator remembering an
extra prompt. A required completion gate makes documentation maintenance part of
the normal development workflow while preserving MasterAgent's existing
fail-closed subagent boundary.

## Scenarios

### A feature changes reader-visible behavior

- GIVEN implementation and tests for a non-trivial change are complete
- WHEN MasterAgent prepares to declare the repository task complete
- THEN it applies Docs Agent maintenance mode to the final change
- AND it proceeds only after an `updated` or justified `no_change` result

### Direct child invocation is unavailable

- GIVEN the GitHub host cannot enforce MasterAgent's subagent safety controls
- WHEN the documentation completion gate runs
- THEN the selected MasterAgent parent performs the review directly
- AND no additional live host child profile is required or implied

## Implementation

- `.ai/DOCS_AGENT.md`
- `AGENTS.md`
- `.ai/MASTER_AGENT.md`
- `.github/agents/MasterAgent.agent.md`
- `docs/advisory-subagents.md`

## Verification

- `tests/test_docs_agent_contract.py`
- `scripts/validate_release.py`

## History

- Introduced by GitHub issue #87.
