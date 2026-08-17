# MA-DOCS-003 — Documentation changes preserve evidence and lifecycle boundaries

## Status

Active

## Requirement

Before editing documentation, the Docs Agent MUST compare the strongest
available issue, acceptance criteria, current specifications, architecture
decisions, tests, implementation, configuration, and existing documentation.
It MUST NOT silently document an apparent defect as intended behavior.

The Docs Agent MUST distinguish current-state, historical, planned, and
generated documentation; preserve one authoritative source where practical;
allow a justified `no_change` result; and report material conflicts as
`needs_review` with the relevant evidence. Its default writable scope MUST
remain limited to documentation surfaces unless the task explicitly authorizes
more.

## Rationale

Blindly matching prose to code can legitimize bugs, rewrite history, present
future work as shipped, or create duplicate sources of truth. Explicit evidence,
lifecycle, scope, and result rules make the maintenance pass predictable and
reviewable.

## Scenarios

### Implementation conflicts with accepted behavior

- GIVEN a requirement and test specify one behavior
- AND the implementation exhibits a materially different behavior
- WHEN the Docs Agent performs maintenance
- THEN it does not rewrite the documentation to legitimize the implementation
- AND returns `needs_review` with the conflicting evidence

### No reader-facing knowledge changed

- GIVEN a completed change does not alter what readers need to know or do
- WHEN relevant documentation is reviewed
- THEN the Docs Agent returns `no_change`
- AND records which plausible documents were reviewed and why they remain valid

### Generated output is stale

- GIVEN documentation is derived from an authoritative schema or generator
- WHEN the derived output needs to change
- THEN the Docs Agent updates or identifies the authoritative source
- AND does not deceptively hand-edit the generated output

## Implementation

- `.ai/DOCS_AGENT.md`
- `docs/docs-agent.md`

## Verification

- `tests/test_docs_agent_contract.py`

## History

- Introduced by GitHub issue #87.
