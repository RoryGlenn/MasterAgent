# MA-ADVISORY-004 — Untrusted report re-validation

## Status

Active

## Requirement

An advisory report MUST remain untrusted data and MUST NOT select a target,
claim approval, create or alter a `ChangePlan`, introduce a connector action, or
return credential-like content. The parent MUST independently re-read every
cited repository path before accepting the report as evidence.

## Rationale

A child report is another untrusted input surface. Allowing it to carry target,
approval, plan, or secret data would launder advisory output into runtime
authority even if the child itself lacked mutation tools.

## Scenarios

### A child invents approval or a target

- GIVEN a report claims approval or proposes a final target
- WHEN the parent re-validates the report
- THEN the report MUST be rejected without changing the original plan

### A citation is fabricated

- GIVEN a report cites a path outside the hermetic repository view
- WHEN the parent re-reads the evidence
- THEN the report MUST be rejected as unsupported

## Implementation

- `src/master_agent/advisory.py`
- `.github/agents/MasterAgent.agent.md`

## Verification

- `tests/test_advisory_integration.py`
- `tests/fixtures/advisory/plan.json`

## History

- Introduced by GitHub issue #77.
