# MA-DOCS-002 — Documentation matches the intended audience

## Status

Active

## Requirement

The Docs Agent MUST classify each affected document as serving a non-technical
user, mixed audience, developer, maintainer, or decision-maker and MUST write
for the least technical member of that intended audience without removing
necessary precision.

For mixed audiences, documentation MUST begin with a plain-language explanation
and progressively introduce the technical detail needed to act correctly. An
analogy MAY be used only when it materially improves understanding, MUST be
followed by the literal technical explanation, and MUST NOT replace exact
syntax, schemas, configuration, constraints, or failure behavior.

## Rationale

Documentation should be understandable without becoming technically vague.
Audience classification prevents both engineer-only prose for ordinary users
and oversimplified reference material for developers and maintainers.

## Scenarios

### A mixed audience needs to understand a component

- GIVEN a document serves both non-technical readers and developers
- WHEN the Docs Agent updates the explanation
- THEN it provides a plain-language mental model first
- AND follows it with the exact technical behavior needed by developers

### An analogy would hide important detail

- GIVEN a command or configuration contract requires exact syntax
- WHEN the Docs Agent writes the reference material
- THEN it omits the analogy
- AND preserves the literal syntax, constraints, and expected behavior

## Implementation

- `.ai/DOCS_AGENT.md`
- `docs/docs-agent.md`

## Verification

- `tests/test_docs_agent_contract.py`

## History

- Introduced by GitHub issue #87.
