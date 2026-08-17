# MA-ADVISORY-002 — Profile-derived read and search dispatch

## Status

Active

## Requirement

The repository-owned advisory dispatcher MUST derive each child tool surface
from the checked-in profile and MUST admit only bounded repository `read` and
`search`. Generic execute, edit, agent, MCP, HTTP, environment, credential,
provider, approval, audit, and mutation tools MUST be denied before dispatch.

## Rationale

The previous researcher profile exposed generic command execution while relying
on prose to constrain it. A prompt injection could therefore have reached the
shell, credentials, or provider network despite the stated read-only intent.

## Scenarios

### Bounded repository research succeeds

- GIVEN the researcher profile contains only `read` and `search`
- WHEN a sanitized task searches a hermetic repository fixture
- THEN cited evidence MAY be returned without changing protected state

### Untrusted content requests an effect

- GIVEN repository or provider content requests shell, network, credential,
  approval, provider, or nested-agent access
- WHEN the child attempts the corresponding tool
- THEN the dispatcher MUST deny the request before any recorder or external
  state changes

## Implementation

- `src/master_agent/advisory.py`
- `.github/agents/MasterAgent-Read-Researcher.agent.md`
- `.github/agents/MasterAgent-Plan-Reviewer.agent.md`

## Verification

- `tests/test_advisory_integration.py`
- `tests/fixtures/advisory/repository_prompt_injection.txt`
- `tests/fixtures/advisory/provider_prompt_injection.txt`

## History

- Introduced by GitHub issue #77.
