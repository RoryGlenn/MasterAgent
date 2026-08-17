# Proposal

## Problem

MasterAgent's documentation can drift because maintenance depends on the
operator remembering to request an additional documentation pass after each
implementation. A generic “update docs” prompt also leaves audience, evidence,
document lifecycle, scope, and completion behavior underspecified.

The repository deliberately disables direct GitHub-host child-agent invocation.
Adding an apparently active Docs Agent profile would conflict with the exact
reviewed profile inventory and imply a delegation path whose parent, depth,
tool, context, and call-budget controls cannot currently be enforced.

## Desired outcome

Define one authoritative Docs Agent contract, make its maintenance review part
of MasterAgent's definition of done, and have the selected parent apply the
contract directly until a governed adapter can safely delegate it.

The contract should produce documentation that non-technical readers can
understand while preserving the exact detail developers and maintainers need.
It should use analogies only when helpful, detect conflicts rather than document
bugs as intent, respect historical/planned/generated documents, allow a real
`no_change` result, and return a predictable structured status.

## Scope

- add the authoritative `.ai/DOCS_AGENT.md` contract;
- add a plain-language guide at `docs/docs-agent.md`;
- update `AGENTS.md`, `.ai/MASTER_AGENT.md`, and
  `.github/agents/MasterAgent.agent.md` with the documentation completion gate;
- add drift tests in `tests/test_docs_agent_contract.py`;
- add maintained current requirements and this archived issue package; and
- preserve the existing fail-closed advisory profile inventory and provider
  execution boundary.

## Rationale

A narrow repository-owned contract provides most of the value of automated
living documentation without introducing a separate service or complex
workflow. Making it a completion gate removes the memory burden from the
operator. Keeping execution on the selected parent avoids pretending that a
safe host subagent adapter already exists.

Audience classification and progressive disclosure are more accurate than a
universal “write for non-technical people” rule. Conditional analogies improve
mental models without weakening command, schema, API, or configuration
precision.

## Alternatives considered

- Relying on the operator to type “update docs” was rejected because it remains
  easy to forget and does not define quality or conflict behavior.
- Adding a fourth `.github/agents/` profile was rejected because the repository
  intentionally pins an exact safe inventory and has no approved host adapter
  for documentation edits.
- Building a full documentation automation pipeline was rejected as unnecessary
  setup for the current repository and team size.
- Treating every document as non-technical was rejected because API, command,
  architecture, and maintainer references require exact technical language.

## Non-goals

- activating a new GitHub-host child-agent path;
- changing runtime capabilities, provider connectors, approval, or `ChangePlan`
  behavior;
- automatically publishing repository documentation to external systems;
- reproducing copyrighted book text; or
- requiring documentation churn when a reviewed change has no documentation
  impact.

## Risks

- The selected parent performs the specialist work directly until a governed
  adapter exists, so execution is logically specialized rather than a separate
  model process.
- A long contract can become ineffective if its core rules are not pinned;
  focused tests therefore protect the required markers and parent integration.
- Overuse of analogies could reduce precision; the contract prohibits them in
  exact reference surfaces and requires the literal explanation afterward.
- A strict conflict result can temporarily block completion, but that is safer
  than converting an apparent implementation defect into documented policy.
