# Design

## Approach

Use `.ai/DOCS_AGENT.md` as the single authoritative specialist contract. The
selected MasterAgent parent reads and applies it as a completion gate after
implementation and tests. The contract defines operating modes, audience and
analogy rules, evidence precedence, document lifecycle handling, edit scope,
validation, and a structured result.

Keep the existing GitHub-host advisory boundary unchanged. No fourth host child
profile is added. If a future adapter can enforce MasterAgent's full delegation
controls, it may execute the same contract without changing its semantics.

## Affected components

- `.ai/DOCS_AGENT.md` owns the specialist behavior.
- `AGENTS.md`, `.ai/MASTER_AGENT.md`, and
  `.github/agents/MasterAgent.agent.md` require the completion gate.
- `docs/docs-agent.md` explains the workflow to non-technical and technical
  readers.
- `tests/test_docs_agent_contract.py` protects the required contract and parent
  integration markers.
- `specs/current/development/MA-DOCS-001.md`,
  `specs/current/development/MA-DOCS-002.md`, and
  `specs/current/development/MA-DOCS-003.md` record maintained behavior.

## Data flow

```text
Task, issue, and accepted requirements
                 ↓
Final changed files, diff, tests, and implementation evidence
                 ↓
Selected MasterAgent applies Docs Agent maintenance mode
                 ↓
Audience + purpose + lifecycle classification
                 ↓
Repository-wide impact search and authoritative-document review
                 ↓
Documentation edits or justified no-change
                 ↓
Validation and structured updated/no_change/needs_review result
```

No provider content, credential, approval artifact, or runtime `ChangePlan`
enters this development-only workflow as authority.

## Compatibility

The change adds Markdown contracts, documentation, tests, and specifications. It
does not change the Python runtime API, command-line interface, capability
catalog, provider contracts, or configuration format.

The source distribution already includes `.ai/`, documentation, tests, and
specifications through `MANIFEST.in`, so no packaging rule changes are needed.
Existing GitHub Copilot parent and advisory profile names, flags, and tool
surfaces remain unchanged.

## Security

Direct GitHub-host child invocation remains disabled. The selected parent uses
its existing repository edit surface and remains bound by `AGENTS.md` and
`.ai/MASTER_AGENT.md`.

The Docs Agent contract cannot authorize provider operations, resolve
credentials, select targets, satisfy approval, alter a `ChangePlan`, or create a
second execution path. It prohibits secret persistence, invented validation,
unrelated edits, and silent reconciliation of conflicting authoritative
sources.

## Rejected alternatives

- A live `.github/agents/MasterAgent-Docs.agent.md` profile was rejected because
  the repository cannot currently enforce a safe host dispatch path for it.
- A new Python subagent runtime was rejected because the requirement is a
  development completion contract, not an enterprise provider capability.
- CI-only automatic rewriting was rejected because generated documentation
  changes still require review and because the selected-parent workflow is
  simpler for the current repository.
- Copying the contract into several instruction files was rejected because it
  would recreate the documentation-drift problem inside the agent design.
