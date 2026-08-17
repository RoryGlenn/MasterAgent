# MasterAgent Behavioral Specifications

This directory is the repository-owned record of MasterAgent's required
behavior and proposed behavioral changes. It is part of the development plane,
not a runtime authority or provider execution path.

For the architectural rationale and the distinction from agent instruction
files, see [Development Specifications](../docs/development-specifications.md).

## What each artifact owns

| Artifact | Responsibility |
|---|---|
| `AGENTS.md`, `.ai/`, `.github/agents/` | How coding agents must work |
| GitHub issues | Tracking, discussion, priority, and problem context |
| `specs/current/` | Maintained current behavioral requirements |
| `specs/changes/` | Active requirement deltas, design, and implementation tasks |
| `specs/archive/` | Completed, rejected, or superseded change history |
| `docs/` | Architecture, explanation, and operator/developer guidance |
| Tests | Executable evidence |
| Code and configuration | Implementation |
| Runtime `ChangePlan` | Exact provider effects and approval binding |

Agent instructions can require an agent to follow a process. They do not provide
a maintained, versioned statement of required behavior. Specifications fill
that gap with stable requirement IDs, explicit deltas, validated references,
and archival.

**Specifications govern changes to MasterAgent.**

**`ChangePlan` governs actions performed by MasterAgent.**

Specifications never grant capabilities, provide credentials, satisfy
approval, or override policy, governance, source-of-truth, verification,
compensation, retention, or audit controls.

## When a change specification is required

Create a change specification for non-trivial changes to observable,
architectural, or security-relevant behavior, including:

- capabilities and capability semantics;
- approval, policy, governance, and source-of-truth behavior;
- connectors and provider contracts;
- workflows and cross-component architecture;
- verification, compensation, idempotency, retention, and audit; and
- security boundaries or significant user-visible behavior.

Do not create one for formatting, typo fixes, comments, minor documentation
corrections, ordinary dependency metadata maintenance, mechanical refactors
with no behavior change, or normal MasterAgent runtime operations.

Use the workflow in intermediate cases when requirements or acceptance criteria
would otherwise live only in a conversation or issue body.

## Directory model

```text
specs/
├── current/                  # accepted current requirements
├── changes/<change-id>/      # active change
├── archive/<change-id>/      # terminal change history
└── templates/                # starting points
```

Each active change contains:

```text
change.toml
proposal.md
requirements.md
design.md        # required only when change.toml declares it
tasks.md
current/*.md     # final snapshots for add/modify deltas
```

`change.toml` is the machine-readable source for lifecycle state, issue
linkage, design requirements, and requirement deltas. The numeric change-ID
prefix must match the linked GitHub issue, for example
`0075-native-specification-lifecycle` for issue #75.

`requirements.md` describes the same behavioral delta for human review under
`ADDED`, `MODIFIED`, and `REMOVED` headings. Final current-requirement snapshots
for added or modified behavior live under the change's `current/` directory.

## Lifecycle

```text
draft → proposed → accepted → implementing → verifying → archived
```

Rejected and superseded changes remain in `specs/archive/` with explicit
terminal states.

For a non-trivial change:

1. Inspect relevant files in `specs/current/`.
2. Create or update `specs/changes/<change-id>/`.
3. Keep the proposal, requirement deltas, design, and tasks synchronized with
   implementation.
4. Add real executable evidence.
5. Run relevant tests, specification validation, and release validation.
6. Set the change to `verifying` only when every task and required evidence is
   complete.
7. Archive it with the repository tool.

Archival applies declared deltas to `specs/current/`, validates the resulting
tree, and then moves the change into `specs/archive/`. Historical snapshots
remain immutable, and the latest archived delta for each requirement must match
the maintained current requirement. A checked task or prose assertion is not
verification evidence.

## Commands

**Machine: development computer, from the repository root**

```bash
python scripts/specs.py validate
python scripts/specs.py status
python scripts/specs.py archive <change-id>
```

The tool uses bounded UTF-8 reads, deterministic ordering, repository-confined
path handling, and transactional archival. It rejects symlinks, traversal,
malformed or duplicate IDs, unsupported lifecycle states, missing files,
broken references, conflicting deltas, incomplete verification, and stale
archive/current snapshots.

It uses only the Python standard library and is not imported by the MasterAgent
runtime.

## Current requirement format

Each current file contains one stable requirement ID and these ordered
sections:

```text
# MA-DOMAIN-001 — Title
## Status
## Requirement
## Rationale
## Scenarios
## Implementation
## Verification
## History
```

Use normative `MUST`, `MUST NOT`, `SHOULD`, and `MAY` language where
appropriate. Implementation and verification references must point to existing
repository files.

## Relationship to OpenSpec

MasterAgent borrows useful specification-workflow concepts but does not add the
OpenSpec package, invoke its CLI, adopt its runtime formats, or promise
repository-format compatibility. The native layer exists only to bridge
GitHub issue intent and maintained current behavior.

It does not replace:

- repository agent instructions;
- GitHub issues;
- architecture or operator documentation;
- tests or release validation; or
- runtime `ChangePlan`, approval, execution, verification, compensation, and
  audit.

## Brownfield adoption

Do not bulk-convert historical behavior. The initial pilot is archived under
`specs/archive/0075-native-specification-lifecycle/`. Add or modify current
requirements as real behavioral work touches each area.

Existing documentation, configuration, tests, and implementation remain
evidence for areas not yet captured. Selective backfilling is appropriate only
when it supports an active change or resolves a concrete ambiguity.
