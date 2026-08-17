# MasterAgent Behavioral Specifications

This directory is the repository-owned record of MasterAgent's required
behavior and proposed behavioral changes. It is a development system, not a
runtime authority or provider execution path.

## Artifact responsibilities

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
| `ChangePlan` | Immutable runtime effects and approval binding |

Specifications never grant capabilities, provide credentials, satisfy
approval, or override policy, governance, source-of-truth, verification,
compensation, retention, or audit controls.

## When a change specification is required

Create a change specification for non-trivial changes to observable,
architectural, or security-relevant behavior, including capabilities,
approvals, policy, connectors, workflows, verification, compensation,
retention, audit, and cross-component contracts.

Do not create one for formatting, typo fixes, comments, mechanical refactors
with no behavior change, minor documentation corrections, ordinary dependency
metadata maintenance, or normal MasterAgent runtime operations.

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
design.md        # optional only when change.toml says so
tasks.md
current/*.md     # final snapshots for add/modify deltas
```

`change.toml` is the machine-readable source for lifecycle state, issue
linkage, and requirement deltas. The numeric change-ID prefix must match the
linked GitHub issue, for example `0075-short-description` for issue #75. `requirements.md` explains the same deltas for
human review under `ADDED`, `MODIFIED`, and `REMOVED` headings.

## Lifecycle

```text
draft -> proposed -> accepted -> implementing -> verifying -> archived
```

Rejected and superseded changes are retained in `specs/archive/` with their
explicit terminal state.

For a non-trivial change:

1. inspect relevant files in `specs/current/`;
2. create or update `specs/changes/<change-id>/`;
3. implement the smallest complete change;
4. add real verification evidence;
5. run relevant tests and release validation;
6. set the change to `verifying` with every task complete;
7. archive it with the repository tool.

Archival applies the declared requirement deltas, verifies the resulting tree,
and moves the change into `specs/archive/`. Historical snapshots remain
immutable; the latest archived delta for each requirement must match
`specs/current/`. A checkbox or prose assertion is not verification evidence.

## Commands

Run these on the development machine from the repository root:

```bash
python scripts/specs.py validate
python scripts/specs.py status
python scripts/specs.py archive <change-id>
```

The tool uses bounded UTF-8 reads, rejects symlinks and traversal, validates
references, detects duplicate and conflicting IDs, and keeps output
stable. It uses only the Python standard library and is not imported by the
MasterAgent runtime.

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

## Brownfield adoption

Do not bulk-convert historical behavior. The initial pilot is archived under
`specs/archive/0075-native-specification-lifecycle/`. Add or modify current
requirements as real behavioral work touches each area. Existing docs, tests,
configuration, and implementation remain evidence for areas not yet captured.
