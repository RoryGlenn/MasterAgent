# Development Specifications

MasterAgent uses a repository-native behavioral specification system to keep
required behavior explicit while preserving the existing runtime authorization
model. It borrows useful ideas from specification-driven development—current
requirements, proposed deltas, designs, tasks, and archival—but does not depend
on OpenSpec or another external specification runtime.

## Why agent instructions are not enough

Agent instructions and behavioral specifications solve different problems.

| Artifact | Question it answers | What it does not do |
|---|---|---|
| `AGENTS.md`, `.ai/`, `.github/agents/` | How should a coding agent behave while working? | Maintain a versioned statement of product behavior |
| GitHub issue | What problem are we discussing and why is it important? | Become the durable, normalized behavioral contract |
| `specs/current/` | What behavior is currently required? | Authorize a runtime action |
| `specs/changes/` | What requirement delta is being proposed or implemented? | Replace implementation or executable evidence |
| `docs/` | How does the system work and how should it be operated? | Define every stable normative requirement |
| Tests | Does executable behavior satisfy the contract? | Explain the complete intent or rationale |
| Code and configuration | How is the behavior implemented? | Explain why the behavior must remain stable |
| Runtime `ChangePlan` | Which exact provider effects are authorized for this run? | Govern repository development |

A prompt or agent file can instruct an agent to “write a proposal, update tests,
and document the result.” That is useful process guidance, but it does not by
itself provide:

- a maintained set of current requirements;
- stable requirement identifiers;
- explicit added, modified, and removed behavior;
- a bounded lifecycle with terminal states;
- machine-checked links between requirements, implementation, and evidence; or
- archival that updates current requirements without losing change history.

The native specification layer supplies those missing repository artifacts. It
does not replace the instructions that tell agents how to use them.

## Two independent planes

### Development plane

```text
Feature, defect, or architecture concern
                  ↓
              GitHub issue
                  ↓
       behavioral change specification
       proposal + deltas + design + tasks
                  ↓
         implementation + executable tests
                  ↓
      specification and release validation
                  ↓
                archive
                  ↓
       maintained current requirements
```

The development plane governs changes **to MasterAgent**.

### Runtime plane

```text
User or registered workflow request
                  ↓
                planner
                  ↓
       immutable typed ChangePlan
                  ↓
 capability + governance + policy checks
                  ↓
 authenticated exact-plan approval
                  ↓
        deterministic connector execution
                  ↓
 verification + compensation + audit
```

The runtime plane governs actions performed **by MasterAgent**.

No development specification is read as runtime authority, added to an approval
fingerprint, treated as a credential, or used to bypass the typed connector
path. Normal provider operations do not require a development change
specification.

## Why the repository owns the format

MasterAgent already has purpose-built systems for:

- agent behavior and safety rules;
- GitHub issue tracking;
- immutable runtime plans;
- capability and governance configuration;
- authenticated approval;
- deterministic verification and compensation;
- release validation and adversarial tests; and
- architecture, threat-model, operator, and developer documentation.

Adding OpenSpec as a dependency would introduce another general workflow and
format where the repository only needed a narrow bridge between issue intent
and maintained current behavior. MasterAgent therefore owns the schema,
lifecycle, validation, and compatibility decisions.

OpenSpec can remain a design reference. MasterAgent does not invoke its CLI,
depend on its package, promise compatibility with its repository format, or use
it as a runtime planner or authorization layer.

## Repository model

```text
specs/
├── README.md
├── current/                  # accepted current requirements
├── changes/<change-id>/      # active change records
├── archive/<change-id>/      # archived, rejected, or superseded history
└── templates/                # bounded starting points
```

A normal active change contains:

```text
change.toml
proposal.md
requirements.md
design.md        # required when change.toml declares it
tasks.md
current/*.md     # final snapshots for added or modified requirements
```

`change.toml` is the machine-readable source for the change ID, GitHub issue,
status, design requirement, and requirement deltas. The Markdown files provide
the human review surface.

Current requirements use stable IDs and a fixed structure:

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

The requirement section uses normative `MUST`, `MUST NOT`, `SHOULD`, and `MAY`
language where appropriate. Implementation and verification references must
resolve to existing repository files.

## Lifecycle

```text
draft → proposed → accepted → implementing → verifying → archived
```

A rejected or superseded change remains in the archive with an explicit
terminal state.

For a non-trivial behavioral change:

1. Read the relevant files in `specs/current/`.
2. Create or update the linked directory under `specs/changes/`.
3. Keep the proposal, requirement deltas, design, and tasks synchronized with
   the implementation.
4. Add or update executable evidence.
5. Run the relevant tests, specification validation, and release validation.
6. Move the change to `verifying` only when implementation and evidence are
   complete.
7. Archive it through the repository tool.

Archival applies declared deltas to `specs/current/`, verifies the resulting
tree, and then moves the change into `specs/archive/`. Checked tasks or prose
assertions are not evidence by themselves.

## Commands

**Machine: development computer, from the repository root**

```bash
python scripts/specs.py validate
python scripts/specs.py status
python scripts/specs.py archive <change-id>
```

The standard-library tool performs bounded UTF-8 reads, deterministic ordering,
path and symlink checks, ID and lifecycle validation, reference checks, conflict
detection, transactional delta application, and rollback on failed archival.

## When the workflow is required

Use a change specification for non-trivial changes to:

- observable user or operator behavior;
- capabilities or capability semantics;
- approval, policy, governance, or source-of-truth behavior;
- connectors and provider contracts;
- workflows and cross-component architecture;
- verification, compensation, idempotency, retention, or audit behavior; and
- security boundaries.

Skip the full workflow for clearly non-behavioral changes such as formatting,
typo fixes, comments, minor documentation corrections, ordinary dependency
metadata maintenance, and mechanical refactors with no observable effect.

Use the workflow in intermediate cases when the acceptance criteria or intended
behavior would otherwise exist only in a conversation or issue body.

## Brownfield adoption

MasterAgent does not attempt to rewrite all historical behavior into
specifications. The repository started with one self-hosted pilot and grows the
current requirement set organically as real changes touch each area.

Existing code, configuration, documentation, and tests remain evidence for
behavior not yet represented in `specs/current/`. Selective backfilling is
appropriate only when it supports an active change or resolves a concrete
ambiguity.

## Authority and security boundary

Specifications are repository development data. They must never:

- grant or enable a capability;
- authorize a provider effect;
- provide or select credentials;
- satisfy authenticated approval;
- modify a runtime `ChangePlan`;
- override governance, policy, source-of-truth, verification, compensation,
  retention, or audit;
- introduce arbitrary shell or HTTP execution; or
- create a second execution path around the governed runtime.

Retrieved content copied into a proposed specification remains untrusted until
reviewed as repository development work.

See the authoritative [specification workflow](../specs/README.md), the
[current requirements](../specs/current/), and the
[architecture](architecture.md).
