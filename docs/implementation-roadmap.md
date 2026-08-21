# Implementation Roadmap and Completion Status

## Overall status

The v1 governed core, provider contracts, bounded advisory profiles, capability
capsule path, native behavioral specification lifecycle, and audience-aware
documentation completion gate are implemented. Release-hardening gates keep
incomplete local-Git mutation, non-manifest workflow execution, recurring
execution, destructive retention maintenance, raw plugin execution, and unsafe
provider mutations non-routable.

| Area | Software status | Operational status |
|---|---|---|
| 0 — environment and governance | Complete | Replace example governance and run readiness in the target organization |
| 1 — local governed runtime | Complete | Ready |
| 2A — Jira, Confluence, Bitbucket, GitHub, and SharePoint reads | Complete | Contract-tested; authenticated capabilities need approved credentials, while `github.public_repository.list` and `bitbucket.public_repository.list` operate anonymously |
| 2B — Outlook, Teams, identity, citations, and retention | Complete | Contract-tested; authenticated deployment requires approved applications and credentials |
| 2C — authentication and readiness | Complete | App registration, consent, Conditional Access, and token issuance are organization tasks |
| 3 — draft-only output | Complete | Usable locally without provider credentials |
| 4 — approved reversible writes | Typed persisted compensation complete; non-atomic recovery is manual; unsafe mutations and local Git remain disabled | Provider-specific gates and approvals required; opt-in Confluence Cloud sandbox automation is available |
| 5 — external communication | Complete | Disabled until exact-content approval and provider send gates are configured |
| 6 — recurring autonomy | Registration and status only | Execution disabled pending exact target, configuration, source, and runtime binding |
| Advisory sub-agents | Checked-in contracts, deterministic broker, and optional live Copilot SDK worker complete | Direct GitHub-host invocation is disabled; the selected parent may use the broker-owned read-only adapter and falls back to direct work when unavailable |
| Documentation completion gate | Complete | The selected parent applies the repository-owned Docs Agent contract directly; no live host child profile is implied |
| Capability promotion | Complete for dependency-free pure test/local capsules | Provider, side-effect, dependent, raw-plugin, and production capsules remain fail closed |
| Behavioral specifications | Complete | Native current/change/archive model, validation, archival, templates, CI integration, and self-hosted pilot shipped; current requirements grow organically |

## What “complete” means

“Complete” means the source release contains the typed contract, validation,
tests, and fail-closed behavior claimed for that area. It does not claim that a
particular organization has approved applications, connected credentials,
configured retention, or enabled provider effects.

Provider access remains inactive until the selected deployment supplies its
approved configuration. Anonymous public-data routes are the exception to the
credential requirement, not to governance, bounded retrieval, or independent
verification.

## Phase acceptance criteria

### Phase 0 — environment and governance

- capability owners and approval tiers are machine-readable;
- production configuration fails closed without explicit organization choices;
- secret-free readiness identifies missing variable names and permissions; and
- configuration-only readiness performs no network request.

### Phase 1 — governed runtime

- plans and actions are immutable and fingerprinted;
- approvals bind to the exact plan and action IDs;
- policy, governance, and canonical-source rules are independently enforced;
- idempotency records pending, completed, failed, and indeterminate outcomes;
- connector results are independently verified;
- reversible failures use typed compensation only where atomic preconditions
  can be enforced; and
- audit records form a tamper-evident chain.

### Phase 2 — read-only context

- all target systems expose typed, bounded read contracts;
- authentication class is selected by the capability, not a provider-wide
  default;
- anonymous public routes never resolve ambient credentials;
- retrieved content remains untrusted;
- normalized evidence, citations, and retention are implemented; and
- live provider probes are explicit rather than automatic.

### Phase 3 — draft-only output

- one local review package can contain Jira and Confluence proposals, Outlook
  and Teams drafts, PowerPoint, and a repository patch;
- the package includes an integrity manifest; and
- no external side effect occurs.

### Phase 4 — approved reversible writes

- write connectors are separate from read and draft connectors;
- every enabled modifying capability has an exact target and reviewed parameter
  contract;
- the provider operation uses an expected version or equivalent atomic
  precondition;
- approval, idempotency, readback verification, and compensation descriptors
  are enforced; and
- protected branches, force pushes, merges, broad deletion, invitations,
  arbitrary permissions, and non-atomic administration remain prohibited.

### Phase 5 — external communication

- exact recipients or destinations and exact content are inside the approved
  plan;
- Outlook provider drafts are re-read before send;
- Teams results are independently re-read;
- uncertain sends remain indeterminate rather than guessed successful; and
- correction is a new approved action because sends are non-reversible.

### Phase 6 — recurring workflow boundary

- built-in registrations and due state can be inspected;
- schedules are timezone-aware and have maximum lateness;
- capability, recipient, source, and delivery allowlists are explicit; and
- execution remains disabled until every target, source, configuration, and
  runtime identity is included in the immutable execution manifest.

### Advisory sub-agent boundary

- direct GitHub-host child invocation remains disabled; the generic host
  `agent` tool and automatic child-model invocation stay outside the reviewed
  path;
- the repository broker permits no more than three depth-one research tasks and
  one plan review for one operator goal, with private authenticated reservations
  shared by retries and independent or concurrent runner processes;
- an optional broker-owned Copilot SDK worker may execute one explicitly
  preselected read-only Researcher or Plan Reviewer session after payload
  sanitization;
- live specialist sessions disable ambient config, skill, and MCP discovery,
  expose only repository-owned read/search tools scoped to the required route,
  and bind results to the exact task, profile, path/file inventory, HEAD, index,
  tracked and staged changes, and bounded untracked file contents;
- same-process work for one goal may reuse one SDK client while every specialist
  call remains an isolated session;
- specialists cannot edit, approve, execute provider effects, or recursively
  delegate;
- all specialist output is untrusted advisory data and cited files are reread by
  the selected parent;
- the selected parent performs equivalent work directly when delegation is
  unavailable or rejected;
- the parent owns final target selection and typed plan construction; and
- the deterministic runtime remains the only connector, approval, and audit
  path.

### Documentation-completion boundary

- [`.ai/DOCS_AGENT.md`](../.ai/DOCS_AGENT.md) is the single authoritative
  specialist contract;
- `maintenance`, `authoring`, and `audit` modes classify reader goals, audience,
  document purpose, and lifecycle before editing;
- non-trivial repository changes receive a maintenance review after
  implementation and tests but before completion;
- mixed-audience documentation starts with plain language and progressively
  introduces the exact technical detail needed to act correctly;
- implementation, tests, requirements, decisions, configuration, and existing
  documentation are compared rather than treating code as automatic intent;
- `updated` and justified `no_change` results permit completion, while a material
  conflict returns `needs_review` to planning or implementation;
- current-state, historical, planned, and generated documentation keep distinct
  lifecycle rules; and
- the selected parent applies the contract directly without adding a misleading
  live GitHub-host child profile.

### Capability-promotion boundary

- lifecycle states and transitions are immutable and separately signed;
- source, artifact, dependency, SBOM, test, contract, worker, publisher, and
  reviewer identities are bound;
- Linux bubblewrap supplies no network, ambient credentials, or writable
  runtime mounts;
- process, CPU, memory, time, input, and output resources are bounded;
- activated capabilities enter the normal catalog, policy, session,
  orchestrator, verification, audit, and receipt path;
- dependency-free pure read/local-generation execution is demonstrated; and
- provider destinations, side effects, runtime dependencies, raw plugins, and
  production promotion remain blocked before connector construction.

### Behavioral-specification boundary

- accepted requirements live under `specs/current/` with stable IDs, normative
  behavior, scenarios, implementation references, and executable evidence;
- active changes have machine-readable metadata, proposal, requirement deltas,
  tasks, and design when required;
- validation detects malformed IDs, lifecycle errors, conflicts, missing
  references, unsafe paths, symlinks, and incomplete archival;
- archival transactionally applies deltas, validates the result, and preserves
  history;
- CI and source-distribution validation run `python scripts/specs.py validate`;
- the workflow is required for non-trivial behavioral changes and skipped for
  clearly non-behavioral edits;
- brownfield adoption is delta-first rather than a bulk conversion; and
- specifications remain development data and cannot alter runtime `ChangePlan`,
  approval, credentials, policy, connector execution, or audit.

## Remaining product and deployment work

### Source-code boundaries intentionally deferred

- descriptor-bound local and remote Git mutation;
- recurring execution under a complete immutable runtime manifest;
- destructive retention pruning;
- raw plugin execution with a sealed dependency filesystem;
- provider or side-effect capability capsules;
- production credential-broker and external receipt/audit adapters;
- provider operations that cannot enforce an atomic concurrency precondition;
  and
- any broad permission, merge, deletion, or arbitrary execution surface.

### Organization-specific deployment work

A target organization must still:

1. choose Cloud or Data Center endpoints;
2. register Microsoft Entra and/or Atlassian applications;
3. obtain administrator consent and assign least-privilege scopes;
4. satisfy Conditional Access and device or network requirements;
5. provision a secret manager and external tamper-resistant audit sink;
6. define data classification, retention, legal hold, and external-model policy;
7. replace sample identities, project keys, sites, repositories, recipients,
   and canonical resources;
8. validate read-only probes in non-production;
9. validate reversible writes using disposable resources; and
10. approve a narrow production rollout.

The runtime reports this distinction instead of representing contract tests or
a local demonstration as a successful company deployment.
