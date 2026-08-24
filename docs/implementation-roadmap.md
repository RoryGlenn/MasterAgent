# Implementation Roadmap and Completion Status

## Overall status

The v1 governed core, provider contracts, bounded advisory profiles, capability
capsule path, native behavioral specification lifecycle, and audience-aware
documentation completion gate are implemented. A common platform-runtime
contract now keeps imports and configuration diagnostics platform neutral. The
native Windows filesystem/ACL, locking, atomic local-state, credential,
process, trusted Git, and AppContainer pure-capsule tranche is implemented.
Three-version hosted Windows CI, an exhaustive skip-intolerant adversarial
registry, and the protected x64 workflow are implemented. Organization-managed
configuration trust and hosted-safe ACL/support-principal policy evidence are
implemented. The final certification tranche stays operationally planned on
#106 until real Defender/CFA, AppLocker/WDAC, organization ACL, and support/EDR
fixtures run on a clean enrolled standard-user Windows 11 x64 runner; #112
retains the authenticated-proxy and enterprise-CA blockers.
Release-hardening gates keep
incomplete local-Git mutation, non-manifest workflow execution, raw plugin execution, and
unsafe provider mutations non-routable.

| Area | Software status | Operational status |
|---|---|---|
| Progressive user workflow | Complete | Install a reviewed organization profile; local installation, selected reads, governed effects, and enterprise deployment report independent readiness |
| Platform runtime | Common contract, native Windows backends, three-version hosted CI, and protected x64 certification workflow complete; existing POSIX behavior preserved | Windows supports trusted reads, protected persistence, bounded processes, local Git inspection, and dependency-free pure capsules; provider/side-effect capsules remain gated, and live x64 certification requires an enrolled clean standard-user runner |
| 0 — environment and governance | Complete | Replace example governance and run readiness in the target organization |
| 1 — local governed runtime | Complete | Ready |
| 2A — Jira, Confluence, Bitbucket, GitHub, and SharePoint reads | Complete | Contract-tested; authenticated capabilities need approved credentials, while `github.public_repository.list` and `bitbucket.public_repository.list` operate anonymously |
| 2B — Outlook, Teams, identity, citations, and retention | Complete on POSIX and native Windows | Contract-tested; authenticated deployment requires approved applications and credentials |
| 2C — authentication and readiness | Complete | App registration, consent, Conditional Access, and token issuance are organization tasks |
| Provider-data model-context boundary | Complete | Replace development destination/tenancy/classification rules and supply any required external audit or DLP adapters |
| Protected credentialed integration evidence | Repository workflow and static contract complete | Configure least-privilege credentials, tenant consent, stable fixtures, dedicated communication targets, and run the approved manual matrix |
| 3 — draft-only output | Complete | Usable locally without provider credentials |
| 4 — approved reversible writes | Typed persisted compensation complete; non-atomic recovery is manual; unsafe mutations and local Git remain disabled | Provider-specific gates and approvals required; opt-in Confluence Cloud sandbox automation is available |
| 5 — external communication | Complete | Disabled until exact-content approval and provider send gates are configured |
| 6 — recurring autonomy | Exact authenticated occurrence, single-host fencing, approval resume/recovery, and local-only reference workflow complete | Registrations remain disabled until an organization supplies private roots, exact resources, credentials, and scheduler operations |
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

The protected integration workflow is implementation, not provider evidence by
itself. Its repository gates, environment separation, preflight, and recovery
contract can be complete while the live matrix remains operationally incomplete
because credentials, consent, fixtures, targets, or enablement variables are
absent.

## Phase acceptance criteria

### Phase 0 — environment and governance

- capability owners and approval tiers are machine-readable;
- production configuration fails closed without explicit organization choices;
- secret-free readiness identifies missing variable names and permissions; and
- configuration-only readiness performs no network request.

### Platform-runtime boundary

- platform-neutral package and CLI imports do not initialize operating-system-
  specific backends;
- readiness exposes stable `platform`, `backend`, and per-contract availability
  for secure filesystem, cross-process locking, atomic publication/recovery,
  process supervision, trusted Git, and capsule isolation;
- help, version, deployment readiness, install-level progressive doctor, and
  trusted bounded file reads use the partial native Windows runtime;
- a dependent operation fails with a bounded `runtime_defect` before protected
  state, credentials, connector construction, provider access, or effects when
  its exact backend is unavailable;
- no compatibility shim or weaker cross-platform fallback can satisfy a secure
  contract; and
- existing POSIX filesystem, locking, atomic-state, process, and Git semantics
  remain covered; Linux capsule isolation identifies a selected trusted
  bubblewrap executable or reports that independent contract unavailable, as
  does macOS; Windows filesystem, locking, atomic state, credential storage,
  Job Object process supervision, trusted Git, and zero-capability AppContainer
  pure-capsule isolation have native standard-user evidence; the hosted matrix
  and protected x64 workflow are implemented, while the certification route
  stays planned until a clean enrolled runner produces its own evidence.

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
- normalized evidence, citations, and retention are implemented;
- expired retained-evidence pairs can be previewed and explicitly deleted on
  POSIX through one bounded descriptor plan, locked rescan, and recoverable
  pair transaction, or on Windows through retained handles, exact identities,
  a tree lock, and a content-free recovery intent;
- live provider probes are explicit rather than automatic;
- every direct, applied, probe, and repository-shortcut provider read is
  classified and authorized before access, rebound before return, exact-schema
  sanitized, item/byte bounded, and content-free in audit; and
- the complete credentialed provider matrix is manual-only, default-branch
  bound, privilege-separated, statically checked, and never counts a skip or
  missing external setup as provider evidence.

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

- strict canonical artifacts authenticate through separately trusted local
  state; a self-contained digest is insufficient;
- pre-secret validation precedes atomic reservation and credential/principal
  attestation;
- every effect rechecks the current occurrence generation/token immediately
  before dispatch and uses occurrence-scoped idempotency;
- approval waits are lease-free and resume only the same occurrence;
- DST/tzdata, latest-only catch-up, disable/revoke, deadlines, and explicit
  recovery are deterministic; and
- local claims are documented as single-host, while indeterminate provider
  outcomes remain blocked.

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
- live x64 managed-workstation certification evidence from an enrolled clean
  standard-user runner;
- raw plugin execution with a sealed dependency filesystem;
- provider or side-effect capability capsules;
- additional organization secret-manager, receipt, and external audit adapters;
- provider operations that cannot enforce an atomic concurrency precondition;
  and
- any broad permission, merge, deletion, or arbitrary execution surface.

### Organization-specific deployment work

### Tier-1 workflow certification (#169-#172)

The first prioritized employee workflow is the proposed `T1-EWIR-001`
Engineering Work Item Review in [the Tier-1 workflow plan](tier-1-engineering-work-item-review-plan.md).
It is a read-only Jira, Bitbucket, and Confluence workflow that produces a
private cited local package through native connectors. The plan and its
provisional p50/p95 objectives take priority over increasing raw capability
count; #164 instrumentation, #170 implementation identity, #94 protected
fixtures, and #172 managed-workstation runs provide the evidence before any
workflow is presented as certified.

A target organization must still:

1. choose Cloud or Data Center endpoints;
2. register Microsoft Entra and/or Atlassian applications;
3. obtain administrator consent and assign least-privilege scopes;
4. satisfy Conditional Access and device or network requirements;
5. provision a secret manager and external tamper-resistant audit sink;
6. define provider-data classifications, model destination and tenancy,
   source-data environment, audited-route and DLP requirements, retention,
   legal hold, and external-model policy;
7. replace sample identities, project keys, sites, repositories, recipients,
   and canonical resources;
8. configure the three protected integration environments with independent
   read, effect, and administration credentials, stable fixtures, dedicated
   communication targets, reviewer rules, and exact default-branch restrictions;
9. validate read-only probes in non-production;
10. run the approved manual credentialed matrix and reconcile any indeterminate
    provider operation;
11. validate reversible writes using disposable resources; and
12. approve a narrow production rollout.

The runtime reports this distinction instead of representing contract tests or
a local demonstration as a successful company deployment.

The CLI cannot cryptographically attest its surrounding model tenancy, and the
shipped runtime has no centralized DLP adapter. Those remain reviewed deployment
assertions and organization-provided adapter work, not guarantees implied by the
completed software boundary.
