# Architecture

## Design objective

Master Agent is a governed workflow runtime, not one omnipotent model process. The planning layer proposes typed work. Deterministic code decides whether that work is permitted, executes only registered capabilities, verifies the resulting state, and records evidence.

## Runtime flow

```text
Authenticated user
                 │
                 ▼
     user-selected MasterAgent profile
                 │
                 ▼
 direct parent handling / repository-owned advisory harness
                 │ fail closed; no direct GitHub-host child invocation
                 ▼
       parent or registered workflow
                 │
                 ▼
          Planner / plan loader
                 │
                 ▼
       immutable ChangePlan@2.0
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
Capability catalog   Source-of-truth registry
       │                   │
       └─────────┬─────────┘
                 ▼
       Organization governance
                 │
                 ▼
            Policy engine
        ┌────────┼─────────┐
        ▼        ▼         ▼
     permit   approval   prohibit
        │      required
        └────────┬─────────┘
                 ▼
 Workflow orchestrator / direct-read or probe route
                 │
  dependency order / provider-data preflight
                 │
                 ▼
      capability-specific registry
                 │
   ┌─────────────┼────────────────────┐
   ▼             ▼                    ▼
read connector  draft connector  mutation/send connector
   │             │                    │
   ▼             └──────────┬─────────┘
independent verification    │
   │                        │
egress revalidation         │
and sanitization            │
   └─────────────┬──────────┘
                 ▼
       return / compensation / audit
```

Direct GitHub-host advisory invocation is disabled because that surface cannot
prove the selected-parent allowlist, depth-one routing, or per-goal counters.
The repository-owned harness is the deterministic integration-test boundary
and the control plane for the optional current Copilot SDK adapter; it is not a
second runtime or provider path. The parent continues directly whenever that
adapter is absent or cannot satisfy the full boundary.
See [`advisory-subagents.md`](advisory-subagents.md).

### Progressive user front door

The user-facing `setup`, `doctor`, and `execute` commands form a thin adapter
over the same runtime shown above. A strict organization profile supplies
reviewed configuration paths, one employee/developer mode, a private state
root, and an exact installed-capability allowlist. The profile is bound input,
not authority: the catalog, connector registry, governance, policy,
source-of-truth, credential, approval, verification, compensation, retention,
and audit boundaries remain independently decisive.

```text
setup ──> private profile + minimum local state (no provider access)
                 │
doctor ──────────┼──> install / read / draft / effect / enterprise readiness
                 │
execute PLAN ────┴──> stateless direct read
                      or bound inspect/apply/approval/resume
```

Risk determines state and interaction. Eligible single-provider direct reads
remain in memory. Draft/local and effect work use fresh descriptor-safe private
run directories. Approval-required effects emit one exact request whose resume
surface includes the original organization-profile binding. High-impact work
retains its existing mandatory controls and disabled-at-rest posture. The
low-level commands remain available and reach the same implementations.

Employee mode cannot turn a capability gap into executable code. Trusted
developer mode may expose explicit scaffolding in the development plane, but
generated effect code remains untrusted and quarantined until its independent
review, tests, specification archival, signing, deployment, and standard
runtime admission finish. Neither mode can self-approve or self-promote code.

### Platform runtime boundary

Platform-neutral package and CLI modules depend on a descriptive platform
registry instead of importing Unix-only primitives at startup. The registry
normalizes the host to one stable backend identity and reports six independent
contracts:

- `secure_filesystem`;
- `cross_process_locking`;
- `atomic_publication_recovery`;
- `process_supervision`;
- `trusted_git`; and
- `capsule_isolation`.

`platform_runtime_status()` is inspection only. It returns `platform`,
`backend`, and a `capabilities` map whose entries contain `available`,
`backend`, and an optional bounded, secret-free `reason`. Help, version, and
configuration-only readiness can consume that status without initializing a
stateful backend.

Linux and macOS use the top-level `posix-linux` and `posix-macos` identities.
Both select `posix-descriptor-filesystem`, `posix-flock`,
`posix-atomic-publication`, `posix-rlimit`, and `posix-trusted-git`. Linux
selects `linux-bubblewrap` for executable capsule isolation only when a trusted
executable is available and otherwise reports that contract unavailable. macOS
reports
`capsule_isolation` unavailable because owner/group artifact trust is a secure-
filesystem property, not OS worker containment, and no native macOS isolation
backend is certified. Native Windows selects `windows-native-partial` with
`windows-handle-acl-filesystem` and `windows-lockfileex`; atomic publication,
process supervision, trusted Git, and capsule isolation retain bounded
unavailable entries. A non-Windows host that explicitly inspects Windows uses
`windows-unavailable` without importing Win32 code. An unrecognized host uses
`unsupported`.

An operation selects its exact contract immediately before use. Selection
returns only the certified native implementation or raises the typed platform-
unavailable error; it never substitutes a compatibility shim, another platform,
or a weaker implementation. That failure occurs before protected state,
credentials, connector construction, provider access, or effects. Existing
POSIX implementations retain their established ownership, no-follow, locking,
atomicity, process, and Git behavior. Linux reports bubblewrap capsule
isolation only after selecting a trusted executable and otherwise fails closed;
macOS capsule execution also fails closed instead of treating account-private
artifact checks as executable isolation.

Windows therefore has a deliberately split status. Package import, command
help/version, deployment readiness, and install diagnosis are supported.
Protected read paths use a chain of retained non-delete-share Win32 handles,
fixed-volume file identity, owner SID and effective-DACL policy, and bounded
handle reads. Component and handle-path comparisons use Windows ordinal
uppercase-table semantics, preserving distinct non-linguistic Unicode names
instead of applying full case folding. Retained immutable ancestors may grant
unrelated child creation,
as normal Windows system roots do, but delete-child, metadata, generic-write,
ACL, owner, and replacement authority remain forbidden; selected targets keep
the stricter writer/private policy. Approval bindings serialize the exact
versioned Windows identity and policy digest and compare them again at
execution. The filesystem backend can also publish a new private file only
with an explicit protected DACL, bounded write/flush and readback, namespace
revalidation, and exact-created-identity cleanup; it cannot replace an existing
name or satisfy crash recovery. A stateful capability
remains unavailable when atomic publication or another required contract
reports unavailable, and
its readiness issue is `runtime_defect`. The common platform and native
Windows-filesystem routes are released; the other six Windows implementation
and hosted-certification routes remain planned.

## Repository discovery topology

Repository development uses a separate hub-and-spoke discovery map before any
broad source search:

```text
User -> MasterAgent
          -> Read Researcher (optional, read/search only)
          -> Plan Reviewer (optional, read/search only)
          -> Docs contract (applied directly by the parent)
          -> deterministic governed runtime
```

The exact ownership and topology data lives in
[`semantic-router.toml`](../.ai/semantic-router.toml). The compact
[`semantic index`](semantic-index.md) is generated from that manifest and is
navigation data, never authority. After loading the minimum repository policy,
the parent selects one route and loads only its linked policy, specification,
implementation, and verification slice. Exact inventory validation prevents a
new module, test, requirement, command, capability, connector, configuration,
profile, or platform area from silently inheriting an owner.
Configuration discovery covers every repository TOML file except specification
lifecycle metadata and ignored private, cache, or build roots, so packaged
defaults, top-level package metadata, and supply-chain inputs cannot sit outside
the exact ownership table.
Implementation, test, and current-requirement links must agree with that exact
owner. A route that intentionally references another route's shared
configuration, authority, or release gate declares that owner as an exact
dependency, so an unrelated but valid path cannot silently replace it.

Generation opens the destination directory through no-follow descriptors,
writes a private same-directory temporary file, and atomically replaces the
index only after a complete synchronized write. A symbolic-link, non-regular,
or raced destination cannot redirect generated content outside the repository.

A commit-only review phrase selects the semantic-router route. The `changes`
subcommand then resolves one commit or explicit `BASE..HEAD` range through a
time- and output-bounded, read-only Git query and returns its exact changed
paths, every affected route contract, and any unmapped path. This gives the
parent a deterministic first hop without a broad preliminary repository scan.

Each specialist receives only its parent, scoped role, tool allowlist,
input/output contract, return path, and selected repository route. Specialists
do not load sibling prompts or require peer-to-peer awareness. The parent alone
knows the complete topology and independently revalidates specialist output.
The common platform-runtime and Windows-filesystem routes are released, while
the other six Windows routes remain `planned`; a generated index cannot present
those native backends or hosted certification as released until their own
implementation changes advance the manifest under validation.

## Principal components

### Advisory sub-agents

The selected `MasterAgent.agent.md` profile omits the `agent` tool. Both child
profiles are non-user- and non-model-invocable and contain only `read` and
`search`. This fail-closed host configuration prevents unsupported direct or
nested child invocation.

`src/master_agent/advisory.py` loads those exact profiles for a deterministic
repository-owned boundary. A session is bound to the selected parent, depth is
fixed at one, and `src/master_agent/advisory_budget.py` atomically admits at
most three research attempts and one plan review for an authenticated goal
across independent processes. The broker rejects credential, approval, signing,
target, recipient, connector, tenant, private-context, and `ChangePlan` fields
before a worker is invoked.

The optional SDK worker binds the exact task, immutable profile, normalized
path/file inventory, HEAD, raw index entries, descriptor-read tracked bytes,
and bounded untracked file contents. The runner rehashes every commit, tree, and
prompt-bearing blob used for its manifest or profile inventory and disables Git
content conversion, replacement refs, lazy fetch, and transports. It exposes
only repository-owned route-scoped read/search tools; SDK
filesystem built-ins and ambient config, skill, and MCP discovery remain
disabled. Each specialist call has an isolated session. One client may be
reused for same-process calls in one goal and is closed at the goal boundary.
Reports remain untrusted,
cannot carry targets, approvals, plans, connectors, or secret-like content, and
become evidence only after the parent independently re-reads every citation.

If an adapter is missing or fails, the broker returns an explicit parent fallback. The deterministic policy, approval, credential, connector,
verification, compensation, retention, and audit runtime remains the only
provider-effect path.

### Domain models

`ResourceRef`, `AgentAction`, `ChangePlan`, `Approval`, `ExecutionResult`, and
`VerificationResult` are immutable dataclasses. Plans have stable SHA-256
fingerprints. The plan loader rejects an oversized file before JSON parsing,
then applies iterative depth, fan-out, node, string, action, dependency, and
aggregate parameter budgets before recursive model construction. Dependencies
are validated for missing references and cycles.

### Capability catalog

`config/capabilities.toml` defines the public execution surface. Each dotted capability declares:

- enabled state;
- authentication class;
- risk tier;
- reversibility;
- exact target system and allowed resource types;
- a top-level parameter schema for every enabled side effect;
- explicit input and output byte quotas for every local-generation capability;
- an exact versioned result schema, content-bearing resource descriptors, and
  fixed envelope metadata for every read-only capability;
- required effective OAuth scopes, expected-version requirements, and the
  provider precondition that makes a modifying write atomic;
- whether the capability uses an external model;
- optional description.

A connector may not expose an uncatalogued capability in the standard runtime.
The orchestrator rechecks the resolved connector's approval-bound principal,
authentication mode, granted scopes, and compensation interface before any
effect. High-impact merge is represented but disabled, making prohibition
explicit rather than relying on an absent endpoint.

### Capability capsule promotion

Generated capability source remains quarantined data. A capsule packages its
typed contract, immutable source/artifact identity, dependency lock, CycloneDX
SBOM, licenses/notices, tests, verification and compensation contracts,
destinations, credential requirements, resource limits, and provenance. Six
separate roles sign the ordered lifecycle from quarantine through validation,
review, publication, and enablement; deprecation and revocation append new
terminal states.

A foreign custom-agent capability enters through an earlier descriptive gate.
The versioned self-contained export is captured as immutable bytes and parsed
without loading or running its embedded source. Inspection classifies
references, compatible pure capsules, catalog conflicts, unsupported surfaces,
and unsafe authority or executable requirements. Selecting one compatible
ability requires its exact previewed source digest and derives a capsule policy
identity that binds that digest and the declared publisher. The result is only
an installed signed quarantine; it does not create a catalog definition or
routing card.

The current worker admits only dependency-free pure read/local-generation
capsules. It executes their AST-restricted program in Linux bubblewrap with no
network, no ambient environment, read-only runtime mounts, an ephemeral work
directory, and process/CPU/memory/time/input/output quotas. Complete signed
manifest and artifact verification occurs before a connector is constructed.
Provider destinations, credentials, or declared effects cause activation to
fail closed because a production provider-capsule adapter is not bundled.

An enabled capsule contributes one normal `CapabilityDefinition` and one typed
connector. Its version, all security-relevant digests, publisher/reviewer,
principal/account, classification/retention, destinations, scopes, and quotas
are stored in `ExecutionContext`, and therefore in the plan and approval
fingerprint. Policy filters compact capability cards before advisory intent
matching. A time/call/byte-bounded active session then admits only those exact
selected identities. See
[`capability-capsules.md`](capability-capsules.md).

### Organization governance

`organization-profile.toml` is the user-workflow selector: it points at the
reviewed configuration set and narrows the installed capabilities exposed to
that employee or trusted developer. It does not replace the governance file or
make a listed capability permissible.

`config/governance.toml` maps capability patterns to:

- accountable owner;
- authentication expectation;
- allowed data classifications;
- allowed environments;
- approval tier;
- enabled state.

The most specific matching rule wins. Uncovered capabilities fail closed. Dual approval requires two distinct approvers.

The same governance file owns `[model_context]`, which selects the active
provider-data destination and model tenancy and matches classification-aware
handling rules independently of whether a capability itself invokes a model.

### Policy engine

`config/policy.toml` provides hard runtime rules:

- read/local generation may be automatic;
- reversible writes, external communication, and high impact require approval;
- destructive actions are prohibited;
- retrieved content cannot authorize writes;
- merge, deletion, generic permission changes, invitations, protected-branch
  operations, and GitHub administration without provider compare-and-swap are
  denied.

### Provider-data model-context boundary

`provider_egress.py` owns the cross-cutting return boundary for direct reads,
applied reads, provider probes, and repository-list shortcuts. A no-I/O
preflight selects one unambiguous rule and validates fields, collection limit,
route, audit, and DLP availability before principal attestation or connector
content access. The immutable binding then incorporates connector
configuration/origin/account digests, action and request fingerprints, the
exact requested projection or catalog result contract, size limits,
classification, destination, tenancy, and handling. Attestation and content
access reuse one captured credential snapshot; the exact endpoint, origin, and
CA identity are checked before provider access and again before return.

After independent connector verification, the runtime recomputes that binding
and returns only a private schema-projected, recursively redacted, reference-
minimized, byte-limited copy. One separator-insensitive identity covers nested
reserved, secret, configured-redaction, reference, and prompt-finding keys.
Applied audit records contain binding facts,
digests, counts, and outcomes only. An ephemeral route creates no provider-data
state.

### Source-of-truth registry

Canonical resources are validated before execution. Identity includes the
exact system, resource type, resource ID, governed field, and reviewed
parameter selector. A governed projection,
including a matching local-generation target, cannot be updated without an
authorized canonical change in the same plan when the registry says the field
is outbound-only. Each allowed capability has a reviewed scalar parameter
selector; the registry hashes the actual immutable canonical and projection
values and requires an exact match through the dependency graph. Caller-supplied binding
digests do not grant authority, and missing capability verifiers fail during
configuration loading. Composite outputs without a typed field-addressed schema
are denied for exact governed targets.

### Connector registry

Connectors register a system name and explicit capability set. Multiple connectors may serve one system only when their capability sets do not overlap. This allows, for example, live Outlook reads and local Outlook draft generation to coexist safely.

Authentication is selected by the typed capability contract, not by a blanket
provider default. The runtime uses the least-authorized registered route that
can return the requested data. A capability classified for anonymous public
access constructs an authentication-free connector and does not consult
credential resolution, even when an ambient provider credential exists.
Authenticated routes are reserved for private, account-visible, or otherwise
identity-bound data.

Raw plugin connectors are discovered, locked, and bound to plans without import.
Before hashing, the complete bounded distribution inventory must pass strict
relative-path validation. Every artifact is then opened without following
links beneath one descriptor-pinned, owner-checked distribution root; type,
owner, identity, per-file size, and aggregate size are verified. They are not
loaded during apply. The capsule worker does not change that raw entry-point
boundary: it accepts only a separately reviewed, dependency-free pure capsule.
A plugin with dependencies still needs a sealed complete dependency filesystem
before it can become executable.

### Ephemeral direct read sessions

`run --direct-read` is a separate execution type for a direct-user plan made of
read-only actions against exactly one built-in typed provider. It performs the
same catalog, governance, policy, source-of-truth, credential, connector
identity/scope, endpoint, response-budget, prompt-injection, and independent
re-read validation required for typed reads. It additionally authorizes an
ephemeral provider-data binding before access, recomputes it after verification,
and returns only the exact-schema sanitized copy plus content-free metadata. It
holds its binding and report in memory and does not construct the applied
runtime's audit, idempotency, artifact, approval, result-publication, plugin, or
capsule state.

The direct executor validates the whole plan before provider setup, uses a
`ReadOnlyConnector` only, and shares one HTTP budget across each read and its
verification. It rejects workflow or persisted execution context, multiple
providers, effects, non-direct authority, and approval-required actions. This
keeps the convenient path structurally unable to become an effect bypass; the
orchestrator below remains the only execution owner for provider effects.

### Orchestrator

The orchestrator:

1. validates capability and source-of-truth rules;
2. evaluates approvals;
3. resolves dependencies;
4. preauthorizes provider-read egress on the audited route before dispatch;
5. atomically claims side effects by action fingerprint and records explicit
   pending, completed, failed, or indeterminate outcomes;
6. executes one typed connector capability;
7. immediately records `side_effect_may_have_occurred` with content-free result
   metadata before invoking verification;
8. preserves the exact returned result and records an `indeterminate` incident
   if verification fails or raises;
9. for a verified read, recomputes its binding, sanitizes the private result,
   and records only content-free egress metadata;
10. records the final action state;
11. compensates reversible actions in reverse order only when the typed
   descriptor permits automatic execution and the adapter can enforce an
   atomic post-state precondition.

There is no claim of an atomic transaction across external systems. Partial results are explicit.

A certified pre-effect failure is durable but can be atomically claimed by a
later explicit retry. An indeterminate effect remains blocked. It can become a
reused completion only when a connector stored bounded content-free provider
metadata and independently re-reads the exact provider resource successfully;
otherwise operator reconciliation is required.

`ExecutionResult.compensation` is a `CompensationDescriptor`, not an arbitrary
mapping. Its persisted form is `master-agent/compensation@1`; unversioned
legacy rollback metadata is rejected. Mode `plan` supports reconstruction as a
new approval-bound plan, `in_process` is limited to the originating verified
connector flow, and `manual` prevents the orchestrator from invoking rollback.

When policy returns `approval_required`, the CLI publishes a mode-`0600`,
create-only request inside the already pinned artifact root. The request copies
the exact pending action manifests and captures the complete non-secret run
selection. It is not an authorization input. `approve-request` checks the
request fingerprint, referenced plan, and bound authority digest before
issuing the existing authenticated exact-plan approval; `resume-approval`
replays the captured arguments through the normal execution-context gates.
This closes the usability gap without letting chat text, an edited request, or
the agent create authority.

All other CLI JSON output uses that same restricted publication boundary:
pin and validate the preexisting parent, create the final name exclusively as
mode `0600` without following symlinks, verify its descriptor identity, write
and read back the exact serialized bytes, and fsync the file and directory.
Publication never creates a security-boundary directory or replaces an
existing name.

Structured artifacts preserve reviewed raw content only inside those explicit
restricted outputs. Terminal diagnostics use a separate centralized renderer:
ordinary Unicode remains readable, while terminal controls and bidirectional
formatting controls become visible `\uXXXX` text and each dynamic field has a
hard rendered-length ceiling. A retrieved excerpt therefore cannot erase or
reorder its diagnostic prefix.

Local draft connectors share one bounded artifact budget for the complete run.
They check each capability's declared bundle quota and the shared budget before
creating any final name. Artifact readback and later verification hash bounded
chunks instead of retaining a second whole-artifact buffer.

### Audit

The SQLite audit log is tamper-evident through a hash chain. Provider-read audit
events contain egress bindings, fingerprints, digests, counts, and outcomes but
exclude provider bodies, query values, raw account identities, injection
excerpts, and secrets. Other full evidence is written only through an explicit
output/retention path.

Capsule runs add an atomic content-free checkpoint state machine and a signed
terminal receipt. Resume requires the exact plan and capsule-binding digest;
normal action idempotency controls decide whether connector work may continue.
Receipts bind policy/approval identity, capsule digests, action/readback and
compensation digests, and the audit-chain anchor. Production requires an
external healthy tamper-resistant receipt sink; local SQLite cannot satisfy
that gate.

### Retention and citations

Normalized resources receive stable citation IDs. Metadata-only persistence is
projected through fixed nested schemas, with opaque identifiers and provider
messages represented by stable digests/reason codes. Prohibited retention
matches override every allow rule. Retained evidence and its sidecar are
fsynced through mode-`0600` same-directory staging files and create-only
published manifest-first. Descriptor-relative repair can move orphaned
identities into a private same-filesystem quarantine.

Expiration preview and explicit POSIX deletion share one deterministic,
bounded descriptor-relative validation plan beneath a pinned root. The runtime
first exposes and exclusively holds the exact selected-parent retention lock
for publication. It then shared-locks every existing retention boundary in the
owner-controlled pinned ancestor chain. Maintenance uses the same handshake:
an exclusive selected-root lock, shared existing ancestor retention locks, and
every discovered evidence-parent lock. Thus it still holds the root retention
lock plus every discovered evidence-parent lock. A parent operation either owns
an ancestor lock before a child starts or discovers the child's already-visible
leaf lock during its bounded scan. It rescans the exact descriptor tree and
rejects identity, mode, link, manifest, digest, sibling, size, limit, or
concurrency drift before starting new deletion. Each expired evidence/sidecar
pair is hard-linked into a private, bounded, same-filesystem, content-free transaction before either public name
is removed. The common source parent is fsynced with both public names absent
before recovery links are discarded, allowing a later apply to complete or
roll back interrupted staging without losing deletion durability. Pending
transactions beneath a nested retention root make an ancestor scan fail closed
until the exact child root is recovered. Native Windows retention preview,
apply, and orphan repair remain unavailable until equivalent filesystem and
atomic-state contracts exist.

Descriptor-relative orphan repair participates in the same selected-root,
ancestor, and descendant-parent lock handshake. It repeats the bounded scan
while those locks are held before classification or quarantine, so ancestor
repair cannot move a manifest from an active child-first publication.

### Recurring runner

Recurring workflows are immutable registrations with:

- a built-in workflow kind;
- timezone-aware schedule;
- maximum lateness;
- delivery mode;
- capability allowlist;
- recipient allowlist;
- canonical-source allowlist;
- persistent occurrence state;
- a per-workflow lock.

Built-in recurring definitions can be inspected for due state, but execution is
disabled. Weekly-status and communication-context plans can be generated for
review; their legacy direct execution/package commands are not routable until
they share the immutable manifest and descriptor-pinned runtime boundary.

## Trust boundary

Authority order, highest to lowest:

1. platform security policy;
2. organization governance;
3. master-agent constitution;
4. registered workflow definition;
5. direct authenticated user instruction;
6. retrieved internal content;
7. retrieved external content.

Lower-trust content cannot grant permissions, introduce credentials, change recipients, add capabilities, alter approvals, or redefine canonical sources.

## Process boundaries

For a production deployment, separate these operational identities where possible:

- read-only connector identity;
- reversible-write identity;
- communication identity;
- scheduler identity;
- audit sink writer;
- capsule promotion authorities and isolated worker identity;
- production credential broker and external receipt sink;
- human approvers.

Do not give the planning model raw provider credentials. The deterministic runtime resolves secret references immediately before constructing an approved connector.
