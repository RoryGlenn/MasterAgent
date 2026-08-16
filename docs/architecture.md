# Architecture

## Design objective

Master Agent is a governed workflow runtime, not one omnipotent model process. The planning layer proposes typed work. Deterministic code decides whether that work is permitted, executes only registered capabilities, verifies the resulting state, and records evidence.

## Runtime flow

```text
Authenticated user or registered workflow
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
       Workflow orchestrator
                 │
    dependency order / idempotency
                 │
                 ▼
      capability-specific registry
                 │
   ┌─────────────┼────────────────────┐
   ▼             ▼                    ▼
read connector  draft connector  mutation/send connector
   │             │                    │
   └─────────────┼────────────────────┘
                 ▼
       independent verification
                 │
       ┌─────────┴──────────┐
       ▼                    ▼
 compensation          audit/evidence
```

## Principal components

### Domain models

`ResourceRef`, `AgentAction`, `ChangePlan`, `Approval`, `ExecutionResult`, and `VerificationResult` are immutable dataclasses. Plans have stable SHA-256 fingerprints. Dependencies are validated for missing references and cycles.

### Capability catalog

`config/capabilities.toml` defines the public execution surface. Each dotted capability declares:

- enabled state;
- authentication class;
- risk tier;
- reversibility;
- exact target system and allowed resource types;
- a top-level parameter schema for every enabled side effect;
- required effective OAuth scopes, expected-version requirements, and the
  provider precondition that makes a modifying write atomic;
- whether the capability uses an external model;
- optional description.

A connector may not expose an uncatalogued capability in the standard runtime.
The orchestrator rechecks the resolved connector's approval-bound principal,
authentication mode, granted scopes, and compensation interface before any
effect. High-impact merge is represented but disabled, making prohibition
explicit rather than relying on an absent endpoint.

### Organization governance

`config/governance.toml` maps capability patterns to:

- accountable owner;
- authentication expectation;
- allowed data classifications;
- allowed environments;
- approval tier;
- enabled state.

The most specific matching rule wins. Uncovered capabilities fail closed. Dual approval requires two distinct approvers.

### Policy engine

`config/policy.toml` provides hard runtime rules:

- read/local generation may be automatic;
- reversible writes, external communication, and high impact require approval;
- destructive actions are prohibited;
- retrieved content cannot authorize writes;
- merge, deletion, generic permission changes, invitations, protected-branch
  operations, and GitHub administration without provider compare-and-swap are
  denied.

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

Plugin connectors are discovered, locked, and bound to plans without import.
They are not loaded during apply: the CLI fails closed until a separate worker
can seal the plugin and transitive dependency closure before execution.

### Orchestrator

The orchestrator:

1. validates capability and source-of-truth rules;
2. evaluates approvals;
3. resolves dependencies;
4. atomically claims side effects by action fingerprint and records explicit
   pending, completed, failed, or indeterminate outcomes;
5. executes one typed connector capability;
6. immediately records `side_effect_may_have_occurred` with content-free result
   metadata before invoking verification;
7. preserves the exact returned result and records an `indeterminate` incident
   if verification fails or raises;
8. records the final action state;
9. compensates reversible actions in reverse order only when the typed
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

### Audit

The SQLite audit log is tamper-evident through a hash chain. Default audit summaries exclude document/message bodies and secret values. Full evidence is written only through an explicit output/retention path.

### Retention and citations

Normalized resources receive stable citation IDs. Metadata-only persistence is
projected through fixed nested schemas, with opaque identifiers and provider
messages represented by stable digests/reason codes. Prohibited retention
matches override every allow rule. Retained evidence and its sidecar are
fsynced through mode-`0600` same-directory staging files and create-only
published manifest-first. Descriptor-relative repair can move orphaned
identities into a private same-filesystem quarantine; expiry deletion remains
preview-only.

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
- human approvers.

Do not give the planning model raw provider credentials. The deterministic runtime resolves secret references immediately before constructing an approved connector.
