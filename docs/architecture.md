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
- optional description.

A connector may not expose an uncatalogued capability in the standard runtime. High-impact merge is represented but disabled, making prohibition explicit rather than relying on an absent endpoint.

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
- merge, deletion, permission changes, and protected-branch operations are denied.

### Source-of-truth registry

Canonical resources are validated before execution. A projection cannot be updated without an authorized canonical change in the same plan when the registry says the field is outbound-only.

### Connector registry

Connectors register a system name and explicit capability set. Multiple connectors may serve one system only when their capability sets do not overlap. This allows, for example, live Outlook reads and local Outlook draft generation to coexist safely.

Plugin connectors are discovered without import and loaded only by exact name during an apply. They enter the same registry and cannot bypass overlap, catalog, governance, policy, approval, or audit checks.

### Orchestrator

The orchestrator:

1. validates capability and source-of-truth rules;
2. evaluates approvals;
3. resolves dependencies;
4. checks idempotency for side effects;
5. executes one typed connector capability;
6. invokes independent verification;
7. records action state;
8. compensates previously verified reversible actions when `compensate_on_failure` is enabled.

There is no claim of an atomic transaction across external systems. Partial results are explicit.

### Audit

The SQLite audit log is tamper-evident through a hash chain. Default audit summaries exclude document/message bodies and secret values. Full evidence is written only through an explicit output/retention path.

### Retention and citations

Normalized resources receive stable citation IDs. Retained evidence receives a sidecar with creation time, expiration, evidence type, digest, persistence mode, and citations. Cleanup is constrained to sibling evidence files beneath the selected root.

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

The current built-in recurring workflows generate local weekly-status or communication-context packages. They do not send messages or publish changes.

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
