# Design

## Approach

Introduce `master_agent.advisory` as a deterministic development and integration
boundary. It parses the exact checked-in profile frontmatter with bounded reads,
validates the profile inventory and invocation flags, sanitizes delegated
payloads, enforces one parent-bound session budget, dispatches only read/search
to a hermetic repository view, and validates untrusted reports before accepting
cited evidence.

The parent and both child profiles block direct model invocation; the parent
also omits `agent`. A future host adapter may implement the worker protocol only
if it preserves the same envelope and dispatcher boundary. Without such an
adapter, the broker returns an explicit parent fallback.

## Affected components

- GitHub Copilot parent and advisory profiles;
- `src/master_agent/advisory.py`;
- integration and mutation tests plus adversarial fixtures;
- agent, architecture, threat-model, release, and semantic-index guidance;
- release validation and source-distribution contents;
- current behavioral specifications.

## Data flow

```text
selected MasterAgent parent
        -> parent-bound advisory session
        -> payload sanitizer
        -> profile-derived read/search dispatcher
        -> optional approved worker adapter
        -> untrusted advisory report
        -> independent citation re-read
        -> parent decision
```

Every unsupported invocation, sensitive payload, budget overflow, nested call,
worker failure, forbidden tool, or invalid report returns to the parent path
without touching the runtime or protected effect recorders.

## Compatibility

Normal MasterAgent planning and provider operations are unchanged. The visible
behavioral change is that Copilot-host advisory delegation is disabled rather
than exposed with an unenforceable generic command tool. The parent already has
the ability and obligation to complete the same work directly.

## Security

- exact profile inventory, names, tools, and invocation flags;
- no generic execute, edit, agent, MCP, HTTP, provider, credential, approval,
  environment, audit, or mutation dispatcher;
- bounded profile, payload, fixture, search, citation, and report sizes;
- normalized repository paths and immutable sanitized payloads;
- deterministic depth and call counters;
- pre-dispatch rejection of secrets and authority-bearing fields;
- report rejection for target, approval, plan, secret, or missing citation;
- protected-state snapshots proving no filesystem, environment, network,
  provider, credential, approval, or audit effects in adversarial tests.

## Rejected alternatives

- Prompt-only restrictions cannot technically constrain a generic tool.
- A broad MCP server would recreate the same confused-deputy surface.
- A live canary without a deterministic adapter would observe model behavior,
  not prove the authorization boundary.
