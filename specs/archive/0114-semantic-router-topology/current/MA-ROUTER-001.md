# MA-ROUTER-001 — Enforced semantic ownership and bounded agent topology

## Status

Active

## Requirement

MasterAgent MUST maintain one bounded machine-readable manifest that assigns
every production Python module, test module, current behavioral requirement,
configuration, CLI command, capability, connector module, checked-in agent
profile, and declared platform capability to exactly one semantic route. The
configuration inventory MUST cover every repository TOML surface outside the
specification lifecycle tree and ignored private, cache, or build roots,
including packaged defaults and top-level supply-chain metadata. Each route
MUST record lifecycle, authoritative policy or specification,
implementation, tests, release gates, search aliases, and its owning agent.
Validation MUST reject missing or duplicate ownership, stale or unsafe paths,
cross-owned route links without an exact declared dependency,
profile/topology drift, lifecycle contradictions, ambiguous routing fixtures,
and generated-router drift. Distinct Windows filesystem, atomic-state and
retention, credential, process-supervision, Git-isolation, capsule-isolation,
and certification routes MUST remain planned until their own verified changes
advance them. The generated compact router MUST be the first discovery hop
after minimum global authority policy. Specialists MUST receive only their
parent, scoped role, tool allowlist, input/output contract, and return path,
without sibling prompt awareness. A brokered specialist call MUST bind exactly
one validated parent-selected route before invoking a worker, and its readable
scope MUST exclude the global policy, full manifest or generated index, and all
parent or sibling profiles. The manifest and generated router MUST remain
navigation data and MUST NOT grant runtime authority. A commit- or explicit
two-dot range-only review request MUST first route to the semantic router,
which MUST derive a bounded, deterministic, read-only Git changed-path
inventory and return every affected exact semantic route plus any explicitly
unmapped path without requiring broad repository inspection.

## Rationale

Exact ownership turns repository navigation into a fail-closed maintenance
contract while keeping canonical behavior in policy, specifications, code, and
tests. Hub-and-spoke context minimizes prompt size and prevents unrelated
specialist roles from becoming implicit authority.

## Scenarios

### A new production module has no reviewed owner

- GIVEN a production Python module is added
- WHEN semantic-router validation runs before its exact path is assigned
- THEN validation fails and the generated router is not accepted

### Planned Windows behavior cannot appear released

- GIVEN a Windows platform route is declared planned
- WHEN its lifecycle is changed to released without the required implementation and certification state
- THEN validation fails closed

### A specialist receives bounded context

- GIVEN the parent selects a semantic route
- WHEN a bounded specialist is used
- THEN it receives its parent, scoped role, tools, input/output contract, and return path
- AND it does not require sibling prompt awareness or the complete policy corpus

### A specialist cannot widen its selected route

- GIVEN a brokered specialist call has one parent-selected route
- WHEN the route is absent, unknown, duplicated, or its path scope includes the global routing corpus
- THEN delegation fails before a worker is invoked

### A commit-only review starts from bounded evidence

- GIVEN an operator supplies only a commit identifier or `BASE..HEAD` range
- WHEN semantic routing starts
- THEN the request selects the semantic-router discovery path
- AND bounded read-only Git discovery returns the exact changed paths, affected
  semantic routes, and any unmapped paths

### A governed TOML file cannot evade ownership

- GIVEN a TOML configuration is added outside `config/` and outside `specs/`
- WHEN semantic-router validation runs
- THEN validation fails until the file has one exact configuration owner
- AND specification change, archive, and template metadata remain excluded

## Implementation

- `.ai/semantic-router.toml`
- `scripts/semantic_router.py`
- `docs/semantic-index.md`
- `AGENTS.md`
- `.ai/MASTER_AGENT.md`
- `.github/agents/MasterAgent.agent.md`
- `scripts/advisory_subagent.py`
- `src/master_agent/copilot_advisory.py`

## Verification

- `tests/test_semantic_router.py`
- `tests/test_advisory_runner.py`
- `tests/test_copilot_advisory.py`
- `scripts/validate_release.py`
- `.github/workflows/ci.yml`

## History

- Introduced by GitHub issue #114.
- Closed commit-routing and out-of-tree configuration inventory gaps during
  pull request #121 review.
