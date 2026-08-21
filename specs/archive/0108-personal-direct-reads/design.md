# Design

## Approach

`run --direct-read` branches before the manifest-bound applied execution path.
It creates a private in-memory execution context for the selected provider,
attests the connector identity and effective scopes, and delegates the action
to a dedicated direct-read session executor. The executor accepts only
one-provider `ReadOnlyConnector` actions, retains a shared HTTP budget across
retrieval and verification, and returns the verified report directly to
standard output. It owns no durable audit, artifact, result, or approval state.

The existing applied path remains unchanged. It still owns mutable effects,
runtime path identities, durable audit/idempotency, approvals, and result
publication.

Core package dependencies contain only command/runtime needs. Local draft and
office-rendering dependencies move to an explicit optional extra; bootstrap
reports successful local installation independently from optional provider
configuration readiness.

## Affected components

- `src/master_agent/cli.py`
- `src/master_agent/direct_read.py`
- `pyproject.toml`
- `supply-chain/runtime-dependencies.toml`
- `scripts/bootstrap_agent.py`
- focused CLI, direct-read, bootstrap, package, and release tests
- current user and maintainer documentation

## Data flow

The user explicitly chooses `--direct-read`. The CLI parses the plan,
validates that it qualifies, resolves credentials only for its one selected
provider, captures an in-memory connector execution identity, builds the
typed live read connector, and executes/re-reads each action under one bounded
transport budget. The result is rendered to stdout only. No user-controlled
output path, runtime directory, or provider-effect connector is opened.

## Compatibility

Existing `run`, `bind-context`, approval handoff, and `connect` behavior remain
available. Existing plans can use the new direct mode only when they already
satisfy its narrower read-only contract. The package retains an explicit draft
extra for users who need local Office-style artifacts.

## Security

The direct route is a distinct execution type rather than a bypass in catalog
or policy validation. It cannot construct a write/send connector, load a raw
plugin, inherit an approval binding, write a result, or expand to another
provider. It binds attested provider identity/scopes in memory and preserves
the connector's same-origin, bounded-response, and independent verification
controls.

## Rejected alternatives

Reusing the applied execution path with temporary filesystem roots would still
make reads depend on local state backends and would blur read/effect guarantees.
Treating an installed plugin package as safe to import would let unreviewed
code run in the parent process. A generic HTTP escape hatch would lose typed
provider constraints.
