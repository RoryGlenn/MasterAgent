# Connector Plugin Development

## Entry point

A plugin package exposes one entry point in the `master_agent.connectors` group:

```toml
[project.entry-points."master_agent.connectors"]
servicenow = "my_master_agent_plugin:build_connectors"
```

The factory receives no automatic credentials from Master Agent. It must return one connector or an iterable of connectors implementing the connector contract.

## Connector contract

A connector provides:

- `system`;
- explicit `capabilities`;
- `execute(action)`;
- `read(resource)` where meaningful;
- `verify(action, result)`.

A reversible connector additionally implements `compensate` and
`verify_compensation`, returns a typed `CompensationDescriptor` from every
effect, and selects `manual` mode unless rollback has an adapter-enforced
atomic precondition.

## Inventory and approval binding

Discovery is metadata-only. Persist the inventory as an operator-controlled
lock after reviewing the distribution name, version, entry point, and artifact
digest:

```bash
master-agent plugins --output /trusted/config/connector-plugins.json
```

The installed distribution inventory is untrusted input. Discovery validates
the complete list before locating or opening any artifact, accepts only unique
normalized relative POSIX paths, and rejects absolute, dot, parent-relative,
backslash, symlink-parent, hardlink, and non-regular entries. It pins one
current-user- or root-owned distribution root, opens every component relative
to descriptors without following links, and requires each directory and file
to have the root's owner, a stable identity, and no world-write permission. One
distribution is limited to 4,096 files, 32 MiB per file, and 128 MiB total. Any
invalid or changing entry aborts the inventory; it is never silently omitted
from the lock or snapshot.

Bind the selected plugin and live integrations identity into the plan before a
human approves its new fingerprint:

```bash
master-agent bind-context plan.json \
  --integrations /trusted/config/integrations.toml \
  --plugin servicenow \
  --plugin-lock /trusted/config/connector-plugins.json \
  --output bound-plan.json
```

The CLI does not currently activate connector plugins. Every attempted
`run --apply --plugin ...` fails before importing the entry module or invoking
its factory, including attempts with valid locks and exact-plan approvals.

Locking only the plugin distribution cannot authenticate transitive or
already-cached dependency code in the host interpreter. Production activation
therefore remains disabled until an isolated worker can verify a complete
locked dependency closure and expose only the typed connector protocol.

## Required governance work

Before a future isolated worker can use a plugin capability:

1. add it to `capabilities.toml` with the correct risk and authentication;
2. add an accountable governance rule;
3. add source-of-truth policy where relevant;
4. test approval, idempotency, verification, failure, and compensation behavior;
5. ensure it does not overlap an existing capability for the same system;
6. pin and review the plugin package.

Discovery and binding remain useful review groundwork, but do not grant
execution authority. Do not describe a plugin as runnable through Master Agent
until the isolated worker boundary is implemented and validated.
