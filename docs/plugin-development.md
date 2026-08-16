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

The CLI does not activate raw connector entry points. Every attempted
`run --apply --plugin ...` fails before importing the entry module or invoking
its factory, including attempts with valid locks and exact-plan approvals.

Locking only the plugin distribution cannot authenticate transitive or
already-cached dependency code in the host interpreter. Production activation
therefore remains disabled until an isolated worker can verify and mount a
complete locked dependency closure and expose only the typed connector
protocol.

MasterAgent now has a separate capability-capsule worker. It demonstrates safe
promotion and normal governed execution for dependency-free pure
read/local-generation code. It is not an entry-point compatibility layer and
does not make a discovered distribution executable. A plugin may enter that
path only after its needed behavior has been converted into the strict capsule
contract, separately reviewed, signed, and promoted. Any provider access,
side effect, or third-party runtime dependency still fails before connector
construction. See [`capability-capsules.md`](capability-capsules.md).

## Required governance work

Before a provider or dependent plugin capability can run:

1. add it to `capabilities.toml` with the correct risk and authentication;
2. add an accountable governance rule;
3. add source-of-truth policy where relevant;
4. test approval, idempotency, verification, failure, and compensation behavior;
5. ensure it does not overlap an existing capability for the same system;
6. pin and review the plugin package and its complete dependency filesystem;
7. convert the exact typed surface into a capsule and complete every signed
   promotion state; and
8. satisfy production credential-broker, authenticated-approval, and external
   tamper-resistant receipt gates.

Discovery and binding remain useful review groundwork, but do not grant
execution authority. Do not describe a raw plugin, a dependent capsule, or a
provider/side-effect capsule as runnable through MasterAgent; only the narrow
pure capsule path documented above is demonstrated.
