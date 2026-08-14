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

A reversible connector additionally implements `compensate` and `verify_compensation`.

## Activation

Discovery is metadata-only. Persist the inventory as an operator-controlled
lock after reviewing the distribution name, version, entry point, and artifact
digest:

```bash
master-agent plugins --output /trusted/config/connector-plugins.json
```

Bind the selected plugin and live integrations identity into the plan before a
human approves its new fingerprint:

```bash
master-agent bind-context plan.json \
  --integrations /trusted/config/integrations.toml \
  --plugin servicenow \
  --plugin-lock /trusted/config/connector-plugins.json \
  --output bound-plan.json
```

Loading occurs only during live apply, only for exact names in the approved
plan, and only when the current installed artifact still matches the lock:

```bash
master-agent run bound-plan.json \
  --apply \
  --connector-mode live \
  --integrations /trusted/config/integrations.toml \
  --plugin servicenow \
  --plugin-lock /trusted/config/connector-plugins.json
```

The loader imports from a private snapshot of the locked distribution and
removes ambient working-directory import paths. Editable plugin installs and
entry modules not owned by the locked distribution fail closed.

## Required governance work

Before using a plugin capability:

1. add it to `capabilities.toml` with the correct risk and authentication;
2. add an accountable governance rule;
3. add source-of-truth policy where relevant;
4. test approval, idempotency, verification, failure, and compensation behavior;
5. ensure it does not overlap an existing capability for the same system;
6. pin and review the plugin package.

Plugins do not bypass Master Agent policy. Unknown names, invalid factories, overlapping capabilities, uncatalogued actions, or missing governance fail closed.
