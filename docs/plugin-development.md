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

Discovery is metadata-only:

```bash
master-agent plugins
```

Loading occurs only during apply and only for exact names:

```bash
master-agent run plan.json --apply --connector-mode live --plugin servicenow
```

## Required governance work

Before using a plugin capability:

1. add it to `capabilities.toml` with the correct risk and authentication;
2. add an accountable governance rule;
3. add source-of-truth policy where relevant;
4. test approval, idempotency, verification, failure, and compensation behavior;
5. ensure it does not overlap an existing capability for the same system;
6. pin and review the plugin package.

Plugins do not bypass Master Agent policy. Unknown names, invalid factories, overlapping capabilities, uncatalogued actions, or missing governance fail closed.
