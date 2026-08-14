# Phase 2C — Authentication and Deployment Readiness

## Delivered

- disabled-by-default OAuth profiles;
- Microsoft Entra delegated device-code and client-credentials provider implementations;
- operator-supplied existing token support;
- restricted token-file writing;
- token expiry/scope/claim inspection;
- capability-governance coverage reports;
- connector configuration diagnostics that expose variable names, not values;
- explicit read-only live probes.

## Safe readiness

```bash
master-agent readiness --output .master-agent/readiness.json
```

Readiness performs no network calls. A safe unconnected installation may be `ready=true` with a warning that no live connectors are enabled, because the configuration and governance are internally valid but not activated.

## Device code

```bash
master-agent oauth-device-code \
  --profile microsoft_delegated \
  --token-file .master-agent/tokens/microsoft.json
```

Only an enabled `entra_device_code` profile can run. The operator completes the provider's interactive authentication. The runtime writes the access token to a user-restricted file and prints expiry, not the token.

## Real deployment gate

Phase 2C code does not create tenant applications or grant consent. Before live use, administrators must review:

- requested scopes;
- delegated vs application identity;
- tenant restrictions and national-cloud Graph root;
- Conditional Access;
- token lifetime and storage;
- Atlassian authentication type;
- internal CA roots and proxy requirements;
- audit and retention obligations.
