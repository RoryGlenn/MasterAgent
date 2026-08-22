# Phase 2C — Authentication and Deployment Readiness

## Delivered

- disabled-by-default OAuth profiles;
- Microsoft Entra delegated device-code and client-credentials provider implementations;
- operator-supplied existing token support;
- restricted token-file writing;
- current-user Windows Credential Manager and DPAPI providers;
- token expiry/scope/claim inspection;
- Microsoft delegated principal attestation through Graph `/me`;
- capability-governance coverage reports;
- connector configuration diagnostics that expose variable names, not values;
- offline provider/classification model-context egress readiness checks;
- explicit read-only live probes.

This phase governs capabilities that require authentication. A capability
explicitly cataloged for anonymous public access does not acquire, resolve, or
forward a credential; `github.public_repository.list` and
`bitbucket.public_repository.list` are the current production examples.

## Safe readiness

```bash
mkdir -p "$HOME/.master-agent/MasterAgent"
chmod 700 "$HOME/.master-agent" "$HOME/.master-agent/MasterAgent"
master-agent readiness \
  --integrations /trusted/config/integrations.toml \
  --capabilities /trusted/config/capabilities.toml \
  --governance /trusted/config/governance.toml \
  --credentials-file /absolute/path/to/private-credentials.json \
  --egress-check jira:internal \
  --output "$HOME/.master-agent/MasterAgent/readiness.json"
```

Readiness performs no network calls. A safe unconnected installation may be
`ready=true` while warning that available connectors are inactive until their
credentials are supplied. The human-readable CLI output makes that state
explicit as `live connectors: 5 available, 0 credential-ready`.

That permissive credential warning applies to ordinary readiness. A selected
`--egress-check PROVIDER:CLASSIFICATION` still makes no network call, but it
fails unless the selected connector is present and enabled, required credential
names are available, its principal-attestation and feature gates are usable,
and the current destination, model tenancy, classification, audit sink, and DLP
availability permit at least one ephemeral or audited route.

## Device code

```bash
master-agent oauth-device-code \
  --profile microsoft_delegated \
  --token-file "$HOME/.master-agent/MasterAgent/tokens/microsoft.json"
```

Only an enabled `entra_device_code` profile can run. The operator completes the provider's interactive authentication. The runtime writes the access token to a user-restricted file and prints expiry, not the token.

Microsoft delegated token-file and environment bearer credentials are
provider-attested through Graph `/me` at bind and apply time. The immutable user
object ID and the configured or restricted-token-file effective scopes become
part of the execution binding; a configured identity label or unverified JWT
claim parsing is not proof. The credentialed integration matrix additionally
requires the purpose-specific `microsoft_integration_read` or
`microsoft_integration_effects` delegated profile and verifies the exact scopes
and remaining token lifetime before provider work. It has no token refresh
path, so the full matrix is manual-only. Application credentials do not
substitute for delegated OneNote reads or normal Teams sends.

GitHub bearer tokens are a separate supported flow: the GitHub connector
verifies `GET /user` at bind and apply time and binds the returned numeric ID.

## Windows secret storage

On native Windows 11, a connector may explicitly select either
`windows-credential-manager` or `windows-dpapi` in `integrations.toml`.
Credential Manager is recommended for individual short named tokens or
passwords. DPAPI is recommended when one connector needs a structured group of
values such as an Entra tenant, client ID, and client secret. Both use the
current Windows user; machine-scoped DPAPI is not enabled.

The connector continues to declare credential names through `username_env`,
`secret_env`, `tenant_id_env`, `client_id_env`, `client_secret_env`, or
`token_file_env`. These are allowlist names, not a requirement that values come
from the process environment. Add one reviewed source:

```toml
[connectors.microsoft]
enabled = true
deployment = "cloud"
base_url = "https://graph.microsoft.com/v1.0"
auth_mode = "oauth_application"
oauth_flow = "client_credentials"
tenant_id_env = "MASTER_AGENT_ENTRA_TENANT_ID"
client_id_env = "MASTER_AGENT_ENTRA_APP_CLIENT_ID"
client_secret_env = "MASTER_AGENT_ENTRA_APP_CLIENT_SECRET"
scopes = ["https://graph.microsoft.com/.default"]
credential_provider = "windows-dpapi"
credential_target = 'C:\MasterAgent\secrets\microsoft.dpapi'
```

For Credential Manager, use a bounded namespace such as
`credential_target = "MasterAgent/production/jira"`. The trusted setup adapter
stores one Generic entry at `NAMESPACE/DECLARED_NAME`; each UTF-8 value is
limited to the Windows `5*512`-byte credential-blob ceiling. For DPAPI,
`credential_target` must be an absolute local drive file beneath a protected
directory. Only a versioned ciphertext envelope reaches that path, through the
native atomic-state backend.

An explicit native source wins over same-name ambient variables. Readiness may
list the shadowed declared names but never their values. Windows environment
names are compared case-insensitively, so multiple implicit case variants fail
closed. The environment remains the default when `credential_provider` is
absent. `--credentials-file` remains the development-only restricted JSON
adapter and is never imported, migrated, or rewritten into a native store.

Provision native values only through trusted deployment/setup code using the
typed credential-storage backend; do not place values in TOML, command-line
arguments, logs, or evidence. DPAPI recovery normally requires the same user
profile and machine. Plan for credential rotation or reprovisioning if an
administrator resets that user's password or the profile becomes unavailable.

## Real deployment gate

Phase 2C code does not create tenant applications or grant consent. Before live
use of an authenticated capability, administrators must review:

- requested scopes;
- delegated vs application identity;
- tenant restrictions and national-cloud Graph root;
- Conditional Access;
- token lifetime and storage;
- Atlassian authentication type;
- internal CA roots and proxy requirements;
- model destination and tenancy;
- source-data environment and explicit provider-data classifications;
- route-specific audit and DLP availability;
- audit and retention obligations.
