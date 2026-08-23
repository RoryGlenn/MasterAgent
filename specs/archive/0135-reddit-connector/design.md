# Design

## Approach

The read adapter uses the fixed `https://oauth.reddit.com` origin and the
existing read-only connector boundary. A dedicated refresh provider sends
client Basic authentication and a refresh-token form only to Reddit's fixed
token origin, caches access tokens in memory, and exposes no credential values.
`/api/v1/me` supplies the immutable Reddit user ID and granted scopes bound into
the execution context. The packaged read profile and the private communication
profile use separate OAuth grants, environment-variable names, scope sets, and
feature-gate contracts. Token responses must report effective scopes, and any
scope outside the selected profile is rejected before connector use.

The effect adapter accepts only typed capability-specific fields, requires the
approval flag and the catalog risk tier, and uses a transport configured with
zero retries. Create and edit responses are independently read back through
`/api/info`; deletion succeeds only after a separate read confirms the item is
absent. Create operations expose a manual recovery descriptor because Reddit
does not offer atomic close or delete preconditions. Edit and deletion require
an expected provider version and a fresh pre-read; they are refused on drift.

Draft capabilities write only local Markdown artifacts through the existing
bounded draft-output contract. All provider content remains untrusted data.
Configuration contains names of credential environment variables, never their
values. The read profile cannot enable any effect; the communication profile
can enable post and comment/reply only. All default write feature flags remain
disabled until explicitly enabled in private configuration.

## Affected components

- OAuth token acquisition and integration configuration
- Reddit read, write, and local-draft connectors
- connector factory, execution-context attestation, direct-read allowlist, and discovery
- capability, governance, organization, semantic ownership, and documentation data
- mock-transport connector and configuration tests

## Data flow

The runtime resolves client and refresh credentials from an approved source,
exchanges them at the fixed Reddit token endpoint, and pins the access token in
memory. It validates the provider-reported scopes against the selected
purpose-specific profile, attests `/api/v1/me`, binds the immutable account ID
and scopes, and then routes one typed read or approved effect to the fixed OAuth
API origin.
Reads are normalized and independently repeated. Effects send one request and
independently read the created poststate. Drafts contact no provider.

## Compatibility

Existing connector, CLI, plan, and applied-run interfaces remain unchanged.
Reddit adds one configuration and capability namespace. Packaged read
availability does not load credentials or contact Reddit; effect flags default
false, and edit/delete stay catalog-disabled.

## Security

Token and API origins are fixed and separately constrained. OAuth credentials
remain out of reprs and returned data. Purpose-separated grants prevent the
default read credential from acquiring submission authority. Reads inherit
same-origin, response, pagination, prompt-injection, and model-egress controls.
Effects require exact approval, send no unapproved fields, do not retry, and
independently verify.
The edit/delete quarantine preserves the provider-side atomic-precondition
invariant.

## Rejected alternatives

Password-grant authentication, browser automation, generic HTTP access, silent
write retries, and enabling non-atomic edit/delete were rejected because they
weaken identity, endpoint, or effect guarantees.
