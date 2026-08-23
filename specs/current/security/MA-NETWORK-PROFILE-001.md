# MA-NETWORK-PROFILE-001 — Governed enterprise provider networking

## Status

Active

## Requirement

Every live provider request MUST select an immutable named network profile. A
profile MUST be one of direct, fixed credential-free HTTP proxy, or explicit
ambient-proxy selection. Direct mode MUST remain the default. Ambient
`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` values MUST NOT affect transport
unless a reviewed profile explicitly selects the relevant value; an explicit
proxy MUST ignore ambient bypass rules.

The execution binding MUST include the selected profile name and digest, exact
credential-free proxy authority when present, fixed provider endpoint and
origin, and captured enterprise certificate-authority path and digest. The
runtime MUST revalidate those facts before connector construction, provider
access, verification, compensation, and return. Proxy credentials MUST be
resolved through the existing credential broker as an exact username/password
pair, remain memory-only, and appear only in the HTTP CONNECT authentication
header. They MUST NOT appear in configuration URLs, provider requests, plans,
bindings, logs, audit, diagnostics, exceptions, environment snapshots, or
redirects.

Before direct or tunneled I/O, provider DNS MUST resolve only to public
addresses. The transport MUST preserve provider Server Name Indication and
certificate-hostname validation through CONNECT and MUST validate the provider
chain against the captured configured CA bytes. Proxy CONNECT redirects,
unsupported schemes, loopback or unstable proxy address classes, private
provider pivots, cross-origin or out-of-scope redirects and responses, and
credential forwarding to another authority MUST fail closed. Existing request,
response, retry, timeout, and indeterminate-effect bounds MUST remain in force.

Offline readiness MUST report selected profile mode, proxy selection,
enterprise-CA selection, credential availability, and configuration failures
without network access. Connectivity failures MUST have bounded secret-free
classes for DNS, proxy authentication, TLS/CA, provider authentication,
provider scope, rate limit, policy, timeout, and transport failures. Protected
managed-network integration evidence MUST be opt-in and MUST NOT expose proxy
or provider credentials to pull-request code.

## Rationale

Company networks may require a proxy or enterprise inspection CA, but ambient
process configuration and credential-bearing URLs cannot be trusted as runtime
authority. A named immutable profile exposes exactly which managed network path
is approved while preserving the fixed provider boundary.

## Scenarios

### Authenticated corporate proxy with enterprise CA

- GIVEN a connector selects a fixed proxy profile with brokered credentials and
  a captured enterprise CA bundle
- WHEN a typed provider read executes
- THEN proxy authentication is used only for CONNECT, provider TLS validates
  the original provider hostname through the tunnel, and the result remains
  confined to the approved provider origin.

### Ambient proxy is not authority by default

- GIVEN the process contains proxy and bypass environment variables but the
  connector selects direct mode
- WHEN a provider request is constructed
- THEN none of those ambient values affect destination, routing, credentials,
  or diagnostics.

### Proxy cannot pivot the provider request

- GIVEN a proxy attempts a CONNECT redirect, private provider resolution,
  cross-origin response, or credential-forwarding change
- WHEN the transport validates the request or response
- THEN the request fails closed before accepting provider data or broadening
  authority.

### Actionable secret-free failure

- GIVEN proxy authentication or enterprise CA validation fails
- WHEN readiness or connectivity diagnostics are reported
- THEN the output names the stable failure class and recovery category without
  proxy credentials, provider response text, or unsafe network details.

## Implementation

- `src/master_agent/config.py`
- `src/master_agent/http.py`
- `src/master_agent/models.py`
- `src/master_agent/execution_context.py`
- `src/master_agent/connectors/factory.py`
- `src/master_agent/readiness.py`

## Verification

- `tests/test_config.py`
- `tests/test_http.py`
- `tests/test_execution_context.py`
- `tests/test_oauth_readiness.py`
- `tests/test_live_connector_workflow.py`

## History

- Introduced by GitHub issue #112.
