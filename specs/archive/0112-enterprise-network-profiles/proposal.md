# Governed enterprise network profiles

## Problem

Provider transport deliberately ignores ambient proxy configuration and rejects
HTTP CONNECT tunnels. That is safe on an unmanaged network but prevents typed
provider operations on company workstations that require an authenticated
proxy, enterprise Transport Layer Security (TLS) inspection certificate, or
both.

## Desired outcome

An organization can select a named direct, explicit-proxy, or explicitly
ambient-proxy profile. The exact secret-free profile, proxy authority, provider
origin, and captured certificate-authority digest are bound before execution.
Proxy credentials come from the existing credential broker and are used only
for CONNECT. Provider origin, redirect, DNS, response, retry, and output limits
remain unchanged.

## Scope

- Add typed named network profiles to integration configuration.
- Add authenticated HTTP CONNECT to the pinned standard-library transport.
- Capture network-profile, proxy, and certificate identities in connector
  execution bindings and revalidate them throughout execution.
- Add secret-free connectivity classifications and offline readiness details.
- Document an opt-in managed-network integration test.

## Rationale

Managed-network support must be configuration and approval data, not ambient
process behavior. A single immutable profile lets administrators enable the
required route without turning the connector into a generic HTTP client.

## Alternatives considered

- Trust `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` by default: rejected because
  ambient process state is not organization policy and may contain credentials.
- Put credentials in the proxy URL: rejected because URLs flow into plans,
  diagnostics, libraries, and logs.
- Disable provider certificate validation behind TLS inspection: rejected
  because the enterprise CA must extend trust while the provider hostname and
  final certificate identity remain validated.

## Non-goals

- Arbitrary execution-time proxy URLs.
- HTTPS, SOCKS, transparent, or unrestricted generic proxy transports.
- Certificate-validation bypasses.
- Provider-origin or redirect-policy expansion.

## Risks

A proxy can observe connection metadata and, when paired with a trusted
inspection CA, provider plaintext. Named organization configuration, exact
profile and CA binding, brokered credentials, fixed provider origins, bounded
diagnostics, and opt-in live evidence make that authority explicit and
reviewable.
