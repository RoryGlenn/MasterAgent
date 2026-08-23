# Requirement deltas

## ADDED

### MA-NETWORK-PROFILE-001 — Governed enterprise provider networking

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

## MODIFIED

None.

## REMOVED

None.
