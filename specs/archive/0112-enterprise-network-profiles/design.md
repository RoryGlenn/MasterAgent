# Design

## Approach

`IntegrationConfig` parses closed `network_profiles` tables and embeds the
selected immutable `NetworkProfile` in each connector. Direct is synthesized as
the compatibility default. Fixed proxy profiles contain only an HTTP authority;
ambient mode reads only `HTTPS_PROXY` after explicit selection. Proxy username,
password, and enterprise-CA environment references use fixed reviewed names.

`ConnectorConfig.capture_execution_target` captures the provider endpoint,
network profile identity, proxy authority, and immutable CA bytes without
opening proxy credentials. Credential resolution later overlays the approved
broker snapshot and creates a `ResolvedConnectorConfig` whose secret proxy
fields are excluded from representations. Connector and OAuth clients pass the
resolved values into `UrllibTransport`.

## Affected components

- Configuration and bindings: `config/integrations.toml`,
  `src/master_agent/config.py`, `src/master_agent/models.py`, and execution
  binding validators.
- Transport: `src/master_agent/http.py` and connector client construction.
- Operations: `src/master_agent/readiness.py` and configuration documentation.
- Evidence: configuration, HTTP, binding, readiness, and live-integration tests.

## Data flow

1. Trusted integration configuration selects a named profile.
2. Planning captures the secret-free profile, proxy authority, provider origin,
   and CA snapshot into the execution binding.
3. Credential resolution obtains proxy and provider credentials from the same
   bounded broker overlay.
4. The transport vets provider DNS, connects to the configured proxy, sends
   proxy authentication only on CONNECT, and performs provider TLS with the
   original hostname and captured CA bytes.
5. Existing same-origin, path, redirect, response, retry, and lifecycle checks
   validate the tunneled provider request exactly like a direct request.

## Compatibility

Connectors that omit `network_profile` select synthesized direct mode. Existing
connector-level `ca_bundle_env` remains supported. A profile-level CA and a
connector-level CA cannot be combined because there must be one unambiguous
captured trust identity.

## Security

Proxy URLs forbid user information, paths, query strings, fragments, implicit
ports, and non-HTTP schemes. Explicit proxy handling bypasses urllib's ambient
`NO_PROXY` lookup. CONNECT targets are fixed provider hostnames whose local DNS
records must all be public. The provider authentication header is sent only
inside the established provider TLS tunnel; proxy authentication is stripped
from provider requests by the standard library's tunnel boundary. Errors are
classified from types rather than rendered provider or proxy text.

## Rejected alternatives

Generic environment proxy handling, credential-bearing URLs, certificate
validation bypasses, and arbitrary per-action network settings were rejected
because each would escape configuration, approval, redaction, or provider
origin binding.
