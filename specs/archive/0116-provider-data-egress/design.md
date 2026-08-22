# Design

## Approach

A new typed provider-egress module parses the `[model_context]` policy owned by
the organization governance profile. Rules match provider/capability,
classification, active destination, model tenancy, and route. A rule decides
whether the data is allowed, redacted, audited, DLP-dependent, or denied and
sets a maximum returned size.

Before credentials or provider principal attestation, the runtime performs a
static policy and shape preflight from the immutable action and capability
catalog. Authenticated GitHub and delegated Microsoft control-plane attestation
may then establish the provider account, but no provider content read is
allowed yet. The runtime combines that attested connector binding with the
preflighted rule to construct a content-free binding carrying request,
configuration, origin, and account digests—not provider data or query values.
It also carries the destination, model tenancy, source-data environment,
classification, DLP/audit declaration, byte/item caps, and exact versioned
output envelope. Attestation and content requests reuse one captured credential
snapshot, and the exact endpoint, origin, and CA identity are checked before
provider access and again before return.

Raw content is independently verified first. Only then is a private copy
recursively stripped of standard and normalized secret-key variants and
organization-configured field names. The sanitizer requires the exact schema
and declared resource fields, rejects undeclared envelope siblings, copies only
strictly shaped metadata, rejects case/camel/acronym/separator aliases of
omitted or runtime-generated contract fields at both catalog and persisted
binding boundaries, and applies an explicit requested-field projection
inside each resource. One separator-insensitive field identity also drives
nested omission, secret/configured redaction, reference minimization, and
prompt-finding minimization. Incoming evidence/security objects are discarded;
evidence digests and prompt-injection categories, severities, and hashes are
rebuilt from the projected content without raw paths or excerpts. The result
must fit the bound item and byte ceilings; oversized data fails rather than
being ambiguously truncated. The policy and binding are recomputed immediately
before the copy crosses the return boundary.

## Affected components

- `src/master_agent/provider_egress.py`: typed configuration, binding,
  authorization, sanitization, and content-free serialization.
- `src/master_agent/governance.py`: strict model-context configuration loading.
- `src/master_agent/models.py`: explicit classification for serialized reads.
- `src/master_agent/direct_read.py`: pre-dispatch and pre-return stateless gate.
- `src/master_agent/orchestrator.py`: applied-read gate and audit metadata.
- `src/master_agent/discovery.py` and `src/master_agent/cli.py`: probe and
  convenience-route enforcement.
- `src/master_agent/readiness.py`: selected provider/classification assessment.
- `src/master_agent/resource_limits.py`: cause-free invalid-Unicode rejection.
- Governance defaults, configuration/privacy/deployment/connector/CLI docs,
  and focused security regressions.

## Data flow

1. Trusted action or probe code supplies a data classification before provider
   content is requested.
2. Organization policy selects the active destination and model tenancy and a
   single matching route rule; the capability catalog supplies the exact output
   envelope and collection reads require an explicit limit.
3. After static approval, authenticated control-plane attestation establishes
   the account. The runtime combines those facts with connector configuration,
   origin, source-data environment, action field/request shape, and account
   identity digests.
4. A denied, unaudited, unclassified, unavailable-DLP, or oversized route fails
   closed. No provider content is returned.
5. An allowed connector content fetch is independently verified while private.
6. The runtime recomputes the binding, validates and projects the exact output
   contract, rebuilds evidence/security metadata, enforces item and byte limits,
   and returns only that copy plus content-free binding metadata.
7. An applied route records the same metadata and outcome in the audit chain;
   the stateless route creates no durable state.

## Compatibility

Existing programmatic action construction retains its typed internal default,
but serialized provider reads must now state `data_classification` explicitly.
Non-read serialized actions retain their legacy default. Existing external-model
policy remains in place for capabilities that directly invoke a model; provider
egress enforcement is independent and additive.

Packaged development configuration explicitly identifies a nonproduction model
tenancy and allows public/internal direct or audited reads. Confidential and
restricted data remain denied unless an organization adds a reviewed rule and
the selected route satisfies it. Ordinary readiness remains offline and
unchanged unless a provider/classification check is selected.

## Security

- Returned content never selects its policy, classification, fields, route,
  destination, tenancy, or authority.
- Account identity, action parameters, provider origin/configuration, and
  policy are represented by stable digests in persisted metadata.
- Redaction does not lower classification and cannot substitute for a required
  DLP adapter or audited route.
- A live authenticated read requires a pre-content provider-account binding;
  anonymous routes use an explicit anonymous sentinel.
- The host cannot currently prove which external model tenancy surrounds the
  CLI. Deployment must bind that reviewed fact and use readiness before live
  company data; future host attestation can replace the configuration assertion.
- Audit records exclude bodies, query values, secret values, raw account names,
  free-form provider failures, and prompt-injection paths or excerpts.
- No central DLP adapter ships in this version. Any rule that requires DLP
  fails closed until a named adapter has executable enforcement.

## Rejected alternatives

### Capability `uses_external_model` flags

Rejected as the provider-result boundary because connector implementation
details do not describe where returned data goes, and probes have no capability
definition at all.

### Automatic truncation

Rejected because truncating arbitrary structured evidence can change meaning
or verification. The runtime uses connector limits before retrieval and fails
if the sanitized result still exceeds the egress ceiling.

### Retrieved-content classification

Rejected because provider content is untrusted and may contain prompt injection.
Classification is supplied by trusted plan/probe input and bound before I/O.
