# MA-DATA-EGRESS-001 — Provider-data model-context boundary

## Status

Active

## Requirement

Before any typed provider-read result can be returned to an agent, user, or
model context, the runtime MUST evaluate organization model-context policy and
construct an immutable egress binding. The binding MUST include the provider,
connector configuration and provider-account identity digests, explicit data
classification, exact requested field projection and versioned connector
output contract, request-parameter digest, item and byte limits, destination,
model tenancy, source-data environment, handling mode, DLP declaration, and
audit requirement. Policy MUST be evaluated independently of whether the
connector capability itself declares a model call. Static policy, field,
schema, and limit checks MUST run before provider principal attestation;
authenticated control-plane attestation MAY then establish the account binding
but MUST complete before the provider content request. When credentials are
required, attestation and provider content access MUST use the same captured
credential snapshot. The runtime MUST bind the exact provider endpoint, origin,
and CA identity and recheck them before provider access and before return.

The runtime MUST revalidate the same binding before output, require the exact
versioned envelope and declared resource fields, reject undeclared envelope
siblings, project explicit requested fields only inside declared resources,
recursively remove secret-key values and configured redacted fields, enforce
the bound byte limit, and preserve the original data classification. Resource
and metadata contract names MUST reject normalized case, camel-case, acronym,
or separator aliases of omitted or runtime-generated fields. Collection
reads MUST declare a positive item limit before provider access. Provider or
retrieved content, including prompt injection, MUST NOT change provider scope,
authority, classification, destination, tenancy, field projection, handling,
schema, resource shape, or audit requirements. Incoming evidence and security
metadata MUST be discarded and rebuilt from the sanitized projection without
raw prompt-injection paths or excerpts. Omitted, runtime-generated, secret,
configured-redaction, reference, and prompt-finding names MUST use the same
separator-insensitive identity throughout nested resource content. A serialized
provider-read action
without an explicit supported classification MUST fail before provider access.

Public or internal data MAY use an explicitly allowed stateless route without
effect approval. A rule requiring audit MUST NOT use that route. Confidential
or restricted data MUST be redacted/minimized, handled through an approved
audited route, or denied according to organization policy, and MUST never enter
an unapproved destination or tenancy. Development MAY use an explicitly
configured nonproduction default for trusted probe routes; non-development
profiles MUST reject an unknown classification.

Governed access metadata MUST contain policy and binding facts, digests,
counts, and outcomes only. It MUST NOT contain provider bodies, query values,
prompt-injection paths or excerpts, secrets, raw provider-account identities,
free-form provider failures, malformed references, or invalid-Unicode codec
details. A DLP-required rule MUST fail closed unless its
named adapter has executable runtime enforcement; merely declaring an adapter
name is insufficient.
Readiness MUST be able to report whether a selected provider/classification is
usable with the active connector, destination, tenancy, handling, DLP, and
audit configuration without making a network request.

Every provider-read return path is in scope, including stateless direct reads,
applied workflow reads, connection/discovery probes, and dedicated provider
read shortcuts.

## Rationale

The data boundary is where provider content leaves a connector for a human or
model context, regardless of whether connector code directly invokes a model.

## Scenarios

### Approved internal direct read

- GIVEN an explicitly internal provider read and an organization rule allowing
  the active nonproduction destination and tenancy without audit
- WHEN a direct user requests the read
- THEN static policy and shape checks complete before any account attestation,
  the immutable account-bound egress binding is approved before provider
  content access, and the verified sanitized result returns without effect
  approval or durable state.

### Confidential data requires governance

- GIVEN confidential provider data whose matching rule requires audit
- WHEN the stateless direct route is requested
- THEN the request is denied before provider content is fetched.

### Retrieved injection cannot broaden egress

- GIVEN provider content that claims a different classification, destination,
  tenancy, provider, or field set
- WHEN the verified result reaches the return boundary
- THEN the original pre-dispatch binding remains unchanged and only its
  sanitized bounded copy can be returned.

### Content-free governed audit

- GIVEN an approved applied provider read
- WHEN the audited route returns verified content
- THEN the audit chain records binding and outcome metadata and no provider
  body, query value, raw account identity, secret, or injection excerpt.

### Exact collection boundary

- GIVEN a provider collection read with a versioned result contract
- WHEN its action omits a positive item limit or the provider returns an
  undeclared envelope sibling or missing resource
- THEN the request fails before provider access for the missing limit or fails
  closed at the return boundary for the invalid envelope.

## Implementation

- `src/master_agent/provider_egress.py`
- `src/master_agent/governance.py`
- `src/master_agent/direct_read.py`
- `src/master_agent/orchestrator.py`
- `src/master_agent/discovery.py`
- `src/master_agent/cli.py`
- `src/master_agent/readiness.py`

## Verification

- `tests/test_provider_egress.py`
- `tests/test_direct_read.py`
- `tests/test_orchestrator.py`
- `tests/test_discovery.py`
- `tests/test_cli.py`
- `tests/test_oauth_readiness.py`

## History

- Introduced by GitHub issue #116.
