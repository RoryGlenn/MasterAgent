# Requirement deltas

## ADDED

### MA-DATA-EGRESS-001 — Provider-data model-context boundary

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

## MODIFIED

### MA-DIRECT-READ-001 — Direct read-only provider session

The runtime MUST provide an explicit direct-read route for a plan containing
only direct-user, `read_only` actions for exactly one built-in typed provider.
Before credentials or principal attestation, the route MUST statically approve
provider-data egress for its stateless destination and model tenancy and bind
the exact field, schema, item, and byte shape. After authenticated control-plane
attestation and before provider content dispatch, it MUST construct the complete
account-bound egress binding. It MUST reject missing or denied classification,
unapproved destination or tenancy, and any policy rule that requires persistent
audit or unavailable handling before provider content access.

The route MUST otherwise validate each action through the capability catalog,
governance, policy, source-of-truth, authenticated connector identity/scope,
fixed provider endpoint, bounded transport, prompt-injection marking, and an
independent provider re-read. Before returning content it MUST revalidate the
egress binding, apply its deterministic minimization/redaction and byte limit,
and return the content-free binding metadata. It MUST not require a persisted
audit database, artifact directory, approval artifact, or pre-bound runtime
context for an approved public/internal read.

The route MUST reject a plan that contains a non-read risk, non-direct
authority, more than one provider, plugin or capsule binding, persisted output,
or a connector that is not an exact built-in typed `ReadOnlyConnector`, before
it dispatches a provider request. Provider effects, communications,
administration, deletes, merges, raw plugins, capsules, and recurring execution
MUST continue to use their existing governed boundaries.

## REMOVED

None.
