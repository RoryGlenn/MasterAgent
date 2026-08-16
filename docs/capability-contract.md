# Capability Contract

## Capability-gap parity

Every capability surface follows the same gap contract. When an actionable,
in-scope request lacks required repository code, MasterAgent implements the
minimum governed path on the spot, validates it, and resumes the original
request in the same run. This includes connectors, planners, workflows,
adapters, policy wiring, verification, compensation, rendering, CLI surfaces,
future capabilities, and plugins. Different operations may require different
authentication, approval, or external permissions, but missing repository code
cannot become an operator-facing dead end.

## Domain-specific capabilities

Capabilities preserve the semantics required for policy and verification:

```text
jira.issue.search
jira.issue.read
confluence.page.search
confluence.page.read
confluence.space.create
bitbucket.pull_request.search
bitbucket.public_repository.list
github.public_repository.list
github.repository.list
github.repository.read
github.pull_request.search
github.pull_request.read
github.checks.read
github.issue.create
github.pull_request.create
microsoft.identity.search
outlook.message.search
outlook.message.read
outlook.attachment.text.read
teams.chat.message.list
teams.channel.message.replies.list
sharepoint.file.text.read
powerpoint.presentation.generate
outlook.email.draft
teams.message.draft
```

Do not reduce these to generic `create`, `read`, or `update`. Domain semantics determine authentication, limits, risk, reversibility, concurrency, retention, and verification.

GitHub issue and pull-request creation are reversible writes. The typed
repository-settings and existing-collaborator adapters remain implemented, but
their catalog and governance routes are disabled: GitHub does not document a
provider-side conditional precondition for those unsafe updates. Jira issue
update, transition, and compensation routes are disabled for the same reason.
SharePoint small-file replacement is also disabled because its exact
`PUT /content` endpoint does not document a conditional precondition. An
approval cannot substitute for atomic provider concurrency control.

## Action envelope

Every action contains:

- unique action ID;
- domain-specific capability;
- typed target system, resource type, resource ID, and optional expected version;
- validated parameters;
- risk level;
- authority source;
- approval requirement;
- dependency IDs;
- stable idempotency key;
- human-readable justification.

The complete plan is serialized deterministically and hashed. Approval applies only to that exact fingerprint and selected action IDs.

## Connector declaration

A connector must expose:

```python
system: str
capabilities: frozenset[str]
```

The registry guarantees one unambiguous connector for each `(system, capability)` pair. Overlapping capability registrations fail closed.

## Connector requirements

A connector must:

- reject a different target system;
- reject unsupported capabilities or risk tiers;
- validate required parameters and reject excessive limits;
- satisfy the catalog's exact target, authentication, effective identity, and
  scope contract;
- quote external identifiers before path construction;
- bound collection, pagination, enrichment, response, and download sizes;
- construct endpoints internally rather than accepting arbitrary URLs;
- return normalized data with a schema identifier;
- attach retention classification and resource citations;
- scan retrieved strings as untrusted data;
- return a structured `ExecutionResult`;
- verify the result independently;
- implement verified compensation whenever the catalog marks it reversible;
- avoid placing secrets or retrieved bodies in audit metadata.

## Read-only result envelope

Live read-only connectors add:

```json
{
  "schema": "master-agent/vendor-resource@1",
  "retention": {
    "evidence_type": "outlook.message.content",
    "content_kind": "communication_content"
  },
  "citations": [
    {
      "citation_id": "CIT-...",
      "marker": "[CIT-...]",
      "system": "outlook",
      "resource_type": "message",
      "resource_id": "...",
      "title": "...",
      "url": "query-free HTTPS reference"
    }
  ],
  "evidence": {
    "content_digest": "sha256:...",
    "retrieved_at": "ISO-8601 timestamp",
    "connector_reference": "sanitized resource reference"
  },
  "security": {
    "content_is_untrusted": true,
    "prompt_injection_findings": []
  }
}
```

The digest excludes retrieval timestamps and security annotations so an independent read can be compared consistently.

## Citation contract

Citation IDs are stable for a resource identity and independent of mutable content. A citation URL:

- is optional;
- must not contain embedded credentials;
- is stripped of query and fragment components;
- must satisfy capability-specific scheme/host rules.

Records that represent a specific resource carry their citation ID so reports can cite exact rows rather than only a collection endpoint.

## Retention contract

Every normalized result identifies an evidence type. Persistence is evaluated by the ordered retention policy:

```text
prohibited
metadata_only
explicit_content
```

A caller cannot persist full content under a `metadata_only` rule. Retained files receive sibling sidecars with digest, timestamps, expiration, citation IDs, and content-included state.

## Audit summary

The durable audit representation retains:

- action and state;
- query-free connector reference plus digest;
- schema and normalized result keys;
- item counts;
- evidence content digest;
- verification outcome.

It excludes issue/page/message bodies, attachment text, source diffs, recipients, search terms, temporary URLs, and credentials.

## Write contract

Every write or external-communication capability additionally defines:

- dedicated parameter model;
- exact before-state;
- expected-version or revision precondition;
- approval tier and authority source;
- idempotency behavior;
- retry classification;
- post-write re-read;
- compensation or correction strategy;
- data-classification constraints;
- exact external audience for publish/send operations.
