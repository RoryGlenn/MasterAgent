# Phase 2A — Read-Only Integration Layer

## Scope

Phase 2A connects the governed runtime to real enterprise APIs without granting
write authority. It supports deployment discovery, bounded reads, normalized
evidence, independent verification, and weekly-status plan generation. The
legacy direct weekly-status execution/package command is disabled until it uses
the immutable manifest and descriptor-pinned output boundary.

This release does not acquire credentials. It consumes already-issued credentials supplied through environment variables at process start.

## Runtime systems

| Runtime system | Deployment support | Capabilities |
|---|---|---|
| Jira | Cloud, Data Center | `jira.server.info`, `jira.issue.search`, `jira.issue.read` |
| Confluence | Cloud, Data Center | `confluence.page.search`, `confluence.page.read` |
| Bitbucket | Cloud, Data Center | instance, repository, PR search/read, diffstat, build-status reads |
| GitHub | Cloud | repository, PR search/read, commit check-run reads |
| Microsoft identity | Microsoft Graph | `microsoft.identity.read` |
| SharePoint/OneDrive | Microsoft Graph | site search/read, drive list, children, metadata, bounded text read |
| PowerPoint | Local | weekly-status `.pptx` generation |

## Authentication modes

### Basic

Used when a service expects a username plus API token or password-like secret.

```toml
[connectors.jira]
auth_mode = "basic"
username_env = "MASTER_AGENT_JIRA_USERNAME"
secret_env = "MASTER_AGENT_JIRA_TOKEN"
```

### Bearer

Used for personal access tokens or OAuth access tokens.

```toml
[connectors.microsoft]
auth_mode = "bearer"
secret_env = "MASTER_AGENT_GRAPH_ACCESS_TOKEN"
```

### None

Available only for explicitly unauthenticated test or internal endpoints. Production environments should normally use authenticated connectors.

## Configuration resolution

`config/integrations.toml` stores only:

- deployment type;
- base URL;
- authentication mode;
- names of environment variables;
- timeout and response limits;
- non-secret connector settings.

Credential values are resolved at runtime and excluded from dataclass representations, discovery reports, errors, and audit payloads.

## Discovery states

| State | Meaning |
|---|---|
| `disabled` | Connector is configured but intentionally inactive. |
| `missing_environment` | Required environment variables are absent. |
| `ready` | Local configuration resolved successfully; no API request was made. |
| `reachable` | A bounded read-only API probe succeeded. |
| `failed` | Configuration, authentication, authorization, transport, or response validation failed. |

Run configuration-only discovery first:

```bash
master-agent discover --integrations config/integrations.toml
```

Then probe only approved systems:

```bash
master-agent discover \
  --integrations config/integrations.toml \
  --systems jira,confluence,bitbucket,github,microsoft,sharepoint \
  --probe
```

## Deployment-specific behavior

### Jira

Cloud and Data Center use separate REST paths and response normalization. Search is implemented as a read-only POST because Jira search requests can require structured JQL payloads. The connector's HTTP method allowlist permits only `GET`, `HEAD`, and this read-only `POST` path.

Normalized issue evidence includes identifiers, summary, status, priority, assignee, timestamps, labels, blocker classification, version evidence, and source URLs.

### Confluence

Cloud and Data Center use separate page/search APIs. Storage-format HTML is converted to plain text for report generation while the normalized output retains a bounded excerpt rather than treating the page as instructions.

A requested `expected_version` is validated against the retrieved page version.

### Bitbucket

Cloud and Data Center use separate repository and pull-request paths. The connector can enrich a bounded number of PRs with build/CI statuses and diffstat summaries.

The connector does not clone repositories, retrieve arbitrary source trees, commit, push, or merge.

### GitHub

- Cloud credentials are restricted to `api.github.com` and supplied by
  `MASTER_AGENT_GITHUB_TOKEN`.
- Repository owner/name pairs, pull-request numbers, and commit refs are
  validated before URL construction.
- PR and check-run pagination is bounded by connector page, item, request, and
  response-byte budgets.
- The connector has no GitHub create, update, merge, permission, or generic
  HTTP capability.

### Microsoft identity

`resource_id = "me"` is accepted only when `identity_mode = "delegated"`. Application identity mode requires an explicit user object ID or user principal name.

### SharePoint and OneDrive

Graph handles site, drive, item, and metadata requests. For a text-file read:

1. Graph returns file metadata and a temporary download URL.
2. The runtime validates HTTPS, hostname, extension, and maximum byte count.
3. The temporary URL is fetched without forwarding the Graph bearer token.
4. Retrieved text is marked untrusted and scanned for prompt-injection signals.

Binary files and non-allowlisted extensions are rejected before download.

## HTTP boundary

`SafeHttpClient` enforces:

- HTTPS base URLs;
- no URL-embedded credentials;
- same-origin API requests, pagination, and redirects;
- explicit method allowlists;
- request timeout;
- maximum response size;
- bounded transient retries;
- query-free error messages;
- typed authentication, authorization, not-found, rate-limit, and HTTP errors;
- optional enterprise CA bundles.

The runtime does not expose a generic HTTP tool to the planner.

## Evidence and audit separation

The run report returned to the explicit caller may contain full normalized evidence. The durable audit database stores only:

- plan fingerprint;
- goal digest and length;
- action/capability/target metadata;
- action state;
- normalized payload keys, counts, schemas, and SHA-256 digests;
- query-free connector references plus a digest of the original reference.

A full run result is written only when the user supplies `--apply` and a
manifest-bound `--result-json`. Policy-only dry runs use a temporary audit chain
that is removed before exit and cannot persist a result. Weekly-status plan
generation is non-executing; the direct package command is disabled and writes
no provider-derived evidence.

## Verification model

Read-only actions are verified with a second API retrieval. The connector compares normalized content digests while ignoring retrieval timestamps and security annotations.

A changing resource therefore reports a failed verification rather than being presented as a stable snapshot.

## Current exclusions

Phase 2A intentionally excludes:

- Outlook messages;
- Teams messages;
- OneNote;
- attachment parsing;
- source-code checkout;
- OAuth/device-code flow implementation;
- token caching or refresh;
- any external write or send operation.

These require separate permission, retention, identity, and data-governance decisions.
