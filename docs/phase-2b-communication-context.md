# Phase 2B — Read-Only Communication Context

## Scope

Phase 2B extends the read-only foundation into Outlook and Microsoft Teams without enabling send, reply, edit, delete, or publish operations. It also adds the identity, citation, and retention controls required before workplace communications may be used as agent context.

The Phase 2B read path consumes an already-issued Microsoft Graph access token;
it does not acquire, refresh, cache, or persist tokens. The separate Phase 2C
device-code command can acquire a delegated token and write a restricted token
file, but does not make that opaque credential eligible for governed live
apply.

## Runtime capabilities

### Identity

```text
identity.person.list
identity.person.resolve
identity.identifier.resolve
microsoft.identity.read
microsoft.identity.search
```

The local registry correlates one person with system-specific identifiers. Exact key, display-name, alias, and identifier matches are supported. Ambiguous matches fail closed.

Microsoft Graph identity mode is explicit:

- `delegated` may address `me`;
- `application` requires a concrete user object ID or user principal name.

### Outlook

```text
outlook.mail_folder.list
outlook.message.search
outlook.message.read
outlook.attachment.list
outlook.attachment.text.read
```

Search returns bounded message metadata and preview content. Full message read requests text bodies and records immutable identifiers and version evidence when Graph provides them.

Text attachment reads are intentionally narrow:

1. read attachment metadata;
2. require a file attachment;
3. reject inline attachments;
4. require an allowlisted extension and MIME type;
5. reject a declared size above the configured limit;
6. fetch raw content through the attachment value endpoint;
7. impose the same byte ceiling at the HTTP transport;
8. decode UTF-8 only;
9. mark and scan the result as untrusted communication content.

Embedded item attachments, binary Office files, PDFs, images, and arbitrary archive formats are not parsed.

### Teams

```text
teams.chat.list
teams.chat.message.list
teams.chat.message.read
teams.team.list
teams.channel.list
teams.channel.message.list
teams.channel.message.read
teams.channel.message.replies.list
```

The connector normalizes message body text, sender, mentions, reactions, timestamps, reply relationships, and attachment metadata. HTML message bodies are converted to plain text for analysis.

Chat-message `query` is a bounded local filter over the retrieved page. It is not presented as a tenant-wide Graph search capability.

Attachment content URLs and thumbnails are never fetched by the Teams connector in Phase 2B. Sanitized HTTPS references may be retained as metadata; query strings, fragments, and embedded credentials are removed.

## Registered communication-context workflow

The deterministic plan generator remains available. The direct
`communication-context` execution/package command is disabled before config,
credentials, connectors, or audit access until its provider identities,
targets, retention inputs, audit database, and output package are bound to one
immutable execution manifest.

The default workflow performs four actions:

```text
Resolve configured person
        │
        ├── Search bounded Outlook message context
        ├── List bounded Teams chats
        └── List bounded joined teams
```

The identity action is a dependency for all Microsoft actions. The generated plan is deterministic and read-only.

The workflow deliberately does not automatically traverse every chat, channel, message, reply, or attachment. Those deeper capabilities are available only through separately reviewed plans with explicit identifiers and limits.

## Resource-level citations

Every normalized resource may receive a stable citation:

```json
{
  "citation_id": "CIT-...",
  "marker": "[CIT-...]",
  "system": "outlook",
  "resource_type": "message",
  "resource_id": "...",
  "title": "Release blocker",
  "url": "query-free HTTPS reference"
}
```

Citation IDs are derived from stable resource identity, not message content. URLs are optional and are excluded when unsafe. Safe references remove:

- query strings;
- fragments;
- embedded username/password components;
- non-HTTPS schemes where HTTPS is required.

The evidence package contains a de-duplicated source index, and report rows carry their citation ID.

## Retention model

Retention policy has two independent decisions:

1. **Persistence mode**
   - `prohibited` — the runtime refuses persistence;
   - `metadata_only` — only structural metadata and digests may persist;
   - `explicit_content` — full content may persist only after an explicit command/output choice.
2. **TTL**
   - each evidence type receives the shortest TTL among equally restrictive
     matches; `prohibited` always overrides every allow rule.

The default Phase 2B configuration uses shorter TTLs for message and attachment content than for directory metadata.

Every retained evidence file receives a sibling `*.retention.json` sidecar containing:

- evidence type;
- creation and expiration timestamps;
- persistence decision;
- content-included flag;
- SHA-256 digest;
- citation IDs;
- sibling evidence filename.

Evidence and its manifest are fully written and fsynced through private,
mode-`0600`, same-directory staging files. The manifest is create-only
published before the evidence name; failure rolls back every transaction-owned
name. `evidence-prune` uses the same bounded descriptor-relative validation plan
for preview and explicit POSIX apply. Writers expose an exclusive exact-parent
retention lock and share existing owner-controlled ancestor retention locks;
apply uses the same ancestor handshake plus the selected-root and every
discovered evidence-parent retention lock. It performs an exact rescan and
recoverably deletes only a complete expired
evidence/sidecar pair. Malformed, unsafe, substituted, oversized, or truncated
trees fail closed. Recovery durably syncs absent public names before removing
staged links, and an ancestor scan reports nonempty nested-root transaction
state for exact-root recovery. All Windows execution remains gated.
`evidence-repair` remains separate and can recoverably quarantine an orphan
while refusing identity races.

## Audit boundary

The durable audit database stores action state, schema, item counts, content digests, sanitized references, and verification outcomes. It does not normally store:

- email subject/body/preview text;
- Teams message body or last-message preview;
- attachment text;
- recipient lists;
- Graph access tokens;
- temporary attachment URLs;
- Outlook/Teams search terms.

The disabled direct package command writes no communication evidence. Applied
manifest-bound plans may retain explicit results only through a fresh,
descriptor-pinned create-only result destination.

## Prompt-injection boundary

Email, Teams, attachment, and directory fields are data. They cannot:

- change policy;
- grant permission;
- add recipients;
- authorize writes;
- change the canonical source;
- request credentials;
- select a new tool invocation.

Heuristic findings are recorded with a field path, category, severity, and bounded excerpt. A finding does not make content trusted or untrusted; all retrieved content is always untrusted.

## Verification

Every live read is repeated independently and compared by normalized content digest. A changing mailbox/chat resource may therefore fail verification rather than being reported as a stable snapshot.

This is intentionally conservative. Later production deployments may use vendor-native ETags, change keys, delta links, or immutable IDs where they provide an equivalent or stronger check.

## Phase boundary

Phase 2B itself remains read-only. Later phases in version 1.0.0 add delegated OneNote access, OAuth/device-code primitives, and exact-approval Outlook/Teams sends as separately gated capabilities. The following remain excluded from the routable runtime:

- automatic Teams bot installation or unrestricted proactive messaging;
- binary attachment parsing inside live connectors;
- mailbox or Teams subscription webhooks;
- Graph delta synchronization;
- automatic refresh-token persistence;
- retention-policy discovery from Microsoft Purview;
- legal hold/eDiscovery operations;
- autonomous cross-system actions authorized only by communications content.
