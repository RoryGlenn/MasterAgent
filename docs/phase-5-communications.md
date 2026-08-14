# Phase 5 — External Communication

## Outlook

The runtime:

1. validates delegated identity by default;
2. creates a provider draft using the exact approved recipients, subject, body, and content type;
3. re-reads the provider draft;
4. compares canonical content digests;
5. sends only when the provider draft exactly matches;
6. records provider acceptance and digest evidence.

## Teams

The runtime supports:

- send to an existing chat;
- send to an existing channel;
- reply to an existing channel message.

It posts the exact approved body to an explicit destination and independently reads the created message. Normal sends require delegated identity; application migration permissions are not treated as ordinary messaging authority.

## Approval rule

Recipient/destination and exact final content are inside the immutable plan fingerprint. Editing any of them invalidates prior approval. Retrieved messages or documents cannot add recipients or authorize a send.

## Non-reversibility

Email and Teams messages are treated as non-reversible. A provider may support deletion in some contexts, but the v1 governance model does not represent that as undo. The safe response to an incorrect send is a new, separately approved correction.
