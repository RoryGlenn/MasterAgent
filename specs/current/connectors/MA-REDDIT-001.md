# MA-REDDIT-001 — Governed Reddit provider integration

## Status

Active

## Requirement

The runtime MUST provide typed Reddit capabilities for search; post and comment
reads; subreddit rules; authenticated submitted, commented, and inbox content;
local post and comment/reply drafts; and provider post, comment/reply, edit, and
own-content deletion. It MUST use Reddit's official OAuth API through fixed HTTPS
API and token origins, refresh delegated access tokens into memory without
persisting credential material, send a reviewed User-Agent, attest the provider
user's immutable identity, and bind provider-reported scopes into live
execution. The packaged read profile MUST use a dedicated credential with
exactly `identity`, `read`, `history`, and `privatemessages` and MUST NOT request
`submit` or `edit`. Active post and comment/reply operations MUST use a separate
communication credential with exactly `identity`, `read`, and `submit`. A token
response that omits effective scopes or reports scopes outside the selected
profile MUST fail closed.

Every provider mutation MUST remain disabled in packaged configuration until an
operator explicitly enables its exact feature flag. It MUST require an exact
authenticated approval immediately before dispatch, reject authority derived
from retrieved content, send only approved fields, perform no automatic write
retry, and independently verify provider poststate. Edit and deletion MUST
require an expected version and a fresh ownership/version precondition; drift or
non-owned content MUST fail closed. All reads MUST enforce pagination, item,
response-byte, origin, and model-egress bounds and treat returned Reddit content
as untrusted data. Content references MUST normalize only bounded Reddit
fullnames, bare IDs, or canonical safe HTTPS Reddit URLs. Comment creation MUST
accept only a post target, and reply MUST accept only a comment target.

Because Reddit does not expose a provider-side compare-and-swap precondition,
the edit and deletion adapters MUST remain disabled in the capability catalog
even when their private connector flags are true. Their ownership, version,
approval, zero-retry, and verification contracts MUST remain tested so they can
be admitted only if the modifying-provider invariant can be satisfied without
weakening it.

Authentication, provider, rate-limit, validation, and verification failures
MUST be typed and secret-safe. Access tokens, refresh tokens, client secrets,
and authorization headers MUST NOT appear in configuration files, repr output,
logs, audit records, artifacts, returned payloads, or exception messages.

## Rationale

Reddit reads and visible interactions need the same typed identity, egress,
approval, and verification boundaries as other providers. Quarantining
non-atomic mutations preserves those guarantees while still documenting and
testing the provider adapter needed for a future safe admission.

## Scenarios

### Read and draft without publication

- GIVEN the purpose-separated read credential and approved provider egress
- WHEN a user searches a subreddit, reads its rules, and prepares a local post draft
- THEN the connector returns bounded sanitized evidence and writes a local draft without performing a Reddit mutation.

### Reject over-broad credential authority

- GIVEN the read profile and a token response that omits scopes or includes `submit`
- WHEN the runtime acquires delegated Reddit access
- THEN authentication fails before the token can authorize a provider read or effect.

### Exact approved reply

- GIVEN the separate communication credential and an approval bound to a reply target and exact body
- WHEN the applied runtime executes `reddit.comment.reply`
- THEN it sends one provider request, independently re-reads the new comment, and returns the canonical Reddit URL.

### Rejected unapproved or drifting mutation

- GIVEN a mutation without exact approval or an edit/delete whose provider item changed after planning
- WHEN execution is attempted
- THEN the connector rejects it before sending the mutation.

## Implementation

- `src/master_agent/oauth.py`
- `src/master_agent/connectors/reddit.py`
- `src/master_agent/connectors/reddit_write.py`
- `src/master_agent/connectors/factory.py`
- `src/master_agent/config.py`

## Verification

- `tests/test_reddit_connector.py`
- `tests/test_reddit_write_connector.py`
- `tests/test_oauth_readiness.py`
- `tests/test_direct_read.py`

## History

- Introduced by GitHub issue #135.
