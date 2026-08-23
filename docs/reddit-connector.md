# Reddit connector

MasterAgent uses Reddit's official OAuth API for bounded reads, local drafts,
and approval-bound interactions. It has no generic HTTP, voting, moderation,
award, chat, bulk-engagement, or automated-posting surface.

## OAuth setup

Create a Reddit OAuth application for the operator account and complete Reddit's
authorization-code flow with `duration=permanent`. Use separate OAuth grants
and credential files for reading and communication. The packaged `read` profile
requests exactly `identity`, `read`, `history`, and `privatemessages`; it has no
authority to submit, edit, or delete content. Put its values in a private
credential-store file; never put values in TOML, a plan, a prompt, an issue, or
a log:

```json
{
  "schema": "master-agent/credential-store@1",
  "credentials": {
    "MASTER_AGENT_REDDIT_READ_CLIENT_ID": "client-id",
    "MASTER_AGENT_REDDIT_READ_CLIENT_SECRET": "client-secret",
    "MASTER_AGENT_REDDIT_READ_REFRESH_TOKEN": "refresh-token"
  }
}
```

The containing directory must be private and the file mode must be `0600` on
POSIX. The connector exchanges the refresh credential only at
`https://www.reddit.com/api/v1/access_token`, holds the returned access token in
memory, and sends bearer credentials only to `https://oauth.reddit.com`.
Reddit must report the effective scopes in every token response. A missing
scope report or any scope outside the selected credential profile fails closed.

Check the connection without changing Reddit:

```bash
.venv/bin/master-agent connect \
  --systems reddit \
  --credentials-file /absolute/path/to/reddit-credentials.json
```

To enable post or comment/reply operations, create a second Reddit OAuth grant
with exactly `identity`, `read`, and `submit`. Store it separately under the
communication-specific names:

```json
{
  "schema": "master-agent/credential-store@1",
  "credentials": {
    "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_ID": "client-id",
    "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_SECRET": "client-secret",
    "MASTER_AGENT_REDDIT_COMMUNICATION_REFRESH_TOKEN": "refresh-token"
  }
}
```

Use a reviewed private copy of `integrations.toml` with the communication
profile and only the required feature flags enabled:

```toml
[connectors.reddit]
credential_profile = "communication"
client_id_env = "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_ID"
client_secret_env = "MASTER_AGENT_REDDIT_COMMUNICATION_CLIENT_SECRET"
refresh_token_env = "MASTER_AGENT_REDDIT_COMMUNICATION_REFRESH_TOKEN"
scopes = ["identity", "read", "submit"]
posts_enabled = true
comments_enabled = true
edits_enabled = false
deletes_enabled = false
```

Keep the read and communication configurations, grants, and credential files
separate. A read credential cannot enable effects, and a communication profile
cannot enable the quarantined edit/delete adapters.

## Supported capabilities

Reads include search, one post or comment by fullname, bare ID, or canonical
Reddit URL, subreddit rules,
authenticated-user submissions and comments, and the inbox. Read actions work
through `run --direct-read`, enforce item/page/byte and model-egress limits, and
treat all returned content as untrusted data.

`reddit.post.draft`, `reddit.comment.draft`, and
`reddit.comment.reply.draft` produce local Markdown and never contact Reddit.

Active provider effects are `reddit.post.create`, `reddit.comment.create`, and
`reddit.comment.reply`. Packaged feature flags remain false. A private
integration config must enable `posts_enabled` or `comments_enabled`, and the
runtime invocation must enable communications. Typed `reddit.content.edit` and
`reddit.content.delete` adapters are implemented and tested but catalog-disabled:
Reddit provides no atomic compare-and-swap precondition, so a local pre-read
cannot safely satisfy MasterAgent's modifying-provider invariant.

Every active effect requires an authenticated approval covering the exact target
and fields immediately before dispatch. The connector sends one mutation
request with no automatic retry and independently re-reads the provider state.
Comment creation accepts only a post target; reply accepts only a comment
target. The quarantined edit and delete adapters are limited to content owned
by the authenticated user and require the expected version from a prior read.
Provider `429` responses remain typed rate-limit failures with the safe retry
interval; the runtime never silently repeats a write.

## Errors

- `401`: the client or refresh credential is invalid or revoked.
- `403`: the token lacks the required scope or the account cannot access the target.
- `404`: the post or comment is absent or not visible.
- `429`: wait for the reported interval, review current provider state, and create a new exact plan before retrying an effect.
- verification failure: inspect Reddit directly; do not repeat the mutation until its outcome is known.
