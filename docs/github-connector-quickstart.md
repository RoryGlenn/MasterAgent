# MasterAgent GitHub Connector Quickstart

Use this guide when a nontechnical operator wants GitHub context through
MasterAgent. Give the agent the outcome; provide a credential-file location
only for private or account-visible data. The agent owns local setup, the
minimum typed read, and verification without asking for permission at each
step.

## What GitHub access can do

The built-in GitHub connector can:

- list a specified user's public repositories anonymously;
- list repositories visible to the authenticated user;
- read repository details;
- list open, closed, or all pull requests;
- read one pull request; and
- read check runs for a branch or commit.

It is read-only. It cannot create issues, comment, push code, create a pull
request, change permissions, or merge a pull request.

## Public repositories need no credential

For a request such as “show the repositories under
`https://github.com/rahul-aravind-opti`,” the agent extracts the username and
runs:

```bash
.venv/bin/master-agent github-repositories --username rahul-aravind-opti
```

This route evaluates `github.public_repository.list`, calls GitHub's fixed
public-user repository endpoint, independently re-reads the result, and never
loads or sends a token. It rejects `--credentials-file` and non-public
visibility. The agent must not search for a credential or attest an unrelated
authenticated GitHub user for this request.

## Supply a credential for account-visible data

Create a GitHub token with read access to the repositories, pull requests, and
checks you need. Store it outside the repository in a file owned by your user,
inside a private directory. The file may use the compact provider shape:

```json
{
  "github": "replace-with-a-real-token"
}
```

It may instead use the canonical MasterAgent credential-store schema described
in [`configuration.md`](configuration.md). The containing directory must be
mode `0700` and the file mode `0600`. Never paste the real token into a prompt,
plan, issue, log, or repository file.

MasterAgent adapts either supported JSON shape in memory. It does not rewrite
the credential file. An explicitly selected credential file also takes
precedence over an ambient GitHub token for the convenience commands.

The ChatGPT/Codex GitHub App is separate from this runtime connector. Installing
that app does not supply MasterAgent's token.

## Ask for authenticated account data

For repositories visible to your authenticated account, tell the agent:

```text
Connect GitHub and show the repositories available to my account.
Use the credential file at /absolute/path/to/private-token.json.
```

The agent bootstraps the repository-local runtime if needed and runs the
complete typed path:

```bash
.venv/bin/master-agent github-repositories \
  --credentials-file /absolute/path/to/private-token.json
```

That command enables GitHub only in memory, verifies the provider-returned
numeric user identity, evaluates `github.repository.list` through catalog,
governance, and policy, lists visible repositories, independently re-reads the
result, and leaves persistent connector settings and credentials unchanged.

For a connectivity check without listing repositories, the agent uses:

```bash
.venv/bin/master-agent connect \
  --systems github \
  --credentials-file /absolute/path/to/private-token.json
```

Connection is an intermediate step, not the requested outcome. After a probe
succeeds, the agent continues automatically through the requested typed GitHub
read. It should not ask you to rewrite the credential, enable the checked-in
connector, approve GitHub network access a second time, or repeat commands it
can run itself.

Other useful requests include:

- “Read repository `OWNER/REPOSITORY` and summarize its current state.”
- List the public repositories under GitHub user `USERNAME`.
- “List the open pull requests and tell me which ones need attention.”
- “Read pull request #27 and summarize its status.”
- “Read PR #27, then check CI for its head commit.”

MasterAgent keeps GitHub disabled in checked-in and packaged configuration. A
direct GitHub request authorizes only the minimum ephemeral read path for that
goal; it does not enable GitHub writes or persistent access.

## If access truly cannot continue

The agent diagnoses and retries safe steps before stopping. A remaining blocker
should require one operator action, such as supplying a missing credential or
granting provider-side repository access:

- `401`: the token is missing, invalid, or expired.
- `403`: the token lacks access to the selected repository or read operation.
- `Resource not accessible by integration`: verify that MasterAgent is using
  the selected credential file rather than an unrelated GitHub App token.
- Private-file error: place the credential in a dedicated private directory and
  ensure the directory is mode `0700` and the file is mode `0600`.
- Provider URL error: the built-in connector currently supports GitHub Cloud at
  `https://api.github.com`, not GitHub Enterprise Server.
