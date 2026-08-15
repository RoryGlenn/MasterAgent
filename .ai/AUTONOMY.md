# MasterAgent Goal-Completion Contract

This file defines how the repository-scoped agent completes an operator's goal
without turning safe prerequisites into a sequence of confirmation prompts. It
is subordinate to [`MASTER_AGENT.md`](MASTER_AGENT.md): autonomy removes
needless conversational stops, not policy, provider, or approval gates.

## One request, one bounded run

Treat the operator's requested outcome as authorization for every reversible,
low-risk prerequisite that is both necessary for that outcome and inside the
same scope. Complete those prerequisites in one run without asking the operator
to approve each step. This includes:

- the bounded repository-local bootstrap in [`FIRST_RUN.md`](FIRST_RUN.md);
- read-only inspection of local configuration and credential structure without
  printing credential values;
- an exact, documented in-memory adaptation of an unambiguous credential
  wrapper;
- an ephemeral, least-privilege read-connector enablement for a provider read
  the operator requested;
- identity probes, bounded reads, independent verification, and safe retries;
  and
- creation of private, agent-owned runtime directories or outputs required by
  the requested read.

A goal such as “connect GitHub and show my repositories” inherently requests a
GitHub network read. That prompt is the explicit scope for the minimum GitHub
read connector and its identity probe; do not ask again whether network access
may be enabled. It does not authorize writes, sends, publication, merges,
deletion, permission changes, broader providers, or persistent connector
enablement.

## Preserve safe defaults

- Keep every connector disabled in checked-in and packaged configuration.
- Use an in-memory connector overlay for a directly requested read. Do not edit
  `config/integrations.toml` merely to complete that read.
- Never rewrite a credential just to change its JSON wrapper. The GitHub
  convenience path may accept exactly `{"github":"<token>"}` and adapt it in
  memory while retaining all private-file checks.
- Do not change permissions on repository-owned configuration directories to
  make an explicit config path pass. Prefer the packaged, immutable defaults.
- Never print, summarize, copy, or persist a credential value. A private output
  explicitly requested by the operator remains mode `0600`.

## Communication contract

Give one short start update, do the work, and lead the final response with the
outcome. Do not narrate each inspected JSON key, configuration field, command,
permission check, probe, or retry. Mention an automatic repair only in the final
summary and only when it materially affects what the operator should know.

Continue automatically after a safe prerequisite succeeds. If several missing
operator inputs can be identified together, request them once as a batch. Do
not stop merely to report an intermediate success such as accepted credentials
or a reachable connector when the requested outcome is not complete.

## Real stop conditions

Stop only when continuing requires one of these:

- a credential, target, or fact only the operator can supply;
- a materially ambiguous product choice;
- destructive or costly work;
- provider consent, elevated scope, or a permission change;
- a write, send, publication, merge, or deletion without approval bound to the
  exact reviewed plan; or
- a safe prerequisite that remains blocked after bounded diagnosis and retry.

When a stop is necessary, report the completed portion, the exact blocker, and
the single smallest operator action that unlocks the rest. Do not make the
operator repeat commands the agent can run itself.

## GitHub repository path

For “show/list my GitHub repositories,” use the single bounded command after
local bootstrap:

```bash
.venv/bin/master-agent github-repositories \
  --credentials-file /absolute/path/to/private-token.json
```

The command enables GitHub read access only in memory, accepts either the
canonical MasterAgent credential store or the exact legacy GitHub wrapper,
attests the numeric GitHub user identity, evaluates the typed
`github.repository.list` action through catalog, governance, and policy, lists
repositories visible to that authenticated user, independently re-reads the
result, and leaves credentials and persistent connector settings unchanged.
