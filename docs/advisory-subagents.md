# Advisory Sub-agent Safety Boundary

MasterAgent has two read-only advisory specialists for repository research and independent plan review. The user still selects **MasterAgent**; the checked-in child profiles are not directly user- or model-invocable through GitHub's host agent mechanism.

Think of the specialists as consultants working through a controlled doorway. They can inspect the repository and return advice, but the MasterAgent parent controls the doorway, checks what information crosses it, and makes every final decision. Technically, that doorway is the repository-owned `AdvisoryBroker`.

## Profiles

| Specialist | Repository contract | Purpose |
|---|---|---|
| **MasterAgent Read Researcher** | `read`, `search` | Bounded repository investigation with cited evidence |
| **MasterAgent Plan Reviewer** | `read`, `search` | Independent review of a concrete implementation plan |

Neither specialist may edit files, execute shell commands, call providers, access credentials, grant approval, mutate audit state, construct a runtime `ChangePlan`, or invoke another agent.

## Hub-and-spoke context

The selected parent is the only node that knows the complete role registry.
The generated [semantic router](semantic-index.md) selects one repository route
before delegation. A specialist then receives only its own checked-in profile,
the selected route, its parent and return path, and the sanitized input/output
contract. It does not load the other specialist's prompt or the complete
repository policy and specification corpus.

This is intentional. Peer-to-peer role awareness would add unrelated context
without adding authority or evidence. The parent already owns routing, budget,
scope, fallback, citation revalidation, and every final decision. The exact
topology and ownership inventory is validated from
[`semantic-router.toml`](../.ai/semantic-router.toml); generated prose cannot
widen the tools or invocation flags enforced by the profiles and broker.

## Two invocation paths

### GitHub host path remains disabled

Direct GitHub-host invocation is disabled. The parent profile does not expose the generic `agent` tool, and both child profiles keep `user-invocable: false` and `disable-model-invocation: true`.

This matters because host-native inference does not pass through MasterAgent's repository-owned parent identity, depth, per-goal budgets, sensitive-context sanitizer, state binding, or report re-validation. Enabling those profiles directly would create a second orchestration control plane.

### Broker-owned Copilot SDK path

MasterAgent now has an optional live adapter in [`copilot_advisory.py`](../src/master_agent/copilot_advisory.py). When the `subagents` optional dependency is installed, the selected parent can run a Researcher or Plan Reviewer through [`scripts/advisory_subagent.py`](../scripts/advisory_subagent.py).

The runner requires one opaque `--goal-id`, reused for every advisory attempt
in the operator goal; exactly one `--route ROUTE_ID` already selected by the
parent; and one or more existing repository-relative `--path` values. It fully
validates the manifest and exact stable route ID before worker construction,
then includes only that route's canonical navigation fields in the sanitized
envelope. It never sends aliases, routing fixtures, the agent registry, sibling
metadata, the full manifest, or the generated index.

Route validation uses the exact immutable HEAD revision captured inside a
complete repository-state binding. The runner parses the manifest from that
commit, loads the exact profile inventory from verified commit/tree/blob
objects, and refuses staged or unstaged manifest or profile drift. The resulting
digest remains parent-owned and must match the worker's first state binding
before any SDK client is created. A transient manifest swap or a change between
route authorization and worker startup therefore falls back to the parent
instead of using a stale route.

Each path must be an exact tracked or non-ignored untracked regular file linked
or owned by the selected route or its recursively declared dependencies.
Directory and ancestor widening is rejected before scope binding, worker
construction, or budget access. Ignored files, symlinks, `.git`, and
`.master-agent` are absent. Parent-only context is also excluded: `AGENTS.md`,
every `.ai` policy or manifest path, `docs/semantic-index.md`, and every
`.github/agents` profile.

The flow is:

```text
MasterAgent parent
    ↓
verified immutable-HEAD manifest/profile validation + repository-state binding
    ↓
private authenticated goal-budget reservation
    ↓
AdvisorySession.delegate + sanitize input
    ↓
CopilotSdkAdvisoryWorker
    ↓
exact task/profile/route/Git-content binding
    ↓
one isolated Copilot SDK session
    ↓
one explicitly preselected specialist + scoped repository-owned tools
    ↓
structured AdvisoryReport
    ↓
state recheck + parent citation revalidation
```

The SDK integration is deliberately not host inference. Each call supplies exactly one specialist and explicitly preselects it. Automatic config discovery is disabled, no skills or MCP servers are loaded, and SDK filesystem built-ins are not exposed. The session receives only the repository-owned `masteragent_read`, `masteragent_search`, and `masteragent_list` tools.

A pre-tool hook independently denies every other tool or malformed argument.
Each custom tool handler repeats the scope check before its read. Reads are
no-follow, stable, size-bounded UTF-8 operations; search is literal and bounded;
listing and search use only the immutable route inventory. Because those custom
tools need no ambient permission grant, the SDK permission handler rejects every
permission request as defense in depth.

## Goal budget

[`advisory_budget.py`](../src/master_agent/advisory_budget.py) reserves an
attempt before the SDK starts. The ignored `.master-agent/advisory/` directory
is mode `0700`; its random HMAC key and race-safe SQLite generations are mode
`0600`. A row stores only the SHA-256 goal identifier, repository identity
digest, two counters, and an authentication tag. The repository's pinned SQLite
layer serializes independent processes, so failures and retries cannot reset or
race past three research attempts and one plan review. Directory creation walks
a no-follow descriptor chain, so a symlinked state ancestor is rejected before
any key or database file is created.

The selected parent owns goal identity: it creates one opaque ID and reuses it
for the complete operator goal. A new ID means a new goal; changing IDs to evade
a limit violates the parent contract. This local integrity design does not
protect against an attacker who controls the same operating-system account and
can replace both the private key and all state while no runner is active.

## Technical route scope

The prompt's path list is descriptive; `AdvisoryPathScope` is the enforcement
boundary. It normalizes the requested entries, rejects traversal, root-wide,
private, ignored-only, and symlink scopes, inventories at most 512 eligible
files, and binds that inventory into the task. The SDK receives no ambient file
tool. A pathless search still operates only on the bound inventory, a direct
read must name one inventory file, and parent citation revalidation uses the
same scope.

## State binding

Before a live specialist starts, MasterAgent hashes five things without storing their contents:

- the sanitized task envelope;
- the exact selected route ID and canonical navigation slice;
- the exact checked-in specialist profile;
- the normalized technical path scope and eligible file inventory; and
- repository HEAD, raw stage-zero index entries, every tracked regular file's
  presence, mode, and raw content digest, untracked paths, and every non-ignored
  untracked regular file's content digest.

The first complete state scan yields both a digest and the exact HEAD object ID
inside that digest. The route and profile inventory are parsed from that
immutable commit, while any worktree manifest or profile drift fails closed.
Every commit, tree, and prompt-bearing blob is rehashed against its requested
Git object ID before parsing. A second complete state scan must match,
the worker requires that authorization digest to match its first scan, and the
route digest covers both the selected route slice and repository digest. The
repository digest itself remains outside the child prompt.

Each repository digest requires two matching complete scans. Git discovery is
pinned to the supplied worktree and cannot use content filters, replacement
refs, lazy fetch, ambient config, or any transport protocol. Git output,
untracked paths, file count, individual bytes, and total bytes have explicit
limits. Files are opened no-follow and their descriptor/path identity, size,
timestamps, and content are checked for races. Truncation, unreadable or special
files, excess, an object-address mismatch, a scan race, or any
task/profile/route/repository change before completion rejects the result and
returns the work to the parent.

## Result validation

The live specialist must return only:

```json
{
  "summary": "...",
  "findings": ["..."],
  "citations": ["relative/path.md"]
}
```

Extra authority-bearing fields are rejected. The result then enters the existing `AdvisoryReport` boundary, where target claims, approval claims, replacement plans, connector actions, secret-like content, and fabricated citations remain invalid. The selected parent independently re-reads cited repository files before treating the report as evidence.

## Failure and fallback

The GitHub Copilot SDK remains an optional integration. If it is not installed, authentication is unavailable, the SDK is incompatible, private budget state cannot be authenticated, a specialist or scoped tool fails, the repository changes during execution, or a per-goal budget is exhausted, the broker returns an explicit content-minimized parent fallback.

That fallback is successful degradation, not a setup failure. MasterAgent completes the same research or review directly and continues the operator's original goal. It does not switch to GitHub's generic `agent` tool, another MCP server, a direct API, or a provider-side workaround.

## Repository-owned integration harness

[`advisory.py`](../src/master_agent/advisory.py) remains the authoritative orchestration boundary and repository-owned integration harness. It enforces:

1. exactly one selected MasterAgent parent and two reviewed read-only specialist profiles;
2. depth one and one authenticated cross-process maximum of three research attempts and one plan review per operator goal;
3. rejection of credential, approval/signing, target, recipient, connector, tenant, private-context, and `ChangePlan` data before worker invocation;
4. repository-owned, route-scoped `read`, literal `search`, and file-listing implementations derived from the profile's read/search authority;
5. denial of shell, edit, nested-agent, MCP, HTTP, provider, environment, credential, approval, audit, and mutation categories;
6. bounded untrusted specialist reports; and
7. independent parent re-reading of every cited repository path.

## Hermetic end-to-end tests

[`test_advisory_integration.py`](../tests/test_advisory_integration.py) proves the deterministic broker boundary with hermetic repository and protected-state fixtures. [`test_advisory_budget.py`](../tests/test_advisory_budget.py) proves authenticated private state, restart persistence, consumed failure attempts, and tamper fallback. [`test_advisory_runner.py`](../tests/test_advisory_runner.py) starts independent and concurrent runner processes and mutates an already-untracked file during a live fake-SDK call. [`test_copilot_advisory.py`](../tests/test_copilot_advisory.py) proves exact Git transitions, scan limits, route-scoped handlers, ignored-file exclusion, immutable profile binding, clean-filter and replacement-ref denial, no lazy fetch, object-address verification, one-client/isolated-session reuse, role selection, ambient-discovery denial, malformed-output rejection, sensitive-context filtering, and optional-SDK fallback.

No live Copilot canary is bundled. A live SDK session is an optional execution adapter, not evidence that host-native inference or an unrestricted child path is safe. Pull-request security remains grounded in deterministic broker, release, packaging, dependency, security, and coverage validation.

## Documentation specialist contract

The Docs Agent remains a repository-owned specialist contract rather than a live writer child. Its authoritative instructions are in [`.ai/DOCS_AGENT.md`](../.ai/DOCS_AGENT.md).

Think of the Docs Agent as the person who checks an instruction manual after the product changes. That is only a mental model. Technically, the selected MasterAgent parent examines the final repository change, identifies affected documentation, applies the contract, validates the result, and reports what was updated or reviewed.

After implementation and tests for a non-trivial repository change, the selected MasterAgent parent applies the contract's `maintenance` mode directly. The Docs Agent may also operate in `authoring` and `audit` modes. Maintenance returns `updated`, `no_change`, or `needs_review`.

The implementation is evidence, but it is not automatically the final statement of intent. The Docs Agent compares accepted requirements, tests, architecture decisions, configuration, implementation, and existing documentation instead of rewriting prose to make an apparent defect look deliberate.

The Docs Agent classifies the intended audience, starts mixed-audience explanations in plain language, uses analogies only when they improve understanding, and never lets simplicity override technical accuracy.

A future writer adapter must use a separate patch-validation boundary. It must not inherit the read-only adapter and simply add `edit` or shell access.

## Authority boundary

Advisory output is untrusted data. It cannot select the final target, grant or claim approval, create or modify a runtime `ChangePlan`, resolve credentials, construct a provider connector, or trigger a provider operation.

The deterministic runtime remains the only path to capabilities, policy, governance, source-of-truth checks, authenticated approval, credentials, provider connectors, verification, compensation, retention, and audit.
