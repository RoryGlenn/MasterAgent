# Design

## Approach

Keep the existing `AdvisoryBroker` as the authority boundary and implement the live model as an `AdvisoryWorker`. The adapter never becomes a second router. `AdvisorySession.delegate()` still sanitizes the payload, reserves the role budget, denies nested delegation, and converts adapter failure into explicit parent fallback.

The `CopilotSdkAdvisoryWorker` then creates exactly one isolated GitHub Copilot SDK session for the already-selected Researcher or Plan Reviewer. Host-native inference remains disabled.

## Architecture

```text
selected MasterAgent parent
        ↓
AdvisorySession.delegate
        ↓
sanitize payload + reserve role budget
        ↓
CopilotSdkAdvisoryWorker
        ↓
exact task/repository/profile binding
        ↓
one isolated Copilot SDK session
        ↓
one explicitly preselected read-only role
        ↓
structured AdvisoryReport
        ↓
repository/profile state recheck
        ↓
existing parent report + citation revalidation
```

## Affected components

- `src/master_agent/advisory.py` remains the broker and report authority boundary.
- `src/master_agent/copilot_advisory.py` provides the optional live SDK worker.
- `scripts/advisory_subagent.py` is the repository-owned invocation entry point used by the selected parent.
- `.github/agents/MasterAgent-Read-Researcher.agent.md` and `.github/agents/MasterAgent-Plan-Reviewer.agent.md` remain the reviewed role contracts; their direct host invocation flags do not change.
- `pyproject.toml` exposes the SDK only through the optional `subagents` extra.
- `tests/test_copilot_advisory.py` proves the adapter-specific isolation and fallback behavior.

## Data flow

1. The selected parent decides that bounded research or plan review is useful.
2. The parent calls the repository-owned advisory runner rather than GitHub's generic `agent` tool.
3. `AdvisorySession.delegate()` sanitizes the payload and reserves the existing per-goal role budget.
4. The worker hashes the sanitized task, selected profile, and repository state.
5. The worker creates one SDK session with one explicitly preselected specialist and only the read-only tool allowlist.
6. The specialist returns bounded JSON containing only `summary`, `findings`, and repository-relative `citations`.
7. The worker rechecks repository/profile/task state and rejects a stale result.
8. The result becomes the existing untrusted `AdvisoryReport`.
9. The selected parent independently rereads every cited repository file before using the findings.
10. Any unavailable, malformed, unsafe, or stale path returns through the existing direct-parent fallback.

## SDK isolation

The SDK client starts in `mode="empty"` at the repository root. The session exposes only the read-only built-in tools `view`, `read_file`, `grep`, and `glob`. The same allowlist is repeated in the custom-agent definition and `available_tools`. Automatic configuration discovery is disabled, skills are empty, MCP servers are empty, and only one specialist definition is supplied to the session.

A pre-tool hook denies every other tool and rejects file-like arguments that resolve outside the repository root. The permission handler independently rejects shell-, write-, and MCP-like request classes.

## Explicit specialist selection

The worker maps the broker-owned role to exactly one SDK agent name and passes it through the session's explicit `agent` selector. No host inference is needed or trusted. The checked-in GitHub custom-agent profiles remain fail-closed for direct user/model invocation.

## State binding

Before the SDK call, the adapter computes content-free digests for:

- the sanitized task envelope;
- the selected checked-in specialist profile; and
- repository HEAD, index, worktree, and untracked-file state.

After the call the same values are recomputed. Any difference rejects the result and returns through the broker's ordinary parent-fallback path. This prevents a specialist result from being accepted across a concurrent repository/profile race.

## Result contract

The specialist is instructed to return only JSON with `summary`, `findings`, and repository-relative `citations`. The adapter bounds response size and item counts and rejects extra fields. It converts accepted JSON into the existing `AdvisoryReport`; the parent still performs the existing authority-field, secret, and citation revalidation.

## Compatibility

The base `master-agent` installation remains unchanged. `github-copilot-sdk` is available only through the optional `subagents` extra and is imported dynamically when the live worker is invoked. Systems without that dependency, a usable Copilot authentication context, or a compatible SDK continue to use direct-parent advisory work.

No runtime `ChangePlan`, provider connector, approval, capability catalog entry, or existing child profile invocation flag changes in this phase.

## Security

- Sensitive or authority-bearing payload keys are rejected before SDK startup by the existing broker sanitizer.
- The adapter exposes no generic edit, shell, HTTP, MCP, provider, credential, approval, audit, or nested-agent tool.
- File-like SDK tool arguments must remain inside the repository root.
- Host config discovery, skills, and MCP discovery are disabled for the isolated session.
- Exactly one specialist is supplied and explicitly selected per session.
- Returned JSON cannot add target, approval, plan, or arbitrary extra fields.
- Repository and profile state are rebound after the call before accepting the report.
- Parent citation revalidation remains mandatory.
- Provider effects remain exclusively in the existing governed runtime.

## Rejected alternatives

### Generic GitHub `agent` delegation

Rejected because it would place host-native routing outside `AdvisoryBroker` and bypass repository-enforced budgets, sanitization, and result handling.

### Model-selected specialist fan-out

Rejected because required roles and limits must be chosen by MasterAgent's deterministic control plane, not model discretion.

### Writer tools in Phase 1

Rejected because adding `edit` or shell access would require a separate patch authority, path policy, precondition binding, and integration workflow.

### Mandatory SDK dependency

Rejected because preview-adapter availability must not become a prerequisite for ordinary MasterAgent use.

## Future phases

Writer specialists, Docs Agent patches, semantic security reviewers, and implementation agents are intentionally excluded. Any future writer must use a separate patch-validation boundary rather than inheriting this read-only worker unchanged.
