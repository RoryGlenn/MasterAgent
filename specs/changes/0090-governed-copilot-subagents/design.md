# Design

## Architecture

The existing `AdvisoryBroker` remains the authority boundary. The new `CopilotSdkAdvisoryWorker` implements the existing `AdvisoryWorker` protocol; it does not replace the broker and is never directly user-selectable.

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

## SDK isolation

The SDK client starts in `mode="empty"` at the repository root. The session exposes only documented read-only built-in tools: `view`, `read_file`, `grep`, and `glob`. The same allowlist is repeated in the custom-agent definition and `available_tools`. Automatic configuration discovery is disabled, skills are empty, MCP servers are empty, and only one specialist definition is supplied to the session.

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

## Optional dependency boundary

`github-copilot-sdk` remains optional because it is a public-preview integration. MasterAgent imports it only when the live worker is actually invoked. Missing or incompatible SDK installations therefore produce an explicit fallback rather than making the base runtime fail to import or start.

## Future phases

Writer specialists, Docs Agent patches, semantic security reviewers, and implementation agents are intentionally excluded. Any future writer must use a separate patch-validation boundary rather than inheriting this read-only worker unchanged.
