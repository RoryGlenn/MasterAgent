# Advisory Sub-agent Safety Boundary

MasterAgent has two read-only advisory specialists for repository research and independent plan review. The user still selects **MasterAgent**; the checked-in child profiles are not directly user- or model-invocable through GitHub's host agent mechanism.

Think of the specialists as consultants working through a controlled doorway. They can inspect the repository and return advice, but the MasterAgent parent controls the doorway, checks what information crosses it, and makes every final decision. Technically, that doorway is the repository-owned `AdvisoryBroker`.

## Profiles

| Specialist | Repository contract | Purpose |
|---|---|---|
| **MasterAgent Read Researcher** | `read`, `search` | Bounded repository investigation with cited evidence |
| **MasterAgent Plan Reviewer** | `read`, `search` | Independent review of a concrete implementation plan |

Neither specialist may edit files, execute shell commands, call providers, access credentials, grant approval, mutate audit state, construct a runtime `ChangePlan`, or invoke another agent.

## Two invocation paths

### GitHub host path remains disabled

Direct GitHub-host invocation is still fail-closed. The parent profile does not expose the generic `agent` tool, and both child profiles keep `user-invocable: false` and `disable-model-invocation: true`.

This matters because host-native inference does not pass through MasterAgent's repository-owned parent identity, depth, per-goal budgets, sensitive-context sanitizer, state binding, or report re-validation. Enabling those profiles directly would create a second orchestration control plane.

### Broker-owned Copilot SDK path

MasterAgent now has an optional live adapter in [`copilot_advisory.py`](../src/master_agent/copilot_advisory.py). When the `subagents` optional dependency is installed, the selected parent can run a Researcher or Plan Reviewer through [`scripts/advisory_subagent.py`](../scripts/advisory_subagent.py).

The flow is:

```text
MasterAgent parent
    ↓
AdvisorySession.delegate
    ↓
sanitize input + reserve role budget
    ↓
CopilotSdkAdvisoryWorker
    ↓
exact task/repository/profile binding
    ↓
one isolated Copilot SDK session
    ↓
one explicitly preselected read-only specialist
    ↓
structured AdvisoryReport
    ↓
state recheck + parent citation revalidation
```

The SDK integration is deliberately not host inference. Each call supplies exactly one specialist and explicitly preselects it. Automatic config discovery is disabled, no skills or MCP servers are loaded, and the session exposes only the documented read-only SDK tools `view`, `read_file`, `grep`, and `glob`.

A pre-tool hook independently denies every other tool and rejects file-like arguments that resolve outside the repository root. The SDK permission handler separately rejects shell-, write-, and MCP-like requests as defense in depth.

## State binding

Before a live specialist starts, MasterAgent hashes three things without storing their contents:

- the sanitized task envelope;
- the exact checked-in specialist profile; and
- repository HEAD, index, worktree, and untracked-file state.

The same values are checked again when the specialist finishes. If the repository or profile changed during the call, the result is rejected and the parent performs the work directly instead. This prevents a review of one repository state from being silently accepted for another.

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

The GitHub Copilot SDK remains an optional integration. If it is not installed, authentication is unavailable, the SDK is incompatible, a specialist fails, the repository changes during execution, or a per-goal budget is exhausted, the broker returns an explicit parent fallback.

That fallback is successful degradation, not a setup failure. MasterAgent completes the same research or review directly and continues the operator's original goal. It does not switch to GitHub's generic `agent` tool, another MCP server, a direct API, or a provider-side workaround.

## Repository-owned broker

[`advisory.py`](../src/master_agent/advisory.py) remains the authoritative orchestration boundary. It enforces:

1. exactly one selected MasterAgent parent and two reviewed read-only specialist profiles;
2. depth one, at most three research attempts, and at most one plan review per operator goal;
3. rejection of credential, approval/signing, target, recipient, connector, tenant, private-context, and `ChangePlan` data before worker invocation;
4. profile-derived repository `read` and `search` authority only;
5. denial of shell, edit, nested-agent, MCP, HTTP, provider, environment, credential, approval, audit, and mutation categories;
6. bounded untrusted specialist reports; and
7. independent parent re-reading of every cited repository path.

[`test_advisory_integration.py`](../tests/test_advisory_integration.py) proves the deterministic broker boundary. [`test_copilot_advisory.py`](../tests/test_copilot_advisory.py) additionally proves that the live adapter preselects one role, disables ambient extension discovery, exposes only read-only tools, denies outside-repository paths, rejects malformed output, rejects stale repository state, preserves pre-dispatch sensitive-context filtering, and falls back when the SDK is unavailable.

## Documentation specialist contract

The Docs Agent remains a repository-owned specialist contract rather than a live writer child. Its authoritative instructions are in [`.ai/DOCS_AGENT.md`](../.ai/DOCS_AGENT.md). After implementation and tests for a non-trivial repository change, the selected parent applies its `maintenance` mode directly.

The Docs Agent may also operate in `authoring` and `audit` modes. Maintenance returns `updated`, `no_change`, or `needs_review`. It classifies the intended audience, starts mixed-audience explanations in plain language, uses analogies only when they improve understanding, and never lets simplicity override technical accuracy.

A future writer adapter must use a separate patch-validation boundary. It must not inherit the read-only adapter and simply add `edit` or shell access.

## Authority boundary

Advisory output is untrusted data. It cannot select the final target, grant or claim approval, create or modify a runtime `ChangePlan`, resolve credentials, construct a provider connector, or trigger a provider operation.

The deterministic MasterAgent runtime remains the only path to capabilities, policy, governance, source-of-truth checks, authenticated approval, credentials, provider connectors, verification, compensation, retention, and audit.
