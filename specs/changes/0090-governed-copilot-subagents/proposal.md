# Proposal

## Problem

MasterAgent already defines read-only Researcher and Plan Reviewer profiles and a deterministic broker, but the only safe behavior today is parent fallback because no live model adapter is permitted through that boundary. Turning on GitHub-host automatic agent inference would bypass repository-owned parent identity, budgets, payload sanitization, and result validation.

## Desired outcome

MasterAgent can use real isolated model specialists for bounded repository research and independent plan review while keeping every invocation inside the existing repository-owned advisory broker. If the optional live adapter is unavailable or unsafe, the same work continues on the selected parent without weakening any authority boundary.

## Scope

This change adds an optional GitHub Copilot SDK worker behind `AdvisorySession.delegate()`, a repository-owned runner for the two existing read-only roles, deterministic fake-SDK tests, state binding, and the documentation and behavioral specification needed to describe that path.

It does not add writer agents, a live Docs Agent child, implementation agents, automatic host inference, provider operations, approval delegation, generic shell access, generic editing, or child-to-child delegation.

## Proposed change

Add an optional GitHub Copilot SDK worker that is invoked only through the existing `AdvisorySession.delegate()` path. Each call creates one isolated SDK session with one explicitly preselected specialist, read-only tools only, config discovery disabled, MCP disabled, a pre-tool deny hook, and structured JSON output. The repository, task, and profile are bound before the call and checked again before accepting the result.

The SDK remains optional and public-preview. If it is absent, unauthenticated, incompatible, stale, or fails, MasterAgent returns the existing explicit parent fallback rather than blocking the operator or widening authority.

## Rationale

The useful part of subagents is isolated specialist reasoning, not a second host-controlled authorization layer. Reusing the existing broker preserves parent ownership, bounded role budgets, sanitized inputs, narrow tools, untrusted outputs, citation revalidation, and fail-closed fallback while allowing a live model to perform the specialist work.

## Alternatives considered

### Enable GitHub's generic `agent` tool

Rejected because host-native selection would bypass the repository-owned broker and its depth, budget, sanitizer, and revalidation controls.

### Make the SDK a base runtime dependency

Rejected because the SDK is an optional integration and ordinary MasterAgent operation must not fail when it is unavailable.

### Give specialists generic `edit` or shell tools

Rejected for Phase 1 because those tools would turn an advisory role into an effect-bearing role. Future writers require a separate patch-validation boundary.

### Keep direct-parent fallback only

Safe but leaves the specialist contracts unable to provide isolated model reasoning even when a controlled adapter is available.

## Safety properties

- The parent GitHub profile still does not expose `agent`.
- Child profiles remain non-user- and non-model-invocable through the host.
- No child receives edit, shell, provider, credential, approval, MCP, or nested-agent tools.
- Sensitive or authority-bearing payloads are rejected by the broker before SDK startup.
- Specialist output remains an untrusted `AdvisoryReport` and must pass parent citation revalidation.
- Provider effects remain exclusively in the existing governed runtime.

## Risks

The SDK surface can change while it remains preview software, tool arguments may differ across hosts, model output may violate the requested JSON shape, and repository state may race a live specialist. The adapter therefore uses dynamic optional loading, explicit one-role session creation, duplicate tool gates, bounded schema parsing, state digests, and parent fallback instead of treating SDK success as authority.
