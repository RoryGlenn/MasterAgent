# Proposal

## Problem

MasterAgent already defines read-only Researcher and Plan Reviewer profiles and a deterministic broker, but the only safe behavior today is parent fallback because no live model adapter is permitted through that boundary. Turning on GitHub-host automatic agent inference would bypass repository-owned parent identity, budgets, payload sanitization, and result validation.

## Proposed change

Add an optional GitHub Copilot SDK worker that is invoked only through the existing `AdvisorySession.delegate()` path. Each call creates one isolated SDK session with one explicitly preselected specialist, read-only tools only, config discovery disabled, MCP disabled, a pre-tool deny hook, and structured JSON output. The repository, task, and profile are bound before the call and checked again before accepting the result.

The SDK remains optional and public-preview. If it is absent, unauthenticated, incompatible, or fails, MasterAgent returns the existing explicit parent fallback rather than blocking the operator or widening authority.

## Safety properties

- The parent GitHub profile still does not expose `agent`.
- Child profiles remain non-user- and non-model-invocable through the host.
- No child receives edit, shell, provider, credential, approval, MCP, or nested-agent tools.
- Sensitive or authority-bearing payloads are rejected by the broker before SDK startup.
- Specialist output remains an untrusted `AdvisoryReport` and must pass parent citation revalidation.
- Provider effects remain exclusively in the existing governed runtime.

## Non-goals

This change does not add writer agents, a live Docs Agent child, implementation agents, automatic host inference, provider operations, or approval delegation.
