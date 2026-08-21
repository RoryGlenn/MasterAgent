# Proposal

## Problem

The advisory profiles added by issue #74 were validated mostly through
frontmatter and required prompt substrings. The researcher still exposed a
generic `execute` tool, so injected repository or provider content could reach
shell, environment, credential, network, provider, or mutation surfaces despite
read-only prose.

## Desired outcome

Create a deterministic repository-owned integration boundary that loads the
checked-in profiles, technically admits only bounded read/search operations,
enforces parent/depth/call/context controls, re-validates child output, and
fails closed when the GitHub host cannot provide equivalent guarantees.

## Scope

- remove generic `execute` and active host delegation from advisory profiles;
- add a profile-derived read/search dispatcher and parent-bound broker;
- add hermetic adversarial fixtures and end-to-end integration tests;
- validate common profile and permission mutations;
- update durable security and contributor guidance;
- keep the deterministic runtime as the only provider-effect path.

## Rationale

Tool absence and deterministic dispatch are enforceable controls. Prompt wording
is not. The issue explicitly permits a repository-owned fail-closed boundary
when the host cannot enforce a parent allowlist, so the safe current behavior is
parent-direct execution plus tested future-adapter infrastructure.

## Alternatives considered

- Retaining `execute` with stronger prose was rejected because injected content
  could still invoke arbitrary commands.
- Keeping the parent `agent` tool while disabling only the children was rejected
  because it leaves an unsupported host routing surface and ambiguous failure
  behavior.
- Adding a live Copilot canary now was rejected because no disposable supported
  adapter can prove the required parent, counter, and tool-dispatch controls;
  security cannot depend on a probabilistic model observation.

## Non-goals

- model-obedience tests as authorization evidence;
- production credentials or provider mutation access;
- a general agent framework, shell, MCP, or HTTP dispatcher;
- changing runtime `ChangePlan`, policy, connector, approval, or audit semantics;
- making optional host availability a pull-request prerequisite.

## Risks

- advisory parallelism is unavailable until a supported adapter proves the
  repository contract;
- a custom adapter could drift from checked-in profiles unless it loads them at
  runtime and passes the same integration suite;
- overbroad payload filters may cause safe fallback to the parent, which is an
  intentional fail-closed tradeoff.
