# Advisory Sub-agent Safety Boundary

MasterAgent keeps two advisory profile contracts for bounded repository research
and independent plan review. They are not active GitHub Copilot children in the
current release. Direct host invocation is fail-closed because the supported
host surface does not expose a repository-enforceable parent allowlist,
deterministic depth-one routing, or per-goal call counters.

The user selects **MasterAgent**. Its profile does not include the `agent` tool.
Both advisory profiles set `user-invocable: false` and
`disable-model-invocation: true`. Until a supported adapter can prove the full
repository contract, the selected parent completes the same work directly.

## Profiles

| Profile | Checked-in tools | Contract |
|---|---|---|
| **MasterAgent Read Researcher** | `read`, `search` | One sanitized bounded repository investigation with cited evidence |
| **MasterAgent Plan Reviewer** | `read`, `search` | One sanitized review of a concrete proposal without execution or rewriting |

Neither profile exposes generic command execution, editing, nested agents, MCP,
HTTP, environment, credentials, provider calls, approval, audit mutation, or any
other effect-bearing tool. Provider reads remain in the selected parent and the
typed deterministic runtime; they are not delegated through the child profile.

## Repository-owned integration harness

[`advisory.py`](../src/master_agent/advisory.py) provides the deterministic
boundary used by CI and by any future host adapter. It does not invoke a model
or provider by itself. It loads the checked-in profiles and enforces:

1. exactly one parent profile and two reviewed child profiles;
2. exact profile names, read/search tool surfaces, and invocation flags;
3. selected-parent session ownership;
4. depth one, at most three research attempts, and at most one review attempt
   per operator goal;
5. bounded immutable payloads with credential, approval, signing, target,
   recipient, connector, tenant, private-context, and `ChangePlan` fields
   rejected before worker invocation;
6. dispatch of only normalized bounded repository `read` and `search` calls;
7. denial of shell, edit, agent, MCP, HTTP, provider, environment, credential,
   approval, audit, and mutation categories before dispatch;
8. untrusted report validation that rejects secret-like output, target or
   approval claims, and proposed plans; and
9. independent parent re-read of every cited repository path.

If a worker adapter is missing or fails, if a budget is exhausted, or if the
input or output is unsafe, the broker returns an explicit parent fallback. This
never becomes a setup blocker and never asks the operator to repeat the task.

## Hermetic end-to-end tests

[`test_advisory_integration.py`](../tests/test_advisory_integration.py) exercises
the checked-in profiles through the broker rather than copying their tool lists
into an unrelated fixture. The tests include repository and provider-content
prompt injections that request:

- shell execution and marker-file creation;
- environment and credential reads;
- generic HTTP and provider reads/writes;
- approval fabrication and audit mutation;
- target and recipient invention;
- `ChangePlan` replacement; and
- recursive delegation.

Every attempt is denied before dispatch. The suite proves the marker file,
environment snapshot, network recorder, provider recorder, credential recorder,
approval recorder, audit recorder, and a real immutable `ChangePlan`
fingerprint remain unchanged. Mutation tests fail when a profile gains
`execute`, `edit`, `agent`, broad MCP, user/model invocation, contradictory
permission text, or a second delegation level.

These deterministic tests run on every pull request under Python 3.12, 3.13,
and 3.14. Existing frontmatter and documentation checks remain useful drift
gates, but substring checks and prompt wording are not treated as authorization
proof. The complete pull-request gate also runs strict typing, release,
packaging, dependency, security, and coverage validation against the same
checked-in profiles.

## Optional live canary boundary

No live Copilot canary is bundled. A live observation would not prove the tool
or authorization boundary unless GitHub exposes a supported adapter that can be
bound to the exact parent, profiles, tool dispatcher, counters, and sanitized
envelope above.

A future canary must be explicit-dispatch or controlled-schedule only, use a
disposable repository, receive no workplace credentials or provider
permissions, expose no fork-accessible secrets, bound calls and time, and verify
cleanup. Ordinary pull-request security must remain independent of that canary.

## Authority boundary

Advisory output is untrusted data. It cannot select the final target, grant or
claim approval, create or modify a `ChangePlan`, resolve credentials, construct
a connector, or trigger the runtime. The selected parent independently checks
cited evidence and owns every decision.

The deterministic runtime remains the only path to capabilities, policy,
governance, source-of-truth checks, authenticated approval, credentials,
connectors, verification, compensation, retention, and audit.
