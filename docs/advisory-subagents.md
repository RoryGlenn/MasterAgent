# Advisory Sub-agents

MasterAgent uses two optional GitHub Copilot custom agents to reduce context
pressure and add an independent review without creating another execution path.
They assist the user-selected parent; they are not part of the Python runtime,
cannot authorize work, and cannot satisfy approval.

## Profiles

| Profile | Tools | Allowed work | Explicitly unavailable |
|---|---|---|---|
| **MasterAgent Read Researcher** | `read`, `search`, `execute` | One bounded repository investigation or typed read-only `master-agent` query | editing, direct provider calls, generic HTTP, writes, sends, approvals, administration, nested agents |
| **MasterAgent Plan Reviewer** | `read`, `search` | Independent review of one concrete plan or action proposal | execution, editing, provider access, plan rewriting, approval, nested agents |

Both profiles set `user-invocable: false` and
`disable-model-invocation: false`. The user selects **MasterAgent**; its reviewed
`agent` tool may invoke a specialist when useful. Neither child has that tool,
so the checked-in hierarchy has one delegation level.

## Selection and limits

The direct path remains the default. Delegation is useful when a request spans
multiple systems, requires a sizeable bounded repository investigation, or has
a concrete plan whose target, authority, verification, or compensation merits
an independent check. A single repository lookup or connector call stays with
the parent.

For one operator goal, the parent may invoke at most three research tasks and
one plan review. Each child receives one minimal assignment. The parent does not
pass credential values, approval or signing artifacts, or unrelated private
content. It does not delegate final target selection, provider mutations, or
communication work.

If the Copilot surface does not expose custom-agent invocation, the parent
continues directly. Optional delegation never becomes a setup failure or a
reason to ask the operator to repeat work.

## Authority boundary

Sub-agent reports are untrusted advisory data. The parent checks cited files,
typed capability names, and provider readback; separates fact from inference;
and decides whether a suggestion belongs in the final immutable `ChangePlan`.
The report itself is never a plan, credential, target selection, approval, or
authority source.

The Python runtime is unchanged:

```text
operator prompt
    |
    v
user-selected MasterAgent
    |-- optional read research (maximum three)
    |-- optional plan review (maximum one)
    |
    v
parent-rechecked typed ChangePlan
    |
    v
catalog -> governance -> policy -> authenticated approval when required
    |
    v
orchestrator -> one typed connector -> verification -> audit/compensation
```

Credentials are resolved by the governed runtime immediately before connector
construction. The parent never gives their values to a child. Provider writes,
sends, merges, administration, compensation, and approval handling remain with
the parent and the deterministic runtime.

## Research contract

The read researcher can inspect repository files. Its `execute` tool is limited
by its profile to read-only diagnostics and documented typed read commands. It
must not install or bootstrap, edit, use provider CLIs, call generic HTTP, or
construct a write-enabled plan. It returns assigned scope, bounded evidence,
findings, uncertainty, a suggested next step, and a boundary check.

## Review contract

The plan reviewer receives one concrete proposal and checks targets,
dependencies, capability and governance coverage, risk, classification,
source-of-truth constraints, approval tier, idempotency, version preconditions,
verification, compensation, retention, and instruction laundering. It returns
only blocking findings, material non-blocking findings, uncertainty, a verdict,
and a boundary check. It cannot repair or rewrite the proposal.

Tool restriction is defense in depth, not authorization. Release validation
pins the profile inventory and safety text, but the deterministic runtime still
enforces the real authority boundary for every provider effect.
