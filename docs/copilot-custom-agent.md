# GitHub Copilot Custom Agent

MasterAgent is available as a repository-scoped GitHub Copilot custom agent
through [`.github/agents/MasterAgent.agent.md`](../.github/agents/MasterAgent.agent.md).
The profile is the Copilot entry point; the Python package remains the governed
execution runtime.

New to the project? Use the [quickstart](quickstart.md) for the shortest safe
path or browse concrete prompts in [Use cases](use-cases.md). This guide is the
exact reference for the repository agent's setup, autonomy, advisory, and
approval boundaries.

## Use in an IDE

1. Open the repository root as the workspace. Opening only its parent directory
   does not use this repository's default `.github/agents` discovery location.
2. Open GitHub Copilot Chat and select **MasterAgent** from the agents dropdown.
   If it is hidden, open **Configure Custom Agents** and enable its eye icon.
3. Send any ordinary first prompt, for example:

   ```text
   Help me get started with MasterAgent and tell me what is safe to do.
   ```

   Before handling that request, MasterAgent says that it is preparing the
   runtime locally and runs one idempotent command:

   ```bash
   python3 scripts/bootstrap_agent.py
   ```

   In native Windows PowerShell, the equivalent command is
   `py -3.12 scripts\bootstrap_agent.py`; the managed interpreter and launcher
   are `.venv\Scripts\python.exe` and `.venv\Scripts\master-agent.exe`. Neither
   platform requires virtual-environment activation.

   Depending on the Copilot client and its terminal policy, approve that one
   command if prompted. The script creates `.venv` only when needed, installs
   this project and its declared dependencies there without upgrading pip, and
   runs the offline readiness check. It may use the machine's configured Python
   package index, but it never accesses a workplace system.

4. Look for this plain-language confirmation:

   ```text
   MasterAgent is ready locally. No workplace connection has been opened, and write actions are still off.
   ```

   The agent then continues the original request. Read connectors being
   available but inactive is the expected safe starting state.

5. For ordinary runtime work, the agent uses the private organization profile
   and capability-scoped checks:

   **Ubuntu 24.04, macOS, or WSL**

   ```bash
   .venv/bin/master-agent setup --non-interactive
   .venv/bin/master-agent doctor
   ```

   **Native Windows 11 PowerShell**

   ```powershell
   .\.venv\Scripts\master-agent.exe setup --non-interactive
   .\.venv\Scripts\master-agent.exe doctor
   ```

   These commands do not contact a workplace provider. A missing optional
   credential can make a selected read unavailable without making
   `install_ready` false. The profile's default `employee` mode exposes only
   installed, reviewed capabilities and keeps write and communication gates
   off. The report also names the selected platform backends. On Windows,
   imports, help/version, deployment readiness, and configuration-only
   `doctor --require-level install` remain available; any stateful capability
   whose secure backend is absent fails with `runtime_defect` and does not use
   a weaker fallback.

For a non-mutating first interaction, say so explicitly: “Inspect the
repository without changing or installing anything.” MasterAgent will answer
without creating `.venv` or running pip. A provider operation, feature, build,
or fix is an operational request, so the agent performs the bounded local
bootstrap when needed and continues to the requested outcome in the same run.

The repository profile is committed to the default branch, so supported
GitHub.com and Copilot CLI surfaces can discover it as well. In Copilot CLI,
use `/agent` and select **MasterAgent**. Use a current stable IDE and Copilot
extension; support in some IDEs remains a preview feature.

See GitHub's [custom-agent creation guide](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/cloud-agent/create-custom-agents-in-your-ide?tool=vscode)
and the [custom-agent configuration reference](https://docs.github.com/en/copilot/reference/custom-agents-configuration)
for product-level behavior and surface support.

## What the profile does

The profile:

- makes **MasterAgent** explicitly user-invocable while disabling automatic
  model invocation;
- loads [`AGENTS.md`](../AGENTS.md) and the authoritative
  [repository policy](../.ai/MASTER_AGENT.md), then applies the
  [first-run contract](../.ai/FIRST_RUN.md) and
  [force-multiplier contract](../.ai/AUTONOMY.md) before work begins;
- applies the [Docs Agent contract](../.ai/DOCS_AGENT.md) as a completion gate
  for non-trivial repository changes after implementation and tests;
- limits Copilot to repository read, search, edit, and command-execution
  tools; the parent profile does not expose direct custom-agent invocation;
- keeps both advisory profiles non-user- and non-model-invocable until a
  supported adapter can prove the repository-owned boundary;
- gives nontechnical users a stable success or blocked response, defaults to
  action, and owns setup, connection, implementation, repair, tests,
  documentation, and verification without repeated confirmation prompts;
- requires enterprise operations to use the existing typed `master-agent`
  runtime rather than direct provider tools, CLIs, or generic HTTP; and
- preserves every capability, governance, approval, retention, audit, and live
  connector gate already enforced by the runtime.

The GitHub Copilot **MasterAgent** profile and the runtime's `employee` or
`developer` organization-profile value solve different problems. The Copilot
profile governs repository work. The organization profile narrows what the
installed runtime may execute. Employee execution never writes missing
capability code. When a repository change is authorized, the selected Copilot
parent may implement that governed path in the development plane, but the code
still needs its tests, behavioral specification, documentation, review,
signing or release controls, and deployment before an employee profile can use
it. Selecting `developer` does not skip those controls or grant approval.

## Advisory sub-agents

The repository keeps **MasterAgent Read Researcher** and **MasterAgent Plan
Reviewer** as checked-in read/search-only contracts, but direct GitHub-host invocation is disabled. The current host cannot enforce the selected-parent
allowlist, deterministic depth-one routing, or the per-goal maximum of three
research attempts and one review. The parent profile therefore omits `agent`,
and both child profiles set `user-invocable: false` and
`disable-model-invocation: true`.

The repository-owned integration harness in
[`advisory.py`](../src/master_agent/advisory.py) exercises the exact profile
inventory, derives the child dispatcher from those profiles, minimizes context,
denies every effect-bearing tool before dispatch, and makes every report pass a
parent citation re-read. When the optional `subagents` extra is installed, the
current broker-owned adapter may instantiate one profile through
[`advisory_subagent.py`](../scripts/advisory_subagent.py) with an authenticated
cross-process goal budget, exactly one parent-selected `--route ROUTE_ID`, a
required minimum path route, repository-owned scoped read/search tools, and
route/tracked/staged/untracked-content binding. The runner parses the manifest
and exact profile inventory from content-address-verified objects at the
immutable HEAD revision inside that binding, rejects worktree manifest or
profile drift, and fully validates the exact route before worker construction. The
child receives only the selected route's canonical navigation fields—not the
agent registry, sibling prompts, full manifest, or generated index. That is not
direct GitHub-host invocation and is never a route to providers.

When the optional adapter is unavailable or a task fails closed, MasterAgent
completes the same work directly. It does not ask the operator to repeat the
request and never substitutes another host mechanism, MCP server, direct API,
or shell workaround. See the complete
[advisory and documentation specialist contracts](advisory-subagents.md).

## Documentation completion gate

For a non-trivial repository change, the selected MasterAgent parent applies
`maintenance` mode from [`.ai/DOCS_AGENT.md`](../.ai/DOCS_AGENT.md) after
implementation and tests but before declaring the work complete. The Docs Agent
is a repository-owned specialist contract, not an additional live GitHub-host
child profile.

The review compares the issue or task, accepted requirements, current
specifications, architecture decisions, tests, implementation, configuration,
and existing documentation. It classifies the intended audience and document
lifecycle, searches for indirect terminology and command impact, and then
updates only documentation that became inaccurate, incomplete, misleading, or
hard to use.

A result of `updated` means affected documentation changed. A justified
`no_change` means the relevant documents were reviewed and remain correct. A
material conflict returns `needs_review` to planning or implementation; the
parent does not make an apparent defect official by rewriting documentation to
match it.

For mixed audiences, the documentation starts with a plain-language
explanation and progressively introduces the exact technical detail needed to
act correctly. An analogy is optional, must improve understanding, and is
always followed by the literal technical explanation.

The first ordinary prompt permits only the bounded `.venv` bootstrap above. It
never upgrades pip, installs globally or into the user site, uses `sudo` or an
OS package manager, modifies persistent `PATH`, provides credentials, enables
a connector, or grants approval. A tool appearing in Copilot means it is
available, not that MasterAgent is authorized to use it for an external side
effect.

Repository-inspection, diagnosis-only, and explicit no-local-change
instructions always take precedence. In those modes, the agent inspects
the available Python launchers, pip, the project script declaration, and
`PATH`, then
reports the missing prerequisite without creating `.venv` or installing
anything. Setup failures must be read and reported rather than redirected to an
uninspected log.

The default response to an actionable prompt is execution. MasterAgent searches
existing context, chooses safe reasonable defaults, runs every ordinary
in-scope prerequisite, and resolves errors rather than handing commands back to
the operator. A capability gap that can safely be filled in this repository is
implementation work: add the typed capability and regression tests, then
continue the original request.

“No governed capability exists” and “the connector is read-only” are diagnosis,
not valid final responses to an actionable request. The agent must implement
the minimum complete Python connector path, typed catalog and governance
entries, factory and planner wiring, verification or compensation, tests, and
documentation before asking for external input. It then resumes the original
provider operation in the same run.

For example, given `create a Kanban board for me and create the first todo
item`, the agent should use safe names such as `Kanban Board` and `First todo
item`, inspect Jira for a unique usable project, and implement missing Jira
board and issue capabilities immediately. If a project cannot be selected
unambiguously, the agent completes and validates the local implementation
first, then asks one project-target question instead of returning a hypothetical
implementation checklist.

The behavior is universal rather than Jira- or connector-specific. Any missing
in-scope connector, planner, workflow, adapter, policy binding, verifier,
compensation path, renderer, or CLI capability must be implemented on the spot,
validated, and resumed. Security and authority requirements still apply, but
missing local code is never the final blocker.

For an outcome that requires authenticated provider access, the request itself
authorizes the minimum selected read connector, fixed probe, and provider
network access in memory without a second confirmation. Use
`master-agent connect --systems <requested-systems>` for Jira, Confluence,
Bitbucket, authenticated GitHub, Microsoft identity, SharePoint, Outlook,
Teams, or OneNote; then continue the requested feature. The connector setting
is never persisted unless persistent setup was requested.

Credential files may use canonical, provider-keyed, exact environment-name, or
unambiguous friendly-key forms. Infer friendly mappings only from key names. If
a key is ambiguous, ask once what it represents and retry `connect` with
`--credential-map FILE_KEY=DECLARED_NAME`; never inspect a secret value to
guess, and never rewrite the credential file merely to change its wrapper.
When Jira or Confluence Cloud is selected, the runtime may reuse a missing
Atlassian account email from the other configured product in memory. A legacy
static tenant-root configuration may also reuse one unscoped API-token pair.
Scoped `api.atlassian.com/ex/{product}/{cloudId}` configurations require an
explicit token for each product. The selected product's explicit names take
precedence, the other connector remains inactive, and the provider probe—not
the JSON key label—decides whether access exists.

If the operator supplies a Jira or Confluence Cloud page or site URL, pass it
as `--connector-url SYSTEM=URL` instead of stopping at the packaged placeholder
or creating a persistent configuration. The runtime reduces the UI URL to a
validated Atlassian tenant browser origin and preserves any configured scoped
API gateway root. Reuse that exact argument for `bind-context` and
`run --apply` so both destinations remain approval-bound.
Data Center deployments still require an explicitly reviewed context root.

GitHub repository discovery is routed by the data the operator requested. When
the operator names a GitHub user or supplies a public profile URL, extract the
username and run:

```bash
master-agent github-repositories --username USERNAME
```

That credential-free typed route reads only public repositories and never
resolves, searches for, or requests a GitHub token. Use the authenticated route
only for “my repositories,” private repositories, or other account-visible
results.

For a named public Bitbucket Cloud workspace, run:

```bash
master-agent bitbucket-repositories --workspace WORKSPACE
```

This credential-free typed route ignores ambient Bitbucket credentials,
returns only repositories explicitly marked public, and independently verifies
the bounded result.

An explicit request to create, update, send, publish, push, or merge is not
followed by redundant conversational permission prompts. MasterAgent prepares
and validates the exact outcome automatically. If policy requires
authenticated exact-plan approval that the agent cannot create, it asks once
at that final unavoidable boundary. Before binding, it includes the private
operator-controlled approval-authority configuration so the plan remains
resumable. The blocked run emits a mode-`0600` request under its approved
artifact root; MasterAgent uses `inspect-approval-request` to summarize that
one exact effect. A trusted operator creates the authenticated artifact with
`approve-request`, never the agent. Once supplied, MasterAgent calls
`resume-approval`, which restores the original connector URLs, credential
mappings, paths, gates, and any partial dual approval without rebuilding the
apply command. A chat response is direction, not authenticated approval, and
the agent never self-signs or bypasses approval.

## If automatic setup is blocked

Only after safe alternatives are exhausted, MasterAgent reports the exact
prerequisite it could not satisfy and confirms what remained unchanged. Common
blockers are Python older than 3.12, a Python installation without the `venv`
module, exhaustion of the bounded safe side-by-side environment names, or
unavailable package-index access. The agent never deletes, executes, or
replaces an unverified existing environment and never repairs the operating
system automatically.

A technical operator can run `python3 scripts/bootstrap_agent.py` on POSIX or
`py -3.12 scripts\bootstrap_agent.py` in native Windows PowerShell to see the
same check. There is no need to activate `.venv`; later commands use
the exact launcher printed on bootstrap's final `command:` line. That is
`.venv/bin/master-agent` on POSIX or
`.venv\Scripts\master-agent.exe` on Windows when the primary path is safe, and
the digest-named side-by-side equivalent when bootstrap preserves a collision.

## Scope

This profile is repository-scoped. Cloning the repository makes it available
only while the repository root is open. A user-level profile under
`~/.copilot/agents` would be available in every workspace, but distributing or
installing one is a separate product decision because its source, update, and
trust boundaries differ from this repository-controlled profile.

No separate MCP server is required for discovery or the initial integration.
The custom agent uses documented `master-agent` commands for governed runtime
operations. A future MCP transport should be considered only if it can expose
the same typed capability surface without creating a bypass around immutable
plans, approvals, provider gates, or audit evidence.

## Validation

`python scripts/validate_release.py` fails if the parent profile is missing,
malformed, not user-invocable, automatically model-invocable, expanded beyond
its reviewed read/search/edit/execute tools, detached from required policy, or
missing its bounded bootstrap and fail-closed advisory safeguards. It pins the
exact three-profile inventory, disables direct child user/model invocation,
requires read/search-only child tools, and checks the repository-owned harness,
adversarial fixtures, and integration tests in the source distribution.

[`tests/test_docs_agent_contract.py`](../tests/test_docs_agent_contract.py)
independently pins the Docs Agent methodology, audience and analogy rules,
evidence-conflict behavior, lifecycle and scope boundaries, structured result,
direct-parent execution model, and parent instruction integration.
