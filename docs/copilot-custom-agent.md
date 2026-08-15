# GitHub Copilot Custom Agent

MasterAgent is available as a repository-scoped GitHub Copilot custom agent
through [`.github/agents/MasterAgent.agent.md`](../.github/agents/MasterAgent.agent.md).
The profile is the Copilot entry point; the Python package remains the governed
execution runtime.

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

   Depending on the Copilot client and its terminal policy, approve that one
   command if prompted. The script creates `.venv` only when needed, installs
   this project and its declared dependencies there without upgrading pip, and
   runs the offline readiness check. It may use the machine's configured Python
   package index, but it never accesses a workplace system.

4. Look for this plain-language confirmation:

   ```text
   MasterAgent is ready locally. Workplace connections and write actions are still off.
   ```

   The agent then continues the original request. The warning that no live
   connectors are enabled is the expected safe starting state.

For a read-only first interaction, say so explicitly: “Inspect the repository
without changing or installing anything.” MasterAgent will answer without
creating `.venv` or running pip.

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
  [first-run contract](../.ai/FIRST_RUN.md) before work begins;
- limits Copilot to repository read, search, edit, and command-execution tools;
- gives nontechnical users a stable success or blocked response and continues
  their original request after setup;
- requires enterprise operations to use the existing typed `master-agent`
  runtime rather than direct provider tools, CLIs, or generic HTTP; and
- preserves every capability, governance, approval, retention, audit, and live
  connector gate already enforced by the runtime.

The first ordinary prompt permits only the bounded `.venv` bootstrap above. It
never upgrades pip, installs globally or into the user site, uses `sudo` or an
OS package manager, modifies persistent `PATH`, provides credentials, enables
a connector, or grants approval. A tool appearing in Copilot means it is
available, not that MasterAgent is authorized to use it for an external side
effect.

Explicit read-only, diagnosis-only, and no-change instructions always take
precedence. In those modes, the agent inspects `python`, `python3`, pip, the
project script declaration, and `PATH`, then reports the missing prerequisite
without creating `.venv` or installing anything. Setup failures must be read
and reported rather than redirected to an uninspected log.

## If automatic setup is blocked

MasterAgent reports the exact prerequisite it could not satisfy and confirms
that nothing was connected or enabled. Common blockers are Python older than
3.12, a Python installation without the `venv` module, an existing incomplete
or symbolic-link `.venv`, or unavailable package-index access. The agent never
deletes or replaces an existing environment and never repairs the operating
system automatically.

A technical operator can run `python3 scripts/bootstrap_agent.py` directly to
see the same check. There is no need to activate `.venv`; all later commands
use `.venv/bin/master-agent` explicitly.

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

`python scripts/validate_release.py` fails if the profile is missing, malformed,
not user-invocable, automatically model-invocable, expanded to unreviewed tools,
detached from the required policy files, inconsistent with the first-run
contract, or missing the bounded bootstrap, stable response text, and read-only
safeguards. The source-distribution validation also requires the profile,
first-run contract, and bootstrap script to be packaged.
