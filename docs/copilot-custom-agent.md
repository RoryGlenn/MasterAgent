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
3. Ask MasterAgent to run a documented command, for example:

   ```text
   Run the repository's documented readiness check and summarize the result.
   ```

   If the command is unavailable and the request permits local setup,
   MasterAgent creates `.venv`, installs this project and its declared
   dependencies there, and runs `.venv/bin/master-agent readiness`. It uses
   `python3`, so a system without a `python` alias still works. The equivalent
   manual commands are:

   ```bash
   python3 -m venv .venv
   .venv/bin/python -m pip install -e .
   .venv/bin/master-agent readiness
   ```

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
  [repository policy](../.ai/MASTER_AGENT.md) before work begins;
- limits Copilot to repository read, search, edit, and command-execution tools;
- requires enterprise operations to use the existing typed `master-agent`
  runtime rather than direct provider tools, CLIs, or generic HTTP; and
- preserves every capability, governance, approval, retention, audit, and live
  connector gate already enforced by the runtime.

The profile may perform the bounded `.venv` bootstrap above when the operator
asks it to run a documented command. It never upgrades pip, installs globally
or into the user site, uses `sudo` or an OS package manager, modifies persistent
`PATH`, provides credentials, enables a connector, or grants approval. A tool
appearing in Copilot means it is available, not that MasterAgent is authorized
to use it for an external side effect.

Explicit read-only, diagnosis-only, and no-change instructions always take
precedence. In those modes, the agent inspects `python`, `python3`, pip, the
project script declaration, and `PATH`, then reports the missing prerequisite
without creating `.venv` or installing anything. Setup failures must be read
and reported rather than redirected to an uninspected log.

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
detached from the required policy files, or missing the bounded bootstrap and
read-only safeguards. The source-distribution validation also requires the
profile to be packaged.
