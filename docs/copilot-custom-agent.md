# GitHub Copilot Custom Agent

MasterAgent is available as a repository-scoped GitHub Copilot custom agent
through [`.github/agents/MasterAgent.agent.md`](../.github/agents/MasterAgent.agent.md).
The profile is the Copilot entry point; the Python package remains the governed
execution runtime.

## Use in an IDE

1. Open the repository root as the workspace. Opening only its parent directory
   does not use this repository's default `.github/agents` discovery location.
2. Install the runtime in a Python 3.12 or newer virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -e .
   master-agent readiness
   ```

3. Open GitHub Copilot Chat and select **MasterAgent** from the agents dropdown.
   If it is hidden, open **Configure Custom Agents** and enable its eye icon.

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

The profile does not install Python dependencies, provide credentials, enable a
connector, or grant approval. A tool appearing in Copilot means it is available,
not that MasterAgent is authorized to use it for an external side effect.

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
or detached from the required policy files. The source-distribution validation
also requires the profile to be packaged.
