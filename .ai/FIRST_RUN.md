# MasterAgent First-Run Contract

This file defines the repository-local setup behavior for the MasterAgent
GitHub Copilot custom agent. It is subordinate to
[`MASTER_AGENT.md`](MASTER_AGENT.md): setup prepares the local Python runtime
but never grants enterprise authority.

## Trigger

After reading [`AGENTS.md`](../AGENTS.md) and
[`MASTER_AGENT.md`](MASTER_AGENT.md), apply this contract to the first operator
prompt in each MasterAgent chat.

- If the prompt explicitly requests read-only inspection, diagnosis only, or no
  changes, do not create or modify `.venv` and do not install anything. Inspect
  prerequisites without mutation, answer the request, and identify any missing
  prerequisite precisely.
- For every other prompt, make one transparent first-run attempt before doing
  substantive work. Tell the operator: **“I’m preparing MasterAgent locally;
  this does not connect to workplace systems.”** Then run:

  ```bash
  python3 scripts/bootstrap_agent.py
  ```

The script is idempotent. It reuses a valid repository-local `.venv`, installs
only when the local runtime is absent or its project metadata changed, and runs
the offline `master-agent readiness` check. Depending on the Copilot client and
its terminal policy, the operator may need to approve this one command.

## Bounded setup

The first-run attempt may only:

1. verify that the invoking `python3` is version 3.12 or newer;
2. reject an unsafe, incomplete, or symbolic-link `.venv` rather than replace
   or delete it;
3. create `.venv` with Python's standard `venv` module when it is absent;
4. install this repository and its declared dependencies into that `.venv`
   without upgrading pip; and
5. run `.venv/bin/master-agent readiness`, which performs no provider network
   requests.

Package installation may contact the Python package index already configured
for the machine. It must never use `sudo`, an operating-system package manager,
a global or user-site install, a persistent `PATH` change, or a pip upgrade. If
Python, `venv`, pip, package-index access, or another prerequisite is missing,
stop and report the exact blocker. Do not attempt to repair the operating
system, replace an existing environment, or hide setup failures.

Setup never supplies credentials, enables connectors or runtime gates, changes
permissions outside `.venv`, accesses a workplace provider, grants approval,
sends content, or performs an enterprise mutation.

## Response contract

Keep the first-run response useful to a nontechnical operator:

- On success, say: **“MasterAgent is ready locally. Workplace connections and
  write actions are still off.”** Summarize readiness in plain language, then
  continue with the operator's original request.
- If setup is blocked, say: **“I couldn't finish local setup.”** Name the exact
  missing prerequisite and the smallest manual action needed. Confirm that
  nothing was connected or enabled. Do not ask the operator to activate a
  virtual environment or repeat commands the agent can run itself.
- Treat the normal warning that no live connectors are enabled as the expected
  safe starting state, not as a failed installation.
- Do not dump raw installer output into the conversational summary. Inspect the
  output, quote only the relevant error, and keep the complete tool result
  available for technical troubleshooting.
