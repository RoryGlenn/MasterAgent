# MasterAgent First-Run Contract

This file defines the repository-local setup behavior for the MasterAgent
GitHub Copilot custom agent. It is subordinate to
[`MASTER_AGENT.md`](MASTER_AGENT.md): setup prepares the local Python runtime
but never grants enterprise authority. After setup, apply the default-to-action
and response rules in [`AUTONOMY.md`](AUTONOMY.md).

## Trigger

After reading [`AGENTS.md`](../AGENTS.md) and
[`MASTER_AGENT.md`](MASTER_AGENT.md), apply this contract to the first operator
prompt in each MasterAgent chat.

- If the prompt requests only repository inspection, diagnosis, or explicitly
  no local changes, do not create or modify `.venv` and do not install anything.
  Inspect prerequisites without mutation, answer the request, and identify any
  missing prerequisite precisely.
- A requested provider operation, feature, build, or fix is an ordinary
  operational prompt. Perform this bounded local setup when needed, then
  continue the complete outcome in the same run under `AUTONOMY.md`.
- For every other prompt, make one transparent first-run attempt before doing
  substantive work. Tell the operator: **“I’m preparing MasterAgent locally;
  this does not connect to workplace systems.”** Then run:

  **Ubuntu 24.04 or macOS**

  ```bash
  python3 scripts/bootstrap_agent.py
  ```

  **Native Windows 11 PowerShell**

  ```powershell
  py -3.12 scripts\bootstrap_agent.py
  ```

The script is idempotent. It reuses a bootstrap-managed local runtime only when
a versioned attestation matches the current source, dependency policy, project
version, interpreter, launcher, distribution identities, and installed files.
The bootstrap process verifies POSIX permissions/ACLs or retained Windows
DACLs and hashes installed files before it executes the isolated interpreter
probe; the probe disables site initialization and imports no environment code.
A pre-existing
repository-local `.venv` with a legacy marker, missing or mismatched
attestation, broken probe, or unsafe object is never executed or rewritten.
Bootstrap leaves it untouched and creates a digest-named side-by-side managed
environment instead.
The final `command:` line names the exact launcher to use afterward, including
the side-by-side path when a collision was preserved.

## Bounded setup

The first-run attempt may only:

1. verify that the invoking Python interpreter is version 3.12 or newer;
2. independently attest an existing environment, or leave an unsafe,
   incomplete, legacy, altered, symbolic-link, or unverifiable `.venv`
   untouched and select a fresh side-by-side environment;
3. create `.venv` with Python's standard `venv` module when it is absent;
4. install this repository and its declared dependencies into that `.venv`
   without upgrading pip; and
5. run the native console launcher—`.venv/bin/master-agent` on POSIX or
   `.venv\Scripts\master-agent.exe` on Windows—with
   `doctor --require-level install`, which performs no provider network
   requests.

Package installation may contact the Python package index already configured
for the machine. It must never use `sudo`, an operating-system package manager,
a global or user-site install, a persistent `PATH` change, or a pip upgrade. If
Python, `venv`, pip, package-index access, or another prerequisite is missing,
exhaust safe repository-local alternatives before reporting the exact blocker.
Do not repair the operating system or replace an existing environment.

For an internal or offline installation, `--install-source` accepts a local
source tree, wheel, or source archive. Combine `--no-index` with one or more
local `--find-links DIRECTORY` values to resolve dependencies without a public
index. Index credentials stay in organization-managed pip configuration and
must not be placed on the command line.

Read connectors are available but inactive during setup. Setup never supplies
credentials, activates a connector, enables mutation or communication gates,
changes permissions outside `.venv`, accesses a workplace provider, grants
approval, sends content, or performs an enterprise mutation.

Bootstrap also does not select a trusted developer mode or admit generated
capabilities. The installed CLI may subsequently run its dedicated
`master-agent setup` and `master-agent doctor` employee workflow; those commands
remain offline, treat optional provider credentials as level-specific gaps,
and grant no provider, effect, approval, or code-promotion authority.

The bounded setup installs the lightweight core. A task that needs local
PowerPoint or draft rendering may install the declared `.[drafts]` extra later;
that extra is not required for readiness or direct provider reads. PowerPoint
generation remains outside the high-level employee allowlist until its optional
in-process import is isolated from ambient project modules.

## Response contract

Keep the first-run response useful to a nontechnical operator:

- On success, say: **“MasterAgent is ready locally. No workplace connection has
  been opened, and write actions are still off.”** Summarize readiness in plain language, then
  continue with the operator's original request.
- If setup is blocked, say: **“I couldn't finish local setup.”** Name the exact
  missing prerequisite and the smallest manual action needed. Confirm that
  nothing was connected or enabled. Do not ask the operator to activate a
  virtual environment or repeat commands the agent can run itself.
- Treat available connectors without credentials as the expected safe starting
  state, not as a failed installation or an active workplace connection.
- When a capability-scoped summary is useful, explain `install_ready`,
  `read_ready`, `draft_ready`, `effect_ready`, and `enterprise_ready`
  independently. Do not present local installation success as effect or
  enterprise approval.
- Do not stop after local readiness when the original prompt requested an
  operation. Continue through setup, connection, implementation, validation,
  and verification needed for the requested outcome under the force-multiplier
  contract.
- Do not dump raw installer output into the conversational summary. Inspect the
  output, quote only the relevant error, and keep the complete tool result
  available for technical troubleshooting.
