# Quickstart

This walkthrough gets a source checkout to a credential-free, verified local
result. It does not connect to Jira, GitHub, Microsoft, Reddit, or any other
provider, and it does not enable write actions.

You need Python 3.12 or newer and a checkout of this repository. Run every
command from the repository root.

## 1. Prepare the local runtime

Choose the command for your operating system.

### macOS or Ubuntu 24.04

```bash
python3 scripts/bootstrap_agent.py
```

### Native Windows 11 PowerShell

```powershell
py -3.12 scripts\bootstrap_agent.py
```

Bootstrap verifies the interpreter, builds a repository-local environment,
installs the lightweight core, and runs an offline install-readiness check. It
does not look for credentials or contact workplace systems.

The last `command:` line names the exact launcher to use. It is normally
`.venv/bin/master-agent` on macOS or Ubuntu and
`.venv\Scripts\master-agent.exe` on Windows. If an existing environment cannot
be trusted or reused, bootstrap preserves it and prints a digest-named
side-by-side launcher instead. Use that printed path in the following steps.

## 2. Check what is ready

On macOS or Ubuntu, the common-path command is:

```bash
.venv/bin/master-agent doctor
```

On native Windows:

```powershell
.\.venv\Scripts\master-agent.exe doctor
```

`doctor` is offline. It reports readiness as separate levels:

| Level | Meaning |
|---|---|
| `install_ready` | The local package and required platform contracts are usable. |
| `read_ready` | Selected read connectors have the required reviewed configuration. |
| `draft_ready` | Local draft rendering dependencies and paths are available. |
| `effect_ready` | Effect capabilities, credentials, policy, and approval infrastructure are ready. |
| `enterprise_ready` | The external controls required by the organization are present. |

A healthy local installation can have `install_ready: true` while every
provider remains disconnected and every effect stays off. That is the expected
safe starting state.

## 3. Run the local demonstration

The demonstration needs the optional draft-rendering packages. Install them
into the same managed environment, then run `demo`.

### macOS or Ubuntu 24.04

```bash
.venv/bin/python -m pip install -e '.[drafts]'
.venv/bin/master-agent demo
```

### Native Windows 11 PowerShell

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[drafts]"
.\.venv\Scripts\master-agent.exe demo
```

Use the side-by-side paths printed by bootstrap when they differ from `.venv`.

The command prints a unique `demo workspace:` path below the private
MasterAgent data root. It creates Jira and Confluence proposals, Outlook and
Teams drafts, a PowerPoint review deck, a repository patch, an integrity
manifest, and a local audit database. It then verifies the audit chain.

Expected safety signals include:

```text
mode: safe local demonstration (no credentials or provider writes)
mode: local generation
successful: True
verified 8 audit events
```

Nothing is sent, published, committed, or uploaded. On POSIX systems the
workspace lives below `~/.master-agent/MasterAgent/demo-*`; on native Windows
it lives below `%LOCALAPPDATA%\MasterAgent\demo-*`.

## 4. Try one anonymous provider read

A named GitHub user's public repositories need no credential:

```bash
.venv/bin/master-agent github-repositories --username USERNAME
```

For a public Bitbucket Cloud workspace:

```bash
.venv/bin/master-agent bitbucket-repositories --workspace WORKSPACE
```

These commands do contact the selected public provider. They do not resolve or
send ambient provider credentials, and they independently verify that returned
repositories are public.

## Install a release artifact instead

The steps above are for a source checkout. If you received a reviewed release
artifact, install it into a fresh private virtual environment and run the same
offline readiness check before configuring a provider.

### macOS or Ubuntu 24.04

From the wheel:

```bash
umask 077
python3 -m venv .venv
.venv/bin/python -m pip install ./master_agent-1.0.0-py3-none-any.whl
.venv/bin/master-agent readiness
.venv/bin/master-agent doctor --require-level install
```

From the source distribution:

```bash
tar -xzf master_agent-1.0.0.tar.gz
cd master_agent-1.0.0
umask 077
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/master-agent readiness
.venv/bin/master-agent doctor --require-level install
```

### Native Windows 11 PowerShell

From the wheel:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\master_agent-1.0.0-py3-none-any.whl
.\.venv\Scripts\master-agent.exe readiness
.\.venv\Scripts\master-agent.exe doctor --require-level install
```

From the source distribution:

```powershell
tar -xzf .\master_agent-1.0.0.tar.gz
Set-Location .\master_agent-1.0.0
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\master-agent.exe readiness
.\.venv\Scripts\master-agent.exe doctor --require-level install
```

For an internal or offline wheelhouse, keep index credentials in approved pip
configuration and use local paths on the command line. On macOS or Ubuntu:

```bash
.venv/bin/python -m pip install \
  --no-index \
  --find-links /approved/wheelhouse \
  ./master_agent-1.0.0-py3-none-any.whl
```

On native Windows:

```powershell
.\.venv\Scripts\python.exe -m pip install `
  --no-index `
  --find-links C:\ApprovedPackages `
  .\master_agent-1.0.0-py3-none-any.whl
```

The core artifact deliberately omits local Office renderers. Install
`master-agent[drafts]` from the same approved package source when you need
`demo` or `draft-package`; the base CLI and install-readiness check do not need
that extra. See [Phase 3 draft-only output](phase-3-drafts.md) for the exact
optional-extra procedure.

## Next steps

- Choose an outcome in [Use cases](use-cases.md).
- Use MasterAgent inside GitHub Copilot with the
  [custom-agent guide](copilot-custom-agent.md).
- Configure a provider with [Configuration](configuration.md) and the
  [deployment runbook](deployment-runbook.md).
- If setup or readiness stops, use [Troubleshooting](troubleshooting.md).
- See every guide in the [documentation index](index.md).
