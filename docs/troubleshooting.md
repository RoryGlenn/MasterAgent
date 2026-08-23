# Troubleshooting

Start with the symptom you can see. MasterAgent fails closed, so many failures
mean a safety prerequisite is missing or changed—not that the runtime is
partially executing in the background.

Never paste credentials, OAuth tokens, approval artifacts, or provider content
into an issue or chat while troubleshooting.

## Fast diagnosis

| Symptom | First check | What it usually means |
|---|---|---|
| Bootstrap reports `setup_status: blocked` | Read the exact `reason:` line | Python, environment identity, permissions, or package access did not meet the local trust contract. |
| `doctor` says install-ready but not read-ready | Inspect the named provider level | The local package works; reviewed provider configuration or credentials are intentionally absent. |
| `demo` reports missing imports | Install `.[drafts]` into the same managed environment | The lightweight core omits local Office renderers. |
| A public GitHub or Bitbucket read asks for credentials | Confirm the anonymous command form | A public named-user/workspace route must not resolve ambient credentials. |
| An effect returns an approval request | Inspect the request; do not re-plan | Policy requires an authenticated artifact bound to that exact plan. |
| A write stops on stale state | Re-read and prepare a new plan | Provider state changed after review; the old approval must not be reused. |
| A capsule cannot run on macOS | Check the platform report | Pure capsule execution currently needs Linux bubblewrap or Windows AppContainer. |
| A recurring occurrence is indeterminate | Use inspect/reconcile; never force | The runtime cannot prove whether an earlier process crossed the effect boundary. |

## Bootstrap is blocked

Run the platform command from the repository root and read its final lines:

```bash
python3 scripts/bootstrap_agent.py
```

```powershell
py -3.12 scripts\bootstrap_agent.py
```

Common reasons include:

- Python is older than 3.12 or lacks `venv`/pip support;
- the selected environment or interpreter is writable by a principal outside
  the trust profile;
- an existing `.venv` is a link, incomplete, altered, or otherwise cannot be
  attested;
- every bounded side-by-side environment name is already occupied; or
- required packages cannot be resolved from the configured index or approved
  wheelhouse.

Bootstrap preserves an untrusted existing environment rather than deleting or
executing it. When it succeeds with a side-by-side environment, use the exact
launcher from its final `command:` line. Do not repair shared operating-system
permissions by making them broader; use a Python installation whose executable
and ancestors satisfy your local or organization trust policy.

See [GitHub Copilot custom agent: automatic setup](copilot-custom-agent.md#if-automatic-setup-is-blocked)
for the full contract.

## Local setup works, but a provider is not ready

Run the offline readiness report:

```bash
master-agent doctor
```

Then inspect the level that matches the requested outcome. Missing optional
credentials do not make `install_ready` false. A provider stays inactive until
the goal selects it, the organization profile permits it, its reviewed
configuration is valid, and any required credential is supplied through the
governed credential path.

Use [Configuration](configuration.md) for exact variable names and the
[deployment runbook](deployment-runbook.md) for the activation sequence.

## The local demonstration cannot render drafts

Install the optional renderer set into the same environment as the launcher:

```bash
.venv/bin/python -m pip install -e '.[drafts]'
.venv/bin/master-agent demo
```

On Windows, use `.venv\Scripts\python.exe` and
`.venv\Scripts\master-agent.exe`. If bootstrap printed a side-by-side path, use
that path instead. The base installation is intentionally usable without these
packages.

## A public repository read is asking for a token

Use the explicitly anonymous commands:

```bash
master-agent github-repositories --username USERNAME
master-agent bitbucket-repositories --workspace WORKSPACE
```

The first uses `github.public_repository.list`; the second uses
`bitbucket.public_repository.list`. Both must ignore ambient credentials and
independently verify public visibility. Use authenticated repository discovery
only for “my repositories,” private repositories, or account-visible data.

## Execution is waiting for approval

Do not rebuild the command or treat a chat response as approval. Inspect the
private request:

```bash
master-agent inspect-approval-request /absolute/state/drafts/approval-request.json
```

A trusted operator with access to the configured approval authority creates
the exact authenticated artifact with `approve-request`. Resume with
`resume-approval`; that restores the original URLs, credentials mappings,
paths, gates, fingerprints, and partial multi-approval state.

The complete procedure is in [Operations](operations.md#low-level-run-lifecycle).

## Provider state changed after review

A version or content precondition failure protects against overwriting newer
provider state. Re-read the target, prepare and inspect a new plan, and obtain
new approval if the effect-bearing fingerprint changed. Do not weaken the
precondition or reuse the old approval.

## Platform capability is unavailable

Run `master-agent doctor` and inspect its `platform_runtime` section. A missing
secure filesystem, locking, atomic publication, process, trusted-Git, or
capsule-isolation contract stops protected work instead of selecting a weaker
fallback.

macOS currently supports ordinary local/runtime work but not capability-capsule
execution. Linux capsule execution requires a trusted bubblewrap executable;
native Windows uses the reviewed AppContainer path. See
[Architecture](architecture.md#process-boundaries) and
[Capability capsule promotion](capability-capsules.md#isolation-boundary).

## Recurring work cannot prove its state

Inspect the exact occurrence first:

```bash
master-agent recurring-inspect /absolute/private/occurrences/review.json
```

Use `recurring-recover` only for a certified pre-effect failure. Use
`recurring-reconcile` when an expired process can be reconciled from exact
idempotency records. An uncertain effect remains indeterminate, and there is no
`--force` path. See [Phase 6](phase-6-autonomy.md).

## Prepare a redacted support bundle

When a helpdesk needs offline diagnostics, use the dedicated command and a
fresh path in an already private parent directory:

```bash
master-agent support-bundle --output /absolute/private/support-bundle.json
```

The bundle is content-minimized and redacted, but it is still private operator
data. Review it before sharing. See [Operations](operations.md#helpdesk-support-bundles).

## Still stuck

Capture the command name, exit status, exact non-secret error, operating system,
Python version, and the relevant `doctor` level. Do not include credential
values, provider bodies, approval signatures, or private paths that reveal
sensitive organization data.

Return to the [documentation index](index.md) or use the exact command syntax
in the [CLI reference](cli-reference.md).
