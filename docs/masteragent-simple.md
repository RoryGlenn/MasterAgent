# MasterAgent Simple architecture and development

MasterAgent Simple is a small personal automation runtime selected through the
**MasterAgent Simple** Copilot profile or the `masteragent` CLI. It implements
the usable tool portion of three workflows: review an engineering issue,
prepare and publish development work, and prepare a status update. The host
assistant interprets the request, edits application code, and explains results.

The authoritative command examples and setup instructions are in
[simple/README.md](../simple/README.md). This document explains implementation
choices, recovery, and the limits of the shipped profile.

## Component responsibilities

| Component | Responsibility |
|---|---|
| Copilot custom agent | Interpret goals, make code edits, ask necessary questions, and summarize evidence |
| Python CLI and workflow functions | Run explicit operations and continue stored tasks |
| Native provider adapters | Jira, Bitbucket, and Confluence Cloud or Server operations |
| HTTP transport | Authentication, timeouts, bounded read retries, and useful provider errors |
| Git helpers | Prepare isolated worktrees, run checks, and publish task branches |
| SQLite task store | Persist task progress, step results, notes, and partial completion |
| Markdown project context | Keep user-editable conventions and decisions |

The runtime uses Python 3.12 and the standard library. It does not import
`src/master_agent`, invoke a separate model API, or require the governed
runtime's policy engine, immutable plans, signed capsules, authenticated
approval artifacts, or append-only memory machinery.

## Workflow behavior

### Review an issue

The workflow reads the selected Jira issue and relevant linked resources. It
uses configured project context and explicit links to enrich the result with
Bitbucket pull requests/build status and Confluence pages. Provider results
and source links become a local task artifact. The host assistant turns that
material into an explanation. Missing configuration or inaccessible resources
must be reported, never replaced by invented content.

### Develop and publish

Development preparation creates a task and a separate Git worktree. The handoff
states where the host assistant should work and supplies relevant issue and
project context. Source editing and committing remain the host's work.

The host commits intended changes, then configured checks run in the clean
worktree and record evidence for that final commit. Explicit publication
pushes the task branch, requests a draft Bitbucket pull request, and comments
on the Jira issue with the result. Completed steps are stored so an interrupted
workflow can continue without repeating successful provider writes. There is
no guarantee that every server version honors the draft request. The normalized
provider result reports `draft: true`, `false`, or `null` (unreported), plus
whether a draft was requested. The host must report actual returned state.
There is no automatic merge or rollback of completed writes.

### Prepare status

The status workflow builds a local draft from stored tasks, progress, notes,
links, and blockers. It does not send messages. The host can turn the draft into
a concise update for the user to review or use through a separately authorized
communications capability.

## Continuity and failure recovery

Configuration stores provider endpoints and credential environment-variable
names. Credentials are resolved when a selected provider is needed. A local
offline doctor checks setup without claiming live authentication succeeded.

Each task lazily checkpoints a provider's URL and deployment type on first use.
Resume rejects a changed destination while allowing credential refreshes.
Unused providers do not need configuration. Output files are replaced
atomically so interruption does not leave a partially written artifact.

The task store records completed results after each step. Resuming checks that
record before doing work again. After a confirmed push, the saved branch and
commit are enough to finish pull-request creation and the Jira update; those
remaining steps do not depend on the local worktree or check artifact.
Publication settings can change until the first external write starts and are
then retained for recovery. Cancellation is a task-state change, not a remote
undo operation or deletion of local worktrees.

A timeout or broken connection during a write can mean the remote service
accepted the request without returning its result. Such a step must remain
uncertain. Automatic retry is inappropriate because it could create a duplicate
pull request or Jira comment. The operator or host must inspect the service and
explicitly reconcile a confirmed result before resuming. If inspection confirms
the write did not happen, `resolve --not-applied` records that finding and
allows a later resume to retry. A lost response by itself does not establish
absence. Read retries may use bounded backoff; writes are not silently replayed.

This profile optimizes for a single user and local task state. SQLite state is
not a distributed scheduler or external audit system. Local artifacts may
contain private work content and belong on an appropriate device.

## Practical boundaries

The user's requested outcome supplies ordinary task authority in this profile;
the host and employer still control tool use, authentication, and provider
permissions. Selecting Simple does not make credentials available, increase
account permissions, or remove prompts enforced by the host.

Issue descriptions, pages, source files, and provider responses remain task
data. They cannot authorize extra actions or override the user's instructions.
Credentials stay outside prompts and logs. Process arguments are passed as
arrays, operations have timeouts, and repository changes use isolated worktrees.

The profile intentionally does not include Outlook, Teams, OneNote, PowerPoint,
scheduled execution, dynamic plugins, specialist-agent orchestration, a web UI,
or a separate LLM backend. These are possible future workflows, not shipped
capabilities. Add them when a concrete user task justifies the cost.

## Compatibility

`masteragent` and `master-agent` select distinct products. The governed runtime,
its entry point, configuration, and current requirements remain supported.
Existing users are not automatically migrated. No Simple command should use
the governed runtime as a fallback, and no governed command should fall back to
Simple when a policy check fails.

Simple uses its own state directory, configurable with `--home` or
`MASTERAGENT_HOME`. It does not transform old approval artifacts or import old
audit databases into task state. Repository development still uses behavioral
specifications, reviewable changes, and meaningful tests.

## Development and validation

Add capabilities as typed Python adapter functions plus a small workflow step.
Keep predictable sequences in Python and reasoning in the host instructions.
Use executable examples and deterministic local fixtures to cover complete
workflows, partial failures, stale checks, credential omission, and uncertain
writes. Test outcomes rather than the incidental structure of functions.

Use `demo` for a credential-free first run, then run the focused Simple test
suite and applicable repository release checks before completion.

**Machine: Ubuntu or macOS development computer, from the `simple` directory**

```bash
python3 -m unittest discover -s tests -v
```

**Machine: Ubuntu or macOS development computer, from the repository root**

```bash
python3 scripts/specs.py validate
python3 scripts/validate_release.py
```

On Windows, substitute `py -3.12` for `python3`. Tests using
fixtures establish local behavior; they do not certify a live organization
account or every server version. Native Windows behavior requires a Windows
runner even when the launch command is documented on Linux.

Evaluate future changes by completed useful tasks, elapsed time, avoidable
interruptions, repeated configuration questions, and successful recovery after
failure. Collect simple evidence before adding another framework.

## Repository subprocess environment

Git operations and project checks receive a copy of the environment with
configured provider credential variable names and standard provider
`TOKEN`/`USERNAME` names removed. Ordinary build settings and Git/SSH
configuration remain available. Parent provider clients keep their credentials;
Simple never clears or rewrites the process environment. This boundary does
not isolate same-user filesystem access or replace an operating-system sandbox.

Bitbucket Server/Data Center build-status reads require the repository builds
API introduced in 7.14. The implementation retains this documented endpoint
rather than switching to the deprecated global commit build-status resource.
