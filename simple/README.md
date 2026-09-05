# MasterAgent Simple

MasterAgent Simple helps a coding assistant review a Jira issue, prepare an
isolated Git workspace, publish a Bitbucket pull request, and keep track of
unfinished work. Select **MasterAgent Simple** in GitHub Copilot and describe
the outcome. The assistant handles reasoning and code edits; a small Python
command-line tool handles connections, task state, and repeatable operations.

This is a separately selected profile. The existing **MasterAgent** profile and
`master-agent` command continue to use the governed runtime. Simple does not
import that runtime or require its installation, signed plans, or approval
artifacts. Your host and organization permissions still apply.

## Try it without accounts

You need Python 3.12 or newer. Development workflows also need Git and a local
clone of the target repository. Run these commands from this repository's root.
The demo uses temporary local state and fixtures; it does not contact workplace
systems or use credentials.

**Machine: Ubuntu or macOS development computer**

```bash
python3 simple/run.py demo
```

**Machine: Windows 11 development computer, PowerShell**

```powershell
py -3.12 simple/run.py demo
```

For an installed checkout, `masteragent` is the equivalent entry point. The
examples below use `python3 simple/run.py`; on Windows, substitute
`py -3.12 simple/run.py`.

## Connect your project once

Configuration stores provider URLs and environment-variable names. Keep the
actual credentials in your environment or your organization's credential
manager. Do not put token values in configuration, project notes, or chat.

The example assumes your environment already supplies `JIRA_TOKEN`,
`JIRA_USERNAME`, `BITBUCKET_TOKEN`, and `BITBUCKET_USERNAME`. Cloud connections
use your Atlassian account email and API token. Server connections use a bearer
token and their configured server URL. Account permissions must cover the
operations you use.

For Jira and Confluence Cloud, this version uses site URLs and unscoped API
tokens. Scoped tokens require Atlassian's separate gateway URL, which this
profile does not yet map. See [Atlassian API tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/).
For Bitbucket Cloud, follow [API token authentication](https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/)
with your account email and a token permitting the requested operations.

**Machine: Ubuntu or macOS development computer, from this repository root**

```bash
python3 simple/run.py setup --provider jira --deployment cloud --url https://example.atlassian.net --token-env JIRA_TOKEN --username-env JIRA_USERNAME
python3 simple/run.py setup --provider bitbucket --deployment cloud --url https://bitbucket.org --token-env BITBUCKET_TOKEN --username-env BITBUCKET_USERNAME
python3 simple/run.py setup --project APP --repository /home/rory/projects/app --bitbucket-repository my-workspace/app
python3 simple/run.py doctor
python3 simple/run.py context
```

Use your actual provider URLs, project key, repository path, and Bitbucket
repository. For Bitbucket Server, use `PROJECT/repo` as the repository mapping.
A server example is `--deployment server --url https://jira.example.com
--token-env JIRA_TOKEN`. Confluence is optional; add it
with `--provider confluence` when the issue review needs its pages. Use
`--page URL` on project setup to remember relevant documentation links.

`doctor` checks local setup and whether the named environment variables exist.
It does not validate your account with a live request. A later operation can
still report an expired token, missing permission, or an unreachable service.

`context` shows the path and contents of the editable project notes. Record
conventions, decisions, and useful background there. The host assistant reads
the current notes for its work, so you can correct them directly.

Set checks once with repeated JSON argument arrays. Each command runs directly
in the task's worktree; shell operators such as pipes are not interpreted.
Choose checks appropriate to the target project rather than copying this
Python example into every project.

Project settings, including checks, are captured when a development task is
created. Set them before `develop`; changing setup does not rewrite existing
tasks. Git push uses your existing Git credentials or SSH configuration,
separately from the API token used to create the pull request.

**Machine: Ubuntu or macOS development computer**

```bash
python3 simple/run.py setup --project APP --check-json '["python3", "-m", "unittest", "discover"]'
```

## Review an issue

**Machine: Ubuntu or macOS development computer**

```bash
python3 simple/run.py review APP-123
```

The result records the issue and available linked pull requests, build status,
and relevant pages in a local task. Add an explicit `--pr URL` or `--page URL`
when the link is not available from the issue or project settings. The coding
assistant reads this material and explains the work and remaining questions.
The CLI itself does not interpret a free-form request or call a language model.

A review includes up to five pull requests and three pages and reports omitted
links. Failed related reads leave the available evidence in the task; resume
retries those missing sources. A completed review is a saved snapshot, so start
a new review when you need fresh provider state.

## Finish a development task

**Machine: Ubuntu or macOS development computer**

```bash
python3 simple/run.py develop APP-123 --base main
```

This prepares a separate Git worktree and a handoff for the coding assistant.
Keep the returned task ID. The assistant works in that worktree, implements the
requested change, reviews the diff, and commits the intended files. Run the
configured checks against the final clean commit:

```bash
python3 simple/run.py checks TASK_ID
```

If you change code or commit again, rerun checks before publishing. Prepare the
pull-request description in a local file, then run:

```bash
python3 simple/run.py publish TASK_ID --title "Improve dashboard caching" --description-file /home/rory/pr-description.md --target main --remote origin
```

`publish` pushes the task branch, reuses an existing pull request for the same
branch pair or requests a new draft, and adds its link to Jira. It is an
explicit write command. Inspect the returned
`draft` flag: `true` confirms a draft, `false` reports an ordinary pull request,
and `null` means the provider did not report its draft state. Older Bitbucket
Server versions may ignore the draft request; Bitbucket Data Center added draft
support in [8.18](https://developer.atlassian.com/server/bitbucket/reference/api-changelog/).
The command does not merge the
pull request. Provider permissions and host prompts remain in force.

Use `python3 simple/run.py --json show TASK_ID` to inspect the saved provider
result, including draft state and the Jira comment link.

You can correct the title, description, target, or remote until the first
publication write starts. After that, these settings stay with the task; use
`resume` to finish that publication.

The CLI does not generate or commit application code by itself. Selecting the
custom agent supplies the reasoning and editing part of this workflow.

## Continue unfinished work

**Machine: Ubuntu or macOS development computer**

```bash
python3 simple/run.py tasks
python3 simple/run.py show TASK_ID
python3 simple/run.py note TASK_ID "Reviewer wants cache invalidation on update."
python3 simple/run.py resume TASK_ID
python3 simple/run.py cancel TASK_ID
```

Task state and completed step results survive process restarts. Resume reuses
successful steps so, for example, a failed Jira update does not require a
second pull request. After a confirmed push, resume can finish the pull request
and Jira update without requiring the local worktree or checks again.
Cancellation records the task as cancelled; it does not
undo a push, delete a worktree, or remove a pull request.

A task remembers a provider's URL and deployment type when it first uses that
connection. You can refresh credentials and retry. If you change the provider
destination, restore the saved destination to resume or start a new task for
the new one.

If the connection fails during a write, the server may have accepted it before
the response was lost. Simple stops with an uncertain step instead of blindly
repeating it. Inspect the target service, then reconcile the result explicitly:

```bash
python3 simple/run.py resolve TASK_ID STEP --result-file /home/rory/confirmed-result.json
python3 simple/run.py resume TASK_ID
```

Only record a result you have actually confirmed. This command records evidence
for a completed step; it is not a force-retry switch. Use a JSON object matching
the affected step:

| Step | Confirmed result fields |
|---|---|
| `git.push` | `branch`, `commit` (full commit ID), and `remote` |
| `bitbucket.create_pr` | `url`; preserve the normalized provider result, including `id` and `draft`, when available |
| `jira.comment` | `id` and `url` of the actual Jira comment |

For example, a confirmed Jira comment result could be
`{"id":"12345","url":"https://example.atlassian.net/browse/APP-123?focusedCommentId=12345#comment-12345"}`.
Replace every value with the actual result; never fabricate IDs to unblock a task.

If inspection instead confirms that the write did **not** happen, record that
finding with `resolve TASK_ID STEP --not-applied`, then `resume TASK_ID` to retry
it. Choose this only after checking the remote state; a missing response alone
does not establish that the write failed.

## Prepare a status update

**Machine: Ubuntu or macOS development computer**

```bash
python3 simple/run.py status --task TASK_ID
```

Repeat `--task` to select several tasks, or omit it for the default task summary.
The output is a local status draft with saved progress, links, and blockers;
it does not refresh provider state. Review
and edit it with the assistant. This version does not send to Outlook, Teams,
or any other messaging service.

## Command reference

Global options precede the command: `--home PATH` selects the state directory;
`--json` requests machine-readable output. Run `COMMAND --help` for exact
arguments.

| Command | Result |
|---|---|
| `setup` | Create or update local provider and project configuration |
| `doctor` | Inspect local setup and credential presence, offline |
| `context` | Show the editable context file and its contents |
| `review ISSUE` | Gather issue, pull-request, build, and page context |
| `develop ISSUE` | Prepare a worktree and coding-assistant handoff |
| `checks TASK` | Run configured project checks in the task worktree |
| `publish TASK` | Push the branch, create a pull request, and update Jira |
| `status` | Create a local status draft |
| `tasks`, `show TASK` | Inspect task progress, step results, and paths |
| `note TASK TEXT` | Replace the task's editable handoff note |
| `resume TASK` | Continue the stored workflow using completed results |
| `cancel TASK` | Mark a task cancelled |
| `resolve TASK STEP` | Record a confirmed result or confirmed absence for an uncertain write |
| `demo` | Exercise local fixture workflows without credentials |

By default state lives under `~/.masteragent`; `MASTERAGENT_HOME` or `--home`
overrides it. `config.json` stores setup, `context.md` stores editable notes,
and `tasks.sqlite3` stores tasks and step results. Outputs and worktrees also
live below the selected home, under `outputs/TASK_ID/` and `worktrees/TASK_ID/`.
This state can contain private issue content;
keep it on an appropriate local device and outside source control.

## Troubleshooting

| Symptom | Next action |
|---|---|
| Missing provider or project | Run `setup` with the values shown in the command above |
| Missing credential | Supply the configured environment variable, then rerun the task |
| HTTP authentication or permission error | Check the account/token's access to that service |
| Provider destination changed | Restore the task's original URL/deployment or start a task for the new destination |
| Project checks fail | Read the captured result, fix the worktree, rerun `checks` |
| Write outcome is uncertain | Inspect the service, record the confirmed result with `resolve`, then resume |
| Requested operation has no command | Complete available local work and identify the remaining unsupported action |

See [the architecture and development guide](../docs/masteragent-simple.md)
for implementation boundaries and focused tests.
