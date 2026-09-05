# MA-SIMPLE-001 — Usability-first personal workflow profile

## Status

Active

## Requirement

MasterAgent MUST provide a separately selected personal workflow profile using
a standalone Python 3.12 standard-library runtime under `simple/`. Its entry
point MUST be `masteragent`, with a direct repository launcher supporting
POSIX and Windows. It MUST NOT import the governed `master-agent` runtime or
silently replace that runtime after a policy denial.

The profile MUST provide local setup, an offline doctor, editable Markdown
project context, native Jira/Bitbucket/Confluence Cloud and Server adapters,
and durable SQLite tasks. Configuration MUST store provider URLs and credential
environment-variable names without storing credential values. Provider clients
SHOULD be reused within a workflow. The host assistant MUST own interpretation,
code edits, and conversation; the CLI MUST NOT claim autonomous prose-to-code
execution or call a separate language-model API.

The runtime MUST support issue review with source evidence; isolated Git
worktree preparation and host handoff; configured project checks; explicit
branch push, Bitbucket pull-request creation requesting draft state, and Jira
update; and local status drafts. It MUST report the provider's actual draft
flag as true, false, or unreported rather than infer success from its request.
It MUST explain that older server versions may not honor the draft request.
Merges, communications sending, and scheduled execution MUST remain unsupported
by this profile. A credential-free demo MUST use isolated temporary state and
avoid provider network calls.

Tasks MUST retain confirmed step results across restarts and reuse successful
steps on resume. A confirmed branch push MUST let remaining pull-request and
Jira work resume from its saved result without requiring the local worktree
again. Provider URL and deployment MUST remain consistent after first use in a
task; refreshing credentials MUST remain possible. Publication settings MAY
change before its first external write starts but MUST remain fixed afterward.
Cancellation MUST preserve completed results without claiming
to undo remote effects. Ambiguous write outcomes MUST pause automatic replay
until explicit reconciliation records a confirmed result or confirmed absence
of the remote effect. Only confirmed absence MAY allow a later retry. Read retries MUST
be bounded. Operations MUST use timeouts and meaningful result/error reporting.

Ordinary in-scope requests in this profile MUST NOT require legacy signed
plans, capsule promotion, authenticated approval artifacts, blanket independent
verification, or append-only memory integrity machinery. The profile MUST
respect account permissions, host/employer controls, secret-handling boundaries,
and the distinction between user instructions and retrieved task data. Existing
governed runtime requirements MUST remain applicable to that separate runtime.

## Rationale

The operator requested a rebuild focused on useful task completion with less
configuration repetition and governance overhead. A distinct profile supports
that choice without changing the contract of the existing governed product.
Durable tasks and careful recovery preserve everyday reliability.

## Scenarios

### First useful run needs no accounts

- GIVEN Python 3.12 is available and no workplace credentials are configured
- WHEN the operator runs the repository launcher's demo command
- THEN it demonstrates local fixture workflows in temporary state without
  provider requests or installation of the governed runtime

### Review continues across a partial failure

- GIVEN a configured issue workflow has already fetched its issue successfully
- WHEN a related provider request fails and the operator later resumes
- THEN the task preserves evidence and continues remaining steps without
  replacing confirmed results with invented content

### Development separates host edits from tool operations

- GIVEN a Jira issue and local repository mapping
- WHEN the operator starts development
- THEN Simple creates an isolated worktree and a handoff for the host assistant
- AND the host edits, reviews, commits code, and checks the clean commit before explicitly
  publishing a branch, requesting a draft pull request, and adding a Jira link
- AND the host reports the actual draft flag returned by the provider

### Completed publication steps are not repeated

- GIVEN a pull request was created successfully and the subsequent Jira update
  did not complete
- WHEN the workflow resumes
- THEN it reuses the confirmed pull-request result and continues the remaining
  work without creating a duplicate pull request

### Uncertain writes require reconciliation

- GIVEN a transport interruption leaves a write's remote outcome unknown
- WHEN the workflow is resumed
- THEN it pauses before replaying that write until a confirmed result or
  confirmed absence is explicitly reconciled
- AND a later resume may retry only a write confirmed not to have happened

### Status remains a local draft

- GIVEN stored tasks include completed steps, notes, links, and blockers
- WHEN the operator requests status
- THEN the runtime creates a local draft and does not claim a message was sent

### Legacy users retain their selected runtime

- GIVEN a user selects the governed MasterAgent profile or `master-agent` CLI
- WHEN its policy denies an operation
- THEN it retains its existing controls without silently invoking Simple

## Implementation

- `simple/masteragent/cli.py`
- `simple/masteragent/demo.py`
- `simple/masteragent/settings.py`
- `simple/masteragent/state.py`
- `simple/masteragent/providers.py`
- `simple/masteragent/transport.py`
- `simple/masteragent/workflows.py`
- `simple/masteragent/workspace.py`
- `simple/run.py`
- `.github/agents/MasterAgent-Simple.agent.md`

## Verification

- `simple/tests/test_cli.py`
- `simple/tests/test_workflows.py`
- `simple/tests/test_state.py`
- `simple/tests/test_providers.py`
- `simple/tests/test_workspace.py`

## History

- Introduced by GitHub issue #184 at the operator's explicit request for a
  usability-first rebuild with substantially less runtime governance.
