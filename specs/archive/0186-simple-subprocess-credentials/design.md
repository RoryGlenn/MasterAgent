# Design

## Approach

`simple/masteragent/workspace.py` builds each child environment from the current
process environment, removing conventional provider names plus names selected
by the current workflow configuration. A context-local credential-name scope
allows nested Git helpers to share this boundary without mutating os.environ
or passing tokens through workspace functions. The scope resets on failure.

`simple/masteragent/workflows.py` scopes checkpoint actions and direct workspace
inspections/checks. Provider HTTP requests still use the parent environment.
Git and its hooks and timeout cleanup receive the filtered environment.

Real temporary Git hooks and Python check subprocesses verify absence of the
provider variables and preservation of an unrelated build setting. Parent
credential state is checked after completion and exceptions. This is an
environment boundary, not an OS sandbox or a claim to isolate same-user files.

## Affected components

`simple/masteragent/workspace.py`, `simple/masteragent/workflows.py`, their tests,
and the Simple usage/architecture guides.

## Data flow

Saved configuration supplies variable names. A context-local scope passes the
names to the child-environment builder. Values stay in the parent environment.

## Compatibility

Keep ordinary build, Git credential helper, and SSH settings. Projects that
used provider API variables must use separate purpose-specific test credentials.

## Security

Remove both configured names and conventional provider token/username names.
Normalize names for Windows case-insensitive environment semantics. Reset the
scope even when a workflow action raises; never mutate the parent environment.

## Rejected alternatives

No global environment mutation, blanket environment allowlist, or changes to
provider authentication. The repository-scoped Bitbucket build endpoint is
retained: Atlassian documents it from Server/Data Center 7.14 onward.
