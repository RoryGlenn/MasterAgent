# Tasks

- [x] Record the user-authorized separate profile and issue #184 scope.
- [x] Add the requirement delta and final current snapshot.
- [x] Implement the standalone package, setup, and CLI workflows.
- [x] Implement native provider adapters and isolated Git worktree operations.
- [x] Implement task continuity, cancellation, and uncertain-write recovery.
- [x] Add executable workflow and failure-recovery evidence.
- [x] Update and validate user documentation, navigation, and agent guidance.
- [x] Run focused tests, specification validation, and release validation.
- [x] Complete the Docs Agent maintenance review and inspect the final diff.

## Verification evidence

Validated on September 5, 2026, using Linux and Python 3.12:

- All 79 Simple tests passed, covering setup, CLI, providers, task state,
  worktrees, complete workflows, partial failures, and recovery.
- All 146 selected legacy, router, specification, release, profile, and
  advisory tests passed.
- `python3 scripts/specs.py validate` and
  `python3 scripts/validate_release.py` passed completely.
- Compilation with `compileall` and `git diff --check` passed.
- The standalone wheel built using local dependencies without index access,
  installed in a fresh virtual environment, and its installed
  `masteragent --json demo` and `masteragent --version` commands passed.
- The documented source demo, command help, recovery help, and relative
  documentation links were checked. The Docs Agent maintenance result was
  `updated`, with no unresolved documentation conflict.

## Validation limits

Live workplace APIs, native Windows execution, and the Copilot user interface
were not exercised locally. The Simple CI workflow includes a Windows runner;
adding that job is not a claim that a hosted run has already passed. Fixture
tests establish local behavior without certifying a particular enterprise
deployment or account.

Ruff and mypy were unavailable in the local environment. Their installation
did not complete after the development dependency install request was
cancelled; no passing formatter, lint, or mypy result is claimed.
