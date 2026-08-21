# MA-DIRECT-READ-002 — Lightweight local bootstrap reuse

## Status

Active

## Requirement

The bootstrap MUST install a dependency-light core runtime without requiring
draft-rendering dependencies. When a pre-existing repository-local virtual
environment has a usable interpreter and MasterAgent entry point but has no
bootstrap freshness marker, bootstrap MUST run only offline readiness and MUST
not modify that environment or assert that it is trusted. A malformed,
non-directory, symbolic-link, or interpreter-missing environment MUST still be
rejected. Credential stores, provider effect paths, and approval-bound runtime
paths remain subject to their existing trust requirements.

## Rationale

An ordinary local development environment is sufficient for offline setup but
must never become authority to use credentials or mutate a provider. Reusing
it without writing a provenance marker avoids setup friction without relaxing
the effect boundary.

## Scenarios

### Reused local environment

- GIVEN a repository-local `.venv` containing a usable MasterAgent entry point
  but no bootstrap marker
- WHEN the operator runs `scripts/bootstrap_agent.py`
- THEN bootstrap runs offline readiness and does not install, create, or write
  a marker in that environment.

### Unsafe local environment

- GIVEN a `.venv` that is a symbolic link or does not contain its expected
  interpreter
- WHEN bootstrap runs
- THEN it rejects the environment before it uses or modifies it.

## Implementation

- `scripts/bootstrap_agent.py`

## Verification

- `tests/test_agent_bootstrap.py`

## History

- Introduced by GitHub issue #108.
