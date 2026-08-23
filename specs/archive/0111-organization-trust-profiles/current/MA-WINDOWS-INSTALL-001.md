# MA-WINDOWS-INSTALL-001 — Native Windows installation

## Status

Active

## Requirement

Bootstrap MUST use native virtual-environment interpreter and console-launcher
paths, MUST apply POSIX permission operations only on POSIX, and MUST NOT
execute or rewrite an unverified existing environment. A collision MUST select
a fresh bounded side-by-side managed environment. Source, wheel, source archive,
and explicit local offline package directories MUST be supported without
requiring activation or placing index credentials on the command line.

A marker MUST NOT authorize reuse by itself. Bootstrap MUST require a
versioned bounded attestation that matches the current installation-source
digest, declared dependency-policy digest, and project version. It MUST run a
fixed isolated interpreter probe with environment site initialization disabled
and independently hash the environment configuration, interpreter target,
console launcher, distribution identities, and all bounded installed package
files without importing environment code. Before any candidate executable runs,
POSIX runtime objects MUST reject shared mode-bit or extended-ACL authority and
Windows runtime objects MUST pass retained-handle owner/DACL validation. The
complete runtime digest MUST match the attestation before the isolated probe;
the observed MasterAgent version MUST match before the launcher is executed. A
legacy marker, mismatch, missing file, link, malformed metadata, unsafe writer,
or probe failure MUST preserve the candidate and continue to a fresh bounded
side-by-side path.

Native default configuration and runtime state MUST use an absolute
current-user platform directory and MUST NOT derive authority from the current
working directory. Release construction MUST exclude environment, runtime,
credential, audit-database, cache, and build artifacts. Hosted native Windows
evidence MUST cover standard-user source bootstrap idempotency, a built-wheel
console launcher, and spaces, Unicode, and long local paths while preserving
the POSIX installation path.

## Rationale

Platform support begins with a safe, reproducible installation. Native paths,
artifact-based testing, and preservation of unverified local state prevent
bootstrap convenience from becoming implicit trust.

## Scenarios

### Fresh native Windows source bootstrap

- GIVEN a standard Windows 11 user and a source checkout on a supported local drive
- WHEN the user invokes `py -3.12 scripts\bootstrap_agent.py` twice
- THEN `.venv\Scripts\master-agent.exe` is installed and both runs succeed
- AND no activation, POSIX permission operation, provider access, or CWD config discovery occurs

### Existing unverified environment

- GIVEN `.venv` exists without a valid bootstrap marker
- WHEN bootstrap runs
- THEN that environment is not executed, rewritten, or deleted
- AND a bounded digest-named managed environment is created beside it

### Existing attested environment is independently verified

- GIVEN a bootstrap-managed environment with a versioned attestation
- WHEN bootstrap is invoked again
- THEN the current source, dependency policy, project version, interpreter,
  environment metadata, launcher, distributions, and installed files are
  independently observed without importing installed code
- AND the launcher is reused only when every identity matches
- AND any mismatch preserves the old environment and repairs side by side

### Built artifacts and difficult local paths

- GIVEN a wheel, source archive, or local offline dependency directory
- WHEN installation runs through spaced, Unicode, and long native paths
- THEN the artifact installs and its native console launcher runs
- AND release archives contain no local environment, state, credential, audit, cache, or build output

## Implementation

- `scripts/bootstrap_agent.py`
- `src/master_agent/platform_paths.py`
- `src/master_agent/operating.py`
- `src/master_agent/cli.py`
- `scripts/validate_release.py`
- `.github/workflows/ci.yml`

## Verification

- `tests/test_agent_bootstrap.py`
- `tests/test_platform_paths.py`
- `tests/test_operating_modes.py`
- `tests/test_cli_v1.py`
- `tests/test_release_metadata.py`

## History

- Introduced by GitHub issue #105.
- Replaced marker-only reuse with independent attestation in GitHub issue #111.
