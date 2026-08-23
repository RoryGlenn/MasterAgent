# MA-WINDOWS-CERTIFICATION-001 — Windows release certification

## Status

Active

## Requirement

Required pull-request CI MUST run native Windows 11 evidence on Python 3.12,
3.13, and 3.14. Windows-specific failures, artifact construction and isolated
installation, behavioral specification validation, and release validation MUST
block merge.

Platform-independent release tooling that compares path and descriptor metadata
MUST use stable Windows file identity and content-bearing metadata rather than
requiring POSIX permission, link-count, or change-time projections to match.
Replacement or mutation during a bounded file read MUST still fail closed.

The protected Windows 11 x64 certification workflow MUST select only the
current protected default-branch commit before checkout, MUST NOT run for
untrusted pull-request code, and MUST use an environment-reviewed ephemeral
self-hosted runner whose service account is a non-administrator. It MUST verify
workstation version, x64 architecture, long-path policy, absent production
credential names, native ACL, locking, atomic state, credential, Job Object,
trusted Git, and AppContainer behavior. It MUST build and install the wheel and
source distribution outside the checkout, run the complete test/specification/
release suite, and remove work products afterward.

The workflow MUST remain disabled until the protected branch, protected
environment, exact runner labels, standard-user account, ephemeral enrollment,
and clean-image lifecycle are configured. Repository workflow availability is
not successful certification evidence.

## Rationale

Hosted administrator-oriented evidence is useful for compatibility but cannot
prove that ACLs, process containment, and native isolation survive a real
standard-user Windows 11 x64 deployment. A separate protected gate preserves
that distinction and keeps untrusted code away from the retained machine.

## Scenarios

### Pull-request compatibility matrix

- GIVEN a pull request changes Windows-relevant or shared code
- WHEN required CI runs
- THEN Python 3.12, 3.13, and 3.14 each execute the native Windows 11 job
- AND any required Windows, artifact, specification, or release failure blocks merge

### Protected default-branch certification

- GIVEN successful CI for the current protected default-branch head
- AND a reviewed ephemeral Windows 11 x64 runner using a non-administrator account
- WHEN certification is enabled and the protected environment approves the job
- THEN the host is verified before exact-SHA checkout
- AND built artifacts plus native ACL, locking, atomic, credential, process, Git, and AppContainer behavior are certified

### Unsafe or incomplete infrastructure

- GIVEN an unprotected, stale, fork-derived, or non-default-branch SHA
- OR a server, non-x64, administrator, credential-bearing, persistent, or missing runner
- WHEN the workflow is considered for dispatch
- THEN protected certification does not execute or fails before checkout
- AND repository workflow presence alone is not reported as certification evidence

## Implementation

- `.github/workflows/ci.yml`
- `.github/workflows/windows-certification.yml`

## Verification

- `tests/test_release_metadata.py`
- `scripts/validate_release.py`
- `scripts/semantic_router.py`
- `tests/test_semantic_router.py`

## History

- Introduced by GitHub issue #106.
