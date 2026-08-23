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

Windows adversarial evidence MUST be maintained in a machine-readable registry
that enumerates every filesystem, process, credential, Git, capsule, and
managed-workstation security invariant and binds it to an exact test ID, a
stable secret-free expected reason, and one execution group. Hosted-runner-safe
cases MUST remain separate from Windows-11-certification-only cases. Relevant
native attacks MUST execute under the certification runner's standard
non-administrator account.

The adversarial runner MUST reject a missing, duplicate, or unknown invariant
and a missing or unresolvable test ID. Every active expected reason MUST be
bound on its owning test and reproduced in the started-test execution ledger.
A selected required case that is skipped, errors, fails, does not execute, or
has a missing or mismatched reason binding MUST fail its workflow.
Certification MUST include the entire certification-only group and MUST NOT
pass through ordinary `unittest` skip semantics. Failure assertions MUST use
stable bounded reasons rather than secret-bearing operating-system text.

The registry MUST cross-reference preserved POSIX adversarial evidence where an
equivalent invariant exists. Managed-workstation ACL inheritance, support/EDR
principal, OneDrive/reparse, Defender/Controlled Folder Access, AppLocker/WDAC,
authenticated proxy, enterprise CA, standard-user, and antivirus-like
contention cases MUST remain explicit certification requirements. Authenticated
proxy and enterprise-CA cases owned by #112 MUST fail closed until their
implementation and managed-host evidence are available. Defender/Controlled
Folder Access, AppLocker/WDAC, organization ACL inheritance, and approved
support/EDR principal cases MUST remain blocked on #106 until real managed-host
fixtures and an enrolled standard-user runner replace hosted-safe policy or
mocked-error evidence. Blocked cases MUST NOT be silently omitted or counted as
successful certification.

## Rationale

Hosted administrator-oriented evidence is useful for compatibility but cannot
prove that ACLs, process containment, and native isolation survive a real
standard-user Windows 11 x64 deployment. A separate protected gate preserves
that distinction and keeps untrusted code away from the retained machine.
Explicit invariant-to-test bindings prevent discovery changes or native skips
from silently weakening the claimed security evidence.

## Scenarios

### Pull-request compatibility matrix

- GIVEN a pull request changes Windows-relevant or shared code
- WHEN required CI runs
- THEN Python 3.12, 3.13, and 3.14 each execute the native Windows 11 job
- AND the hosted-safe adversarial group executes without a missing or skipped case
- AND any required Windows, artifact, specification, or release failure blocks merge

### Protected default-branch certification

- GIVEN successful CI for the current protected default-branch head
- AND a reviewed ephemeral Windows 11 x64 runner using a non-administrator account
- WHEN certification is enabled and the protected environment approves the job
- THEN the host is verified before exact-SHA checkout
- AND every certification-only adversarial case executes without a skip
- AND built artifacts plus native ACL, locking, atomic, credential, process, Git, and AppContainer behavior are certified

### Required adversarial case is absent or skipped

- GIVEN the registry declares a required Windows security invariant
- WHEN its test ID is missing, renamed, unresolved, skipped, failed, or errors
- THEN the selected workflow fails with a stable content-free reason
- AND certification is not reported as successful

### Managed-workstation prerequisite is incomplete

- GIVEN an ACL, endpoint-security, application-control, proxy, or enterprise-CA case requires managed-host setup or behavior owned by #106 or #112
- WHEN the setup or behavior is unavailable
- THEN the certification-only case fails rather than skips or disappears
- AND hosted-safe pull-request tests remain independently runnable

### Unsafe or incomplete infrastructure

- GIVEN an unprotected, stale, fork-derived, or non-default-branch SHA
- OR a server, non-x64, administrator, credential-bearing, persistent, or missing runner
- WHEN the workflow is considered for dispatch
- THEN protected certification does not execute or fails before checkout
- AND repository workflow presence alone is not reported as certification evidence

## Implementation

- `.github/workflows/ci.yml`
- `.github/workflows/windows-certification.yml`
- `scripts/run_windows_adversarial.py`
- `tests/windows_adversarial_matrix.json`

## Verification

- `tests/test_windows_adversarial_runner.py`
- `tests/test_windows_certification_workflow.py`
- `tests/test_release_metadata.py`
- `scripts/validate_release.py`
- `scripts/semantic_router.py`
- `tests/test_semantic_router.py`

## History

- Introduced by GitHub issue #106.
- Added an exhaustive skip-intolerant adversarial matrix in GitHub issue #107.
- Bound implemented organization-trust policy cases to live certification issue #106 in GitHub issue #111.
