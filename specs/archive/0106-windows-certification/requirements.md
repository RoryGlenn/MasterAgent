# Requirement deltas

## ADDED

### MA-WINDOWS-CERTIFICATION-001 — Windows release certification

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

## MODIFIED

None.

## REMOVED

None.
