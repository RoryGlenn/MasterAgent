# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-WINDOWS-CERTIFICATION-001 — Windows release certification

Windows adversarial evidence MUST be maintained in a machine-readable registry
that enumerates every filesystem, process, credential, Git, capsule, and
managed-workstation security invariant and binds it to an exact test ID, a
stable secret-free expected reason, and one execution group. Hosted-runner-safe
cases MUST remain separate from Windows-11-certification-only cases. Relevant
native attacks MUST execute under the certification runner's standard
non-administrator account.

The adversarial runner MUST reject a missing, duplicate, or unknown invariant
and a missing or unresolvable test ID. A selected required case that is skipped,
errors, fails, or does not execute MUST fail its workflow. Certification MUST
include the entire certification-only group and MUST NOT pass through ordinary
`unittest` skip semantics. Failure assertions MUST use stable bounded reasons
rather than secret-bearing operating-system text.

The registry MUST cross-reference preserved POSIX adversarial evidence where
an equivalent invariant exists. Managed-workstation ACL inheritance,
support/EDR principal, OneDrive/reparse, Defender/Controlled Folder Access,
AppLocker/WDAC, authenticated proxy, enterprise CA, standard-user, and
antivirus-like contention cases MUST remain explicit certification
requirements. Cases owned jointly by #111 or #112 MUST fail closed until their
implementation and managed-host evidence are available; they MUST NOT be
silently omitted or counted as successful certification.

## REMOVED

None.
