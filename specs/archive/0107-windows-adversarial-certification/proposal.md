# Proposal

## Problem

Windows filesystem, process, credential, Git, and AppContainer tests contain
substantial adversarial coverage, but the repository has no exhaustive,
machine-checked map from the Windows security invariants to exact tests.
`unittest` also treats skipped native cases as a successful run, so release
certification can appear green without executing a required attack case.

## Desired outcome

Every Windows security invariant is registered against exact executable
evidence. Hosted-safe tests run on every pull request, native and managed-host
tests run only in protected Windows 11 x64 certification, and either group
fails if a selected test is absent, unresolved, skipped, or unsuccessful.

## Scope

A versioned adversarial matrix, a bounded test runner, runner unit tests,
hosted and protected workflow integration, stable failure-reason assertions,
POSIX-equivalence references, and operator documentation for the managed-host
fixtures coordinated with issues #111 and #112.

## Rationale

An explicit registry turns a broad security claim into reviewable evidence and
prevents an accidental skip, rename, or workflow omission from silently
reducing release coverage.

## Alternatives considered

Relying on test filenames or ordinary discovery was rejected because neither
proves invariant coverage and discovery exits successfully with skipped tests.
Running managed-workstation attacks on pull-request hosts was rejected because
those machines do not provide the relevant ACL, endpoint-security, network, or
application-control policy.

## Non-goals

This change does not implement the organization trust model owned by #111, the
enterprise proxy/CA transport owned by #112, or provision the external Windows
11 x64 runner. It makes their certification cases explicit and fail closed
rather than claiming evidence before those prerequisites exist.

## Risks

A stale registry could create false confidence. Validation therefore requires
the complete invariant ID set, resolves every exact test ID, rejects duplicate
or unknown entries, and is exercised by both workflow-contract and runner
regression tests.
