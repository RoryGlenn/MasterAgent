# Design

## Approach

Add a JSON registry whose invariant identifiers are checked against a
hard-coded required set in a small standard-library runner. Each entry selects
exactly one `hosted` or `certification` group, names an exact `unittest` ID,
declares the stable expected failure reason, and may point to an equivalent
POSIX test. One exact test may cover multiple tightly coupled invariants. The
runner loads only the selected IDs, verifies they resolve to one test each,
records execution, and exits unsuccessfully for any skip, failure,
error, unexpected success, or missing result.

Pull-request Windows jobs run the hosted group. The protected Windows 11 x64
workflow runs both groups after its existing non-administrator host check.
Managed-workstation cases live in the certification group and treat absent
fixtures or incomplete #111/#112 behavior as failures, never successful skips.

## Affected components

- `scripts/run_windows_adversarial.py`
- `tests/windows_adversarial_matrix.json`
- `tests/test_windows_adversarial_runner.py`
- focused Windows test modules where an invariant lacks direct evidence
- `.github/workflows/ci.yml`
- `.github/workflows/windows-certification.yml`
- `docs/windows-certification.md`
- `docs/threat-model.md`

## Data flow

The workflow selects a group. The runner reads the repository-confined JSON
registry, validates its complete schema and invariant set, resolves exact test
IDs through `unittest`, executes them once, and compares the result ledger with
the selected registry entries. Only a complete, skip-free successful ledger
returns zero.

## Compatibility

The registry and runner use only the Python standard library. Existing test
modules and POSIX coverage remain unchanged. Hosted CI gains an explicit
portable adversarial gate; native and managed-only cases remain confined to
the protected x64 environment.

## Security

The matrix contains test identifiers and stable reason tokens only, never
paths, SIDs, credentials, proxy secrets, native diagnostics, or workstation
inventory. Exact test resolution prevents wildcard discovery from masking a
rename. The protected workflow retains its current-SHA, environment-review,
standard-user, and clean-runner boundaries.

## Rejected alternatives

Pytest markers were rejected because the repository uses `unittest` and does
not need a second runner. A skip-count grep was rejected because it cannot bind
results to exact required cases. Treating #111/#112 cases as optional was
rejected because optional release security evidence can silently disappear.
