# Design

## Approach

Bootstrap derives `bin/python` and `bin/master-agent` on POSIX or
`Scripts/python.exe` and `Scripts/master-agent.exe` on Windows. A managed marker
binds the selected environment to repository metadata and an explicit local
install artifact. An explicit source tree is editable and its own package
metadata controls refresh. Unmarked, unsafe, or incomplete collisions are skipped in
favor of one of four digest-named side-by-side candidates. Offline mode accepts
only explicit existing local directories and never accepts an index credential
argument. The marker must be an ordinary single-link file; reads bind the
directory entry to the opened descriptor, and updates use a private temporary
file plus atomic replacement so links are neither trusted nor followed.
Bootstrap prints the exact selected console launcher after readiness succeeds.

One platform-neutral path helper retains the POSIX home layout and selects
`LOCALAPPDATA\MasterAgent` on native Windows. Setup and demo reuse that helper.
Manifest and archive validation enumerate excluded development and runtime
trees.

## Affected components

- `scripts/bootstrap_agent.py`
- `src/master_agent/platform_paths.py`
- `src/master_agent/operating.py`
- `src/master_agent/cli.py`
- `.github/workflows/ci.yml`
- `MANIFEST.in`
- release, configuration, deployment, and first-run documentation

## Data flow

The invoking interpreter selects the native venv layout, validates project
metadata and local install inputs, selects a safe managed destination, installs
with argument-separated pip invocation, records the digest only after the
console launcher exists, and runs offline install-level doctor. Runtime setup
selects a fixed current-user product root before secure filesystem publication.

## Compatibility

Fresh POSIX checkouts retain `.venv/bin` and scoped `umask 077`. Existing
bootstrap-managed environments remain idempotent. Native Windows requires no
PowerShell activation and produces the wheel console `.exe` declared by the
existing project entry point.

## Security

Unverified environments never execute. No environment is deleted or replaced.
Symbolic, hard-linked, non-regular, oversized, or identity-changing markers do
not establish provenance, and marker refresh cannot overwrite a link target.
Current working directory is not a default configuration source. Local offline
directories are explicit, and package-index credentials remain outside command
arguments. Existing native secure-filesystem policy continues to reject remote,
reparse, unsupported, or untrusted state paths.

## Rejected alternatives

The bootstrap does not try to infer trust from executable presence, repair a
foreign environment, accept authenticated index URLs as arguments, or emulate
POSIX permissions on Windows.
