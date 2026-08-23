# Design

## Approach

The existing Windows 11 ARM job becomes a three-version matrix and retains its
fresh nested standard-user execution. A separate workflow is triggered only by
a completed default-branch CI push or an explicit dispatch from the default
branch. Its GitHub-hosted authorization job performs no checkout, verifies that
the selected full SHA is the current protected default-branch head, and passes
only that SHA to the certification job.

The certification job targets exact self-hosted Windows/x64/custom labels and
a protected environment. Before checkout it verifies a Windows workstation
build, AMD64 process architecture, a non-administrator token, long-path policy,
and absence of named production credentials. It checks out only the authorized
SHA without persisted credentials, installs wheel and source distribution into
separate temporary environments, runs the complete suite, and cleans bounded
work products.

The semantic router's bounded manifest reader preserves its path-before-open,
descriptor, and path-after-read identity checks. On Windows it compares the
stable volume/file identity, size, and modification time because Win32 path
metadata and C-runtime descriptor metadata do not share a POSIX permission,
link-count, or change-time projection for the same regular file.

## Affected components

- `.github/workflows/ci.yml`
- `.github/workflows/windows-certification.yml`
- `scripts/semantic_router.py`
- `tests/test_release_metadata.py`
- `tests/test_semantic_router.py`
- `.ai/semantic-router.toml`
- `docs/windows-certification.md`
- release, deployment, architecture, roadmap, README, and changelog documentation

## Data flow

Default-branch CI completes, the authorization job reads current branch
protection and head identity through the read-only GitHub token, and an exact
SHA output crosses to the protected environment. The environment dispatches
only to an enrolled ephemeral Windows 11 x64 runner. Host checks occur before
repository checkout; artifact and test evidence remains local to the clean VM.

## Compatibility

Linux CI remains unchanged. Pull requests gain two additional Windows 11 ARM
matrix entries. The protected workflow is inert unless the repository enable
variable is true, so merging repository support does not queue work on a
missing external runner.

## Security

No pull-request trigger reaches the self-hosted runner. The workflow has no
secret references, uses a read-only checkout token without persistence, and
requires both a protected current head and environment review. Host identity,
OS product type, architecture, privilege, and long-path policy fail closed.
Operators must enroll only ephemeral clean-image runners and reimage after each
security-sensitive run.

## Rejected alternatives

Windows Server is not treated as Windows 11. GitHub-hosted ARM evidence is not
treated as x64 certification. A persistent self-hosted runner, arbitrary ref
input, tag supplied by untrusted text, and any pull-request checkout on the
protected machine are excluded.
