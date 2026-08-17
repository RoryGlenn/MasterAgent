# Design

## Approach

Use repository-owned Markdown for human-reviewable requirements and TOML for
bounded machine-readable change metadata. Implement a standard-library Python
script with `validate`, `status`, and `archive` subcommands. The archived pilot
stores exact final snapshots of the current requirements created by issue #75.

## Affected components

- `specs/` for current, active, archived, and template artifacts;
- `scripts/specs.py` for validation and lifecycle operations;
- `tests/test_specifications.py` for unit and adversarial coverage;
- agent contracts for workflow enforcement;
- CI and source-distribution metadata;

## Data flow

```text
GitHub issue
    -> change.toml + proposal + requirements + design + tasks
    -> implementation and executable evidence
    -> verifying state
    -> archive preflight
    -> current requirement deltas
    -> final validation
    -> archived terminal change
```

The script reads only an explicitly resolved repository root. Current
requirement destinations are relative to `specs/current/`; change snapshots are
relative to the selected change directory.

## Compatibility

The feature adds no package dependency and no runtime command. Normal
MasterAgent installation and provider operations remain unchanged. The source
distribution includes the development specifications and tooling so extracted
source validation remains reproducible.

## Security

- bound file size, count, change count, and delta count;
- require normalized POSIX-relative paths;
- reject symlinks, traversal, backslash ambiguity, and non-regular files;
- validate requirement identity before modify/remove;
- stage archive metadata and retain rollback copies before changing current
  requirements;
- validate the final tree before committing the archive transition;
- treat every specification as repository data, never runtime authority.

## Rejected alternatives

- Importing the OpenSpec CLI or schema would introduce an unnecessary external
  compatibility obligation.
- Adding specification digests to runtime plans would incorrectly mix software
  development intent with provider action authorization.
- Storing only prose change files would prevent deterministic conflict,
  lifecycle, reference, and archival validation.
