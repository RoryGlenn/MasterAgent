# Design

## Context

The existing manual workflow already owns the three protected privilege
environments. The production Tier-1 command already performs normal profile
admission, immutable plan binding, native connector selection, provider reads,
independent verification, private rendering, and performance recording. The
missing boundary is a protected selector that supplies only the narrow initial
fixture and independently verifies the resulting evidence without retaining
provider content.

## Approach

Add a `test_case` choice with `disabled` and `T1-EWIR-001` to the existing
workflow. The validation job rejects a named case combined with either effect
or administration mode. Each provider job has an explicit non-overlapping
condition; the broad read path runs only while the selector is disabled and no
privileged mode is selected.

The dedicated Tier-1 job reuses `connector-integration-read`, the existing read
enablement gate, and the pinned checkout/setup actions. It installs the reviewed
project into a runner-temporary virtual environment and maps only the three
Atlassian credential pairs, optional read-proxy credentials, and optional
enterprise CA.

`tests/test_connector_integration_matrix.py` remains the executable live
harness boundary. A preparation subcommand creates one fresh private case root,
materializes the protected integrations/workflow bytes and a fixed local
profile with exclusive no-follow writes, validates exact permissions and
settings, and emits no provider data. A verification subcommand securely reads
the single run, validates the result, bound plan, artifacts, manifest digests,
and typed performance snapshot, and emits only a fixed content-free summary.
All failure output is a fixed case-stage message rather than an exception or
configuration value.

The initial case requires exactly one Confluence page and
`include_diffstat = false`. The production workflow keeps its general zero-to-
three-page and optional-diffstat behavior.

The high-level command attests each selected provider during immutable context
binding and again immediately before applied execution. The protected selector
therefore requires six attestations, two per provider. This is intentionally
different from the deterministic benchmark's setup-only three-attestation
record.

## Affected components

- `.github/workflows/live-connector-integration.yml`
- `tests/test_connector_integration_matrix.py`
- `tests/test_live_connector_workflow.py`
- `tests/test_operating_modes.py`
- the protected-live, Tier-1, security, release, and deployment documentation
- `MA-LIVE-INTEGRATION-001`

## Data flow

```text
manual selector + protected environment
        |
        v
create-only integrations/workflow/fixed profile
        |
        v
offline exact-scope preflight
        |
        v
installed production high-level command
        |
        v
private single run + three private artifacts
        |
        v
strict content-free evidence verification
        |
        v
GitHub step summary (no provider content)
```

## Compatibility

The selector defaults to `disabled`. Existing read, effect, communication, and
administration dispatches retain their credentials, fixtures, and commands;
their only behavior change is explicit mutual exclusion from the named case.
The general production Tier-1 configuration remains flexible up to three
Confluence pages with optional diffstat.

## Security

The selector runs only on reviewed default-branch code in the existing read
environment, materializes secret values only in create-only private files,
executes one fixed production command, and retains no provider artifact. Both
preflight and readback fail closed, and command exceptions never enter workflow
logs or summaries.

## Failure handling

Any selector conflict fails in the credential-free validation job. Any unsafe
path, missing secret, malformed configuration, write-capable connector, wrong
credential reference, extra page, diffstat selection, public classification, or
scope mismatch fails before the production command. The command output stays
private even on failure. Nonzero, missing, partial, stale, ambiguous, malformed,
over-budget, unbound, or unselected-provider evidence fails with a fixed
content-free message and produces no successful summary.

## Evidence limits

The job does not upload provider artifacts. Its summary contains only the
checked-out commit, completion boolean, three-file/mode fact, measurement mode
and baseline eligibility, fixed implementation dimensions, and bounded numeric
counters. A successful Ubuntu job proves only the repository-side protected
fixture path; Windows standard-user baseline evidence remains external.

## Rejected alternatives

A second workflow was rejected because it would duplicate the protected read
environment and action boundary. Reusing the broad read test was rejected
because that path exposes unrelated GitHub and Microsoft credentials and does
not invoke the high-level production command. A new production verifier was
rejected because the existing typed models, descriptor-pinned filesystem
boundary, and integration harness can provide the required independent
readback without widening the installed runtime surface.
