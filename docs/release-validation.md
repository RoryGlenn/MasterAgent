# Release Validation — v1.0.0

The source tree and built artifacts are validated offline before release.
Organization-specific authenticated activation remains a deployment task
because no real workplace credentials, tenant consent, production resources,
authenticated approval service, or external audit-sink adapter is bundled.
Typed anonymous public-data capabilities require no credential activation.

## Automated validation

- The complete unit, integration-contract, and adversarial regression suite
  passes on Python 3.12, 3.13, and 3.14 in CI.
- A separately protected, opt-in Confluence Cloud sandbox workflow supplements
  those required scripted gates with a real page lifecycle, authenticated
  approval resume, exact cleanup, bounded stale-page recovery, and an optional
  independently gated disposable-space lifecycle. It never runs on pull-request
  code and is not required when sandbox secrets are unavailable.
- Repository configuration and all 13 wheel-packaged TOML defaults match exactly.
- The repository license, exact complete runtime dependency closure,
  dependency-license admission policy, CycloneDX 1.5 SBOM, and third-party
  notices agree. CI rechecks installed distribution versions and license
  metadata; unknown or denied licenses fail closed.
- Every packaged live connector, provider mutation gate, and recurring workflow is disabled.
- All 82 typed capabilities have governance coverage; GitHub administration,
  Jira read-check-write mutations, and high-impact Bitbucket merge remain
  explicitly prohibited.
- Release/version claims, the README guide index, the complete CLI command
  reference, capability summaries, checked-in plan schemas, local Markdown
  links, source-tree hygiene, and the credential-free v1 demonstration
  manifest pass validation.
- The repository-scoped GitHub Copilot profile is user-invocable,
  policy-bound, constrained to its reviewed tools, and aligned with the
  first-prompt contract and force-multiplier default-to-action contract across
  every instruction and onboarding Markdown file.
  Its idempotent repository-local bootstrap, stable nontechnical responses,
  explicit no-local-change safeguards, provider-neutral ephemeral connection,
  capability-gap ownership, last-resort question rules, script, and policy are
  included in the source distribution.
- The resumable approval handoff is tested from missing approval through
  private request inspection, trusted signing, exact-run resume, and dual
  approval. Tampered, stale, unsafe-permission, symlinked, or authority-drifted
  requests fail closed without weakening the existing plan or runtime gates.
- The capability-capsule acceptance flow generates, quarantines, validates,
  reviews, signs, enables, routes, executes, independently replays, audits, and
  receipts a synthetic missing capability through the normal orchestrator.
  Hosted test and coverage jobs install bubblewrap; unpromoted, tampered,
  dependency-confused, deprecated/revoked, path-escaped, secret/file/network/
  process-seeking, resource-exhausting, signature-substituted,
  approval-replayed, routing-confused, and exact-resume adversarial cases fail
  closed.
- Instruction, connector, configuration, deployment, and operations guides
  distinguish typed anonymous public reads from authenticated access. Release
  validation rejects the stale blanket claims that all live use requires a
  credential or that authentication-free endpoints are only for tests.
- The checked-in demonstration PowerPoint opens as a three-slide presentation;
  its separately recorded rendered review reports no overflow.
- The source archive is extracted and tested independently before release.
- The wheel is installed outside the source tree and exercised with safe defaults before release.
- Release archives are checked for integrity, forbidden secret/runtime files,
  symbolic links, and a capability worker writable by another OS account.
- Package builds normalize shipped Python modules to mode `0644`, independent
  of the builder's umask.
- CI installs and tests the runtime from owner-private virtual environments,
  never from the hosted runner's shared site-packages. The exact setup-python
  runtime tree is made non-writable by group/others before those environments
  are created.
- The source archive includes both workflow definitions alongside the
  workflow-contract tests that validate them.

Ruff linting and formatting plus strict mypy checks pass without file
exclusions and are required CI gates. Tool versions are pinned in the project
development dependencies so local and CI results use the same rule set.
Release validation also pins the capability-gap contract: an actionable request
must implement a missing governed connector path and resume the original goal,
never return a hypothetical implementation checklist as the outcome.

Run the equivalent local gates from the project root:

```bash
ruff check .
ruff format --check .
mypy
python3 scripts/generate_sbom.py --check --verify-installed
python3 -m unittest discover -s tests -v
python3 scripts/validate_release.py
```

## Deployment boundary

The release does not claim successful authentication against a particular
organization and cannot report production-ready while no implemented external,
tamper-resistant audit sink exists. Before authenticated live use,
administrators must approve applicable applications, scopes, Conditional
Access behavior, retention, data handling, provider URLs, secret storage, and
production governance. Anonymous public-data capabilities still require
reviewed endpoints, data handling, governance, and bounded verification, but
not application registration or secret storage. The deployment runbook
requires read-only non-production probes before any reversible write or
communication capability is enabled.
