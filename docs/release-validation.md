# Release Validation — v1.0.0

The source tree and built artifacts are validated offline before release.
Organization-specific activation remains a deployment task because no real
workplace credentials, tenant consent, production resources, authenticated
approval service, or external audit-sink adapter is bundled.

## Automated validation

- The complete unit, integration-contract, and adversarial regression suite
  passes on Python 3.12, 3.13, and 3.14 in CI.
- Python bytecode compilation passes for `src/` and `tests/`.
- Repository configuration and all 12 wheel-packaged TOML defaults match exactly.
- Every packaged live connector, provider mutation gate, and recurring workflow is disabled.
- All 71 typed capabilities have governance coverage; the sole high-impact merge capability remains disabled.
- Local Markdown links, source-tree hygiene, and the credential-free v1 demonstration manifest pass validation.
- The generated PowerPoint opens as a three-slide presentation and passes rendered overflow testing.
- The source archive is extracted and tested independently before release.
- The wheel is installed outside the source tree and exercised with safe defaults before release.
- Release archives are checked for integrity, forbidden secret/runtime files, and symbolic links.

Ruff linting and formatting plus strict mypy checks pass without file
exclusions and are required CI gates. Tool versions are pinned in the project
development dependencies so local and CI results use the same rule set.

## Deployment boundary

The release does not claim successful authentication against a particular
organization and cannot report production-ready while no implemented external,
tamper-resistant audit sink exists. Before live use, administrators must
approve applications, scopes, Conditional Access behavior, retention, data
handling, provider URLs, secret storage, and production governance. The
deployment runbook requires read-only non-production probes before any
reversible write or communication capability is enabled.
