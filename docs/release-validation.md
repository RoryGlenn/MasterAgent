# Release Validation — v1.0.0

The release is validated as a complete software implementation of Phases 0–6. Organization-specific activation remains a deployment task because no real workplace credentials, tenant consent, or production resources are bundled.

## Automated validation

- 163 unit and integration-contract tests pass.
- Python bytecode compilation passes for `src/` and `tests/`.
- Repository configuration and all 12 wheel-packaged TOML defaults match exactly.
- Every packaged live connector, provider mutation gate, and recurring workflow is disabled.
- All 71 typed capabilities have governance coverage; the sole high-impact merge capability remains disabled.
- Local Markdown links, source-tree hygiene, and the credential-free v1 demonstration manifest pass validation.
- The generated PowerPoint opens as a three-slide presentation and passes rendered overflow testing.
- The source archive is extracted and tested independently before release.
- The wheel is installed outside the source tree and exercised with safe defaults before release.
- Release archives are checked for integrity, forbidden secret/runtime files, and symbolic links.

## Deployment boundary

The release does not claim successful authentication against a particular organization. Before live use, administrators must approve applications, scopes, Conditional Access behavior, retention, data handling, provider URLs, secret storage, and production governance. The deployment runbook requires read-only non-production probes before any reversible write or communication capability is enabled.
