# Release Validation — v1.0.0

The source tree and built artifacts are validated offline before release.
Organization-specific authenticated activation remains a deployment task
because no real workplace credentials, tenant consent, production resources,
authenticated approval service, production credential broker, or external
tamper-resistant audit sink is bundled.

Typed anonymous public-data capabilities require no credential activation.
They still require reviewed endpoints, bounded retrieval, governance, data
handling, and independent verification.

## Required CI gates

### Code quality and compatibility

- Ruff linting and formatting pass with the versions pinned in
  `pyproject.toml`.
- Strict mypy passes without source-file exclusions.
- The complete unit, integration-contract, and adversarial suite passes on
  Python 3.12, 3.13, and 3.14.
- Package imports, CLI entry points, generated artifacts, and checked-in
  examples are validated against the current source.

### Behavioral specifications

- `python scripts/specs.py validate` passes in the normal source test job.
- The extracted source distribution runs the same specification validation.
- The `specs/current/`, `specs/changes/`, `specs/archive/`, and
  `specs/templates/` trees are included in the source archive.
- Stable requirement IDs, change IDs, lifecycle states, required files,
  references, deltas, and archive/current consistency are checked.
- Adversarial tests cover path traversal, symlinks, duplicate IDs, conflicting
  deltas, incomplete tasks or evidence, unsafe archival, transaction rollback,
  and historical snapshot drift.
- The completed self-hosted pilot proves the full issue → change specification
  → implementation/tests → current requirement → archive lifecycle.
- Validation keeps specifications in the development plane. They cannot grant
  a capability, satisfy approval, alter a runtime `ChangePlan`, resolve
  credentials, authorize provider execution, or enter runtime audit authority.

### Runtime and provider contracts

- Repository configuration and all 13 wheel-packaged TOML defaults match
  exactly.
- Every packaged live connector, provider mutation gate, communication gate,
  and recurring workflow is disabled by default.
- All 82 typed capabilities have governance coverage.
- GitHub administration without provider concurrency, Jira mutations without
  atomic read-check-write support, local/remote Git mutation, and high-impact
  Bitbucket merge remain explicitly prohibited.
- Anonymous public GitHub and Bitbucket routes construct authentication-free
  connectors and never resolve or forward ambient provider credentials.
- Instruction, connector, configuration, deployment, and operations guides
  distinguish anonymous public reads from authenticated access. Release
  validation rejects the stale blanket claims that all live use requires a
  credential or that authentication-free endpoints are only for tests.
- Immutable plan binding, authenticated approval, principal and scope
  attestation, idempotency, version checks, verification, compensation, and
  audit-chain behavior are covered by contract and adversarial tests.
- The resumable approval handoff is tested from missing approval through
  private request inspection, trusted signing, exact-run resume, and partial
  dual approval. Tampered, stale, symlinked, permission-unsafe, or
  authority-drifted requests fail closed.

### Agent profiles and repository automation

- The repository-scoped parent profile is user-invocable, policy-bound, and
  limited to the reviewed tools.
- The first-prompt contract and force-multiplier default-to-action contract stay
  synchronized across `AGENTS.md`, `.ai/`, the parent profile, README, and
  onboarding documentation.
- Validation pins the bounded local bootstrap, stable nontechnical responses,
  explicit no-local-change mode, provider-neutral connection flow,
  capability-gap ownership, late operator-question rule, and resumable
  approval handoff.
- The exact advisory-agent inventory contains one selected parent and two
  read/search-only child contracts. Direct child user/model invocation and the
  parent's `agent` tool are disabled.
- The repository-owned integration harness enforces exact-parent routing,
  depth one, three-research/one-review counters, context minimization,
  profile-derived dispatch, untrusted-output validation, and parent citation
  re-read.
- Adversarial fixtures prove no filesystem, environment, network, provider,
  credential, approval, audit, target, recipient, connector, tenant, or
  `ChangePlan` authority crosses the advisory boundary.
- All profiles, harness code, fixtures, tests, first-run and autonomy contracts,
  and the bootstrap script are present in the source distribution.
- The actionable capability-gap contract is pinned: a safe missing repository
  path must be implemented, tested, documented, and followed by a return to the
  original goal rather than a hypothetical checklist.

### Capability capsules and supply chain

- The capability-capsule acceptance flow generates, quarantines, validates,
  reviews, signs, enables, routes, executes, independently replays, audits, and
  receipts a synthetic missing pure capability through the normal
  orchestrator.
- Hosted jobs install Linux bubblewrap and test the isolated worker boundary.
- Unpromoted, tampered, dependency-confused, deprecated, revoked,
  path-escaped, secret/file/network/process-seeking, resource-exhausting,
  signature-substituted, approval-replayed, routing-confused, and exact-resume
  cases fail closed.
- The repository license, exact runtime dependency closure,
  dependency-license admission policy, CycloneDX 1.5 SBOM, and
  `THIRD_PARTY_NOTICES.md` agree.
- Installed distribution versions and license metadata are rechecked; unknown
  or denied licenses fail closed.
- Raw entry-point plugins, dependent capsules, provider capsules, side-effect
  capsules, and production activation remain outside the shipped execution
  boundary.

### Packaging and source hygiene

- Release/version claims, the README documentation index, CLI command reference,
  capability summaries, checked-in plan schemas, and local Markdown links match
  the source.
- The credential-free demonstration manifest is complete and remains marked
  unpublished and credential-free.
- The demonstration PowerPoint opens as a three-slide presentation and its
  rendered review reports no overflow.
- The source archive is extracted and tested independently.
- The wheel is installed outside the source tree and exercised with safe
  defaults.
- Release archives are checked for integrity, forbidden secrets or runtime
  state, symbolic links, and unsafe file ownership or modes.
- Shipped Python modules are normalized to mode `0644`, independent of the
  builder's umask.
- CI installs and tests from owner-private virtual environments rather than a
  hosted runner's shared site-packages.
- The source archive includes workflow definitions and the tests that validate
  them.

### Optional live sandbox validation

A separately protected, opt-in Confluence Cloud workflow supplements the
required offline gates with a real provider lifecycle:

- fixed read-only connection probe;
- private authenticated-approval resume;
- exact page create/read/versioned-update verification;
- always-run fresh cleanup;
- bounded HMAC-owned stale-page recovery; and
- an independently gated disposable-space lifecycle.

It runs only from trusted default-branch code, never from pull-request code, and
is not required when sandbox secrets are unavailable.

## Local validation

**Machine: development computer, from the repository root**

```bash
ruff check .
ruff format --check .
mypy
python3 scripts/generate_sbom.py --check --verify-installed
python3 -m unittest discover -s tests -v
python3 scripts/specs.py validate
python3 scripts/validate_release.py
```

A release is not valid merely because documentation claims a feature exists.
The executable gates must agree with the catalog, configuration, implementation,
tests, package contents, and current behavioral specifications.

## Deployment boundary

The release does not claim successful authentication against a particular
organization. It also cannot report production-ready while no implemented
external tamper-resistant audit sink and production credential broker exist.

Before authenticated live use, the target organization must approve applicable
applications, scopes, Conditional Access behavior, retention, data handling,
provider URLs, secret storage, production governance, human approval
authorities, and the external audit path. Read-only non-production probes should
precede any reversible write or communication capability.

Anonymous public-data capabilities do not require application registration or
secret storage, but they remain subject to reviewed capability, endpoint,
governance, retention, and verification contracts.
