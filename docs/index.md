# MasterAgent documentation

MasterAgent coordinates work across many systems without giving a model
unrestricted access. Start with the outcome you want; use the deeper references
only when you need to configure, operate, extend, or audit the runtime.

This index is the canonical map of the current documentation set. It separates
reader guidance from exact reference material, operational procedures,
architecture, and historical evidence so the same facts do not need to be
maintained in several places.

## Start here

- [Project overview](../README.md) — the product promise, capability summary,
  safety model, and shortest paths into the project.
- [Quickstart](quickstart.md) — get a credential-free result from a source
  checkout on macOS, Ubuntu, or Windows.
- [Use cases](use-cases.md) — choose a concrete outcome and see its credential,
  approval, and write boundaries.
- [Troubleshooting](troubleshooting.md) — diagnose setup, readiness, approval,
  provider, and platform failures by symptom.
- [GitHub connector quickstart](github-connector-quickstart.md) — public or
  account-visible GitHub context with the least-authorized route.
- [GitHub Copilot custom agent](copilot-custom-agent.md) — select MasterAgent in
  a supported IDE and understand its first-run behavior.

## Use and operate MasterAgent

These are current-state documents.

- [CLI reference](cli-reference.md) — canonical command and side-effect
  reference; generated `--help` remains the exact argument source.
- [Configuration](configuration.md) — canonical files, resolution order,
  credentials, governance, OAuth, retention, and live gates.
- [Integration matrix](integration-matrix.md) — fastest provider-by-provider
  view of reads, drafts, effects, verification, and defaults.
- [Deployment runbook](deployment-runbook.md) — move from local readiness to a
  reviewed non-production and production deployment.
- [Operations guide](operations.md) — execute plans, resume approval, handle
  incidents, rotate state, and monitor the runtime.
- [Reddit connector](reddit-connector.md) — OAuth profiles and bounded Reddit
  reads, drafts, posts, comments, and replies.
- [Live connector contracts](live-connectors.md) — exact shared connector and
  transport behavior.

## Understand the system

- [Architecture](architecture.md) — components, trust boundaries, runtime
  sequence, and development/runtime separation.
- [Capability contract](capability-contract.md) — typed action, result,
  citation, retention, and write contracts.
- [Systems governance for developers](systems-governance.md) — connect a plan
  to a systems diagnosis, strategy, and measurable outcome.
- [Threat model](threat-model.md) — protected assets, threats, controls,
  residual risks, and explicit prohibitions.
- [Implementation roadmap and completion status](implementation-roadmap.md) —
  current delivery status plus clearly labeled remaining deployment work.

## Delivery-phase contracts

These guides use the original delivery phases as stable names for current
runtime surfaces. They are not a suggestion that earlier phases are obsolete.

- [Phase 2A: read-only integrations](phase-2-read-only.md)
- [Phase 2B: communication context](phase-2b-communication-context.md)
- [Phase 2C: authentication and readiness](phase-2c-authentication.md)
- [Phase 3: draft-only output](phase-3-drafts.md)
- [Phase 4: approved reversible writes](phase-4-approved-writes.md)
- [Phase 5: external communication](phase-5-communications.md)
- [Phase 6: exact-bound recurring autonomy](phase-6-autonomy.md)

## Develop and extend MasterAgent

- [Development specifications](development-specifications.md) and the
  [specification workflow](../specs/README.md) — current requirements, change
  deltas, validation, and archival.
- [Advisory specialist safety boundary](advisory-subagents.md) — controlled
  researcher/reviewer routing and the direct parent fallback.
- [Capability capsule promotion](capability-capsules.md) — quarantine, review,
  signing, isolation, promotion, execution, disablement, and revocation.
- [Connector plugin development](plugin-development.md) — plugin entry points,
  typed contracts, catalog admission, and governance work.
- [Semantic router](semantic-index.md) — generated first-hop repository
  navigation. Edit `.ai/semantic-router.toml`, never this generated file.

## Test, release, and evidence

- [Release validation](release-validation.md) — required local, CI, packaging,
  supply-chain, documentation, and deployment gates.
- [Credentialed connector integration tests](live-connector-integration-tests.md)
  — protected live-evidence workflow and fixture boundaries.
- [Confluence Cloud sandbox tests](confluence-sandbox-tests.md) — dedicated
  non-production create/update/verify/compensate lifecycle.
- [Windows 11 x64 release certification](windows-certification.md) — planned
  protected clean-runner release evidence and recovery.
- [Semantic router measurements](semantic-router-metrics.md) — historical
  measurement snapshot for the generated-router transition and later route
  additions.

## Documentation lifecycle

- Current-state guides describe the accepted current system.
- `implementation-roadmap.md` mixes completed status with explicitly labeled
  planned deployment work.
- `semantic-index.md` is generated from `.ai/semantic-router.toml`.
- `semantic-router-metrics.md`, archived specifications, and release history are
  evidence for named snapshots; do not rewrite them to resemble the present.
- `CHANGELOG.md` is historical release history, not a second user guide.

When information overlaps, update the canonical document named above and keep
secondary pages to a short summary plus a link.
