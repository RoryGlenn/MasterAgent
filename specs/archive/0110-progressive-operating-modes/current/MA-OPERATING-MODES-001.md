# MA-OPERATING-MODES-001 — Capability-scoped operating modes

## Status

Active

## Requirement

MasterAgent MUST report separate capability-scoped readiness levels for local
installation, selected-provider reads, local drafts, governed effects, and
enterprise deployment. The report MUST expose stable `install_ready`,
`read_ready`, `draft_ready`, `effect_ready`, and `enterprise_ready` categories and MUST explain unmet
requirements without treating an unused optional provider or missing optional
credential as a broken installation.

A strict organization profile MUST select either `employee` or `developer`
mode, bind normal reviewed configuration locations, define the installed
capability allowlist, and keep write and communication gates disabled unless
explicitly reviewed. Employee mode MUST execute only installed, reviewed
capabilities and MUST NOT scaffold, load, self-promote, or execute missing
capability code. Developer mode MAY support explicit scaffolding, but generated
effect code MUST remain quarantined until independent review, tests,
specification archival, signing, deployment, and normal runtime admission
complete. Neither mode grants a capability, provider credential, or approval.

Setup and doctor MUST be usable without provider credentials, approval
artifacts, audit databases, effect configuration, or provider network requests.
Diagnostics MUST classify failures as `unsupported_capability`,
`missing_organization_setup`, `missing_user_authentication`, `blocked_policy`,
or `runtime_defect`; they MUST remain secret-free and MUST NOT include provider
content. `enterprise_ready` MUST remain false until required organization-owned
production adapters and controls are independently present.

## Rationale

An employee should know which work is ready without confusing installation,
optional account setup, permission to perform an effect, and production
certification. Explicit modes keep product usability separate from capability
development and promotion authority.

## Scenarios

### Fresh installation is healthy without workplace credentials

- GIVEN the core package and reviewed default profile are installed but no
  provider credential is available
- WHEN the employee runs setup and doctor
- THEN `install_ready` is true, unavailable provider reads or effects are
  explained separately, no provider is contacted, and `enterprise_ready`
  remains false

### Employee mode rejects a missing capability

- GIVEN an employee profile that does not list a requested capability
- WHEN a plan requests that capability
- THEN execution fails with `unsupported_capability` before connector,
  credential, audit, or artifact access
- AND the runtime neither scaffolds nor loads implementation code

### Developer output remains quarantined

- GIVEN a trusted developer explicitly scaffolds a missing effect capability
- WHEN scaffolding completes
- THEN the generated source has no runtime or provider authority
- AND employee execution rejects it until review, tests, specification
  archival, signing, deployment, and normal admission are complete

## Implementation

- `src/master_agent/operating.py`
- `src/master_agent/cli.py`
- `src/master_agent/config_sources.py`
- `config/organization-profile.toml`

## Verification

- `tests/test_operating.py`
- `tests/test_operating_modes.py`
- `tests/test_packaged_defaults.py`
- `tests/test_semantic_router.py`

## History

- Introduced by GitHub issue #110.
