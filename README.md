# Master Agent

**Version 1.0.0 — governed enterprise-agent runtime**

Master Agent is a Python control plane for coordinating enterprise work across
Jira, Confluence, Bitbucket, GitHub, Outlook, Microsoft Teams,
SharePoint/OneDrive, OneNote, PowerPoint, and local Git workspaces. An AI planner
can propose work, but deterministic code owns capability selection, policy,
approval, execution, verification, compensation, retention, and audit.

```text
User request
    ↓
Typed immutable ChangePlan
    ↓
Capability catalog + governance + source-of-truth checks
    ↓
Exact-plan human approval where required
    ↓
Deterministic connector execution
    ↓
Independent verification
    ↓
Compensation + audit + retained evidence
```

The model cannot grant itself access, add an unreviewed capability, change an
approved plan, send arbitrary HTTP requests, treat retrieved content as
authority, or silently overwrite newer provider state.

## Development plane and runtime plane

MasterAgent deliberately separates **changing the software** from **using the
software**:

```text
Development plane
GitHub issue → behavioral change specification → code/tests
             → Docs Agent maintenance → verification
             → archive → maintained current requirements

Runtime plane
User/workflow request → ChangePlan → policy/governance → approval
                      → connector execution → verification/audit
```

- Agent and instruction files define **how coding agents work**.
- GitHub issues hold discussion, priority, and problem context.
- [`specs/current/`](specs/current/) records **required current behavior**.
- [`specs/changes/`](specs/changes/) records active behavioral deltas, design,
  and implementation tasks.
- [`.ai/DOCS_AGENT.md`](.ai/DOCS_AGENT.md) defines the evidence-aware
  documentation completion gate for non-trivial repository changes.
- Tests provide executable evidence.
- A runtime `ChangePlan` binds exact provider effects and approvals.

Specifications govern changes to MasterAgent. `ChangePlan` governs actions
performed by MasterAgent. Specifications are development data and never grant
capabilities, credentials, approval, or provider authority. See
[Development specifications](docs/development-specifications.md) and the
[specification workflow](specs/README.md).

## Release status

The v1 governed runtime and provider contracts are implemented. Incomplete or
unsafe surfaces remain deliberately non-routable.

| Area | Current status |
|---|---|
| Environment and governance | Capability ownership, deployment readiness, safe discovery, OAuth profiles, and secret-free diagnostics implemented |
| Governed runtime | Immutable plans, approvals, policy, source-of-truth validation, idempotency, verification, compensation, audit, and prompt-injection controls implemented |
| Read-only context | Jira, Confluence, Bitbucket, GitHub, Microsoft identity, Outlook, Teams, SharePoint/OneDrive, OneNote, citations, and retention implemented |
| Draft-only output | Jira and Confluence proposals, Outlook and Teams drafts, PowerPoint, repository patches, and integrity manifests implemented |
| Approved reversible writes | Narrow Jira, Confluence, Bitbucket, and GitHub operations implemented; unsafe or non-atomic mutations remain disabled |
| External communication | Exact-approved Outlook sends and Teams messages/replies implemented behind separate gates |
| Recurring workflows | Registration and status implemented; execution remains disabled pending complete immutable runtime binding |
| Advisory specialists | Optional broker-owned live Researcher and Plan Reviewer adapter implemented; direct GitHub-host child invocation remains disabled |
| Documentation completion | Audience-aware maintenance, authoring, and audit contract implemented; the selected parent applies it directly before completing non-trivial repository changes |
| Capability capsule promotion | Signed test/local promotion for dependency-free pure capabilities implemented; provider, side-effect, dependent, raw-plugin, and production activation remain fail closed |
| Behavioral specifications | Native current/change/archive lifecycle, validation, archival, templates, CI integration, and a completed self-hosted pilot implemented |

## Capability surface

The catalog contains **82 typed capabilities**:

- 46 read-only capabilities;
- 10 local-generation capabilities;
- 20 reversible-write definitions;
- 4 external-communication capabilities;
- 2 high-impact capability definitions, both disabled.

| Domain | Read | Draft/local generation | Approved effects |
|---|---|---|---|
| Jira | issue search/read and server info | issue/comment/transition proposals | narrow version-aware mutations; unsupported atomic operations remain disabled |
| Confluence | page search/read | page create/update proposals | version-aware Cloud/Data Center page operations and bounded Cloud space creation |
| Bitbucket | public workspace repositories, authenticated repositories, pull requests, changes, and CI status | branch plans and source patches | pull-request creation; merge and local-Git publication disabled |
| GitHub | public/authenticated repositories, repository metadata, pull requests, and checks | — | issue and pull-request creation; unsafe administration disabled |
| Outlook | folders, messages, and allowlisted text attachments | `.eml` draft | exact-content send after provider-draft verification |
| Teams | chats, teams, channels, messages, and replies | message draft | chat/channel sends and channel replies |
| SharePoint/OneDrive | sites, drives, folders, metadata, and bounded text | local files and decks | replacement remains disabled pending exact atomic provider preconditions |
| OneNote | notebooks, sections, and pages | generated HTML/proposals | writes remain disabled pending target-aware DOM verification |
| PowerPoint | — | local `.pptx` generation | publishing follows the separately governed SharePoint path |
| Capability capsules | promoted pure reads | promoted deterministic local generation | provider/side-effect and dependent capsule execution disabled |

## Core safety properties

- **Fail closed:** installing the package enables no workplace access.
- **Independent live gates:** a runtime flag, provider-specific configuration,
  and catalog/governance permission must all permit an effect.
- **Immutable approval:** approval binds to one SHA-256 plan fingerprint and
  exact action IDs. Any effect-bearing mutation invalidates it.
- **Authenticated separation:** governance can require zero, one, or two
  distinct human approvers.
- **Version preconditions:** modifying operations stop when reviewed provider
  state is stale.
- **No false transactions:** partial multi-system success is explicit.
  Compensation runs only where a typed adapter can enforce its precondition.
- **Prompt-injection boundary:** retrieved messages, pages, issues, notes,
  attachments, and source are untrusted data.
- **Constrained networking and source control:** no arbitrary HTTP, arbitrary
  shell, force push, protected-branch write, or autonomous merge path exists.
- **Evidence discipline:** normal audit records store bounded metadata and
  digests; full content requires an explicit retention rule.
- **Generated-code isolation:** Capability capsule promotion uses signed
  lifecycle records and Linux bubblewrap. Raw plugins and unsafe capsules do
  not become executable. See
  [`docs/capability-capsules.md`](docs/capability-capsules.md).

## Requirements

- Python 3.12 or newer.
- Ubuntu 24.04 LTS or macOS for the documented setup commands.
- Linux bubblewrap only when validating or executing capability capsules.
- Approved provider endpoints and credentials only for the selected
  authenticated capability. Anonymous public-data capabilities neither require
  nor load credentials.
- Organization-specific applications, scopes, retention, governance, and
  secrets before authenticated production deployment.

## Use as a GitHub Copilot custom agent

Open the repository root in a supported Copilot IDE and select **MasterAgent**
from the agents dropdown. The repository profile is
[`.github/agents/MasterAgent.agent.md`](.github/agents/MasterAgent.agent.md).

Send an ordinary prompt such as:

```text
Help me get started with MasterAgent and tell me what is safe to do.
```

The first operational prompt runs the bounded, idempotent
`scripts/bootstrap_agent.py` setup and reports:

```text
MasterAgent is ready locally. No workplace connection has been opened, and write actions are still off.
```

A repository-inspection, diagnosis-only, or explicit no-local-change prompt
does not install anything. The detailed behavior lives in the
[first-run contract](.ai/FIRST_RUN.md) and
[force-multiplier contract](.ai/AUTONOMY.md).

The checked-in advisory profiles now define a fail-closed contract for GitHub-host children. Direct GitHub-host advisory invocation is disabled: the parent has no `agent` tool and both children are non-user- and non-model-invocable. MasterAgent can instead run the Researcher or Plan Reviewer through the optional broker-owned Copilot SDK adapter. Every live specialist call passes through the repository-owned advisory integration harness, including parent ownership, depth and call budgets, context sanitization, read-only tool policy, state binding, and parent citation re-read. If the optional adapter is unavailable or fails closed, the parent will complete the same work directly; it completes the same research or review directly rather than weakening the boundary. See the [advisory and documentation specialist contracts](docs/advisory-subagents.md).

For every non-trivial repository change, the selected parent also applies the
[Docs Agent contract](.ai/DOCS_AGENT.md) after implementation and tests but
before completion. It updates affected authoritative documentation or records a
justified `no_change`; a material requirement, test, implementation, or
documentation conflict returns `needs_review` rather than being documented as
intent. This is direct parent work, not a live GitHub-host child-agent path.

A missing safe repository capability is implementation work, not a reason to
stop with “the connector is read-only.” MasterAgent adds the smallest complete
typed path, verification or compensation, tests, configuration, and
documentation, then resumes the original goal. Credentials, genuinely
ambiguous provider targets, and authenticated exact-plan approval remain real
operator boundaries.

## Install

### From a source distribution

**Machine: Ubuntu 24.04 or macOS development computer**

```bash
tar -xzf master_agent-1.0.0.tar.gz
cd master_agent-1.0.0

umask 077
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
master-agent readiness
```

To enable the optional broker-owned Researcher and Plan Reviewer adapter in a
development checkout, install the separate subagent extra:

```bash
python -m pip install -e '.[subagents]'
```

The base installation remains usable without that extra; unavailable specialist
delegation falls back to the selected MasterAgent parent.

### From a wheel

**Machine: Ubuntu 24.04 or macOS development computer**

```bash
umask 077
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./master_agent-1.0.0-py3-none-any.whl

master-agent readiness
master-agent plugins
```

Explicit CLI paths override packaged safe defaults. The current working
directory is never an implicit configuration source.

## Quick safe demonstration

Run a complete local review-package workflow without credentials or provider
writes:

```bash
master-agent demo
```

The command creates a fresh private workspace under
`~/.master-agent/MasterAgent/`, generates Jira, Confluence, Outlook, Teams,
PowerPoint, and patch artifacts, writes an integrity manifest, and verifies the
audit chain. Nothing is published, sent, committed, or uploaded.

## Readiness, discovery, and connection

Configuration-only readiness performs no network requests:

```bash
master-agent readiness \
  --integrations config/integrations.toml \
  --capabilities config/capabilities.toml \
  --governance config/governance.toml \
  --oauth config/oauth.toml
```

Inspect available connectors without activating them:

```bash
master-agent discover --integrations config/integrations.toml
```

Probe or connect only the systems needed for the requested operation:

```bash
master-agent connect \
  --systems jira,confluence,github \
  --credentials-file /absolute/path/to/private-credentials.json
```

For Atlassian Cloud, an operator-provided UI URL can be normalized and bound
for one invocation without changing persistent configuration:

```bash
master-agent connect \
  --systems confluence \
  --connector-url confluence=https://tenant.atlassian.net/wiki/spaces \
  --credentials-file /absolute/path/to/private-credentials.json
```

Reuse the exact `--connector-url` during `bind-context` and `run --apply` so the
destination remains approval-bound.

### Anonymous public repository reads

Anonymous public-data capabilities neither require nor load credentials.

```bash
master-agent github-repositories --username USERNAME
master-agent bitbucket-repositories --workspace WORKSPACE
```

These commands route through `github.public_repository.list` and
`bitbucket.public_repository.list`, ignore ambient provider credentials, bound
the response, and independently verify that returned repositories are public.

Use the authenticated `master-agent github-repositories` path only for “my
repositories,” private repositories, or other account-visible data.

## Exact-plan approval and execution

A provider effect is prepared as an immutable plan, bound to the exact runtime
configuration, inspected, and then executed only after its required approval
and gates are present.

```bash
master-agent bind-context change-plan.json \
  --connector-mode live \
  --integrations /trusted/config/integrations.toml \
  --capabilities /trusted/config/capabilities.toml \
  --governance /trusted/config/governance.toml \
  --policy /trusted/config/policy.toml \
  --sources-of-truth /trusted/config/sources_of_truth.toml \
  --approval-authorities /trusted/config/approval-authorities.toml \
  --output bound-change-plan.json

master-agent inspect bound-change-plan.json
```

When approval is missing, an applied run emits a private, create-only request
that contains the exact non-secret resume surface:

```bash
master-agent inspect-approval-request /absolute/state/drafts/approval-request.json

master-agent approve-request /absolute/state/drafts/approval-request.json \
  --key-id rory \
  --expected-fingerprint REQUEST_FINGERPRINT \
  --output /absolute/state/approvals/approval-rory.json

master-agent resume-approval /absolute/state/drafts/approval-request.json \
  --expected-fingerprint REQUEST_FINGERPRINT \
  --approval /absolute/state/approvals/approval-rory.json
```

Conversational approval is never a substitute for the authenticated artifact.
See the [CLI reference](docs/cli-reference.md),
[operations guide](docs/operations.md), and
[deployment runbook](docs/deployment-runbook.md) for full command contracts and
production setup.

## Behavioral specification workflow

Non-trivial changes to observable, architectural, or security-relevant
MasterAgent behavior use the repository-native specification lifecycle:

```text
draft → proposed → accepted → implementing → verifying → archived
```

```bash
python scripts/specs.py validate
python scripts/specs.py status
python scripts/specs.py archive <change-id>
```

After implementation and relevant tests, apply the Docs Agent maintenance
contract to the final change before declaring it complete. Continue after
`updated` or a justified `no_change`; route `needs_review` back to planning or
implementation, then run final specification and release validation before
archival.

Use the workflow for capabilities, approvals, policy, governance, connectors,
workflows, verification, compensation, retention, audit, and cross-component
contracts. Skip it for formatting, typo fixes, minor documentation corrections,
and mechanical refactors with no behavior change.

This is intentionally native rather than an OpenSpec dependency. It supplies
maintained current requirements and machine-checked change deltas without
creating another runtime planner or authorization layer. See
[`specs/README.md`](specs/README.md) and
[Development specifications](docs/development-specifications.md).

## Configuration map

| File | Purpose |
|---|---|
| `config/capabilities.toml` | Executable capability, target, parameter, authentication, scope, version, and reversibility contracts |
| `config/governance.toml` | Owners, environments, classifications, and approval tiers |
| `config/policy.toml` | Runtime risk policy and hard prohibitions |
| `config/integrations.toml` | Provider endpoints, credential references, and granular live gates |
| `config/oauth.toml` | OAuth profiles and required scopes |
| `config/sources_of_truth.toml` | Canonical resource and projection rules |
| `config/identities.toml` | Cross-system identity mappings, never credentials |
| `config/retention.toml` | Evidence persistence modes and TTLs |
| `config/dependency-licenses.toml` | Runtime and capsule dependency-license policy |
| `config/recurring.toml` | Disabled-by-default recurring workflow registrations |

## Documentation

### Start here

- [Development specifications](docs/development-specifications.md)
- [Architecture](docs/architecture.md)
- [Semantic codebase index](docs/semantic-index.md)
- [CLI reference](docs/cli-reference.md)
- [Configuration](docs/configuration.md)
- [Capability contract](docs/capability-contract.md)
- [Integration matrix](docs/integration-matrix.md)
- [Implementation roadmap and completion status](docs/implementation-roadmap.md)

### Agents and extensibility

- [GitHub Copilot custom agent](docs/copilot-custom-agent.md)
- [Advisory sub-agent and Docs Agent contracts](docs/advisory-subagents.md)
- [Capability capsule promotion](docs/capability-capsules.md)
- [Plugin development](docs/plugin-development.md)

### Providers and phase contracts

- [GitHub connector quickstart](docs/github-connector-quickstart.md)
- [Confluence Cloud sandbox tests](docs/confluence-sandbox-tests.md)
- [Live connector contracts](docs/live-connectors.md)
- [Phase 2 read-only context](docs/phase-2-read-only.md)
- [Phase 2B communication context](docs/phase-2b-communication-context.md)
- [Phase 2C authentication and readiness](docs/phase-2c-authentication.md)
- [Phase 3 draft-only output](docs/phase-3-drafts.md)
- [Phase 4 approved reversible writes](docs/phase-4-approved-writes.md)
- [Phase 5 external communication](docs/phase-5-communications.md)
- [Phase 6 recurring autonomy](docs/phase-6-autonomy.md)

### Security, operations, and release

- [Threat model](docs/threat-model.md)
- [Deployment runbook](docs/deployment-runbook.md)
- [Operations guide](docs/operations.md)
- [Release validation](docs/release-validation.md)

## Explicitly prohibited in v1

- arbitrary HTTP or arbitrary shell execution;
- protected-branch writes, force pushes, or autonomous pull-request merges;
- broad deletion, invitations, arbitrary permission changes, or custom roles;
- approval derived solely from retrieved content;
- automatic use of recipients discovered in untrusted content;
- uncontrolled bidirectional synchronization;
- in-process raw plugin loading;
- provider or side-effect capsule execution outside the implemented boundary;
- enabling a recurring workflow merely because `--force` was supplied.