<p align="center">
  <img src="docs/assets/masteragent-hero.webp" alt="Five abstract work streams pass through visible safety gates, converge in a compass-shaped orchestration core, and leave as one verified path" width="100%" />
</p>

# MasterAgent

[![CI](https://github.com/RoryGlenn/MasterAgent/actions/workflows/ci.yml/badge.svg)](https://github.com/RoryGlenn/MasterAgent/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB.svg)](https://www.python.org/downloads/)
[![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-7c7cff.svg)](CHANGELOG.md)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-334155.svg)](LICENSE)

**Coordinate work across your stack without handing the model a master key.**

**Ask for the outcome. Keep policy, approval, execution, and verification in
deterministic code.**

MasterAgent turns a user request into typed, reviewable actions across Jira,
Confluence, Bitbucket, GitHub, Reddit, Outlook, Microsoft Teams,
SharePoint/OneDrive, OneNote, PowerPoint, and local Git workspaces. An AI can
help plan the work; it cannot grant itself access, invent a tool, change an
approved action, or claim success without an independent check.

**Version 1.0.0 — governed enterprise-agent runtime**

## Why MasterAgent exists

MasterAgent is built for restricted corporate environments where a third-party
Model Context Protocol (MCP) server may be unavailable, unreliable behind the
managed network, or prohibited until the organization reviews and approves it.
A workflow that depends on downloading such a server is therefore not a
dependable employee workflow in those environments.

The project instead ships and maintains first-party native connectors for its
supported providers. Those connectors are part of the governed runtime: they
use typed capabilities, fixed provider boundaries, selected credentials,
independent verification, and the same approval and audit rules as every other
action. Built-in provider workflows do not require a third-party MCP server.

MCP is optional, not the foundation. A specific MCP adapter may be added later
only when the organization approves it, it works reliably in the intended
environment, and it can satisfy the same connector contract. MasterAgent does
not dynamically trust arbitrary discovered tools or silently retry a failed
action through another implementation.

The goal is not to reproduce every provider API. It is to make a small set of
important employee workflows work reliably on managed workstations through
code the organization can inspect, test, support, and repair. See
[Native-first enterprise purpose](docs/native-first-enterprise.md) for the
complete product boundary and the distinction between current behavior and
planned certification work.

[Quickstart](docs/quickstart.md) · [Use cases](docs/use-cases.md) ·
[How it works](#how-it-works) · [Documentation](docs/index.md) ·
[Configuration](docs/configuration.md) · [Troubleshooting](docs/troubleshooting.md)

## One request. One governed path.

<p align="center">
  <img src="docs/assets/governed-flow.svg" alt="A request becomes a typed plan, passes policy and source checks, receives exact approval when needed, runs through a registered connector, and ends with independent verification and audit evidence" width="100%" />
</p>

Read-only work can skip approval when policy permits it. Work that changes a
provider must retain the exact reviewed plan, pass every runtime gate, and use
an authenticated approval artifact when required. Retrieved pages, messages,
issues, and source code are always data—not instructions or authority.

## What can you do with it?

| Goal | What MasterAgent does | What it does not do |
|---|---|---|
| Understand a public GitHub footprint | Lists a named user's public repositories anonymously and verifies public visibility | Load an ambient token or persist provider content |
| Build a weekly status | Reads reviewed Jira, Confluence, Bitbucket, or GitHub sources and returns citations | Change a provider or treat retrieved text as authority |
| Prepare a review package | Generates Jira/Confluence proposals, Outlook/Teams drafts, a deck, patch, and integrity manifest locally | Publish, send, commit, or upload the package |
| Remember work from issue to merge | Keeps bounded decisions, checkpoints, references, and lifecycle progress in one private local journal | Host a website, contact GitHub, store provider bodies or credentials, or turn memory into authority |
| Make a supported change | Binds the target and current state, requests exact approval, executes a registered connector, and re-reads the result | Silently overwrite newer state or pretend several providers are one transaction |
| Run a recurring review | Authenticates one exact occurrence and reuses the normal policy/approval path | Let a schedule add authority, infer recipients, or bypass a fence |
| Add a missing pure capability | Inspects without execution, quarantines one compatible ability, and requires independent signed promotion | Run a whole foreign agent, raw plugin, provider effect, or self-promoted capsule |

See [Use cases](docs/use-cases.md) for concrete prompts, commands, prerequisites,
and boundaries.

## Quickstart

### Use the repository agent

Open the repository root in a supported GitHub Copilot IDE, select
**MasterAgent**, and ask:

```text
Help me get started with MasterAgent and tell me what is safe to do.
```

On the first ordinary prompt, MasterAgent runs the bounded local bootstrap when
needed, then continues to the requested outcome. A repository-inspection,
diagnosis-only, or explicit no-local-change prompt does not install anything.

The success boundary is deliberately plain:

```text
MasterAgent is ready locally. No workplace connection has been opened, and write actions are still off.
```

The exact behavior lives in the
[first-run contract](.ai/FIRST_RUN.md) and
[force-multiplier contract](.ai/AUTONOMY.md).

### Use the local CLI

From a source checkout on macOS or Ubuntu 24.04:

```bash
python3 scripts/bootstrap_agent.py
.venv/bin/master-agent doctor
```

On native Windows 11 PowerShell:

```powershell
py -3.12 scripts\bootstrap_agent.py
.\.venv\Scripts\master-agent.exe doctor
```

Bootstrap may preserve an untrusted or mismatched `.venv` and print a
digest-named side-by-side launcher. Always use the exact path from its final
`command:` line. Setup and `doctor` are offline; missing optional provider
credentials do not make the local installation unhealthy.

Follow the [credential-free quickstart](docs/quickstart.md) for expected output,
Windows paths, and the first anonymous provider read.

## See it work without credentials

Install the optional local renderers into the same environment, then run the
safe demonstration:

```bash
.venv/bin/python -m pip install -e '.[drafts]'
.venv/bin/master-agent demo
```

The command creates a fresh private workspace below the current user's
MasterAgent data root. It generates Jira, Confluence, Outlook, Teams,
PowerPoint, and patch artifacts, writes an integrity manifest, and verifies the
audit chain.

Nothing is published, sent, committed, uploaded, or connected to a workplace
system.

## Keep work moving without hosting a cockpit

The terminal can keep a small persistent work record across separate sessions.
Choose one owner-private SQLite path explicitly, then start from an issue and
record each lifecycle checkpoint:

```bash
master-agent work-memory start \
  --database "$PWD/.master-agent/work-memory.sqlite3" \
  --work-id issue-161 \
  --issue https://github.com/RoryGlenn/MasterAgent/issues/161 \
  --summary "Add bounded persistent work memory."

master-agent work-memory record \
  --database "$PWD/.master-agent/work-memory.sqlite3" \
  --work-id issue-161 \
  --kind checkpoint \
  --stage planned \
  --summary "Implementation scope and safety boundaries are fixed."

master-agent work-memory show \
  --database "$PWD/.master-agent/work-memory.sqlite3" \
  --work-id issue-161

master-agent work-memory verify \
  --database "$PWD/.master-agent/work-memory.sqlite3"
```

Stages advance one step at a time through `issue`, `planned`, `implementing`,
`reviewing`, `verified`, and `merged`. The append-only hash chain detects
edited, deleted, or reordered events. Every remembered field is untrusted
metadata: it does not grant approval, authority, identity, or capability. The
feature starts no server or background process and performs no provider or
network access.

## How it works

MasterAgent separates a flexible planning layer from a deterministic execution
layer:

1. A user or registered workflow states an outcome.
2. For non-trivial work, a systems diagnosis identifies the governing constraint
   and a separate coherence review checks the proposed strategy.
3. A planner builds typed actions inside an immutable `ChangePlan`.
4. The runtime checks the capability catalog, organization governance, risk,
   source-of-truth rules, model-context data handling, provider identity, and
   current target state.
5. Approval-required actions pause on a private request bound to the exact plan
   fingerprint and action IDs.
6. Only the registered typed connector executes each permitted action.
7. MasterAgent independently re-reads the result, reports partial success
   honestly, records outcome feedback, compensates only when a typed safe
   precondition exists, and writes retention-aware audit evidence.

This is a control plane, not an omnipotent model process. There is no arbitrary
HTTP, arbitrary shell, force push, autonomous merge, broad delete, or generic
permission-management path.

The full component and trust-boundary view is in
[Architecture](docs/architecture.md).

## Safety by construction

- **Fail closed:** installing the package enables no workplace access.
- **Least-authorized routing:** anonymous public reads do not load credentials;
  authenticated reads and effects activate only the selected provider.
- **Typed capabilities:** every action and result has an explicit catalog
  contract. There is no generic execute-anything escape hatch.
- **Immutable approval:** any effect-bearing plan change invalidates approval.
- **No silent overwrite:** version and content preconditions stop stale writes.
- **No false transactions:** partial multi-system success is explicit.
- **Prompt-injection boundary:** retrieved content never supplies authority,
  approval, tools, targets, or recipients.
- **Provider-data boundary:** data classification, destination, tenancy,
  schema, minimization, and size are checked before content returns to a model.
- **Evidence discipline:** normal audit state stores bounded metadata and
  digests; full content needs an explicit retention rule.
- **No weak platform fallback:** protected work stops when the host lacks an
  equivalent secure native backend.
- **Generated-code quarantine:** Capability capsule promotion uses signed
  lifecycle records and Linux bubblewrap or the reviewed Windows AppContainer
  path. See [`docs/capability-capsules.md`](docs/capability-capsules.md).

Review the complete [Threat model](docs/threat-model.md).

## Capability surface

The catalog contains **97 typed capabilities**:

- 53 read-only capabilities;
- 13 local-generation capabilities;
- 20 reversible-write definitions;
- 8 external-communication capabilities;
- 3 high-impact capability definitions, all disabled.

| Domain | Read | Draft/local generation | Approved effects |
|---|---|---|---|
| Jira | issue search/read and server info | issue, comment, and transition proposals | narrow version-aware mutations; unsupported atomic operations remain disabled |
| Confluence | page search/read | page create/update proposals | version-aware page operations and bounded Cloud space creation |
| Reddit | purpose-scoped search, content, rules, history, and inbox | post, comment, and reply Markdown | exact approved post/comment/reply; edit/delete remain disabled pending provider compare-and-swap |
| Bitbucket | public or authenticated repositories, pull requests, changes, and CI status | branch plans and source patches | pull-request creation; merge and local-Git publication disabled |
| GitHub | public/authenticated repositories, metadata, pull requests, and checks | — | issue and pull-request creation; unsafe administration disabled |
| Outlook | folders, messages, and allowlisted text attachments | `.eml` draft | exact-content send after provider-draft verification |
| Teams | chats, teams, channels, messages, and replies | message draft | chat/channel sends and channel replies |
| SharePoint/OneDrive | sites, drives, folders, metadata, and bounded text | local files and decks | replacement disabled pending exact atomic provider preconditions |
| OneNote | notebooks, sections, and pages | generated HTML/proposals | writes disabled pending target-aware DOM verification |
| PowerPoint | — | local `.pptx` generation | publishing follows the separately governed SharePoint path |
| Capability capsules | declarative preview and routed promoted pure reads | deterministic local generation | provider/side-effect, dependent, raw-agent, and recursive import execution disabled |

The [Integration matrix](docs/integration-matrix.md) is the canonical compact
provider view. [Capability contract](docs/capability-contract.md) defines the
exact runtime envelope.

## Public reads and provider connections

Anonymous public-data capabilities neither require nor load credentials.

```bash
master-agent github-repositories --username USERNAME
master-agent bitbucket-repositories --workspace WORKSPACE
```

These commands route through `github.public_repository.list` and
`bitbucket.public_repository.list`, ignore ambient provider credentials, bound
the response, classify it as public, and independently verify the result.

For account-visible or private data, select only the systems needed for the
goal and supply an already-issued private credential file:

```bash
master-agent connect \
  --systems jira,confluence,github \
  --data-classification internal \
  --credentials-file /absolute/path/to/private-credentials.json
```

An Atlassian Cloud UI URL can be normalized and bound for one invocation
without changing persistent configuration:

```bash
master-agent connect \
  --systems confluence \
  --data-classification internal \
  --connector-url confluence=https://tenant.atlassian.net/wiki/spaces \
  --credentials-file /absolute/path/to/private-credentials.json
```

Reuse the exact connector URL during context binding and apply so the
destination remains approval-bound. See [Configuration](docs/configuration.md)
and [GitHub connector quickstart](docs/github-connector-quickstart.md).

## Review one engineering work item

An organization-reviewed profile can run the exact read-only `T1-EWIR-001`
workflow across one Jira issue, one configured Bitbucket pull request and its
head-commit build evidence, and up to three configured Confluence pages:

```bash
master-agent engineering-work-item-review PROJECT-123 \
  --profile /absolute/private/organization-profile.toml
```

The command uses only first-party native connectors and publishes one private,
cited, digest-verified three-file bundle. The packaged safe profile does not
enable it, and local implementation evidence is not the protected #94/#172
managed-workstation certification. See the
[Tier-1 workflow plan](docs/tier-1-engineering-work-item-review-plan.md).

## Exact-plan approval and effects

The ordinary employee front door is:

```bash
master-agent setup --non-interactive
master-agent doctor
master-agent execute change-plan.json
```

An allowed single-provider read can stay in memory with no audit, artifact, or
approval state. Draft and effect work receives only the private local state it
needs. If policy requires approval, the same `execute` command can resume the
exact saved request after a trusted operator supplies its authenticated
artifact.

The lower-level approval workflow remains available for automation and
diagnosis:

```bash
master-agent inspect-approval-request /absolute/state/drafts/approval-request.json

master-agent approve-request /absolute/state/drafts/approval-request.json \
  --key-id OPERATOR_KEY_ID \
  --expected-fingerprint REQUEST_FINGERPRINT \
  --output /absolute/state/approvals/approval.json

master-agent resume-approval /absolute/state/drafts/approval-request.json \
  --expected-fingerprint REQUEST_FINGERPRINT \
  --approval /absolute/state/approvals/approval.json
```

MasterAgent may inspect and resume the request, but it never impersonates the
trusted approval authority. Conversational assent is direction, not an
authenticated approval artifact.

A missing safe repository capability is implementation work, not a final
answer that “the connector is read-only.” The development parent adds the
smallest complete typed path, tests, configuration, verification or
compensation, and documentation, then resumes the original outcome. That rule
removes code barriers, not credential, target, policy, or authenticated
approval boundaries.

See [Operations](docs/operations.md) and the
[Deployment runbook](docs/deployment-runbook.md).

## Repository agent and advisory specialists

The repository-scoped profile is
[`.github/agents/MasterAgent.agent.md`](.github/agents/MasterAgent.agent.md).
The checked-in advisory profiles now define a fail-closed contract.

Direct GitHub-host advisory invocation is disabled. Optional live Researcher
and Plan Reviewer calls must pass through the repository-owned advisory integration harness with an authenticated cross-process goal budget, one
parent-selected `--route ROUTE_ID`, minimum path scope, immutable repository
binding, sanitized context, read/search-only tools, structured output, and
parent citation re-read.

If that adapter is unavailable or fails closed, the selected parent must
complete the same work directly; it completes the same research or review directly instead of weakening the boundary. Details are in
[Advisory specialist safety](docs/advisory-subagents.md).

For every non-trivial repository change, the selected parent also applies the
[Docs Agent contract](.ai/DOCS_AGENT.md). A material conflict returns
`needs_review` rather than turning an apparent defect into documented intent.

A missing safe capability remains implementation work, but it must stay inside
the admitted proximate objective, coherent actions, tradeoffs, and complexity
budget. Useful adjacent gaps become follow-up evidence instead of silently
expanding the current goal.

## Development plane and runtime plane

MasterAgent keeps changing the software separate from using the software:

```text
Development plane
Issue → behavioral change specification → code and tests
      → documentation review → validation → archived requirement delta

Runtime plane
Request → systems diagnosis → strategy + coherence review
        → immutable ChangePlan → policy and governance → exact approval
        → registered connector → verification, audit, and feedback
```

Specifications govern changes to MasterAgent. A runtime `ChangePlan` governs
actions performed by MasterAgent. Specifications never grant a capability,
credential, target, provider access, or approval.

Use [Development specifications](docs/development-specifications.md) and the
[specification workflow](specs/README.md) for non-trivial behavioral work. The
generated [Semantic router](docs/semantic-index.md) is the first repository
navigation hop, not runtime authority.

## Requirements and installation choices

- Python 3.12 or newer.
- Ubuntu 24.04 LTS, macOS, native Windows 11, or WSL for documented setup.
- Linux bubblewrap only for capability-capsule validation or execution on
  Linux; native Windows uses AppContainer; macOS capsule execution remains
  unavailable.
- Approved provider endpoints and credentials only for the selected
  authenticated capability.
- Organization-specific governance, retention, application consent, secrets,
  approval verification, and external audit controls before production use.

Release artifacts are named `master_agent-1.0.0.tar.gz` and
`master_agent-1.0.0-py3-none-any.whl`. Source, wheel, offline wheelhouse,
Windows, and optional-extra procedures are in the
[Quickstart](docs/quickstart.md), [Deployment runbook](docs/deployment-runbook.md),
and [Release validation guide](docs/release-validation.md).

## Release status

The v1 governed core and typed provider contracts are implemented. Provider
effects remain disabled at rest, production activation still requires an
organization's own credentials and controls, and the protected Windows 11 x64
certification remains planned until a clean enrolled standard-user runner
produces real evidence.

See the [Implementation roadmap](docs/implementation-roadmap.md) for the
current completion ledger and [Windows certification](docs/windows-certification.md)
for the outstanding release evidence.

## Documentation

The [complete documentation index](docs/index.md) is organized by reader goal
and identifies each canonical source. The full checked-in guide set is also
listed here so release validation can prove that every current document is
discoverable.

### Start and operate

- [Quickstart](docs/quickstart.md)
- [Native-first enterprise purpose](docs/native-first-enterprise.md)
- [Use cases](docs/use-cases.md)
- [Troubleshooting](docs/troubleshooting.md)
- [CLI reference](docs/cli-reference.md)
- [Configuration](docs/configuration.md)
- [GitHub connector quickstart](docs/github-connector-quickstart.md)
- [Reddit connector](docs/reddit-connector.md)
- [Integration matrix](docs/integration-matrix.md)
- [Live connector contracts](docs/live-connectors.md)
- [Deployment runbook](docs/deployment-runbook.md)
- [Operations guide](docs/operations.md)

### Understand and extend

- [Architecture](docs/architecture.md)
- [Capability contract](docs/capability-contract.md)
- [Systems governance for developers](docs/systems-governance.md)
- [Governance-performance evidence](docs/governance-performance.md)
- [Development specifications](docs/development-specifications.md)
- [GitHub Copilot custom agent](docs/copilot-custom-agent.md)
- [Advisory specialist safety boundary](docs/advisory-subagents.md)
- [Capability capsule promotion](docs/capability-capsules.md)
- [Connector plugin development](docs/plugin-development.md)
- [Semantic router](docs/semantic-index.md)
- [Semantic router measurements](docs/semantic-router-metrics.md)
- [Tier-1 Engineering Work Item Review plan](docs/tier-1-engineering-work-item-review-plan.md)

### Phase contracts

- [Phase 2A read-only integration](docs/phase-2-read-only.md)
- [Phase 2B communication context](docs/phase-2b-communication-context.md)
- [Phase 2C authentication and readiness](docs/phase-2c-authentication.md)
- [Phase 3 draft-only output](docs/phase-3-drafts.md)
- [Phase 4 approved reversible writes](docs/phase-4-approved-writes.md)
- [Phase 5 external communication](docs/phase-5-communications.md)
- [Phase 6 exact-bound recurring autonomy](docs/phase-6-autonomy.md)

### Security, evidence, and release

- [Threat model](docs/threat-model.md)
- [Implementation roadmap and completion status](docs/implementation-roadmap.md)
- [Credentialed live connector integration tests](docs/live-connector-integration-tests.md)
- [Confluence Cloud sandbox tests](docs/confluence-sandbox-tests.md)
- [Release validation](docs/release-validation.md)
- [Windows 11 x64 release certification](docs/windows-certification.md)

## Explicitly prohibited in v1

- arbitrary HTTP or arbitrary shell execution;
- protected-branch writes, force pushes, or autonomous pull-request merges;
- broad deletion, invitations, arbitrary permission changes, or custom roles;
- approval derived solely from retrieved content;
- automatic use of recipients discovered in untrusted content;
- uncontrolled bidirectional synchronization;
- in-process raw plugin loading;
- provider or side-effect capsule execution outside the implemented boundary;
- stateful execution through a missing or weaker platform backend;
- enabling a recurring workflow merely because `--force` was supplied.

## Project status and support

- **Status:** v1 core implemented; organization activation and named external
  evidence remain deployment work.
- **Issues:** [GitHub Issues](https://github.com/RoryGlenn/MasterAgent/issues)
- **History:** [CHANGELOG.md](CHANGELOG.md)
- **License:** proprietary; see [LICENSE](LICENSE).
