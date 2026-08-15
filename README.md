# Master Agent

**Version 1.0.0 — governed enterprise-agent runtime**

Master Agent is a Python control plane for coordinating enterprise work across Jira, Confluence, Bitbucket, GitHub, Outlook, Microsoft Teams, SharePoint/OneDrive, OneNote, PowerPoint, and local Git workspaces. Connector-plugin inventory and approval binding are available for review, but plugin execution is disabled.

It separates AI planning from authorization and execution:

```text
User request
    ↓
Typed immutable ChangePlan
    ↓
Capability catalog + organization governance + source-of-truth checks
    ↓
Exact-plan human approval where required
    ↓
Deterministic connector execution
    ↓
Independent verification
    ↓
Compensation, audit, evidence retention, and reporting
```

The model may propose actions. It cannot bypass policy, grant itself access, change an approved plan, send arbitrary HTTP requests, treat retrieved content as authority, or silently overwrite a newer resource version.

## Release status

All planned software phases are implemented:

| Phase | Delivered in v1.0.0 |
|---|---|
| 0 — environment and governance | Capability catalog, governance ownership, deployment readiness, safe discovery, OAuth profiles, and secret-free diagnostics |
| 1 — governed runtime | Immutable plans, approvals, policy, source-of-truth validation, audit, idempotency, verification, and prompt-injection controls |
| 2 — read-only context | Jira, Confluence, Bitbucket, GitHub, Microsoft identity, Outlook, Teams, SharePoint/OneDrive, OneNote, citations, and retention |
| 3 — draft-only output | Jira and Confluence proposals, Outlook and Teams drafts, PowerPoint, repository patches, and integrity manifests |
| 4 — approved reversible writes | Jira, Confluence, Bitbucket PRs, and byte-verified SharePoint files; local/remote Git and unsafe OneNote writes are disabled |
| 5 — external communication | Exact-approval Outlook sends and Teams chat/channel messages or replies |
| 6 — recurring workflow registration | Status and plan-generation surfaces; recurring execution is disabled pending exact target/config and runtime-path binding |

The implemented runtime surfaces remain fail closed until a particular company
deployment approves applications, scopes, retention, data handling, Conditional
Access, secrets, connector URLs, and production governance. Packaged defaults
keep all live connectors, writes, sends, and schedules disabled. Non-manifest
weekly-status, communication-context, and recurring execution are also disabled.

## Capability surface

The catalog contains **74 typed capabilities**:

- 43 read-only capabilities;
- 10 local-generation capabilities;
- 16 reversible-write definitions, including 2 disabled OneNote writes and 5
  disabled local-Git mutations;
- 4 external-communication capabilities;
- 1 high-impact capability, `bitbucket.pull_request.merge`, deliberately disabled.

Supported domains:

| Domain | Read | Draft/local generation | Approved mutation |
|---|---|---|---|
| Jira Cloud/Data Center | issue search/read, server info | issue update/comment/transition proposals | field update, comment, transition, compensation |
| Confluence Cloud/Data Center | page search/read | page create/update proposals | create, update, compensation |
| Bitbucket Cloud/Data Center | repo, PR, diffstat/changes, CI status | branch plan and source patch | PR creation/decline compensation; local-Git branch publication disabled |
| GitHub Cloud | repository, PR, and check-run reads | — | unavailable; the connector exposes no write methods |
| Outlook | folders, messages, allowlisted text attachments | `.eml` draft | exact-content send after provider-draft verification |
| Teams | chats, teams, channels, messages, replies | message draft | chat/channel send and channel reply |
| SharePoint/OneDrive | sites, drives, folders, metadata, bounded text | local files/decks | bounded versioned upload with exact prior/uploaded/restored byte hashes |
| OneNote | notebooks, sections, pages | generated HTML/proposals | disabled pending exact target-aware DOM verification |
| PowerPoint | — | local `.pptx` generation | upload through the separately gated SharePoint connector |
| Git workspace | repository state | branch/patch plan | mutation disabled until all Git metadata transactions are descriptor-bound |
| Plugins | metadata only | metadata only | execution disabled pending an isolated worker and locked dependency closure |

## Core safety properties

- **Fail-closed configuration:** installing the wheel enables no workplace access.
- **Three independent live gates:** runtime flag, provider-specific TOML flag, and capability/governance permission.
- **Immutable approvals:** approvals bind to a SHA-256 plan fingerprint and exact action IDs; any mutation invalidates them.
- **Approval separation:** governance can require zero, one, or two distinct human approvers.
- **Version preconditions:** Jira, Confluence, and SharePoint operations stop on stale state.
- **Compensation:** reversible actions capture enough prior state to restore, decline, delete, or revert the exact resource created or changed.
- **No false transactions:** partial multi-system success is reported explicitly; compensation is attempted only where supported.
- **Prompt-injection boundary:** email, Teams, Jira, Confluence, source, note, and attachment content is untrusted data.
- **Constrained networking:** HTTPS-only, same-origin requests, bounded pagination/response sizes, safe redirects, and secret-free errors.
- **Constrained source control:** no force pushes, no protected-branch writes, no autonomous merges, no standalone destructive worktree restore, and explicit workspace roots.
- **Evidence discipline:** full content is persisted only under an explicit retention rule; durable audit records normally store digests and metadata.
- **Plugin isolation:** discovery, locking, and plan binding do not import plugin code; all CLI plugin execution fails closed pending a sealed isolated worker.

## Requirements

- Python 3.12 or newer.
- Ubuntu 24.04 LTS or macOS for the provided setup commands.
- `python-pptx`, installed automatically.
- Git only for repository inspection and quarantined internal mutation tests;
  no local Git mutation capability is routable.
- Organization-approved HTTPS API endpoints and credentials for live use.

## Install from the complete source ZIP

**Machine: Ubuntu 24.04 or macOS development computer**

```bash
unzip master-agent-v1.0.0.zip
cd master-agent

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

python -m unittest discover -s tests -v
master-agent readiness
```

## Install the wheel

**Machine: Ubuntu 24.04 or macOS development computer**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./master_agent-1.0.0-py3-none-any.whl

master-agent discover
master-agent readiness
master-agent plugins
```

Configuration resolution is:

1. an explicit, permission-checked CLI path;
2. wheel-packaged safe defaults.

The current working directory is never an implicit configuration source;
repository-local files must be selected explicitly.

## Quick safe demonstration

Run the complete Phase 3 review-package workflow without credentials or
provider writes:

```bash
master-agent demo
```

The command creates a fresh private workspace under
`~/.master-agent/MasterAgent/`, prints its path, generates the package, and
verifies its audit chain.
The package contains:

```text
<printed demo workspace>/
├── artifacts/
│   ├── change-package.pptx
│   ├── confluence-update-draft.json
│   ├── confluence-update-draft.md
│   ├── jira-update-draft.json
│   ├── jira-update-draft.md
│   ├── source-change.patch
│   ├── stakeholder-email.eml
│   ├── stakeholder-email.json
│   ├── team-message.json
│   ├── team-message.md
│   ├── README.md
│   └── manifest.json
└── state/
    └── audit.sqlite3
```

Nothing is published, sent, committed, or uploaded.

For persistent local state, use a private directory outside the source
checkout. A `.master-agent` directory inside the checkout is deliberately
rejected by release validation:

```bash
mkdir -p "$HOME/.master-agent/MasterAgent"
chmod 700 "$HOME/.master-agent" "$HOME/.master-agent/MasterAgent"
```

## Deployment readiness

Configuration-only readiness performs no network requests:

```bash
master-agent readiness \
  --integrations config/integrations.toml \
  --capabilities config/capabilities.toml \
  --governance config/governance.toml \
  --oauth config/oauth.toml \
  --output "$HOME/.master-agent/MasterAgent/readiness.json"
```

`ready: True` means the selected configuration is internally safe. The CLI
also prints the live connector count; the packaged default is
`live connectors: 0 (safe local mode only)`.

Safe connector discovery:

```bash
master-agent discover \
  --integrations config/integrations.toml \
  --output "$HOME/.master-agent/MasterAgent/discovery.json"
```

After administrators approve the deployment, run bounded read-only probes:

```bash
master-agent discover \
  --integrations config/integrations.toml \
  --systems jira,confluence,bitbucket,github,microsoft,sharepoint,outlook,teams,onenote \
  --probe \
  --output "$HOME/.master-agent/MasterAgent/discovery-probed.json"
```

For a first GitHub-only connectivity test, enable `[connectors.github]` in a
reviewed integrations file, inject `MASTER_AGENT_GITHUB_TOKEN`, and run:

```bash
master-agent discover \
  --integrations /absolute/path/to/integrations.toml \
  --systems github \
  --probe
```

The probe performs one bounded `GET /user` request and reports only the
authenticated login and numeric user ID. Repository, pull-request, and check
content remains available only through the typed read capabilities.

## Microsoft delegated authentication

Enable only the reviewed OAuth profile in `config/oauth.toml`, then acquire a delegated token:

```bash
master-agent oauth-device-code \
  --oauth config/oauth.toml \
  --profile microsoft_delegated \
  --token-file "$HOME/.master-agent/MasterAgent/tokens/microsoft.json"
```

Point `MASTER_AGENT_GRAPH_TOKEN_FILE` at that mode-`0600` token file. The CLI does not automate tenant consent or administrator approval.

## Exact-plan approvals

Before approving an applied plan, bind the complete runtime manifest into it.
The manifest covers integrations and flow-enforced credential identities, resolved
destinations and CA bundles, policy/source/capability/governance/identity and
retention snapshots, connector gates, filesystem roots, audit database, and
retained-result destination:

Every runtime directory must already exist, be owned by the current account,
and be non-writable by group or world. The binding records the exact directory
identity; neither binding nor apply creates these security boundaries. For
example:

```bash
mkdir -m 700 /absolute/state/audit /absolute/state/results /absolute/state/drafts
mkdir -m 700 /absolute/path/to/approved/workspaces
```

Draft artifacts and retained result/evidence files are create-only. Use fresh
filenames or a fresh private output directory for each applied run; the runtime
will not overwrite a prior or concurrently created file.
`draft-package` additionally requires its dedicated output directory to be
empty before it reads workflow configuration.

```bash
master-agent bind-context change-plan.json \
  --connector-mode live \
  --enable-writes \
  --integrations /trusted/config/integrations.toml \
  --policy /trusted/config/policy.toml \
  --sources-of-truth /trusted/config/sources_of_truth.toml \
  --capabilities /trusted/config/capabilities.toml \
  --governance /trusted/config/governance.toml \
  --identities /trusted/config/identities.toml \
  --approval-authorities /trusted/config/approval-authorities.toml \
  --retention /trusted/config/retention.toml \
  --database /absolute/state/audit.sqlite3 \
  --draft-output-dir /absolute/state/drafts \
  --result-json /absolute/state/run-report.json \
  --workspace-root /absolute/path/to/approved/workspaces \
  --output bound-change-plan.json
```

Every corresponding `run --apply` argument must match. Basic usernames and
Entra client-credential tenant/client IDs are derived and bound automatically;
their password, API-token, or client-secret bytes are never fingerprinted, so
ordinary rotation remains possible for the same flow-enforced identity. Opaque
bearer, delegated, token-file, and application-environment tokens are rejected
for live applied execution: a configured identity label is not attestation.
Those flows require a provider-verified principal or a trusted credential-broker
adapter, neither of which is currently implemented.

Inspect the bound plan and its new fingerprint:

```bash
master-agent inspect bound-change-plan.json
```

Create an approval bound to selected action UUIDs:

```bash
export MASTER_AGENT_APPROVAL_KEY_RORY='at-least-32-random-secret-bytes'
master-agent approve bound-change-plan.json \
  --actions ACTION_UUID_1,ACTION_UUID_2 \
  --key-id rory \
  --approval-authorities /trusted/config/approval-authorities.toml \
  --expected-fingerprint FINGERPRINT_PRINTED_BY_INSPECT \
  --ttl-minutes 30 \
  --output approval-rory.json
```

Approval JSON is not authority by itself. The signature is verified against the
explicit operator-controlled key ring, which binds each key ID to one identity.
Unsigned, tampered, unknown-key, or identity-edited artifacts cannot authorize an
apply. Keep the key ring outside repositories being operated on; use
`config/approval-authorities.example` only as a schema example. A
dual-approval capability requires a second valid key bound to a different identity.

## Execute approved reversible writes

A write requires all of these:

1. the capability is enabled in `config/capabilities.toml`;
2. governance permits it in `config/governance.toml`;
3. the plan binds the complete runtime manifest and uses an exact approval;
4. `--enable-writes` is supplied;
5. the connector and its granular write flag are enabled in `config/integrations.toml`;
6. valid credentials and expected versions are present.

```bash
master-agent run bound-change-plan.json \
  --connector-mode live \
  --apply \
  --enable-writes \
  --integrations /trusted/config/integrations.toml \
  --policy /trusted/config/policy.toml \
  --sources-of-truth /trusted/config/sources_of_truth.toml \
  --capabilities /trusted/config/capabilities.toml \
  --governance /trusted/config/governance.toml \
  --identities /trusted/config/identities.toml \
  --approval approval-rory.json \
  --approval-authorities /trusted/config/approval-authorities.toml \
  --database /absolute/state/audit.sqlite3 \
  --draft-output-dir /absolute/state/drafts \
  --workspace-root /absolute/path/to/approved/workspaces \
  --result-json /absolute/state/run-report.json \
  --retention /trusted/config/retention.toml
```

Local Git patch, branch, commit, and push capabilities are catalog-disabled,
governance-prohibited, and absent from the live registry until every Git
metadata transaction is descriptor-bound. `--workspace-root` remains
manifest-bound but does not enable repository mutation.

Build a separately reviewable compensation plan from a completed run:

```bash
master-agent compensation-plan \
  --plan bound-change-plan.json \
  --report /absolute/state/run-report.json \
  --created-by operator@example.com \
  --output compensation-plan.json
```

## Send approved Outlook or Teams communication

External communication additionally requires `--enable-communications` and the granular `outlook_send_enabled` or `teams_send_enabled` provider flag:

```bash
master-agent run bound-communication-plan.json \
  --connector-mode live \
  --apply \
  --enable-communications \
  --integrations config/integrations.toml \
  --capabilities config/capabilities.toml \
  --governance config/governance.toml \
  --approval communication-approval.json
```

Recipient, destination, subject, and body are part of the immutable approved plan. Sends are non-reversible; the runtime records correction-draft metadata rather than claiming rollback.

## Recurring workflows

Packaged schedules are registered but disabled:

```bash
master-agent recurring-status \
  --recurring config/recurring.toml
```

`recurring-status`, `weekly-status-plan`, and `communication-context-plan` remain
available for offline review. `recurring-run`, `weekly-status`, and
`communication-context` execution fail before configuration, credentials,
connectors, or audit state are opened. Exact registered targets and every
runtime/config identity must first be covered by the same immutable execution
manifest.

```bash
master-agent weekly-status-plan --output weekly-plan.json
master-agent communication-context-plan --output communication-plan.json
```

`evidence-prune` is preview-only. `--apply` and destructive orphan quarantine
are disabled until recursive traversal and deletion are descriptor-bound.

## Connector plugins

Write an exact operator-reviewed lock without importing plugin code:

```bash
master-agent plugins --output /trusted/config/connector-plugins.json
```

Plugin inventory can be bound to a plan fingerprint for review without
importing plugin code:

```bash
master-agent bind-context plan.json \
  --integrations config/integrations.toml \
  --plugin servicenow \
  --plugin-lock /trusted/config/connector-plugins.json \
  --output bound-plan.json
```

`run --apply --plugin ...` is intentionally rejected before plugin import,
even when the lock and approvals are valid. A future activation path requires
an isolated worker that verifies the complete dependency closure before any
plugin code runs. See [`docs/plugin-development.md`](docs/plugin-development.md).

## Configuration map

| File | Purpose |
|---|---|
| `config/capabilities.toml` | Typed capability enablement, risk, authentication, reversibility |
| `config/governance.toml` | Owners, environments, classifications, approval tiers |
| `config/policy.toml` | Runtime risk policy and hard prohibitions |
| `config/integrations.toml` | Provider endpoints, credential variable names, granular live gates |
| `config/oauth.toml` | OAuth profiles and required scopes |
| `config/sources_of_truth.toml` | Canonical resource and projection rules |
| `config/identities.toml` | Cross-system identity mapping, never credentials |
| `config/retention.toml` | Evidence persistence modes and TTLs |
| `config/draft-package.toml` | Phase 3 local package example |
| `config/weekly-status.toml` | Read-only weekly status workflow |
| `config/communication-context.toml` | Read-only communication context workflow |
| `config/recurring.toml` | Disabled-by-default registered schedules and allowlists |

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Capability contract](docs/capability-contract.md)
- [Integration matrix](docs/integration-matrix.md)
- [Threat model](docs/threat-model.md)
- [Phase 2 read-only context](docs/phase-2-read-only.md)
- [Phase 2B communication context](docs/phase-2b-communication-context.md)
- [Phase 2C authentication and readiness](docs/phase-2c-authentication.md)
- [Phase 3 draft-only output](docs/phase-3-drafts.md)
- [Phase 4 approved reversible writes](docs/phase-4-approved-writes.md)
- [Phase 5 external communication](docs/phase-5-communications.md)
- [Phase 6 recurring autonomy](docs/phase-6-autonomy.md)
- [Deployment runbook](docs/deployment-runbook.md)
- [Operations guide](docs/operations.md)
- [Plugin development](docs/plugin-development.md)
- [Implementation roadmap and completion status](docs/implementation-roadmap.md)
- [Release validation](docs/release-validation.md)

## Explicitly prohibited in v1

- arbitrary HTTP or arbitrary shell execution;
- protected-branch writes or force pushes;
- autonomous pull-request merges;
- permission changes;
- broad deletion capabilities;
- approval derived solely from retrieved content;
- automatic use of new recipients discovered in content;
- uncontrolled bidirectional synchronization;
- in-process plugin loading;
- enabling a schedule merely because `--force` was supplied.
