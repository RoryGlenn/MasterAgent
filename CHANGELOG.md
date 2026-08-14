# Changelog

## 1.0.0 — Complete governed enterprise-agent runtime

### Added

- Phase 2C deployment-readiness assessment, OAuth profile configuration, Microsoft delegated device-code acquisition, restricted token files, token/scope inspection, and safe connector probes;
- organization governance profiles with capability ownership, environment constraints, data classifications, and automatic/single/dual/prohibited approval tiers;
- a 70-capability catalog spanning read, local generation, reversible writes, external communication, and prohibited high-impact operations;
- Phase 3 complete local draft packages containing Jira and Confluence proposals, Outlook `.eml`, Teams draft, PowerPoint, repository patch, summary, and integrity manifest;
- approved Jira field updates, comments, transitions, version checks, and compensation;
- approved Confluence page creation/update and compensation for Cloud and Data Center contracts;
- controlled Git workspace patch, branch, commit, push, and content-preserving in-process rollback;
- Bitbucket branch publishing and pull-request creation with decline/delete-ref compensation where safe;
- SharePoint bounded file upload with previous-version restoration;
- delegated OneNote notebook/section/page reads plus page create/update and rollback;
- exact-plan Outlook send with provider-draft content verification;
- exact-plan Teams chat/channel message send and channel reply with provider re-read verification;
- compensation-plan generation bound to the original immutable plan and run report;
- disabled-by-default recurring workflows with timezone-aware scheduling, durable occurrence state, lock directories, scope/recipient/source allowlists, and local/draft-only delivery modes;
- explicit connector plugin discovery and opt-in loading through the `master_agent.connectors` entry-point group;
- command-level and factory-gate tests proving broad runtime flags cannot bypass provider-specific gates.

### Changed

- live read, write, and communication connectors are constructed independently;
- configuration now requires granular provider gates in addition to runtime flags;
- policy evaluation now combines the capability catalog, organization governance, source-of-truth rules, immutable approvals, and risk rules;
- the CLI now exposes `readiness`, `oauth-device-code`, `draft-package`, `compensation-plan`, `recurring-status`, `recurring-run`, and `plugins` commands;
- packaged defaults include every v1 configuration file while keeping all live access, mutations, sends, and schedules disabled;
- HTTP user agent and package version are now `1.0.0`.

### Security

- retrieved content cannot authorize mutations or external communication;
- dual approvals require distinct approvers;
- communication approvals bind to exact recipients/destinations and exact content;
- plugin discovery never imports plugin code, and plugins are loaded only by exact operator-supplied name during apply;
- provider mutation connectors require runtime, generic, and granular provider gates;
- PR merge, permissions, protected-branch writes, arbitrary HTTP, arbitrary shell, and broad deletion remain prohibited.
- standalone Git worktree restore is not exposed because a status precheck followed by `reset --hard` cannot preserve edits made between check and use.

## 0.3.0 — Read-only communication context

- Added read-only Outlook and Teams context, cross-system identities, citations, retention, and communication-context packaging.

## 0.2.0 — Read-only enterprise context

- Added Jira, Confluence, Bitbucket, Microsoft identity, SharePoint/OneDrive, and weekly-status package generation.

## 0.1.0 — Governed local runtime

- Added immutable plans, approvals, policy, audit, verification, prompt-injection controls, and mock connectors.
