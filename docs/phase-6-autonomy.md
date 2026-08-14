# Phase 6 — Narrow Recurring Autonomy

## Scope

Phase 6 retains registered workflow definitions and due-state inspection. It is
not an active autonomous loop in this release.

Current workflow kinds:

- `weekly_status_package` — read Jira, Bitbucket, and Confluence; generate JSON, Markdown, PowerPoint, and manifest locally;
- `communication_context_package` — resolve identity, collect bounded Outlook/Teams context, and write retained local evidence/drafts.

## Safety model

Each registration defines:

- disabled/enabled state;
- timezone, weekday, hour, minute, and maximum lateness;
- local-only or draft-only delivery mode;
- exact capability allowlist;
- recipient allowlist;
- canonical-source allowlist;
- output directory and config paths.

The scheduler state/locking implementation is retained as a non-routable
internal. Capability names alone cannot prove that exact targets, canonical
sources, delivery mode, config snapshots, and runtime output paths match the
reviewed registration, so execution fails closed.

## Operation

```bash
master-agent recurring-status
```

`recurring-run` is disabled before workflow configuration, credentials,
connectors, or audit state are opened. Do not install a scheduler invocation.
Reactivation requires exact immutable target/config/source binding plus the
same descriptor-pinned runtime boundary used by ordinary applied plans.
