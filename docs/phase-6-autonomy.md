# Phase 6 — Narrow Recurring Autonomy

## Scope

Phase 6 schedules only registered built-in workflows. It is not a general autonomous loop.

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

The runner records each scheduled occurrence in SQLite and holds a per-workflow lock. It will not run the same occurrence twice. `--force` bypasses only the due calculation and never enables a disabled workflow.

## Operation

```bash
master-agent recurring-status
master-agent recurring-run weekly_status --connector-mode mock --force
```

For production, invoke the same command from an organization scheduler under a narrowly permissioned service account. Current recurring workflows produce local packages and do not invoke Phase 4 or Phase 5 side effects.
