# Phase 3 — Draft-Only Output

## Goal

Prepare a complete cross-system change package without changing any provider or repository.

## Command

```bash
master-agent draft-package \
  --workflow config/draft-package.toml \
  --output-dir .master-agent/draft-package
```

## Artifacts

- Jira proposal JSON;
- Confluence proposal JSON;
- Outlook MIME draft (`.eml`);
- Teams Markdown draft;
- PowerPoint presentation;
- unified repository patch;
- package README;
- manifest with SHA-256 digests.

Every artifact is local. The plan uses only `local_generation` capabilities and executes through local draft connectors. The PowerPoint is a derived artifact; canonical source changes remain proposals until approved separately.

## Acceptance boundary

Phase 3 does not:

- create provider drafts;
- send communication;
- update Jira or Confluence;
- apply the patch;
- commit or push;
- upload the deck.
