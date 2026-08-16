# Phase 3 — Draft-Only Output

## Goal

Prepare a complete cross-system change package without changing any provider or repository.

## Command

```bash
master-agent demo
```

`demo` creates and prints a fresh private workspace under
`~/.master-agent/MasterAgent/`, generates the complete package, and verifies
its audit chain.
Nothing is sent or published. For a persistent operator-selected location, use
`draft-package` with distinct, pre-existing mode-`0700` artifact and audit
directories outside the source checkout.

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

The output directory must already exist with private permissions (for example,
`mkdir -m 700 OUTPUT_DIR`). Artifact publication is create-only: use a fresh
empty directory for each complete package, because existing files are never
overwritten. The CLI locks and verifies that directory is empty before reading
workflow configuration. The audit database parent and artifact output
directory must be different directories.

Every local-generation capability declares its own input and output quota. A
single action can publish at most 16 MiB across its complete artifact bundle,
and all connectors plus the package summary and manifest share one 64 MiB
budget for the complete run. An over-budget bundle is rejected before any of
its final filenames are created. Verification hashes large files in bounded
chunks rather than keeping another full copy in memory.

## Acceptance boundary

Phase 3 does not:

- create provider drafts;
- send communication;
- update Jira or Confluence;
- apply the patch;
- commit or push;
- upload the deck.
