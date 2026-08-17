# Docs Agent

The Docs Agent keeps MasterAgent's documentation aligned with the software
without requiring the operator to remember a separate “update docs” prompt for
every change.

Think of it as the person who checks an instruction manual after the product has
changed. That comparison is only a mental model: technically, MasterAgent reads
the final repository change, identifies affected documentation, applies the
rules in [the Docs Agent contract](../.ai/DOCS_AGENT.md), validates the result,
and reports what was updated or reviewed.

## Why it runs inside MasterAgent today

The repository does not currently allow direct GitHub-host child-agent
invocation. The host cannot prove all of MasterAgent's required parent, depth,
tool, context, and call-budget controls. Creating an apparently active Docs
Agent profile would therefore promise a delegation path that is not safely
available.

For now, the selected MasterAgent parent completes the same documentation review
directly using one authoritative contract. A future governed adapter may perform
the work as a separate subagent only when it can enforce the same boundaries.
This changes who performs the work, not the documentation standard.

## When it runs

For a non-trivial repository change, the documentation pass occurs after the
implementation and tests and before MasterAgent declares the task complete.

```text
Issue or request
      ↓
Implementation
      ↓
Tests and behavior validation
      ↓
Docs Agent maintenance review
      ↓
updated / no_change / needs_review
      ↓
Final repository validation
```

Formatting, typo, comment, documentation-only wording, and mechanical refactor
changes may skip the full pass when they cannot change what a reader needs to
know or do.

## Operating modes

| Mode | Purpose |
|---|---|
| `maintenance` | Review a completed change and update only affected documentation. This is the default after implementation. |
| `authoring` | Create requested documentation after identifying the reader, goal, prerequisites, document type, and authoritative sources. |
| `audit` | Review existing documentation for inaccuracies, gaps, duplication, stale examples, poor organization, or accessibility problems. |

## Writing for the actual reader

The Docs Agent classifies each affected document before writing:

- **Non-technical user:** ordinary language, concrete tasks, minimal jargon.
- **Mixed audience:** a plain-language overview first, followed by the technical
  detail needed by developers or maintainers.
- **Developer:** precise commands, interfaces, examples, and constraints.
- **Maintainer:** implementation details, tradeoffs, failure modes, and source-of-
  truth boundaries.
- **Decision-maker:** purpose, impact, risks, ownership, and choices without
  unnecessary implementation detail.

This avoids two common failures: documentation that only engineers can decode,
and technical reference material that becomes vague because every reader was
incorrectly treated as a beginner.

## How analogies are used

Analogies are optional. They are used only when they make an unfamiliar concept
easier to understand, and they are followed by the literal technical
explanation.

For example:

> MasterAgent is like a team lead assigning work to specialists.
>
> Technically, its orchestration path selects a typed capability and routes the
> request through policy, approval, execution, verification, and audit controls.

The Docs Agent does not put analogies into command syntax, configuration tables,
API schemas, or other places where exactness matters more than a mental model.

## What it checks

In maintenance mode, MasterAgent gives the Docs Agent contract the final change
and the strongest available evidence. The review compares:

- the issue and accepted criteria;
- current behavioral specifications and architecture decisions;
- tests and observed validation results;
- implementation and configuration; and
- existing documentation.

It also searches the repository for changed public commands, configuration
keys, environment variables, API paths, feature names, errors, and terminology.
This catches indirect impact. Renaming a command, for example, may affect a
README, setup guide, command reference, example, and troubleshooting page even
when none of those files are next to the changed source code.

## It does not document bugs as intended behavior

The implementation is evidence, but it is not automatically the final statement
of intent. Suppose an accepted requirement and test specify a 30-second timeout,
but the implementation uses 3 seconds. The Docs Agent does not update the guide
to say “3 seconds” and make the defect look deliberate. It reports the conflict
as `needs_review` so the implementation or requirement can be corrected first.

## It respects document history

The Docs Agent distinguishes four lifecycles:

- **Current-state documentation** is updated to match accepted current behavior.
- **Historical records** are not rewritten to make old decisions look current;
  new context is appended or recorded separately.
- **Planned documentation** remains clearly labeled as future work.
- **Generated documentation** is changed through its schema, source, or
  generator rather than by editing derived output by hand.

It also prefers one authoritative source for each fact or procedure. Other pages
should link to or summarize that source instead of creating several independent
copies that drift apart.

## Possible results

The review returns one of three statuses:

| Status | Meaning |
|---|---|
| `updated` | Affected documentation was changed and validated as far as practical. |
| `no_change` | Relevant documentation was reviewed and remains correct. This is a successful result, not a failure to do work. |
| `needs_review` | Conflicting evidence or a missing authoritative decision prevents an accurate update. The overall change is not complete yet. |

The result also lists document audiences, files updated, files reviewed but left
unchanged, checks that passed, checks that could not be performed, and any
remaining conflict or gap.

## Default editing boundary

Unless a task explicitly authorizes more, the Docs Agent contract permits edits
to README files, `docs/`, documentation navigation or configuration, and
documentation-only examples.

It does not independently edit production source, tests, continuous integration
workflows, application configuration, code comments, or docstrings. Stale code
comments or docstrings are reported to MasterAgent for the appropriate coding
path.

## Authoritative contract

The complete operating rules and machine-checkable response shape live in
[`.ai/DOCS_AGENT.md`](../.ai/DOCS_AGENT.md). That file is the source of truth;
this page explains the behavior for human readers.
