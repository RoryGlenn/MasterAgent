# Proposal

## Problem

MasterAgent cannot currently attribute end-to-end latency to local governance,
credential and connector setup, provider execution, independent verification,
audit, retention, sanitization, or rendering. It also lacks fixed counters that
prove unselected providers remained inactive and that controlled false-success
or duplicate-effect observations stayed explicit.

## Desired outcome

Every governed run and direct-read session can carry one immutable, bounded,
content-free performance snapshot. A deterministic cross-platform benchmark
produces stable per-run evidence and p50/p95 summaries for the exact Tier-1
`T1-EWIR-001` case and representative risk classes without claiming live-provider
or managed-workstation performance.

## Scope

- A fixed schema, stage vocabulary, phase vocabulary, counters, outcomes, and
  deterministic serializer.
- Injectable monotonic wall and CPU clocks with context-local activation and
  exception-safe cleanup.
- Instrumentation before credential resolution and connector construction and
  through execution, verification, reconciliation, compensation, audit,
  sanitization, and rendering boundaries.
- Immutable snapshots on governed and direct-read reports.
- A deterministic benchmark and adversarial privacy, lifecycle, retry, and
  unselected-provider tests.
- Safe maintainer documentation and exact semantic-router ownership.

## Rationale

A small in-process recorder and context-local phase tag fit the existing typed
runtime and HTTP boundaries. They measure the path without introducing a new
service, dependency, persistence layer, provider call, or user interaction.

## Alternatives considered

- External profilers were rejected because they do not provide the fixed,
  privacy-bounded per-stage and per-phase schema required by CI.
- Logging arbitrary span names or labels was rejected because it creates an
  unbounded content-retention channel.
- Live-provider timing as a per-PR gate was rejected because it is noisy and is
  owned by the managed-workstation pilot in issue #172.

## Non-goals

- Selecting or claiming the trusted `native` connector implementation identity;
  issue #170 owns that binding.
- Producing a Windows or real-provider baseline; issue #172 owns that evidence.
- Persisting prompts, goals, provider bodies, identifiers, URLs, credentials,
  exception text, paths, usernames, environment values, or timestamps.
- Adding a telemetry service, tracing dependency, database, or generic labels.

## Risks

- Instrumentation can accidentally become a content channel; serializers admit
  only fixed enums, bounded numeric values, trusted catalog capability IDs, and
  sanitized version/commit identities.
- Context-local state can leak between runs; every top-level run creates or owns
  a fresh recorder and resets the context even on exceptions.
- Measurement can double-count nested work; selected dimensions are set-valued,
  transport attempts are counted only immediately before dispatch, and phases
  are explicit.
