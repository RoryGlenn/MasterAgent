# Proposal

## Problem

MasterAgent has strong agent policies, architecture documentation, tests,
GitHub issue discipline, and runtime governance, but no maintained and
standardized statement of current required behavior. Implemented issue
requirements become historical context, forcing later agents to reconstruct
intent from multiple artifacts.

## Desired outcome

Add a small repository-native system that maintains current behavioral
requirements, structures proposed deltas, safely archives verified changes,
and guides coding agents without coupling development specifications to runtime
authority.

## Scope

- current, active, archived, and template specification directories;
- stable requirement and change IDs;
- TOML change metadata and Markdown review artifacts;
- bounded validation, deterministic status, and safe archival commands;
- agent instructions and CI checks;
- a self-hosted pilot using GitHub issue #75.

## Rationale

A MasterAgent-native system fills the narrow missing gap while preserving the
project's existing GitHub, documentation, test, and `ChangePlan` roles. It can
borrow the useful current-spec/change-delta model without accepting an external
format or dependency.

## Alternatives considered

- Deep OpenSpec integration into planning, approval, and audit was rejected
  because it duplicates purpose-built runtime controls and adds coupling.
- Lightweight OpenSpec adoption was rejected because the missing surface is
  small and MasterAgent benefits from requirement IDs, references, validation,
  and security rules tailored to this repository.
- Continuing with issues and docs alone was rejected because neither maintains
  accepted current behavior as change deltas are completed.

## Non-goals

- runtime specification loading;
- `ChangePlan`, approval-fingerprint, or audit provenance changes;
- provider, Jira, or Confluence synchronization;
- bulk conversion of historical behavior;
- replacing GitHub issues, tests, architecture docs, or `.ai/` instructions.

## Risks

- duplicated prose can drift unless validation and agent rules keep roles clear;
- overly broad requirements could create unnecessary development overhead;
- unsafe archive paths could overwrite unrelated files without strict
  confinement and adversarial tests.
