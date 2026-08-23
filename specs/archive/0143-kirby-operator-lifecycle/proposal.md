# Proposal

## Problem

The governed import parser and capsule services exist, but the installed CLI
exposes only preview. An operator cannot complete the issue #129 user story
without writing a private integration against internal Python APIs.

## Desired outcome

An operator can inspect, explicitly select, quarantine, independently promote,
route, execute, update, disable, and revoke a supported pure capability through
shipped commands while every existing governance and isolation boundary remains
in force.

## Scope

- Exact-digest single-ability selection through `capability-import`.
- Environment-backed, role-scoped capsule authority configuration.
- Promotion, authenticated status, policy-first routing, governed execution,
  deprecation, and revocation commands.
- Immutable new-version updates and executable end-to-end CLI evidence.
- Operator and CLI documentation for the full supported workflow.

## Rationale

The CLI must compose the already implemented boundaries into a usable product
path. Keeping the first supported import unit to one dependency-free pure typed
capability preserves the safety model while completing the operator workflow.

## Alternatives considered

Leaving promotion to private Python integrations was rejected because that is
not a shipped feature. Automatically promoting during import was rejected
because it collapses quarantine and independent review. Importing raw skills,
tools, prompts, or whole agents remains outside the typed capsule boundary.

## Non-goals

This change does not enable provider, network, side-effect, dependent, raw
plugin, recursive-agent, or production capsule execution. It does not generate
signing keys, copy source credentials, or treat a foreign publisher declaration
as authenticated without an operator authority binding.

## Risks

A convenient command could accidentally bypass normal policy or make disabled
capsules routable. The design resolves only authenticated latest manifests,
filters routing through governance and policy, executes through the existing
orchestrator, and appends signed terminal states instead of mutating history.
