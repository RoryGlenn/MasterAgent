# Proposal

## Problem

MasterAgent can promote a locally generated capability capsule, but it cannot
inspect a capability exported by another custom agent, compare that ability
with the typed catalog, or preserve the foreign source identity when placing a
selected ability into quarantine.

## Desired outcome

An operator can inspect a bounded declarative custom-agent export without
executing it, see a deterministic compatibility preview, and explicitly place
one compatible ability into the existing signed capsule lifecycle. Imported
authority, credentials, approvals, identity, hooks, network access, and
recursive agents remain blocked.

## Scope

- A versioned, self-contained JSON export format for local declarative agent
  abilities.
- Read-only inspection and catalog comparison through a CLI preview.
- Exact source-byte digest and declared-publisher binding for selected imports.
- One-at-a-time quarantine followed by the existing independent promotion,
  activation, deprecation, and revocation lifecycle.
- Adversarial coverage and operator/developer documentation.

## Rationale

The smallest useful import unit is one typed capability. A self-contained
manifest avoids loading a foreign plugin or resolving foreign paths while
letting the existing capsule boundary own validation and execution.

## Alternatives considered

Importing a whole agent, executing foreign discovery hooks, accepting raw MCP
servers, and delegating to the foreign agent were rejected for the first
version because each introduces authority, network, recursion, or runtime
boundaries that a declarative import does not need.

## Non-goals

This change does not make raw skills, prompts, workflows, plugins, MCP servers,
provider calls, side effects, or third-party-dependent capsules executable. It
does not add production capsule promotion or allow imported material to sign,
review, publish, approve, or enable itself.

## Risks

An inspection report could be mistaken for admission, or a manifest could
change between preview and selection. The design labels preview results as
non-routable, re-reads and reclassifies the selected source, and requires the
expected source digest before quarantine.
