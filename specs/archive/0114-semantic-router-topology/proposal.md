# Proposal

## Problem

The semantic index is a manually maintained navigation document. It cannot
prove that every production module, command, capability, connector, current
requirement, configuration, platform route, or checked-in role has an owner,
and its Windows rows can drift ahead of released behavior.

## Desired outcome

Maintain one machine-readable ownership and topology manifest, validate its
exact inventory against the repository, and generate a compact first-hop
semantic router from it. Agents select one route after loading minimum global
authority policy, then load only the linked policy, specification, code, and
test slice needed for the task.

## Scope

This change adds the manifest, a deterministic validator/generator/router,
negative regression tests, generated documentation, agent discovery guidance,
release validation, before-and-after routing measurements, and exact selected-
route binding at the optional advisory worker boundary. It maps the
parent, bounded advisory roles, direct-parent documentation contract,
deterministic runtime, current POSIX behavior, and distinct planned Windows
filesystem, state, credential, process, Git, capsule, and certification paths.

## Rationale

An exact inventory turns stale navigation into a CI-enforced contract without
copying behavioral authority into generated prose. The hub-and-spoke topology
keeps specialists narrow: each knows its parent, local contract, tools, and
return path, but not unrelated sibling prompts.

## Alternatives considered

Continuing to add rows manually was rejected because omissions are silent.
Broad glob ownership was rejected because a new module could inherit an owner
without review. Giving every specialist the complete manifest or policy corpus
was rejected because it increases context and sibling coupling.

## Non-goals

The router does not authorize runtime actions, replace authoritative policy or
specifications, add specialist delegation or effect authority, or claim that
planned Windows capabilities are implemented.

## Risks

The principal risks are false ownership from permissive matching, stale links,
lifecycle inflation, profile drift, ambiguous routing, and generated-document
drift. Exact inventories, bounded parsing, lifecycle rules, fixture accuracy,
and byte-for-byte generation checks fail closed in CI.
