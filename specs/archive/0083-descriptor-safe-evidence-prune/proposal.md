# Proposal

## Problem

MasterAgent can preview expired retained evidence, but apply mode is disabled.
Operators therefore cannot enforce the configured expiration boundary through
the governed maintenance interface.

## Desired outcome

`master-agent evidence-prune --apply` removes only complete, expired, validated
evidence-and-sidecar pairs beneath one pinned root. Preview and apply derive the
same deterministic plan, while unsafe or incomplete trees fail closed.

## Scope

This change replaces path-based preview traversal with descriptor-relative,
bounded scanning and validation; adds retention-lock coordination and
recoverable pair deletion; keeps all Windows execution capability-gated; and
updates the CLI, tests, operating documentation, threat model, roadmap,
changelog, and release validation.

## Rationale

Deletion is a security-sensitive retention effect. Reusing the pinned-root,
no-follow, identity-bound primitives already used by retained publication and
orphan repair keeps the effect within the same trust boundary.

## Alternatives considered

Direct `Path.unlink` after preview was rejected because pathnames can be
substituted between validation and deletion. Independent unlinks without a
transaction boundary were rejected because interruption can leave an
ambiguous half-record. Treating malformed records as skippable was rejected
because apply must not mutate an incompletely inspected tree.

## Non-goals

This change does not delete malformed or orphaned files, alter legal-hold
policy, delete provider-side data, or add native Windows filesystem support.

## Risks

The primary risks are descriptor substitution, symlink or hard-link attacks,
partial pair removal, incomplete scans, lock races, and accidentally exposing
retained content in results. The design binds identities, uses bounded reads,
fails closed before mutation, and emits paths and status only.
