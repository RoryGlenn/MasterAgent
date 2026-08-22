# Proposal

## Problem

MasterAgent's security-sensitive local primitives were designed and certified
around POSIX behavior. Platform-neutral imports can still reach Unix-only
dependencies before a user asks for an operation that needs them, which makes
the package and safe configuration diagnostics unusable on Windows. The
runtime also lacks one explicit contract that identifies the selected platform
backends and distinguishes a deliberately unavailable secure backend from an
installation or provider failure.

## Desired outcome

Introduce a deterministic platform-runtime boundary. The installed package,
command help and version, deployment readiness, and configuration-only
progressive diagnostics remain usable on supported Python versions on Windows
without silently claiming that stateful operations are safe. Every operation
that needs an unavailable secure backend fails closed before protected state,
credentials, connectors, or provider access, while existing certified POSIX
behavior remains unchanged and uncertified isolation is reported unavailable.

## Scope

This change defines backend contracts for filesystem identity and access
control, locking, atomic state, process supervision, Git isolation, and
capability-capsule isolation. It moves Unix-only imports behind the operations
that require them; adds a stable, secret-free platform summary to readiness;
adds a top-level version surface; and certifies Windows package imports and
configuration-only commands. It establishes the common boundary on which the
separate planned Windows backend and certification issues can build.

## Rationale

A secure cross-platform runtime needs an honest answer before it needs every
native backend. One central contract lets harmless discovery work everywhere
while keeping stateful and effect-bearing work unavailable until an equivalent
native implementation is present. Explicit backend identity also prevents a
future platform port from weakening guarantees invisibly.

## Alternatives considered

Importing Unix compatibility shims on Windows was rejected because API
similarity does not prove equivalent identity, locking, atomicity, or isolation
semantics. Marking the entire Windows package unsupported was rejected because
imports, help, version, and offline configuration diagnostics do not require
those primitives. Catching platform errors at arbitrary call sites was
rejected because it produces inconsistent failures and makes accidental weak
fallbacks difficult to audit.

## Non-goals

This change does not implement the seven planned native Windows backend and
hosted-certification areas, certify Windows for state mutation or provider
effects, emulate POSIX descriptor semantics, change the POSIX security
contract, or make enterprise deployment ready. It does not grant a capability,
credential, provider connection, or approval.

## Risks

The principal risks are reporting an unsupported operation as ready, importing
a Unix-only dependency through an indirect neutral module, selecting a weak
fallback after backend failure, and confusing package usability with native
effect support. Typed backend status, lazy platform boundaries, capability-
scoped readiness, explicit unavailable errors, import-isolation tests, and
precise Linux/macOS regression coverage mitigate those risks.
