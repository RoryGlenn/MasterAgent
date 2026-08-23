# Proposal

## Problem

Explicit configuration currently accepts only a current-user-owned POSIX file
or the default Windows trust set. That rejects administrator-managed read-only
configuration, while the bootstrap marker proves only a prior install request
and not the environment that is about to be reused.

## Desired outcome

An installed user-private organization profile can approval-bind exact
administrator-managed configuration bytes and their allowed POSIX or Windows
writer identities. Writable state and credentials retain their stricter,
separate trust paths. A bootstrap-managed environment is reused only after an
independent interpreter, distribution, build, and dependency-policy probe.

## Scope

- optional per-configuration organization-managed trust declarations;
- content digest and platform-principal enforcement during descriptor/handle reads;
- Windows policy support that does not implicitly trust the current user;
- secret-free trust-class reporting;
- independent managed-environment reuse verification;
- adversarial POSIX, Windows-policy, bootstrap, operating-mode, and matrix tests.

## Rationale

The user-private profile is already immutable, locally protected, and bound to
execution. Making it the external source for configuration digests and writer
allowlists prevents a managed file from authorizing itself.

## Alternatives considered

- Trusting any administrator-owned path was rejected because identity alone
  does not bind the intended content or deployment principals.
- Storing the allowlist inside each managed file was rejected as self-authorization.
- Treating read-only configuration like writable effect state or credentials
  was rejected because those classes require different controls.

## Non-goals

- enterprise rollout approval, signing infrastructure, or external audit;
- weakening private effect-state or credential-provider boundaries;
- accepting remote, shared-writable, symbolic-link, or reparse paths.

## Risks

An incomplete POSIX effective-access calculation or an implicit Windows
current-user allowance could let a standard user edit purportedly managed
configuration. Exact digest checks and adversarial writer tests address both.
