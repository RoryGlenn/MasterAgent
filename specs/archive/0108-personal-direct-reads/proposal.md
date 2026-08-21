# Practical personal installation and direct provider reads

## Problem

The existing applied runtime intentionally uses an enterprise effect boundary:
an operator binds an exact runtime, owns private audit and artifact roots, and
supplies an authenticated approval artifact when policy requires it. That is
appropriate for a provider effect, but generic provider reads currently enter
the same path. As a result, a normal direct request to read, search, or list
one configured provider requires setup that does not reduce the risk of that
read.

The base package also installs draft-rendering dependencies that are not
needed for the command line, configuration readiness, or live reads. A
pre-existing local development virtual environment can also be blocked or
rewritten solely to establish bootstrap provenance even though it conveys no
provider or credential authority.

## Desired outcome

A personal user can install a lightweight core package, reuse a usable
pre-existing local development environment for offline readiness, and execute
a direct, typed, read-only request against exactly one built-in provider
without persisting session state or preparing an approval-bound runtime
manifest. Provider effects retain the existing bound, audited, and
approval-aware execution path.

## Scope

- Add a `run --direct-read` route for direct-user, one-provider, read-only
  plans.
- Retain catalog, governance, policy, origin, credential, response-budget,
  prompt-injection, and independent re-read validation.
- Reject effects, plugin/capsule routes, cross-provider plans, persisted
  output, and non-direct authority before a provider request.
- Split optional draft-rendering dependencies from the core package and make
  bootstrap distinguish an installed local runtime from optional readiness
  gaps.
- Reuse an existing non-symlink local virtual environment for offline
  readiness without treating it as trusted provider, credential, or
  effect-path authority; leave it unmodified when it was not bootstrap-managed.

## Rationale

Read-only requests neither mutate a provider nor need durable idempotency
state. Keeping the typed connector and verification boundary makes those
requests safe without imposing the enterprise effect ceremony that prevents
ordinary use.

## Alternatives considered

- Remove approval and binding checks globally: rejected because effects and
  sends still need their stronger execution boundary.
- Import installed connector plugins in the direct route: rejected because a
  package installation is not a trusted execution boundary.
- Add a generic HTTP command: rejected because it would bypass typed provider
  endpoints, parameter validation, response limits, and verification.

## Non-goals

- Enable provider writes, sends, administration, deletes, merges, or
  recurring execution without the existing governed path.
- Make raw connector plugins executable.
- Persist read-session content by default.
- Claim that native Windows stateful execution is complete.

## Risks

Direct reads may expose retrieved provider content to the requesting terminal.
The route therefore writes no result files, treats the content as untrusted,
and preserves connector response limits, redaction, and re-read verification.
