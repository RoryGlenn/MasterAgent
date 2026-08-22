# Proposal

## Problem

The credentialed connector matrix exists, but repository state does not yet
make a full protected run safe or repeatable. The checked-in workflow assumes a
scheduled delegated Microsoft token can remain usable, reuses ambiguous GitHub
secret names across privilege levels, has no static contract test, and relies
only on in-process `finally` cleanup for reversible live effects. Scoped
Atlassian API tokens also require product-and-cloud-ID gateway roots that the
current endpoint policy rejects and whose tenant path is not confined.

## Desired outcome

Make the repository-owned half of issue #94 fail closed and operationally
honest. A manually dispatched, protected default-branch workflow should use
separate read, effect, and administration credentials; validate provider
origins, delegated Microsoft scopes, and token lifetime before effects; retain
a private recovery journal for reversible mutations; and independently run
cleanup after an ordinary test failure. Atlassian scoped-token gateway roots
must be supported without allowing credentials or pagination to escape the
approved product/tenant path.

## Scope

This change hardens endpoint validation and HTTP base-path confinement, adds a
separate Atlassian browser root, corrects Microsoft integration scopes and
lifetime admission, isolates GitHub privilege credentials, adds reversible
effect recovery, and pins the workflow contract with offline tests and
documentation. It also configures the existing GitHub environments to require
a reviewer and the exact default branch where the repository API permits it.

## Rationale

Credentialed integration evidence is trustworthy only when the reviewed code,
credential privilege, provider identity, fixture, and cleanup path are all
bound before the first mutation. Repository safeguards can enforce those
boundaries even though provisioning provider accounts and granting tenant
consent remain operator-owned.

## Alternatives considered

Keeping the scheduled full matrix was rejected because the restricted
delegated token-file provider has no unattended refresh path. Reusing one
GitHub secret across privilege levels was rejected because it obscures which
job can exercise administration. Treating same-origin HTTP as sufficient was
rejected because Atlassian's shared API gateway also requires a product and
cloud-ID path boundary.

## Non-goals

The repository cannot create Atlassian, Bitbucket, or Microsoft accounts,
grant tenant consent, mint provider secrets, choose organization fixtures, or
approve a protected deployment on behalf of an operator. Missing provider
credentials and fixture identifiers remain explicit blocked setup rather than
being replaced with mocks or treated as successful integration evidence.

## Risks

The main risks are credential escape through a same-origin gateway path,
over-privileged or expired tokens failing after a mutation, cleanup data
leaking through artifacts, and workflow edits silently weakening protected
environment boundaries. Exact path checks, pre-effect token admission,
private create-only recovery entries, `always()` cleanup, disabled repository
gates, and static workflow tests mitigate those risks.
