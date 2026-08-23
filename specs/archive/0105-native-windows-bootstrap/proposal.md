# Proposal

## Problem

The repository-local bootstrap hardcodes POSIX virtual-environment launchers,
applies `umask` unconditionally, and reuses unmarked environments. Windows
package tests install source but do not prove built-wheel entry points or a
standard-user bootstrap through realistic path names.

## Desired outcome

Native Windows users can bootstrap source and install built artifacts without
activation, with platform-native current-user paths and hosted standard-user
evidence for spaces, Unicode, and long paths.

## Scope

Bootstrap selection, local/offline install sources, native user-data defaults,
source/archive exclusions, hosted Windows packaging evidence, and Windows/WSL
operator documentation.

## Rationale

Installation is a trust boundary. Platform support is not credible when the
first command uses another platform's layout or silently executes an
unverified environment.

## Alternatives considered

PowerShell activation scripts were rejected because direct executable paths
are deterministic and do not alter shell policy. Reusing any runnable `.venv`
was rejected until issue #111 supplies the required provenance verification.

## Non-goals

This change does not weaken Windows filesystem policy, enable UNC runtime
state, change activation policy, or complete environment provenance work owned
by issue #111.

## Risks

An existing unmarked `.venv` now results in a new side-by-side environment and
therefore consumes additional local disk space. The existing directory remains
untouched and can be reviewed independently.
