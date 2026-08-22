# Proposal

## Problem

Linux platform status advertised capsule isolation even when no trusted
`bwrap` executable was available, so readiness could contradict worker startup.

## Desired outcome

Readiness and execution select the same trusted absolute bubblewrap executable.
Missing, relative, or unsafe executables report one bounded unavailable result.

## Scope

Align Linux capsule backend discovery, caching, artifact trust, readiness,
tests, the maintained platform requirement, and affected documentation.

## Rationale

Executable containment is a security property. Descriptive readiness must not
claim that property unless the executable worker route can use it.

## Alternatives considered

Running a bubblewrap subprocess during readiness was rejected because offline
inspection must remain side-effect free. Keeping independent discovery in the
worker was rejected because status and execution could select different paths.

## Non-goals

This change does not implement a macOS or Windows isolation backend and does not
weaken the test-only subprocess route.

## Risks

An installation whose `bwrap` is reachable only through a relative `PATH` entry
now fails closed until it supplies an absolute trusted executable location.
