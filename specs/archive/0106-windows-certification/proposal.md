# Proposal

## Problem

Pull-request CI certifies one native Windows 11 ARM runtime, but it does not run
every supported Python version and it is not a protected Windows 11 x64 release
gate. The repository has no workflow or operating guide for a non-administrator
x64 certification runner, and the live repository has no such runner enrolled.

## Desired outcome

Every supported Python version receives required native Windows pull-request
coverage. A separate workflow accepts only the current protected default-branch
commit, checks host and account identity before checkout, and runs the complete
release suite on a reviewed ephemeral Windows 11 x64 machine.

## Scope

Hosted Windows CI matrix coverage, a fail-closed protected certification
workflow, static workflow tests, semantic ownership, release documentation, and
an operator runbook for provisioning and reimaging the external runner.

## Rationale

Hosted administrator-oriented tests can hide ACL and isolation defects. The
release gate must prove the actual operating system, architecture, user token,
artifact installation, and native test behavior without exposing untrusted
pull-request code or production credentials to a persistent machine.

## Alternatives considered

Windows Server hosted x64 images were rejected as Windows 11 certification.
Running fork pull requests on a self-hosted runner was rejected because a
repository checkout occurs after arbitrary code has already been selected.

## Non-goals

The repository does not provision, enroll, or pay for the external Windows VM.
The certification route remains operationally planned until an ephemeral
standard-user runner is enrolled and produces successful default-branch
evidence.

## Risks

A misconfigured runner could remain queued, retain state, or run with an
administrator token. The workflow therefore stays disabled behind an explicit
repository variable, requires a protected environment and exact labels, checks
the protected branch before checkout, and rejects an unsuitable host.
