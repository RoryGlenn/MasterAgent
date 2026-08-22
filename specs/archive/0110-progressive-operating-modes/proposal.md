# Proposal

## Problem

MasterAgent's governed runtime already separates stateless reads from applied
effects, but an ordinary employee still has to understand internal stages such
as configuration selection, context binding, plan inspection, approval
handoff, and resume. Existing readiness also describes configuration facts
without answering which classes of work the current user and organization can
actually perform.

## Desired outcome

Give employees a progressive setup, diagnosis, and execution workflow whose
friction matches the requested risk. A checked-in organization profile supplies
reviewed configuration locations and a capability allowlist. One high-level
command chooses the existing stateless read or governed applied-run path and
handles the internal stages without weakening any runtime control.

## Scope

This change adds strict organization profiles; employee and trusted developer
modes; capability-scoped readiness levels; interactive and non-interactive
setup; actionable error categories; private local-state provisioning; and one
high-level command for new plans and approval resume. It preserves the existing
low-level commands and binds the selected organization profile into every
effect-bearing execution context and approval handoff.

## Rationale

The simplest workflow should also be the safest supported workflow. Keeping
the high-level path as an adapter over typed plans, provider selection, policy,
approval, execution, verification, compensation, and audit avoids a second
runtime while removing internal ceremony from the employee experience.

## Alternatives considered

Documenting the existing low-level sequence was rejected because it leaves
ordinary users responsible for security-sensitive wiring. Inferring an
organization profile from the current directory or environment was rejected
because it creates ambient authority. Letting employee mode generate or load
new capability code was rejected because installation is not review or
promotion.

## Non-goals

This change does not remove approval from effects, enable a provider or
capability that the organization profile does not list, make enterprise
deployment ready, activate high-impact capabilities, replace low-level
automation commands, or let developer-generated code approve, sign, promote,
or execute itself.

## Risks

The principal risks are a profile becoming an authority bypass, a readiness
summary overstating production safety, a high-level command weakening provider
selection or approval binding, unsafe automatic directory creation, and a
developer path leaking quarantined code into employee execution. Strict schema
validation, exact capability allowlists, content-bound profile snapshots,
descriptor-safe private state, fail-closed routing, and adversarial tests
mitigate those risks.
