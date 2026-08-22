# Proposal

## Problem

MasterAgent can currently construct a `ChangePlan` directly from a goal. The
existing capability, policy, approval, and execution controls govern whether an
action may run, but they do not require the planner to first determine which
system produces the problem, identify the current constraint, or justify added
complexity. A technically valid plan can therefore optimize a symptom, create a
new agent or service unnecessarily, or automate a process that should instead
be simplified or removed.

## Desired outcome

Every non-trivial planning path completes a structured systems assessment before
creating an actionable plan. The planner receives that assessment, the gate
fails closed when required evidence is absent, and the admitted plan remains
bound to the exact assessment and decision. Low-risk, reversible, well-understood
read-only or local-generation work may use an explicit fast path.

## Scope

This change adds:

- a typed systems assessment covering outcome, current behavior, constraint,
  stocks, flows, feedback loops, delays, leverage, intervention, metrics, stop
  conditions, unintended consequences, and removable complexity;
- a weighted complexity budget for dependencies, services, agents,
  configuration, authoritative documents, state stores, connectors, and user
  workflows;
- a fail-closed gate with a narrow safe fast path;
- an assessor-before-planner wrapper that passes the completed assessment into
  plan construction and binds the decision to its fingerprint;
- tests for safe, denied, over-budget, and sequencing behavior; and
- follow-up integration into immutable plans, orchestration, audit, and
  post-execution review.

## Rationale

The smallest useful intervention is to establish the typed contract and
sequencing boundary in the existing planner layer before changing every
workflow and runtime entry point. This makes the rule executable rather than
prompt-only while preserving current workflows until the migration is complete.

## Alternatives considered

- **Optional systems-thinking agent:** rejected because callers could bypass it
  and its output would not be bound to the plan.
- **Prompt-only checklist:** rejected because it cannot fail closed, enforce a
  complexity budget, or provide deterministic test evidence.
- **Full assessment for every operation:** rejected because routine safe reads
  and local generation would gain unnecessary friction.
- **Immediate breaking `ChangePlan` schema change:** deferred until the typed
  gate and migration tests exist, reducing the chance of silently weakening
  existing approval and fingerprint behavior.

## Non-goals

The first implementation slice does not generate assessments with a language
model, change provider authority, replace capability or approval policy, or
allow a complexity review to authorize an otherwise prohibited action.

## Risks

- A permissive fast path could bypass the intended diagnosis; it is therefore
  limited to explicit low-risk, reversible, well-understood work containing
  only read-only or local-generation actions and no durable complexity.
- A rigid assessment could encourage meaningless filler. Required fields are
  checked structurally, while later integration will retain the evidence for
  review and measurement.
- Adding the gate directly to the runtime before migration could break existing
  registered workflows. The active change therefore separates the contract,
  plan binding, runtime enforcement, and migration tasks.
