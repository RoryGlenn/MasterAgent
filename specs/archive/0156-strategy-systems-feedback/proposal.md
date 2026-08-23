# Proposal

## Problem

The systems-governance types require useful diagnostic fields, but production
code has no concrete assessor for evidence supplied by a trusted planning
boundary. Non-trivial assessments also do not contain an explicit strategy
kernel, so a plan cannot prove that each action follows a diagnosis and guiding
policy. After execution the runtime always reports the success metric and stop
condition as unobserved, even when a caller has independently verified bounded
outcome evidence.

## Desired outcome

Every non-trivial plan carries a fingerprint-bound strategy kernel and an exact
action-to-intent trace. A concrete assessor accepts only explicit typed inputs.
The runtime may consume independently supplied, fingerprint-bound outcome
evidence after execution, while retaining the conservative fallback whenever
that evidence is absent or invalid.

## Scope

Add immutable strategy, trace, and outcome-evidence records; enforce them in the
existing systems gate; wire a concrete assessor and outcome observer into the
planning and execution boundaries; migrate built-in non-trivial workflows;
update focused tests, architecture guidance, and the semantic router.

## Rationale

The change closes the planning and feedback loops inside the existing governed
runtime. It does not add a model, agent, provider, dependency, service, or
authority mechanism.

## Alternatives considered

- Prompt-only strategy prose cannot be validated or bound to a plan.
- Treating connector completion as outcome success would confuse delivery with
  system change.
- A separate strategy agent would add complexity and remain bypassable.

## Non-goals

The runtime will not invent diagnoses, choose organizational strategy without
explicit inputs, collect arbitrary provider content, or let systems evidence
grant execution authority.

## Risks

New immutable fields change plan fingerprints and therefore invalidate old
approvals as intended. Existing safe fast-path plans remain compatible. Older
non-trivial plans without a strategy kernel fail closed when executed and must
be replanned.
