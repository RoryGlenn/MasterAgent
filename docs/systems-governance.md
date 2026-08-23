# Systems governance for developers

This guide is for developers who build planners, registered workflows, or
runtime integrations. It explains how to supply systems and strategy evidence
without accidentally turning that evidence into execution authority.

## Choose the route

Use the fast path only when every action is `read_only` or
`local_generation`, the work is low risk, reversible, and well understood, and
the plan adds no durable complexity. Use `bind_fast_path_governance`; it creates
the explicit static assessment for you.

Every other plan uses the gated route. Its assessment needs the complete
systems diagnosis plus a strategy kernel. Every plan action must trace exactly
once to one declared coherent-action intent, and every intent must be used.

## Build a static intervention

Registered workflows already know their bounded actions. State their strategy
explicitly and let the static binder create the exact traces in action order:

```python
from master_agent.models import (
    StrategyActionIntent,
    StrategyKernel,
    SystemsAssessment,
)
from master_agent.planners import bind_static_intervention_governance

kernel = StrategyKernel(
    diagnosis="The existing review marker is stale.",
    guiding_policy="Correct only the marker through the existing connector.",
    proximate_objective="Write and independently verify one corrected marker.",
    tradeoffs=("Prefer a visible correction over rewriting history.",),
    coherent_actions=(
        StrategyActionIntent(
            intent_id="correct_marker",
            description="Apply the one bounded correction.",
            expected_effect="The corrected marker is independently verified.",
        ),
    ),
)
assessment = SystemsAssessment.for_static_intervention(
    desired_outcome=plan.goal,
    current_behavior="The marker is stale.",
    constraint="Only a verified provider write can correct it.",
    stocks=("the current marker",),
    flows=("approved corrections to the provider",),
    feedback_loops=("verification informs the next review",),
    delays=("provider and verification latency",),
    leverage_point="the existing typed connector",
    simplest_intervention="correct one marker",
    success_metric="the corrected marker is independently verified",
    failure_condition="the correction is absent or unverified",
    unintended_consequences=("the write outcome could become indeterminate",),
    removable_complexity=("the one-use correction plan",),
    strategy_kernel=kernel,
    reversible=True,
    well_understood=True,
)
governed_plan = bind_static_intervention_governance(plan, assessment)
```

The number of coherent-action intents must equal the number of static plan
actions. The binder maps them in order. If a registered workflow changes its
actions, update its kernel in the same change.

## Build an evidence-backed planner

For a planner that receives assessment evidence from a trusted application
boundary, construct the complete immutable `SystemsAssessment`, then wrap it in
`EvidenceBackedSystemsAssessor`. The assessor returns it only for the exact
`desired_outcome`; a different goal fails closed. The `SystemsAwarePlanner`
must consume that same object and add its own `StrategyActionTrace` records to
the returned `ChangePlan` before the gate runs.

The assessor does not invent missing stocks, loops, tradeoffs, or actions. A
model may propose those values upstream, but they remain untrusted planning data
until the caller validates and explicitly supplies the typed assessment.

## Observe outcomes after execution

An outcome observer is optional because many success metrics cannot be measured
inside one run. When a trusted integration can independently measure the
outcome, implement the bounded provider contract and return
`SystemsOutcomeEvidence.for_observation(...)`:

```python
from master_agent.models import SystemsMetricStatus, SystemsOutcomeEvidence
from master_agent.planners import EvidenceBackedSystemsOutcomeObserver

class OutcomeProvider:
    def observe(self, *, assessment, decision, states):
        measured = independently_measure_outcome()
        return SystemsOutcomeEvidence.for_observation(
            assessment=assessment,
            decision=decision,
            metric_status=(
                SystemsMetricStatus.CONFIRMED_MOVED
                if measured.moved
                else SystemsMetricStatus.CONFIRMED_UNCHANGED
            ),
            unintended_effects_detected=measured.unintended_effects,
            observed_complexity_score=measured.complexity_score,
            removal_candidate_count=measured.removal_candidates,
            stop_condition_checked=True,
            stop_condition_triggered=measured.stop,
            reason_codes=("independent_measurement_complete",),
        )

observer = EvidenceBackedSystemsOutcomeObserver(OutcomeProvider())
```

Pass `observer` as `systems_outcome_observer` to `WorkflowOrchestrator` or
`DirectReadSession`. The runtime invokes it after actions finish. It accepts the
evidence only when the assessment, decision, and metric fingerprints match.

Do not report action completion as metric movement unless the declared metric
is actually action completion and the observer measured it independently. If
the observer is absent, fails validation, returns mismatched evidence, or the
run is a dry run, the review records `not_observed` and requires reassessment.

## Compatibility and authority

Existing serialized fast-path plans remain loadable without a kernel or traces.
Older gated plans must be replanned because they cannot prove coherent strategy.
Adding or changing a kernel or trace changes the plan fingerprint, so old
approvals no longer match.

Systems assessment, strategy, and outcome evidence never grant capability,
credential, target, provider, policy, approval, or execution authority. All
ordinary runtime gates remain independently decisive.
