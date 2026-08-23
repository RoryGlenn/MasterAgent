# Design

## Approach

Extend `capability-import` so preview remains its default, read-only behavior
and `--select` requires the exact preview digest plus an explicit capsule store
and generator authority. Add separate commands for promotion, status, routing,
execution, disable, and revoke so quarantine is never silently collapsed into
enablement.

A strict TOML loader maps each capsule role to one independently named subject
and environment-backed secret. Promotion composes the existing worker,
validator, immutable store, and signed promotion service. Routing accepts an
explicit bounded set of capability/version references, authenticates each
complete chain, requires the latest state to be enabled, applies organization
governance and runtime policy, and only then performs lexical intent matching.
Execution binds the chosen manifest into `ExecutionContext`, activates its
typed catalog definition and connector, and runs a one-action `ChangePlan`
through `WorkflowOrchestrator` with normal audit and deterministic readback.

## Affected components

- `src/master_agent/capsule_authorities.py`
- `src/master_agent/cli.py`
- `config/capsule-authorities.example`
- `tests/test_capability_import.py`
- capability-capsule, CLI, configuration, and integration documentation

## Data flow

```text
foreign JSON -> read-only preview + digest
             -> exact one-ability selection -> signed quarantine
             -> worker validation + distinct signed roles -> enabled
             -> governance/policy -> intent route -> exact plan binding
             -> typed connector -> WorkflowOrchestrator -> audit + readback
             -> deprecate/revoke -> future route denied, history retained
```

An update is a separately previewed source with a new semantic version. It is
installed beside prior immutable evidence and repeats the complete lifecycle.

## Compatibility

`capability-import SOURCE` remains a read-only preview. New selection options
are opt-in. Existing Python APIs and capsule stores remain compatible. The CLI
does not scan or implicitly activate all installed capsules; the operator names
the bounded candidate versions considered for routing.

## Security

Authority configuration is an owner-controlled regular file and contains only
environment variable names, not serialized secrets. Enabled authorities own
exactly one role; required keys and case-folded subjects must be distinct.
Source selection re-reads the package and checks the exact digest. Status,
routing, execution, and terminal transitions authenticate the complete chain.
Execution still requires the exact worker identity recorded during quarantine
and promotion. Production promotion continues to require live credential,
approval, isolation, and external tamper-resistant audit controls.

## Rejected alternatives

A one-command automatic absorb-and-run flow was rejected because it would erase
the quarantine and review boundary. Implicit store-wide discovery was rejected
for this tranche because explicit candidate selection is easier to audit and
bound. Reusing the provider `run` CLI without a capsule-specific activation
path was rejected because it does not construct or verify the capsule connector.
