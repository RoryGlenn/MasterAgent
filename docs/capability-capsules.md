# Capability Capsule Promotion

MasterAgent now has a governed test/local lifecycle for code created to fill a
missing capability. Generated code is data at first. It cannot enter the
catalog, receive a credential, or reach the orchestrator until an immutable
capsule passes each signed promotion state.

This is a narrow execution surface, not a general Python plugin runner. The
demonstrated capsule runtime accepts dependency-free, deterministic
read/local-generation programs. Provider access and side effects remain
blocked before connector construction until a reviewed provider adapter can
satisfy the destination, readback, idempotency, and compensation contracts.

## Demonstrated lifecycle

The lifecycle is:

```text
generated
   |
   v
quarantined -> tested -> sandbox_validated -> reviewed
                                               |
                                               v
                                          published -> enabled
                                                           |
                                                           v
                                               deprecated or revoked
```

Each transition has an explicit role: generator, validator, sandbox validator,
reviewer, publisher, or revoker. The actor must be trusted for the selected
environment. The publisher and reviewer must be different identities. Every
manifest is signed over its complete canonical content and chained to the
previous signed manifest. State cannot skip, fork, move backward in time, or
overwrite an existing artifact.

An installed capsule directory contains exactly these bounded files:

- `capsule.json`: versioned typed contract, intent hints, classification,
  retention, destinations, credential names/scopes, and resource limits;
- `program.py`: immutable UTF-8 source;
- `dependencies.lock.json`: complete exact dependency closure;
- `sbom.cdx.json`: matching CycloneDX 1.5 components;
- `tests.json`: typed deterministic test vectors;
- `verification.json`: independent verification mode;
- `compensation.json`: compensation contract;
- `THIRD_PARTY_NOTICES.md`: required dependency notices; and
- one append-only signed manifest per lifecycle transition.

Source, artifact, dependency, SBOM, tests, validation, sandbox validation,
verification, compensation, policy, worker, and notice digests are checked
before activation. The capsule store pins its private root, performs reads and
writes relative to no-follow directory descriptors, rejects hard-linked or
changing files, and serializes transitions with a directory lock.

## Isolation boundary

`CapsuleWorker` requires Linux bubblewrap by default. It launches an isolated
interpreter with:

- new user, mount, PID, IPC, UTS, cgroup, and network namespaces;
- no inherited environment or network;
- a read-only interpreter and worker mount;
- an ephemeral `/tmp` and working directory;
- no capabilities;
- CPU, address-space, process, file, output, request, and wall-time limits; and
- a small AST-validated Python subset with no import, file, socket, subprocess,
  private-introspection, exception, context-manager, or dynamic-call surface.

Validation runs without provider credentials and includes denial probes for
host files, ambient secrets, network, subprocesses, and private object
introspection. The worker, interpreter, and bubblewrap binaries are trusted
regular files and their digests form the worker identity. That identity is
rechecked for each connector action. Package builds normalize worker mode; CI,
sandbox workflows, and the repository bootstrap install into owner-private
virtual environments under umask `077`. Hosted jobs first remove group/other
write access from the exact setup-python runtime tree. A worker or interpreter
writable by another OS account fails closed.

Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor. Where
that control is active, load the distribution-provided
`bwrap-userns-restrict` profile before capsule validation. CI installs the
profile from the signed Ubuntu package and loads that narrow profile; it never
disables the host-wide `kernel.apparmor_restrict_unprivileged_userns` control.
If the profile is absent or cannot be loaded, isolation readiness fails closed.

There is no automatic subprocess fallback. A non-isolated subprocess backend
can be selected only by direct test code and is never production-ready.

## Governed activation and execution

Only the latest `enabled` manifest may be activated. Activation first verifies
the complete signature chain and artifact set, then compares every runtime fact
with the capsule binding already stored in `ExecutionContext`. Only then does
it add the capability definition and connector to the normal catalog and
registry.

The binding includes the capability/version, risk, classification, retention,
principal, agent, tenant, provider account, credential-provider identity,
destination constraints, resource limits, publisher/reviewer, signer, and all
security-relevant digests. It is therefore part of the `ChangePlan`
fingerprint and any exact-plan approval. Changing even one capsule fact
invalidates the approval.

Execution uses the existing `WorkflowOrchestrator`; capsule code does not get a
second policy path. Policy runs before advisory routing. Active capability
sessions admit only the selected ID, version, manifest digest, plan fingerprint,
time window, call count, and byte budget. Read/write confusion, negation, and
confusable names fail closed. Negation scans a bounded clause for the actual
operation term, so intervening modifiers such as `do not ever delete` cannot
re-enable a write candidate. A pure capsule result is independently verified
by a fresh deterministic replay in the sandbox.

`CapsuleRunCoordinator` persists content-free checkpoints for:

```text
planned -> awaiting_connection/awaiting_approval -> executing
        -> verifying -> compensating -> terminal
```

Resume requires the same plan fingerprint and capsule-binding digest. The
normal action reservation and idempotency records prevent a completed effect
from being blindly repeated. A terminal coordinator run cannot be replayed.

Terminal runs produce an HMAC-signed, content-free receipt containing the plan,
approval identities, complete capsule bindings, action/readback/compensation
digests, and audit-chain anchor. A configured external sink must attest that it
is external, healthy, and tamper-resistant before receiving the receipt.
Telemetry exports contain only bounded states, identities, and digests.

## Credential broker boundary

The broker exposes a typed provider interface and keeps the existing restricted
JSON snapshots as a development-only provider. A handle is random, short-lived,
single-use, and bound to the complete capsule, authenticated user, agent,
tenant, account, credential provider, credential name, scopes, exact plan
fingerprint, exact action ID, and normalized origin/method/path. A trusted
provider adapter receives raw material only after all of those facts and the
payload budget are rechecked. A handle issued for one approved resource cannot
be redeemed for another resource that merely shares the capsule allowlist.
Generated or validation code never receives the secret.

The broker rejects widened capsule bindings, encoded path traversal, another
provider/account, an undeclared origin/method/path, reused or expired handles,
and credential material returned for a different principal or name. Connection
requests contain no secrets and bind the account requirement to the exact run;
they do not grant authority.

## Supply-chain admission

The repository records its current all-rights-reserved license status in
[`LICENSE`](../LICENSE). This does not choose an open-source license on the
copyright holder's behalf. Runtime packages are exactly pinned in
[`requirements-runtime.lock`](../requirements-runtime.lock), described as a
complete graph in
[`supply-chain/runtime-dependencies.toml`](../supply-chain/runtime-dependencies.toml),
and represented in [`sbom.cdx.json`](../sbom.cdx.json) with notices in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

[`config/dependency-licenses.toml`](../config/dependency-licenses.toml) denies
unknown licenses by default and explicitly rejects selected strong-copyleft and
source-available licenses. `scripts/generate_sbom.py --check
--verify-installed` checks exact installed versions/licenses and deterministic
lock, SBOM, and notice output. Release validation checks the same closure and
packages the evidence.

Capsule dependencies must match their lock, SBOM, license policy, and notices.
The demonstrated pure worker currently rejects every third-party runtime
dependency after validating that metadata. Supporting dependencies requires a
future sealed dependency filesystem and is not implied by a valid SBOM alone.

## Production boundary

The repository does not claim production capsule execution. Production
promotion requires all four controls to be implemented and healthy at the same
time:

1. the Linux OS-isolated worker;
2. an organization-approved production credential/OAuth provider;
3. authenticated exact-plan approvals; and
4. an external tamper-resistant receipt/audit sink.

Credential, approval, and audit adapters must each pass a bounded live health
probe; configuration booleans alone do not satisfy promotion readiness.

Only the worker is bundled as a production-capable component. The repository
provides typed interfaces for the other controls, not a configured production
secret manager or WORM service. Consequently the shipped deployment remains
fail closed. A local JSON credential source and local SQLite audit log are
development controls and cannot satisfy production readiness.

Provider/network and side-effect capsules, arbitrary HTTP, arbitrary shell,
raw entry-point plugin execution, automatic self-promotion, generated-code
approval, and live credentials during validation are intentionally blocked.
The executable acceptance flow and adversarial cases are in
[`test_capability_capsules.py`](../tests/test_capability_capsules.py) and
[`test_capsule_broker_and_routing.py`](../tests/test_capsule_broker_and_routing.py).
