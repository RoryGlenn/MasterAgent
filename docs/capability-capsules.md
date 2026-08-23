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

## Importing a capability from another agent

MasterAgent can inspect a version 1 declarative custom-agent export without
running the other agent or its code:

```bash
master-agent capability-import \
  /trusted/imports/agent-capabilities.json \
  --output /trusted/reviews/agent-capabilities-preview.json
```

The command captures the exact regular file as immutable bytes, rejects
symlinks, unsafe permissions, duplicate JSON keys, unknown fields, malformed or
unbounded data, and then compares every declared ability with the installed
typed catalog and dependency-license policy. It does not construct a capsule
worker, import a module, run an embedded program or prompt, resolve a
credential, connect to a provider, invoke a hook, or alter the catalog.

The self-contained JSON document uses schema
`master-agent/custom-agent-capabilities@1`. Its top-level fields are
`schema`, `agent_id`, `agent_version`, `publisher`, and `abilities`. Each
ability declares:

- a unique `name` and one `kind`: `capability`, `reference`, `skill`, `tool`,
  `workflow`, or `agent`;
- a bounded display `description`;
- `proposed_mapping`, which is a typed capability ID for `capability` and
  `reference` records;
- an exact dependency list, bounded constraints, and canonical requirements;
  and
- for `capability` only, a self-contained `capsule` with the normal spec,
  source, dependency lock, software bill of materials (SBOM), tests,
  verification, compensation, and notice artifacts.

The preview preserves the declared publisher and SHA-256 digest of the exact
source bytes, but neither value is trusted merely because it was declared. It
classifies every ability as:

- `already_supported` — a reference maps to a typed capability that is already
  installed, so nothing should be copied;
- `safely_importable` — one dependency-free pure capability is eligible for
  explicit quarantine, not execution;
- `conflicting` — the mapping would shadow an existing typed capability;
- `unsupported` — the ability needs a raw skill, tool, workflow, provider,
  side effect, or third-party dependency outside the current capsule boundary;
  or
- `unsafe` — the export requests authority or executable behavior such as
  credentials, approval, identity, background access, hooks, shell, network,
  plugins, recursion, hidden source behavior, or inconsistent dependencies.

Selection is deliberately separate from preview. Copy
[`config/capsule-authorities.example`](../config/capsule-authorities.example)
to an operator-controlled location, set mode `0600`, and populate its six
referenced environment variables from an approved secret source. Each enabled
entry owns exactly one role. Key IDs, secret references, resolved secret values,
and case-insensitive subjects must be distinct;
the reviewed publisher subject must exactly match the imported capsule's
declared publisher. The imported program never receives those environment
variables: the worker starts with a fixed, sanitized environment.

Use the exact digest printed by preview to quarantine one named ability:

```bash
master-agent capability-import \
  /trusted/imports/agent-capabilities.json \
  --select greeting \
  --expected-source-sha256 <preview-source-sha256> \
  --environment development \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml
```

Selection takes a fresh immutable snapshot, reclassifies it, rejects source
drift, replaces the foreign provenance string with an exact
`agent-import:sha256:...` binding, signs the first manifest, and installs only
`quarantined`. It cannot batch-select, self-promote, or add the ability to
planning or routing. On a supported isolation host, `--worker-sha256` defaults
to the current worker identity. A review performed on another host may supply
the exact future promotion-worker digest explicitly; promotion still rejects
any different worker.

Promote the exact quarantine through validation, sandbox validation, review,
publication, and enablement:

```bash
master-agent capability-promote \
  foreign.greeting.generate 1.0.0 \
  --environment development \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml
```

The command validates the installed immutable bundle before each distinct
role-signed transition. It preflights every authority for the selected
environment and exact trust-store binding, then safely resumes an authenticated
partial chain after an interruption; already-recorded evidence must match the
fresh validation. Only the final `enabled` manifest can create a typed catalog
definition or routing card. Inspect the authenticated chain at any time:

```bash
master-agent capability-status \
  foreign.greeting.generate 1.0.0 \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml
```

Route an operator intent across an explicit bounded set of enabled versions:

```bash
master-agent capability-route "generate a greeting" \
  --capsule foreign.greeting.generate@1.0.0 \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml
```

Routing authenticates each complete chain, requires its latest state to be
`enabled`, requires the manifest environment to exactly match the selected
governance profile environment, applies organization governance and runtime
policy, and only then matches the bounded intent hints. The quarantine and
promotion examples use `development`, matching the packaged default governance
profile; pass an explicit matching `--governance` file for another environment.
To execute, save an owner-only JSON request whose fields match the capsule input
schema, then run:

```bash
master-agent capability-run "generate a greeting" \
  --capsule foreign.greeting.generate@1.0.0 \
  --request /trusted/requests/greeting.json \
  --database /trusted/master-agent/capsule-audit.sqlite3 \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml
```

This binds the exact selected manifest into a typed `ChangePlan`, activates its
catalog definition and connector, then uses the normal governance, policy,
audit, isolated worker, independent replay, and `WorkflowOrchestrator` path.

An update is a new semantic version in a newly previewed source. Repeat preview,
selection, and promotion for that version; the prior version is not overwritten.
Name only the reviewed new version during routing. Stop an old version without
deleting history by appending deprecation or revocation:

```bash
master-agent capability-disable \
  foreign.greeting.generate 1.0.0 \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml

master-agent capability-revoke \
  foreign.greeting.generate 1.0.0 \
  --capsule-store /trusted/master-agent/capsules \
  --capsule-authorities /trusted/master-agent/capsule-authorities.toml
```

Deprecation and revocation immediately stop future resolution and routing while
retaining the signed artifact and complete immutable state history.

Promotion accepts only the canonical `development`, `non_production`, and
`production` environment names. The signed quarantine must name the same
environment as the promotion service, so a production capsule cannot enter
through a non-production service and skip production readiness. Promotion also
binds one worker identity across the signed quarantine, promotion worker,
validator, validation evidence, and sandbox evidence. A missing or different
environment or worker identity fails before a promoted state is appended.

Importing is different from the other ways an agent may be mentioned:

- **Import** copies one typed ability as untrusted data into quarantine and
  makes it local only after independent promotion.
- **Reference** says an ability maps to a capability MasterAgent already owns;
  it imports no code.
- **Delegate** would leave execution with the original agent behind a separate
  governed isolation and authority boundary. Capability import does not
  implement or authorize delegation.
- A raw prompt, complete agent, plugin, MCP server, hook, or skill package is
  neither a typed capability nor an import shortcut.

Prompt-like descriptions remain inert preview text. The only behavior hints
that can later affect routing are the capsule spec's bounded `intents` and
`negative_intents`; they become eligible only after independent review and
signing, and the deterministic router treats them as lexical data rather than
instructions or authority.

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

`CapsuleWorker` requires a certified native isolation backend by default. On
Linux, that backend is a trusted bubblewrap executable. On native Windows 11,
it is `windows-appcontainer`: an ephemeral zero-capability AppContainer profile
containing a private, read-only projection of the exact interpreter, standard
library, and Windows capsule worker. Windows Subsystem for Linux (WSL) is a
Linux environment and therefore uses the Linux bubblewrap path; it does not use
or certify the native Windows AppContainer backend.

The Linux boundary launches an isolated interpreter with:

- new user, mount, PID, IPC, UTS, cgroup, and network namespaces;
- no inherited environment or network;
- a read-only interpreter and worker mount;
- an ephemeral `/tmp` and working directory;
- no capabilities;
- CPU, address-space, process, file, output, request, and wall-time limits; and
- a small AST-validated Python subset with no import, file, socket, subprocess,
  private-introspection, exception, context-manager, or dynamic-call surface.

The native Windows boundary launches the projected interpreter suspended with
`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, an empty capability list, and
only its protocol pipes inherited. Before resuming, it assigns the process to a
kill-on-close Job Object with CPU, committed-memory, process-count, wall-time,
and shared stdout/stderr limits. The profile and runtime DACL grant the
AppContainer read/execute only; each request receives one fresh writable work
directory and a minimal allowlisted environment. The runtime projection rejects
links and reparse points, is size- and path-bounded, and is rehashed before
every validation or execution.

Validation runs without provider credentials and includes denial probes for
host files, ambient secrets, IPv4, IPv6, localhost, subprocesses, and private
object introspection. Native Windows promotion additionally requires those
operations to fail inside the actual AppContainer. A network probe accepts
only native access-denied, unavailable-family/network, or listener-backed
timeout/drop results; connection refusal or reachability fails validation. The
signed worker identity
binds the backend, worker, interpreter, process boundary, projected runtime,
and DACL policy; Linux also binds the trusted bubblewrap executable. That
identity is rechecked for each connector action, so source, helper, runtime, or
projection tampering fails closed. Package builds normalize worker mode; CI,
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
Provider-backed, credentialed, dependent, or side-effect capsules remain
blocked before connector construction on both native platforms.

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
probe; configuration booleans alone do not satisfy promotion readiness. The
readiness decision uses the same canonical environment that is signed into the
quarantine and all later manifests.

Only the worker is bundled as a production-capable component. The repository
provides typed interfaces for the other controls, not a configured production
secret manager or WORM service. Consequently the shipped deployment remains
fail closed. A local JSON credential source and local SQLite audit log are
development controls and cannot satisfy production readiness.

Provider/network and side-effect capsules, arbitrary HTTP, arbitrary shell,
raw entry-point plugin execution, automatic self-promotion, generated-code
approval, and live credentials during validation are intentionally blocked.
The executable acceptance flow and adversarial cases are in
[`test_capability_import.py`](../tests/test_capability_import.py),
[`test_capability_capsules.py`](../tests/test_capability_capsules.py) and
[`test_capsule_broker_and_routing.py`](../tests/test_capsule_broker_and_routing.py).
