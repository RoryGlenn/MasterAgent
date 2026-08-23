# Use cases

MasterAgent is useful when one outcome crosses tools or carries enough risk
that a model should not act on its own. The model can help interpret the goal;
typed runtime controls decide what may execute and verify what actually
happened.

## Choose an outcome

| Outcome | Provider credential | Approval | External write |
|---|---:|---:|---:|
| List a named user's public GitHub repositories | No | No | No |
| Build a local cross-system review package | No | No | No |
| Gather a weekly status from workplace systems | Yes | No for an allowed read plan | No |
| Prepare coordinated drafts for review | Only when the source material is live | No provider-effect approval | No |
| Create or update a supported provider resource | Yes | Exact authenticated approval | Yes |
| Run a registered weekly operating review | Yes at apply time | Whatever the bound plan requires | Only if the exact occurrence contains approved effects |
| Inspect and promote one compatible pure capability | No provider credential | Separate signed promotion roles | Local capsule state only |

## Understand a public GitHub footprint

**Example request**

```text
List the public repositories for USERNAME and summarize the active projects.
```

MasterAgent uses the anonymous `github.public_repository.list` capability. It
does not search for or load a GitHub token, bounds the response, independently
confirms every returned repository is public, and prints a sanitized result.

```bash
master-agent github-repositories --username USERNAME
```

Use the authenticated route only for “my repositories,” private repositories,
or other account-visible data. See the
[GitHub connector quickstart](github-connector-quickstart.md).

## Produce a review package without publishing anything

**Example request**

```text
Build a review package that shows the Jira, Confluence, email, Teams, deck,
and repository changes we could make. Do not publish or send anything.
```

The credential-free demonstration renders a synthetic version of that outcome:

```bash
master-agent demo
```

The artifacts stay in a new private local workspace and include an integrity
manifest. Nothing reaches a provider. For a real organization workflow, the
same draft boundary can use approved live reads as inputs while still keeping
every proposed update local. See [Phase 3 draft-only output](phase-3-drafts.md).

## Build a cited weekly status

**Example request**

```text
Build this week's status from the reviewed Jira project, Confluence space, and
Bitbucket repositories. Cite every source and do not change any provider.
```

The workflow plan contains typed reads only. A direct read plan can stay in
memory, return schema-bound content plus citations, and create no effect or
approval state. Live provider credentials and organization configuration are
still required because the source data is account-visible.

Use [Configuration](configuration.md) for the provider profiles and
[Phase 2A](phase-2-read-only.md) for the read/verification boundary.

## Coordinate a reviewed provider change

**Example request**

```text
Create the approved GitHub issue and add the approved Jira comment. Verify both
results and tell me if either provider changed underneath the plan.
```

MasterAgent prepares immutable typed actions, applies capability and governance
rules, binds provider identity and current state, and emits one exact approval
request when required. A trusted operator signs that request; MasterAgent then
resumes the original bound run rather than reconstructing it from chat.

If a provider no longer matches the reviewed precondition, the change stops.
Multi-system partial success is reported explicitly; compensation runs only
when a typed adapter can enforce its own safe precondition. See
[Approved reversible writes](phase-4-approved-writes.md) and the
[operations guide](operations.md).

## Send an exact reviewed communication

**Example request**

```text
Send this approved message to the existing Teams channel after verifying the
exact recipient and body.
```

External communication has its own capability and governance gates. Outlook
creates and re-reads an exact provider draft before send; Teams re-reads the
created message. Sending is non-reversible, so conversational approval is not
enough. See [Phase 5 external communication](phase-5-communications.md).

## Run a weekly operating review on schedule

**Example request**

```text
Run the already reviewed weekly operating review for its exact Monday
occurrence. Do not infer new targets or recipients from provider content.
```

A schedule supplies time, not authority. MasterAgent authenticates one exact
occurrence artifact, reserves it in the single-host claim store, reuses the
normal policy and approval path, and checks the claim fence immediately before
every provider effect. There is no `--force` bypass. See
[Phase 6 recurring autonomy](phase-6-autonomy.md).

## Add one safe missing capability

**Example request**

```text
Inspect this exported capability, quarantine only the compatible pure ability,
and prepare it for independent review. Do not run imported code.
```

MasterAgent can inspect a declarative export without executing it, select one
compatible dependency-free pure capability, and create a signed quarantine.
Promotion requires separate publisher and reviewer roles plus test and
isolation evidence. Provider access, side effects, dependent code, raw plugins,
and whole-agent execution remain fail closed. See
[Capability capsule promotion](capability-capsules.md).

## What MasterAgent is not for

MasterAgent has no generic shell or HTTP capability, autonomous merge path,
force push, broad deletion, arbitrary permission change, uncontrolled sync, or
authority derived from retrieved content. The complete boundary is in the
[threat model](threat-model.md) and [integration matrix](integration-matrix.md).
