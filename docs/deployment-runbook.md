# Deployment Runbook

## 1. Establish ownership

Replace the example organization, security owner, retention owner, system owners, and communications owner in `config/governance.toml`.

## 2. Classify the environment

Start with `development`, then `non_production`. Do not set `production_approved = true` before non-production contract validation and security review.

Review `[model_context]` at the same time. Name the exact destination that will
receive provider results, the model tenancy, whether source data is production
or nonproduction, and the classifications that each route may carry. Do not use
the packaged development placeholders for an organization deployment.

## 3. Select provider deployments

For each Atlassian connector choose Cloud or Data Center and set the exact HTTPS API root. For Microsoft, select the correct Graph national-cloud root and capability-specific identity mode. The built-in Teams send connector is delegated-only; any Teams bot must be implemented and approved as a separate connector.

## 4. Register only required applications and credentials

Request only the scopes needed for the first workflow. If a typed capability is
explicitly anonymous, such as `github.public_repository.list` or
`bitbucket.public_repository.list`, do not provision or attach a credential for
it. For authenticated capabilities, prefer separate credentials for read,
reversible write, and communication, and store persistent secrets in the
approved secret manager.

## 5. Run offline readiness

```bash
mkdir -p "$HOME/.master-agent/MasterAgent"
chmod 700 "$HOME/.master-agent" "$HOME/.master-agent/MasterAgent"
master-agent readiness \
  --integrations /trusted/config/integrations.toml \
  --capabilities /trusted/config/capabilities.toml \
  --governance /trusted/config/governance.toml \
  --oauth /trusted/config/oauth.toml \
  --identities /trusted/config/identities.toml \
  --credentials-file /absolute/path/to/private-credentials.json \
  --egress-check jira:internal \
  --output "$HOME/.master-agent/MasterAgent/readiness.json"
```

Resolve every error and review every warning. `ready: True` validates the
selected configuration; also confirm that the available and credential-ready
connector counts match the intended deployment. Omitting the configuration
arguments validates the packaged safe defaults, not files in the current checkout.
The selected egress check is still offline, but it additionally requires a
usable connector/credential configuration and an allowed route for the active
destination, tenancy, classification, audit sink, and DLP implementation.

## 6. Validate read-only access

Select and probe one read connector at a time:

```bash
master-agent discover \
  --integrations /trusted/config/integrations.toml \
  --governance /trusted/config/governance.toml \
  --systems jira \
  --data-classification internal \
  --probe
```

Then generate and review the relevant read-only plan. A direct-user plan for
one built-in provider can run through `run --direct-read`, which keeps the
verified read session in memory. Use the manifest-bound `run --apply` route for
every provider effect; the legacy weekly-status and communication-context
package commands are disabled.

The classification is trusted operator input, not a value inferred from the
provider response. Outside development it is mandatory for every live probe;
development may omit it only when the model-context policy explicitly selects
a nonproduction default. A policy denial occurs before principal attestation,
connector construction, or provider content access. Successful probes return a
fixed content-minimized digest envelope rather than provider-specific details.

For a specified GitHub user's public repositories, validate the anonymous typed
route directly instead of running an authenticated connection probe:

```bash
master-agent github-repositories --username USERNAME
```

This route must not load an ambient token or require a credential file.

Validate the equivalent anonymous route for a specified Bitbucket Cloud
workspace without an authenticated connection probe:

```bash
master-agent bitbucket-repositories --workspace WORKSPACE
```

This route must ignore ambient Bitbucket credentials and reject any repository
not explicitly marked public.

## 7. Validate draft-only output

Install the optional draft-rendering extra, then run `master-agent demo` for a
credential-free smoke test. The core runtime does not install local Office and
draft renderers:

```bash
python -m pip install 'master-agent[drafts]'
```

For deployment configuration, create distinct private artifact and audit
directories outside the source checkout, then run:

```bash
mkdir -m 700 /absolute/state/draft-package /absolute/state/audit
master-agent draft-package \
  --workflow /trusted/config/draft-package.toml \
  --output-dir /absolute/state/draft-package \
  --database /absolute/state/audit/draft-package.sqlite3
```

Review the generated `.eml`, Teams draft, deck, proposals, patch, and manifest.

## 8. Validate reversible writes in non-production

Use disposable Jira issues, Confluence pages, GitHub issues/pull requests and
test repositories. Capture
expected versions. Obtain exact approvals. Enable only one granular provider
flag. Execute and verify; test automatic compensation only for atomic
version/ref-precondition adapters and test manual descriptors for the rest. Do
not enable local Git or OneNote
writes; their catalog, governance, and live-registry routes are disabled.

Exercise the approval handoff itself: bind the approval-authority configuration,
confirm an unsigned run emits a private request and no pending provider effect,
inspect and sign it from the trusted operator context, then use
`resume-approval`. For dual approval, prove that one approval remains blocked
and that the next request carries it forward before the second identity signs.

For Confluence Cloud, the opt-in
[sandbox workflow](confluence-sandbox-tests.md) automates this exact path on the
default branch with an allowlisted non-production tenant, a least-privilege
identity, authenticated ownership markers, always-run verified cleanup, and a
separately protected optional space lifecycle. It supplements rather than
replaces the scripted connector tests required on every pull request.

Do not activate GitHub administration, Jira issue mutations, or SharePoint file
replacement. Their typed adapters are intentionally catalog/governance-disabled
until a provider-side compare-and-swap can be proven. A test resource and extra
approvers do not repair that concurrency gap.

## 9. Validate communication

Use designated test recipients/chats/channels. Approve exact content. Verify provider identity and tenant restrictions. Confirm the runtime reports provider acceptance rather than claiming delivery/read receipt.

## 10. Inspect recurring registrations

Use the reviewed registration for due-state inspection:

```bash
master-agent recurring-status --recurring /trusted/config/recurring.toml
```

Do not install a
`recurring-run` scheduler invocation; execution is disabled pending exact
target/config/source and runtime-manifest binding.

## 11. Production controls

Before production:

- on Ubuntu 24.04 with AppArmor user-namespace restrictions, install and load
  the distribution-provided `bwrap-userns-restrict` profile; do not disable the
  host-wide `kernel.apparmor_restrict_unprivileged_userns` control;
- install and register a typed external, tamper-resistant audit-sink adapter;
- replace the model-context destination, tenancy, source-data environment, and
  classification rules with reviewed organization values;
- verify which routes require audit and DLP. The shipped runtime has no
  centralized DLP adapter, so DLP-required provider data remains denied;
- use an approved secret manager for every credentialed capability;
- keep capability-capsule production promotion disabled until bubblewrap, a
  production credential/OAuth adapter, authenticated exact-plan approvals, and
  the external tamper-resistant receipt sink all pass one readiness assessment;
- define incident response and token revocation for authenticated connectors;
- define evidence retention/legal hold;
- keep raw plugin and provider/side-effect/dependent capsule execution disabled;
  inventory and pin plugin artifacts only for review;
- review every enabled capability and connector gate;
- preserve a tested rollback procedure;
- monitor provider throttling and authentication failures.
