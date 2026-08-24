# Deployment Runbook

This runbook is for operators moving from a verified local installation to an
organization-controlled environment. Complete the credential-free
[quickstart](quickstart.md) first; then progress one readiness level and one
provider at a time. The [documentation index](index.md) identifies the
canonical reference behind each step.

## 1. Establish ownership

Replace the example organization, security owner, retention owner, system owners, and communications owner in `config/governance.toml`.

## 2. Classify the environment

Start with `development`, then `non_production`. Do not set `production_approved = true` before non-production contract validation and security review.

Review `[model_context]` at the same time. Name the exact destination that will
receive provider results, the model tenancy, whether source data is production
or nonproduction, and the classifications that each route may carry. Do not use
the packaged development placeholders for an organization deployment.

## 3. Select provider deployments

For each Atlassian connector choose Cloud or Data Center and set the exact HTTPS
API root. Jira and Confluence Cloud may use the exact tenant root or their
product-specific `https://api.atlassian.com/ex/{product}/{cloudId}` scoped-token
gateway. A gateway also requires the exact tenant `web_base_url` for
credential-free browser links; requests, redirects, and pagination remain
confined to the configured product/cloud-ID API path. Every Microsoft connector
is Microsoft Graph Cloud-only: set `deployment = "cloud"`, select one of the
supported Graph national-cloud roots, and choose the capability-specific
identity mode. A Data Center or arbitrary Graph origin is rejected before
credentials are resolved. The built-in Teams send connector is delegated-only;
any Teams bot must be implemented and approved as a separate connector.

## 4. Register only required applications and credentials

Request only the scopes needed for the first workflow. If a typed capability is
explicitly anonymous, such as `github.public_repository.list` or
`bitbucket.public_repository.list`, do not provision or attach a credential for
it. For authenticated capabilities, prefer separate credentials for read,
reversible write, and communication, and store persistent secrets in the
approved secret manager.

## 5. Protect credentialed integration evidence

The complete multi-provider workflow is manual-dispatch only and must run from
reviewed default-branch code. Keep three separate GitHub environments:

- `connector-integration-read` for read credentials and fixtures;
- `connector-integration-effects` for reversible effects and dedicated test
  communications; and
- `connector-integration-admin` for the separate GitHub administration
  configuration and personal access token.

Ordinary GitHub read/effect tests use the job-scoped `github.token`, not the
admin token. Use the privilege-specific configuration and token secret names
listed in [Credentialed Live Connector Integration Tests](live-connector-integration-tests.md).
Before enabling a repository variable, complete the environment's reviewer and
exact-default-branch restriction, least-privilege provider credentials, tenant
consent, stable fixtures, and dedicated nonproduction targets.

For this repository, all three environments currently require reviewer
`RoryGlenn` and allow only the exact `main` branch. Self-review prevention is
off because that account is the sole eligible collaborator. No enablement
variables, provider secrets, or fixture variables are configured, so the live
jobs remain disabled and this is incomplete integration setup—not successful
provider evidence. Add a second eligible reviewer and enable self-review
prevention if organization policy requires reviewer separation.

Microsoft live evidence uses restricted delegated token files, not application
credentials for OneNote or normal Teams operations. The harness checks exact
scopes, delegated identity, token lifetime, every fixture, and every gate before
the first mutation. Reversible effects write a private runner-temporary recovery
journal, verify compensation in-process, and retry residual entries in a
same-job `always()` step. Never upload that journal; reconcile the provider
manually if a request may have committed but its response was lost.

## 6. Run offline readiness

Create a reviewed `organization-profile.toml` with absolute paths to this
deployment's configuration, exact installed capabilities, private state root,
and disabled-at-rest effect gates. Install it for the service account, then
check each progressive level without opening a provider connection:

Keep ordinary configuration user-private. When policy must instead be owned by
deployment administrators and read-only to the employee, add a matching
`[configuration_trust.NAME]` table to the private profile with the exact
content SHA-256 and approved POSIX UID/GID or Windows SID writers. Confirm the
employee cannot write the file or its retained parent. Never reuse that trust
table for credentials, executable provenance, or writable state.

```bash
master-agent setup \
  --profile /trusted/config/organization-profile.toml \
  --non-interactive
master-agent doctor --require-level install
```

`install_ready`, `read_ready`, `draft_ready`, `effect_ready`, and
`enterprise_ready` are independent. Do not treat an installed profile as
provider authentication, effect approval, or production certification.
Inspect the additive `platform_runtime` object as a separate prerequisite: it
names every selected backend and unavailable secure contract. Native Windows
selects retained-handle filesystem/ACL validation and `LockFileEx`, so trusted
configuration diagnosis can read approved local paths. It also selects the
native handle-relative atomic-state backend, so `setup`, restricted output,
SQLite state, retention, token/configuration publication, and local artifact
stores no longer use POSIX fallbacks. A focused Windows 11 ARM job exercises
that boundary through a non-administrator local account together with
Credential Manager/DPAPI, Job Object supervision, trusted Git, and AppContainer
capsule isolation. It also builds and installs the wheel, proves the `.exe`
console launcher, and runs the idempotent source bootstrap from a spaced,
Unicode, long path. Do not treat hosted tests as enterprise deployment
approval.

Native Windows release certification is a separate protected gate. Follow
[Windows 11 x64 release certification](windows-certification.md) to provision
an ephemeral clean Windows 11 x64 VM, register its dedicated non-administrator
runner account with the exact labels, protect the default branch and review
environment, and enable the workflow only while that infrastructure is
healthy. A release cannot infer x64 certification from the hosted ARM matrix,
workflow presence, a skip, or a queued self-hosted job.

On native Windows, the no-profile default is
`%LOCALAPPDATA%\MasterAgent\organization-profile.toml`; the current directory
is never an implicit configuration source. Use explicit local drive paths for
reviewed deployment configuration and state. UNC/device namespaces, reparse or
cloud-placeholder paths, unsupported filesystems, unsafe names, and untrusted
writable ancestors fail closed. Ensure Python 3.12 or newer, the `venv` module,
long-path host policy, and a supported local filesystem are available. WSL is
a separate Linux deployment and follows the POSIX path, permission, and
bubblewrap requirements.

Bootstrap reuse also requires the versioned local attestation to match a fresh
source/build and dependency-policy digest, project version, launcher,
distributions, and every installed file. It verifies POSIX permissions and
extended ACLs or retained Windows DACLs and compares the complete runtime
digest before executing the isolated interpreter probe. A legacy marker or any
mismatch is preserved and repaired at the reported side-by-side path; use the
launcher printed on the final `command:` line.

Keep the detailed low-level deployment assessment below for connector, OAuth,
identity, and provider-data egress diagnostics:

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

## 7. Validate read-only access

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

For the protected Tier-1 pilot, first install the exact private
`engineering_work_item_review` configuration and capability allowlist described
in [Configuration](configuration.md#engineering-work-item-review-configuration).
Run only the dedicated #94 nonproduction fixture:

```bash
master-agent engineering-work-item-review PROJECT-123 \
  --profile /trusted/config/organization-profile.toml
```

Require an exit-zero `complete` bundle, exactly three create-only private
artifacts, native implementation identity for each selected connector, zero
approval interactions, no unselected-provider credential or network activity,
and the content-free `T1-EWIR-001` performance record. A local or CI pass is
baseline-ineligible; preserve the protected run metadata for #172 and do not
enable the workflow by default until managed-workstation certification is
complete.

## 8. Validate draft-only output

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

## 9. Validate reversible writes in non-production

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

## 10. Validate communication

Use designated test recipients/chats/channels. Approve exact content. Verify provider identity and tenant restrictions. Confirm the runtime reports provider acceptance rather than claiming delivery/read receipt.

## 11. Inspect recurring registrations

Use the reviewed registration for due-state inspection:

```bash
master-agent recurring-status --recurring /trusted/config/recurring.toml
```

Do not install a
`recurring-run` scheduler invocation; execution is disabled pending exact
target/config/source and runtime-manifest binding.

## 12. Production controls

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
- configure the approved helpdesk channel, owner, response-time objective,
  access/retention policy, and secure deletion process, then test
  `master-agent support-bundle` from the installed artifact;
- define evidence retention/legal hold;
- keep raw plugin and provider/side-effect/dependent capsule execution disabled;
  inventory and pin plugin artifacts only for review;
- review every enabled capability and connector gate;
- preserve a tested rollback procedure;
- monitor provider throttling and authentication failures.
