# Design

## Approach

Add a bounded organization-profile model that accepts only an exact schema,
known operating modes, explicit configuration paths, and a finite capability
allowlist. The profile is data, not authority: every requested action must also
exist in the installed catalog and pass the existing governance and policy
engines. Setup publishes a private profile copy and creates only the approved
private state directories. Doctor derives capability-scoped readiness from the
profile, packaged or explicit configuration, supported platform, and selected
credential availability without probing providers.

The high-level command loads and validates one plan once. Eligible direct-user,
single-provider reads enter the existing in-memory direct-read implementation.
Drafts and effects receive deterministic private run paths, an immutable
unbound-plan snapshot, and the existing bind, inspect, and applied-run stages.
When policy requires approval, the existing private request captures the exact
profile path and digest alongside the other resume inputs. Resume revalidates
the current profile and the original execution binding before dispatch.

## Affected components

- `src/master_agent/operating.py` and `src/master_agent/cli.py`
- `src/master_agent/approval_handoff.py` and
  `src/master_agent/config_sources.py`
- `config/organization-profile.toml` and its packaged default
- operating-mode, CLI, handoff, packaged-default, and semantic-router tests
- `.ai/semantic-router.toml` and generated `docs/semantic-index.md`
- repository agent policy, onboarding, configuration, CLI, architecture, and
  operations documentation
- this behavioral change and its final current-requirement snapshots

## Data flow

`setup` selects an explicit profile source and publishes a restricted local
copy. `doctor` combines that profile with offline installation, platform,
configuration, capability, provider, credential, and enterprise-control facts
to report independent readiness levels. `execute PLAN` validates the profile
and plan before selecting direct read or governed applied run. Applied work
binds the profile snapshot into the execution context, executes through the
existing orchestrator, and either returns verified results or a resumable exact-
plan approval request. `execute --resume REQUEST` restores the captured inputs,
revalidates the profile and request fingerprint, and enters the existing
approval-resume path.

## Compatibility

The existing `readiness`, `run --direct-read`, `bind-context`, `inspect`, `run
--apply`, `inspect-approval-request`, and `resume-approval` interfaces remain
available and keep their current behavior. The high-level path adds no new
provider capability. An organization that does not adopt a profile can keep
using the low-level commands. Enterprise readiness remains false until all
external production controls are implemented and configured.

## Security

Profile paths are explicit or resolved only from the dedicated user profile
location; the current directory and ambient project files are never implicit
sources. The parser rejects unknown fields, unsafe paths, unsupported modes,
and malformed or duplicate capabilities. Pre-runtime validation rejects
catalog-missing or profile-unlisted capabilities and applies the employee risk
boundary before any connector or state access.
Profiles, state roots, run directories, plan snapshots, approval requests, and
results use existing no-follow ownership, permission, create-only, and readback
primitives. The high-level command cannot construct a connector before plan,
profile, provider, credential, and policy checks. Employee mode has no code-
generation or promotion route. Developer output remains untrusted data and
must pass the independent signed capsule or first-party review lifecycle before
runtime admission.

## Rejected alternatives

An untyped natural-language execution path was rejected because it would make
the planner an authority. Automatically enabling every installed capability
was rejected because installation does not express organization policy.
Persisting state for all reads was rejected because it adds unnecessary
sensitive state. Making setup create production approvals, credentials, audit
sinks, or provider connections was rejected because local preparation cannot
grant enterprise authority.
