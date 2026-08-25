# Tier-1 workflow plan: Engineering Work Item Review

## Status

**Implemented locally, including the protected selector; certification
pending.** Issue
[#175](https://github.com/RoryGlenn/MasterAgent/issues/175) implements this
bounded workflow and its deterministic verification path. The repository-side
#94 selector now supplies the default-disabled protected Ubuntu execution path,
but no credentialed run has been performed. The checked-in safe profile does
not enable it. Provider-provisioned #94 fixture evidence and the Windows 11
standard-user managed-workstation baseline under #172 are still required before
it may be described as certified or enabled as a default employee workflow.

Related work:

- [#169](https://github.com/RoryGlenn/MasterAgent/issues/169) — native-first
  enterprise execution path;
- [#164](https://github.com/RoryGlenn/MasterAgent/issues/164) — performance and
  governance instrumentation;
- [#170](https://github.com/RoryGlenn/MasterAgent/issues/170) — connector
  implementation identity;
- [#94](https://github.com/RoryGlenn/MasterAgent/issues/94) — protected live
  connector fixtures;
- [#112](https://github.com/RoryGlenn/MasterAgent/issues/112) — enterprise proxy
  and certificate-authority support;
- [#116](https://github.com/RoryGlenn/MasterAgent/issues/116) — provider-data and
  model-context policy; and
- [#172](https://github.com/RoryGlenn/MasterAgent/issues/172) — managed-workstation
  reliability and performance pilot.

## Purpose

Prove that MasterAgent can complete one valuable cross-system engineering
workflow on a restricted corporate workstation through first-party native
connectors, without installing or invoking a third-party Model Context Protocol
(MCP) server.

The first workflow should demonstrate reliable orchestration rather than broad
capability count. It must exercise the actual company constraints that motivated
MasterAgent: managed Windows, provider authentication, corporate networking,
provider permissions, independent verification, data handling, and low-friction
user experience.

## User outcome

Given one Jira work item, produce a cited local engineering review that compares
the work item against its related Bitbucket pull request, build evidence, and
linked Confluence requirements or decisions.

Example request:

```text
Review Jira item PROJECT-123.

Check its related Bitbucket pull request and build status, read the linked
Confluence requirements or decisions, and produce a cited review package.
Do not change, publish, or send anything.
```

## Why this is the first Tier-1 workflow

This workflow:

- matches normal software-engineering work;
- demonstrates useful orchestration across Jira, Bitbucket, and Confluence;
- uses provider capabilities that already exist in MasterAgent;
- can begin read-only and generate output locally;
- avoids Microsoft Graph consent, messaging, and irreversible communication in
  the first pilot;
- can run against bounded nonproduction or approved low-sensitivity fixtures;
- exposes real proxy, certificate, authentication, permission, provider,
  connector, verification, and latency failures; and
- creates a direct test of the native-first product claim.

## Initial scope

The initial pilot processes:

- exactly one Jira issue;
- exactly one related Bitbucket repository;
- at most one related Bitbucket pull request;
- at most three linked Confluence pages; and
- one private local review package.

The workflow is limited to read-only provider actions and local generation. It
performs no provider mutation, send, publish, merge, permission change, or
scheduled execution.

## Tier-1 case and fixture contract

The first pilot case is `T1-EWIR-001` (Engineering Work Item Review). #94 must
bind this case to one dedicated nonproduction Jira issue, one Bitbucket
workspace/repository and pull request, and zero to three Confluence pages. The
exact provider IDs and URLs are recorded only in protected environment
configuration; they are not committed to this repository.

The initial repository-side #94 selector is narrower than that general
production contract. Its protected `T1-EWIR-001` configuration must select
exactly one Confluence page and must set `include_diffstat = false`. This fixed
shape is the already-proven 14-provider-content-call case; the production
runtime remains capable of zero to three pages and optional diffstat.

The protected case record must contain, without provider bodies or secrets:

- the stable case ID and MasterAgent commit;
- the Jira issue ID/key and its source-of-truth classification;
- the Bitbucket workspace, repository, and pull-request IDs;
- the Confluence space and page IDs, when pages are in scope;
- the approved principal and scope class for each selected connector;
- the proxy and enterprise-CA profile required by the managed workstation; and
- the cleanup owner and retention boundary.

The case is invalid when any required identifier is absent, ambiguous, outside
the dedicated nonproduction boundary, or classified unknown in employee mode.
More than three linked Confluence pages is an explicit bounded-scope failure;
the workflow does not silently select a subset.

## Source-of-truth rules

| Information | Authoritative source |
|---|---|
| Work-item identity, summary, owner, priority, status, acceptance criteria, and explicit provider links | Jira |
| Pull-request identity, source/destination branches, commit state, review state, diff summary, and build/check state | Bitbucket |
| Durable requirements, architecture decisions, and approved project documentation | Confluence |
| Cross-system comparison, inconsistencies, missing evidence, and review narrative | Local MasterAgent-generated package derived only from verified sources |

When systems disagree, the report must identify the disagreement and cite both
sources. It must not silently choose the most convenient value.

## Relationship resolution

The implemented workflow starts from an exact Jira issue key supplied as the
command argument. One reviewed private workflow configuration selects the exact
Bitbucket deployment, origin, workspace or project, repository, pull-request
ID, Confluence origin and space ID/key, and zero to three page IDs before any
credential is resolved or provider content is read.

Verified Jira issue links, remote links, and explicitly allowlisted relation
fields may confirm or conflict with those immutable targets. They never select
a replacement target. A materially different exact relation produces an
`ambiguous` result; an absent relation does not broaden or invalidate the
configured target.

Retrieved prose cannot select a provider, credential, tenant, repository, space,
recipient, connector implementation, or approval.

The initial implementation deliberately performs no provider search. A future
bounded-search extension requires its own accepted behavior and must preserve
the same target, identity, and independent-verification gates.

## Exact provider capabilities

### Jira

Required:

- `jira.issue.review_context.read`

### Bitbucket

Required for an exact related pull request:

- `bitbucket.repository.read`
- `bitbucket.pull_request.read`
- `bitbucket.build_status.read`

Optional when requested or needed for the review:

- `bitbucket.pull_request.diffstat`

### Confluence

Required for each exact linked page:

- `confluence.page.read`

### Local output

The implementation reuses the normal planner, applied runtime, connector,
verification, audit, and create-only bundle primitives. One small
workflow-specific renderer produces the fixed review schema; it is local code,
not a provider effect or generic report framework.

## Connector implementation requirements

- Jira, Bitbucket, and Confluence use the first-party `native` implementation.
- Connector implementation selection comes from trusted organization or
  integration configuration.
- The user is never asked to choose native versus MCP.
- No action automatically falls back to MCP or another implementation after a
  failure.
- Only the three selected provider systems may initialize or resolve
  credentials.
- The exact implementation identity is bound through the trusted integration
  snapshot, execution context, plan, and approval; the managed-workstation
  baseline must preserve that identity.

## Execution sequence

```text
1. Validate the exact Jira issue key and bounded workflow configuration
        |
2. Select the read/local-generation risk path
        |
3. Select and bind the native Jira, Bitbucket, and Confluence implementations
        |
4. Resolve only the selected credentials and provider principals
        |
5. Read and independently verify the Jira issue
        |
6. Compare verified Jira relations with the exact configured targets
        |
7. Read and independently verify the repository, pull request, build status,
   and optional diffstat
        |
8. Resolve and independently verify up to three linked Confluence pages
        |
9. Revalidate provider-data/model-context policy and minimize returned fields
        |
10. Generate the private cited review package locally
        |
11. Verify artifact digests and report complete, partial, failed, stale, or
    ambiguous status
```

Verification is an independent bounded readback, not a successful HTTP response.
For each provider, the verifier confirms the expected provider identity and
resource ID, re-reads the normalized fields needed by the report, and compares
the result with the collected evidence before a factual finding is emitted.
Jira verification covers the issue key and requested work-item fields;
Bitbucket verification covers the repository, pull-request identity, commit
heads, and build/check state; Confluence verification covers each page ID,
space, version, and requested content fields. A changed identity, version,
commit head, or schema fails the affected source closed and is reported as
stale or indeterminate rather than inferred successful.

## Review package

The initial package contains:

- `engineering-work-item-review.json` — normalized evidence and machine-readable
  findings;
- `engineering-work-item-review.md` — human-readable review;
- `manifest.json` — artifact names, byte counts, and SHA-256 digests.

The Markdown report should contain:

1. work-item summary;
2. acceptance criteria and current Jira status;
3. related pull-request and build status;
4. relevant Confluence requirements or decisions;
5. evidence-backed consistency checks;
6. missing, stale, conflicting, or unverifiable information;
7. decisions or follow-up actions needed; and
8. citations for every provider-grounded factual claim.

A PowerPoint deck, Outlook draft, Teams draft, provider comment, or provider
update is outside the initial pilot.

## Data and evidence boundaries

- The pilot uses dedicated nonproduction fixtures or explicitly approved
  low-sensitivity data.
- Unknown classification fails closed in employee mode.
- Only fields needed for the stated review are requested and returned.
- Retrieved content is always untrusted data and cannot grant authority.
- Provider bodies are not written to ordinary audit state.
- The review package is written only to an explicitly selected private local
  output directory under the applicable retention rule.
- Secrets, credentials, tokens, proxy values, local usernames, and sensitive
  paths are excluded from reports, metrics, and diagnostics.
- Content-free metrics and stable test-case identifiers may be retained for the
  #172 pilot.

## Deterministic performance regression evidence

The #164 deterministic harness exercises this exact `T1-EWIR-001` shape for 20
stable iterations. It checks the provisional p50, p95, local-governance,
provider-call, interaction, and selected-provider budgets while keeping the
connector implementation identity at `native` with `bound = true` from the
trusted selection boundary. It also proves that unselected systems perform no
provider-specific credential, construction, attestation, transport, or
verification work.

This evidence is baseline-ineligible: it verifies the binding and attribution
mechanism but does not certify live-provider latency, Windows behavior,
corporate networking, or a managed workstation. Use the command and
interpretation rules in the
[governance-performance evidence guide](governance-performance.md). #172 owns
the live managed-workstation baseline.

That deterministic setup records exactly three principal attestations, one for
each selected provider. The installed high-level command has a stronger
two-phase boundary: it attests each provider while binding the immutable
execution context and re-attests before applied execution, for exactly six
attestations (two per provider) in the protected selector run.

## Completion and partial-success semantics

A **complete success** requires every configured source to return verified data
and every output artifact to pass digest verification.

A **partial result** may be generated when one secondary source is unavailable,
but it must:

- state that the review is incomplete;
- identify the missing or failed source and stage;
- exclude unverified content from factual conclusions;
- avoid claiming the requested review completed successfully; and
- remain outside the complete-success count for reliability objectives.

A failed or ambiguous provider effect is impossible in the initial scope because
there are no provider effects. Provider timeouts or uncertain reads fail or
remain explicitly unresolved; they never become reassuring inferred results.

Recovery is bounded and user-actionable:

| Failure class | Recovery requirement |
|---|---|
| installation, Windows, proxy, DNS, TLS, or CA | report the failing stage and environment prerequisite; retry only after the operator repairs that prerequisite |
| credential, authentication, principal, scope, consent, or permission | identify the selected system and required scope class without exposing secrets; do not prompt for unselected providers |
| target or relation ambiguity, provider schema, consistency, or rate limit | return the exact unresolved resource or field; do not broaden search; retry only with corrected configuration or an eligible provider retry |
| native connector implementation | fail closed with the selected system and implementation identity; never fall back to MCP |
| governance, source-of-truth, data policy, verification, or citation integrity | discard affected conclusions and return the smallest incomplete or indeterminate result for review |
| performance budget | preserve the partial/failed classification, record content-free timing, and require measured #164/#172 triage before retesting |
| user-facing setup or error behavior | retain the stable case ID and failing stage, correct the local setup, and rerun the same bounded case |

No provider cleanup is required for this read/local-generation workflow. Local
artifacts are discarded or retained according to the selected retention rule;
uncertain reads never trigger compensating provider writes.

## Expected user experience

For the normal successful path:

- zero governance confirmation prompts;
- zero effect-approval prompts;
- zero connector-implementation questions;
- zero prompts for unrelated provider credentials;
- one request and one final verified result.

Materially conflicting exact relation evidence returns an `ambiguous` bundle and
nonzero exit rather than prompting, guessing, or broadening provider search.

## Provisional reliability objectives

These objectives apply to the first 20 managed-workstation pilot executions and
are recalibrated only from #164/#172 evidence:

| Measure | Provisional objective |
|---|---:|
| Complete successful runs | At least 19 of 20 |
| False-success results | 0 |
| Duplicate provider effects | 0 |
| Provider mutations | 0 |
| Third-party MCP invocations | 0 |
| Governance confirmation prompts on successful runs | 0 |
| Unexpected credential prompts | 0 |
| Unused connector initializations | 0 |
| Unselected-provider network calls | 0 |
| Uncited provider-grounded factual findings | 0 |
| Partial or indeterminate outcomes reported as complete | 0 |

## Provisional performance objectives

| Measure | Provisional objective |
|---|---:|
| p50 end-to-end latency | 30 seconds or less |
| p95 end-to-end latency | 60 seconds or less |
| Local governance overhead | Less than 5% of total wall-clock time under the representative workload |
| Connector initializations | Exactly 3 |
| Selected connector implementations | Exactly 3; each is `native` with `bound = true` from the trusted integration binding |
| User interactions caused by governance | 0 |

The latency limits are initial user-experience targets, not provider guarantees.
They must be recalibrated after measuring the actual corporate network and
provider environment.

## Provisional provider-call budget

The deterministic implementation remains under the #164 budget; provider
principal attestation, deployment type, optional diffstat, and configured page
count still affect a protected live run's exact count.

Initial expectations:

- one provider-principal attestation per selected provider in each bind/apply
  phase, for six total in the protected high-level run; the deterministic
  setup-only harness records three;
- two content calls for an exact Jira issue read and verification;
- bounded Bitbucket calls for repository, pull request, build status, optional
  diffstat, and independent verification;
- two content calls per exact Confluence page read and verification;
- no provider calls from local rendering; and
- no calls to an unselected provider or implementation.

The one-page deterministic complete-path fixture performs 14 provider content
calls and zero approval interactions. A protected complete workflow must remain
within 20 provider content calls, excluding explicitly measured
authentication/principal attestation. Any higher live baseline must be
explained before optimization. #167 may remove only calls that are proven
redundant without weakening identity, concurrency, or verification.

## Failure taxonomy

Every failed pilot run is assigned to the smallest useful category:

- installation or runtime identity;
- Windows platform contract;
- proxy, DNS, or network;
- TLS or enterprise certificate authority;
- credential source;
- provider authentication;
- principal, scope, application consent, or permission;
- target or relation configuration;
- native connector implementation;
- provider API, schema, consistency, or rate limit;
- governance, source-of-truth, or provider-data policy;
- verification or citation integrity;
- performance budget; or
- user-facing setup or error behavior.

Ambiguous failures remain explicit until evidence resolves them.

## Test and evidence mapping

### Existing foundations to reuse

- `tests/test_connector_contract_matrix.py` for factory and registry contracts;
- `tests/test_connector_integration_matrix.py` for credentialed live provider
  behavior;
- existing Jira, Bitbucket, and Confluence connector tests;
- `src/master_agent/workflows/weekly_status.py` and its tests for read-only
  cross-provider collection and local package rendering; and
- the existing capability catalog, provider-data boundary, orchestrator,
  verification, citation, and artifact-digest mechanisms.

The deterministic workflow regression coverage belongs with the reused weekly
status workflow tests and connector contract matrix; any new case-specific
module must use the same fixtures and test helpers rather than introducing a
second integration framework.

### Implemented deterministic additions

- deterministic workflow tests for exact configured resources and relation
  conflict;
- tests that untrusted content cannot select resources or implementations;
- tests that conflicting relations are ambiguous without broad search;
- tests that partial data cannot produce a complete-success result;
- tests that every factual finding is backed by a verified citation;
- #164 measurements for stages, initialization, credentials, provider calls,
  verification calls, retries, interactions, and outcome;

### Protected evidence still required

- one successful default-branch run of the repository-side #94 protected
  selector against provisioned exact Tier-1 fixtures;
- #112 proxy and enterprise-CA coverage; and
- #172 Windows 11 standard-user baseline and repeated managed-workstation runs.

The GitHub-hosted Ubuntu selector is `local_runtime` evidence and therefore
baseline-ineligible. It demonstrates the repository-owned fixture boundary for
#94 but does not complete #172 or substitute for its external managed Windows
baseline.

## Delivery sequence

```text
1. Accept this workflow contract under #171 — complete
        |
2. Implement #164 instrumentation — complete
        |
3. Implement #170 connector implementation binding — complete
        |
4. Add or adapt the smallest workflow and renderer code under #175 — complete
        |
5. Add the protected #94 selector — complete locally; provision fixtures and
   run it on reviewed default-branch code — pending
        |
6. Run the initial Windows 11 standard-user #172 managed-workstation baseline
   — pending
        |
7. Apply measured #165, #168, #167, and #166 improvements
        |
8. Repeat the same #172 workload
        |
9. Issue a ready / ready_with_restrictions / not_ready recommendation for #113
```

## Non-goals

The first Tier-1 workflow does not include:

- a generic MCP client or MCP tool discovery;
- automatic implementation fallback;
- GitHub as an additional provider;
- Outlook or Teams reads, drafts, or sends;
- Jira, Bitbucket, or Confluence writes;
- pull-request merge or branch publication;
- PowerPoint generation;
- recurring or autonomous execution;
- every capability in the catalog;
- broad searches across unrelated provider resources; or
- company-wide production-readiness claims.

## Implementation completion

The repository implementation is complete when:

- #171 accepts the exact workflow and bounds;
- the required provider capabilities and relation rules are deterministic;
- the native implementation identity is exact-bound;
- the output package and citation contract are implemented and tested;
- the default employee profile remains disabled; and
- an independently reviewed pull request carries the local verification
  evidence.

## Certification completion

The workflow is certified only when:

- stable protected fixtures exist;
- 20 representative managed-workstation runs produce the required metrics;
- false success, duplicate effects, provider mutations, unapproved MCP use,
  unused initialization, and uncited findings remain zero; and
- #172 produces an evidence-backed recommendation for entering the #113 small
  employee pilot.
