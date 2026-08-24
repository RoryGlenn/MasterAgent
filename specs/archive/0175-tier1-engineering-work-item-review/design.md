# Design

## Approach

Add `engineering_work_item_review.py` as the only workflow-specific planner and
renderer. Its settings parser requires a non-unknown classification, one exact
Bitbucket repository and pull-request ID, and no more than three exact
Confluence page IDs inside one exact space ID/key pair. The exact Jira key
remains a command argument. The planner emits only registered-workflow read
actions, fixes `workflow_id` to
`T1-EWIR-001`, binds a code-owned workflow fingerprint, and sequences Jira,
repository, pull request, build status, optional diffstat, and page reads.

The high-level command loads the active organization profile and its selected
workflow snapshot, builds the plan in memory, and hands it to the existing
`execute` preparation path. That path allocates a private run, persists and
binds the plan, captures exact native connector/configuration/principal/path
identity, runs policy and provider-data gates, executes, verifies, audits, and
retains the normal full result.

While the runtime's artifact directory is still descriptor-pinned, a bounded
artifact callback validates the workflow fingerprint and renders the three
fixed filenames with the existing create-only bundle publisher. JSON contains
only verified normalized evidence and findings. Markdown facts carry citation
markers. The manifest records byte counts and SHA-256 digests for the two review
artifacts. Publication readback verifies every digest.
The callback also revalidates the exact action set, connector deployment,
configuration digest, provider-egress binding, execution result, and
descriptor-pinned artifact root before it admits any report content.

## Affected components

- Jira, Bitbucket, and Confluence connector read contracts and configuration;
- the capability catalog and packaged catalog mirror;
- the organization-profile configuration-name schema and high-level CLI;
- the new bounded workflow planner/renderer module;
- connector, workflow, artifact, and end-to-end operating-mode tests; and
- Tier-1, configuration, architecture, operations, troubleshooting, deployment,
  performance, and semantic-routing documentation.

## Data flow

The CLI captures the profile and exact private workflow configuration, builds
the registered plan, captures every normal applied-run configuration source,
and rejects connector/scope mismatches. The shared preparation path allocates
and binds one private run before the selected native connectors read and
independently re-read exact resources. Provider-egress policy admits only each
schema-projected verified result. The pinned renderer consumes the bound plan
and `RunReport`, revalidates their identities, quarantines mismatched evidence,
classifies the outcome, and publishes exactly three digest-verified files.

## Jira review context

`jira.issue.review_context.read` requires an explicit normalized field list.
Connector-owned mappings turn those names into an exact REST field projection,
including only configured `customfield_<digits>` acceptance and relation fields.
Description and acceptance content accept bounded plain text or bounded ADF.
Issue links expose only link/type/direction and linked issue identity. A bounded
remote-link read and configured relation fields are parsed locally; only HTTPS,
credential-free URLs matching the action-bound provider origin and an exact
provider resource path become structured relations. Their observed owner,
repository, space, pull-request ID, and page ID are retained even when they
conflict with configured scope; the renderer compares the full identities and
marks conflicts ambiguous without changing the immutable target. Candidate
titles and prose never select a target. Verification repeats the exact issue and
remote-link reads and compares normalized evidence.

## Bitbucket build identity

`bitbucket.build_status.read` retains its exact-commit behavior. When supplied
an exact pull-request ID instead, it reads the PR, extracts its current source
commit, reads statuses for that commit, and returns both identities. Independent
verification repeats both reads, so PR-head or build-state drift is
indeterminate rather than a false success. The PR-head route fails on a provider
page or item limit instead of silently truncating evidence; legacy callers that
do not supply an explicit limit retain their bounded provider-order behavior.

The optional standalone diffstat action carries an explicit change limit. It
reads the exact pull request, captures both source and destination commits, and
uses a commit-pinned provider range rather than a moving pull-request diff URL.
The renderer quarantines diffstat evidence when either commit or the pull-request
identity differs from the independently verified pull-request evidence.

## Outcome model

Required Jira, repository, pull-request, and build evidence determine the core
result. A required-source failure is `failed`; independent-read/version drift is
`stale`; materially different relation evidence is `ambiguous`; a configured
optional diffstat or Confluence failure is `partial`; otherwise the package is
`complete`. Returned Jira, repository, pull-request, build, and page identities
that differ from the immutable target are quarantined from JSON, Markdown,
citations, and findings. Unverified action content is never copied into factual
findings.

## Compatibility

Existing Jira reads and schemas remain unchanged. Existing commit-based
Bitbucket build-status actions retain their output fields and gain only optional
pull-request metadata. The default organization profile does not silently admit
the authenticated workflow; deployments must explicitly select its capabilities
and workflow configuration.

## Security

The plan is immutable before credentials or provider access. Only Jira,
Bitbucket, and Confluence are selected. Integration configuration remains the
sole connector-implementation authority and only `native` is supported. Exact
provider IDs, URL origins, field allowlists, classification, byte/item limits,
output paths, configuration digests, and retention are approval-bound. Provider
content cannot select credentials, implementations, targets, approvals, output
paths, or citations for resources that were not independently verified.

## Rejected alternatives

Re-enabling the legacy weekly-status shortcut was rejected because it is not the
profile-owned bound runtime. Provider search, a generic staged planner, and a
generic report framework were rejected as broader than the protected exact
fixture. Jira UI scraping, provider CLIs, arbitrary HTTP, and MCP fallback were
rejected because they bypass the typed first-party connector and implementation
identity boundary.
