# MA-TIER1-EWIR-001 — Tier-1 Engineering Work Item Review

## Status

Active

## Requirement

MasterAgent MUST provide one high-level `T1-EWIR-001` Engineering Work Item
Review path that accepts exactly one canonical Jira issue key and trusted,
profile-selected workflow configuration. The configuration MUST bind one
Bitbucket repository, exactly one pull-request ID, zero to three Confluence page
IDs, a known data classification, and bounded optional enrichment. Missing,
duplicated, malformed, over-broad, or unknown scope MUST fail before credentials
or provider content access.

The workflow MUST execute through the normal profile admission, immutable-plan,
execution-context, policy, provider-data, source-of-truth, retention, audit, and
independent-verification boundaries. It MUST select only Jira, Bitbucket, and
Confluence first-party `native` connector implementations. Retrieved content,
action output, project files, prompts, and runtime user input MUST NOT select or
change connector implementations, credentials, tenants, repositories, spaces,
targets, approvals, or output paths. A native failure MUST NOT fall back to MCP
or another implementation.

Jira MUST expose a separate versioned review-context read without changing the
existing issue-read schema. It MUST use an explicit normalized field projection
mapped to exact standard fields and configuration-allowlisted
`customfield_<digits>` identifiers. It MUST bound and normalize plain text or
ADF description and acceptance content, Jira issue links, provider remote
links, and configured relation fields. Returned issue identity MUST exactly
match the requested key. Only HTTPS, credential-free URLs on the action-bound
Bitbucket or Confluence origins and exact repository/pull-request/page patterns
MAY become structured external relations. Titles and prose MUST NOT become
target selectors. Independent verification MUST repeat the same exact reads.

The immutable plan MUST read and independently verify the Jira review context,
configured Bitbucket repository, pull request, pull-request head and build
statuses, optional diffstat, and every configured Confluence page. A changed
Jira result, PR head, build state, repository identity, or Confluence version
MUST fail that evidence closed. Jira relation evidence MAY confirm or conflict
with exact trusted targets but MUST NOT dynamically broaden the first protected
pilot plan. Zero or multiple materially different targets MUST be reported as
ambiguous when relation evidence is present rather than silently selected.
Missing relation evidence MUST NOT broaden the immutable configured scope.

The workflow MUST create exactly `engineering-work-item-review.json`,
`engineering-work-item-review.md`, and `manifest.json` beneath its
descriptor-pinned private run artifact root. Publication MUST be create-only,
mode-restricted, bounded, rollback-safe for owned files, and readback digest
verified. The manifest MUST record each review artifact's filename, byte count,
and SHA-256 digest. Every provider-grounded factual statement in Markdown MUST
carry a citation to independently verified evidence. Unverified content MUST
NOT support factual findings.

Bundle status MUST distinguish `complete`, `partial`, `failed`, `stale`, and
`ambiguous`. Missing optional evidence MAY produce a visibly incomplete partial
bundle, but MUST NOT count as complete. Missing required evidence, drift, or
ambiguity MUST remain explicit and MUST NOT be converted into reassuring
inference.

The run MUST select performance case `T1-EWIR-001` and retain only bounded,
content-free timing, provider, risk, capability, native implementation, call,
retry, interaction, and outcome evidence. Provider bodies, identifiers, URLs,
credentials, environment values, local paths, and exception text MUST NOT enter
audit or performance evidence. A normal successful run MUST require zero
governance or effect-approval interactions and initialize or resolve credentials
for no unselected provider.

## Rationale

One exact cross-system engineering review proves useful native orchestration and
failure honesty without introducing provider effects, dynamic search breadth,
or a second runtime framework.

## Scenarios

### Exact protected fixture succeeds

- GIVEN an admitted profile selects exact Jira, Bitbucket, and Confluence fixture scope
- WHEN the high-level review command runs
- THEN every selected read is independently verified and the three-file cited bundle is digest verified

### Retrieved prose cannot broaden scope

- GIVEN Jira or Confluence content names another tenant, repository, credential, implementation, or target
- WHEN relations and findings are produced
- THEN the immutable trusted targets remain unchanged and the unapproved content grants no authority

### Pull-request head changes during verification

- GIVEN build evidence was read for one PR head
- WHEN the verification read observes another head or status set
- THEN build evidence is stale or indeterminate and the bundle is not complete

### Optional page is unavailable

- GIVEN core Jira and Bitbucket evidence verifies but one configured Confluence page does not
- WHEN the renderer publishes its bounded result
- THEN status is partial, the missing stage is explicit, and no page facts are inferred

### Existing Jira and build callers remain compatible

- GIVEN an existing `jira.issue.read` or commit-based Bitbucket build-status action
- WHEN it executes after this change
- THEN its existing schema and target behavior remain valid

## Implementation

- `src/master_agent/connectors/jira.py`
- `src/master_agent/connectors/bitbucket.py`
- `src/master_agent/workflows/engineering_work_item_review.py`
- `src/master_agent/cli.py`
- `src/master_agent/operating.py`
- `src/master_agent/config.py`
- `config/capabilities.toml`
- `src/master_agent/defaults/capabilities.toml`

## Verification

- `tests/test_atlassian_connectors.py`
- `tests/test_engineering_work_item_review.py`
- `tests/test_operating_modes.py`
- `tests/test_connector_contract_matrix.py`
- `tests/test_performance.py`

## History

- Introduced by GitHub issue #175 from the accepted plan in issue #171.
