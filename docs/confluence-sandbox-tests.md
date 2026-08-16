# Confluence Cloud sandbox tests

The opt-in workflow at
[`confluence-sandbox.yml`](../.github/workflows/confluence-sandbox.yml)
supplements the required per-pull-request scripted tests with a live check
against one dedicated, non-production Confluence Cloud tenant. It proves the
real connection, policy, authenticated approval, create, independent read,
versioned update, exact verification, compensation, and fresh cleanup paths.
It must never target a production tenant.

The workflow has only `workflow_dispatch` and a controlled weekly schedule. It
does not run on `pull_request` or `pull_request_target`, every job is pinned to
the repository's default branch, checkout credentials are not retained, and
workflow permissions are `contents: read`. Keep the ordinary scripted suite as
the required PR gate; do not make this secret-dependent workflow a prerequisite
for contributors who cannot access the sandbox.

## Provider setup

Create a separate Atlassian tenant used only for automated testing. Create a
dedicated page-test identity with product access and only the permissions needed
to view the pre-provisioned test space and create, edit, read, and remove its own
test pages. Do not grant site administration, user administration, permission
management, production-space access, or unrelated application access.

The optional space lifecycle uses a second identity. Give that identity only
the tenant permissions needed to create a space, administer that newly created
space, and remove it. Do not reuse the higher-privilege space identity for the
normal page job. The Cloud page calls and deletion behavior follow Atlassian's
[Confluence Cloud page API](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/);
the optional space calls use the documented
[Confluence Cloud space API](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-space/).

Create two protected GitHub environments:

- `confluence-sandbox` for the page lifecycle and stale-page preview. Restrict
  deployments to the default branch and limit who may change its variables or
  secrets.
- `confluence-space-sandbox` for the optional space lifecycle. Restrict it to
  the default branch, use required reviewers, and limit administrators. This
  environment holds a separate, more privileged identity.

If required reviewers are enabled on `confluence-sandbox`, scheduled runs will
wait for deployment approval. That is valid, but it means the weekly check is
not unattended.

Set the repository-level variable `CONFLUENCE_SANDBOX_ENABLED=true` only when
the page environment is fully configured. Until then, scheduled page and reaper
jobs are skipped, so merging this workflow does not create failing secretless
runs. Remove or set this variable to `false` for an immediate operational kill
switch.

## Page environment configuration

Set these environment variables on `confluence-sandbox`:

| Variable | Required value |
|---|---|
| `CONFLUENCE_SANDBOX_ORIGIN` | Exact tenant origin, for example `https://sandbox-name.atlassian.net` |
| `CONFLUENCE_SANDBOX_ALLOWED_ORIGIN` | The same independently reviewed exact origin |
| `CONFLUENCE_SANDBOX_NON_PRODUCTION` | Literal `true` after an administrator confirms the tenant is non-production |
| `CONFLUENCE_SANDBOX_SPACE_ID` | Provider ID of the pre-provisioned disposable-page space |
| `CONFLUENCE_SANDBOX_SPACE_KEY` | Exact key of that same space |
| `CONFLUENCE_SANDBOX_PARENT_ID` | Optional exact parent page ID; leave empty to verify a root page |
| `CONFLUENCE_SANDBOX_ENABLE_STALE_DELETE` | Literal `true` only after the deletion mode has been reviewed; preview does not require it |

Set these environment secrets:

| Secret | Purpose |
|---|---|
| `CONFLUENCE_SANDBOX_EMAIL` | Dedicated page-test identity email |
| `CONFLUENCE_SANDBOX_API_TOKEN` | API token for that identity |
| `CONFLUENCE_SANDBOX_APPROVAL_SECRET` | At least 32 random bytes used only by the test-only authenticated approval signer |
| `CONFLUENCE_SANDBOX_OWNERSHIP_KEY` | A different value of at least 32 random bytes used to authenticate cleanup markers |

The approval secret and ownership key must be independently generated. They
serve different trust boundaries and must not equal the Atlassian API token.
For example, generate each value independently with an approved secret manager
or `openssl rand -hex 32`, then store it directly as an environment secret.

## Optional space environment

Set the same origin, allowlist, and non-production variables on
`confluence-space-sandbox`, plus
`CONFLUENCE_SANDBOX_ENABLE_SPACE_LIFECYCLE=true`. Store the separate identity
and separate keys under these secret names:

- `CONFLUENCE_SPACE_SANDBOX_EMAIL`
- `CONFLUENCE_SPACE_SANDBOX_API_TOKEN`
- `CONFLUENCE_SPACE_SANDBOX_APPROVAL_SECRET`
- `CONFLUENCE_SPACE_SANDBOX_OWNERSHIP_KEY`

The space job runs only on a manual dispatch whose `run_space_lifecycle` input
is selected. It creates a collision-resistant alphanumeric space key, verifies
the exact space identity, creates and verifies one disposable page, removes the
page, confirms its terminal provider state, checks that no page other than the
provider-created homepage remains, deletes the exact space, and confirms a
fresh not-found response. A gate value other than literal `true` fails the
requested job.

## Invocation and expected output

Open **Actions -> Confluence Cloud sandbox -> Run workflow** on the default
branch.

- Leave both optional inputs off for the normal page lifecycle.
- Choose `preview` to list at most five stale, exact-marker page candidates
  without deleting them.
- Choose `delete` only after reviewing a preview and enabling
  `CONFLUENCE_SANDBOX_ENABLE_STALE_DELETE`.
- Select `run_space_lifecycle` only when the separately protected space test is
  intended.

The scheduled run executes the page lifecycle and a preview-only stale-page
scan. Workflow concurrency admits only one sandbox workflow at a time. Page
jobs time out after 20 minutes, the optional space job after 25 minutes, and
the reaper after 10 minutes. Connector calls use a 15-second request timeout,
one-megabyte response bound, at most five returned items, bounded pagination,
and the runtime's bounded GET retry policy. Provider mutations are never
retried automatically.

A successful page run reports only the safe provider page ID. Its `always()`
cleanup step reports that ID and a credential-free provider reference after a
fresh observation proves the page is absent or trashed. Cleanup failure fails
the job. The optional space job behaves the same way for the page and space IDs.

No workflow artifact is uploaded. Private plans, approval requests, audit
metadata, command logs, credentials, and safe state files exist only under a
mode-0700 directory in `RUNNER_TEMP` for the life of the hosted runner. The API
token is written only to the normal mode-0600 MasterAgent credential-store
schema. Provider-returned page bodies remain in memory; they are not written to
run reports or logs. The immutable plans contain only the fixed benign test
body generated by the harness, never tenant content.

## What the harness proves

Before credentials are made available to the harness or any provider request
is attempted, the standard-library preflight rejects an absent origin, HTTP,
userinfo, ports, UI paths, queries, fragments, non-`atlassian.net` hosts,
placeholder hosts, an allowlist mismatch, or a missing non-production
attestation.

For every write the harness:

1. uses `master-agent connect` for the normal bounded read probe;
2. binds the live connector, restricted credential file, audit path, write
   enablement, policy sources, and approval-authority file into the plan;
3. calls `run --apply` without approval and requires the approval-required exit
   status, proving that the side effect did not run;
4. exercises `inspect-approval-request` while discarding its rendered benign
   body rather than retaining it in a log;
5. signs the exact request with the protected `sandbox_ci` authority through
   `approve-request` and resumes only that captured invocation with
   `resume-approval`; and
6. independently finds and reads the created resource, then uses the connector's
   exact verifier for title, body, representation, space, parent, status, and
   version.

Conversational text is never interpreted as approval. The signer secret is
available only inside the protected environment and every approval expires
after ten minutes.

Each page title includes a random 128-bit marker. Its fixed benign body carries
the marker, UTC creation time, phase, and an HMAC-SHA-256 ownership tag bound to
the exact origin and space ID. Cleanup accepts only version 1/create or version
2/update content with the exact expected body, placement, status, and marker.
It performs another provider read immediately before compensation, so a human
edit, move, publication-state change, version change, marker forgery, or target
drift makes deletion fail closed.

## Stale cleanup and recovery

The reaper always previews before it acts. It searches only the configured
pre-provisioned space, examines at most five matching titles, and accepts a page
only when the title and full benign body are exact, the HMAC marker authenticates,
the provider and signed creation timestamps are at least 24 hours old, the
space/status/version are exact, and a final fresh connector verification still
matches. Deletion then uses created-resource compensation and a fresh provider
lifecycle read. Human-created pages and lookalike titles cannot pass these
checks. Its prefix search uses Atlassian's documented bounded
[CQL wildcard syntax](https://developer.atlassian.com/cloud/confluence/advanced-searching-using-cql/),
then applies the stricter local checks before any candidate can be deleted.

Normal and optional-space jobs set an uncertainty flag immediately before a
create resume. If the provider call fails after the effect may have begun but
before a safe ID is recorded, the `always()` cleanup performs up to three
bounded exact-title searches and removes only the authenticated match. If an
owned page survives because the hosted runner was terminated, use a preview
after the 24-hour threshold and then a separately enabled delete dispatch.

If optional space cleanup fails, do not delete a space merely because its key
starts with `MAS`. Review the safe space ID/key from the failed job, confirm the
full authenticated name from the run's plan, inspect that the space contains no
human content, and use the tenant's normal administrator recovery process. The
harness intentionally refuses to delete a created space that contains any page
other than its homepage.

## Rotation and revocation

Rotate the Atlassian token, approval secret, and ownership key independently.
Revoke the API token immediately if a runner or environment is suspected to be
compromised, remove the identity's product access, and disable both lifecycle
gate variables. Rotating the approval secret invalidates future signing; it
does not authenticate stale ownership markers. Rotating the ownership key
means the automated reaper will deliberately stop recognizing pages created
under the prior key, so preview and clean those pages first or recover them
manually by exact provider ID.

After any rotation, run the page lifecycle manually and verify its cleanup
before restoring the schedule. Review environment access and the test identity's
tenant permissions regularly, and delete the identity entirely when the live
sandbox suite is retired.
