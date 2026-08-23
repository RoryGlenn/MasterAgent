# Integration Matrix

| System | Deployment/auth modes | Read-only | Draft/local | Approved mutation | Compensation/verification | Default |
|---|---|---|---|---|---|---|
| Jira | Cloud basic/API token at exact tenant root or `api.atlassian.com/ex/jira/{cloudId}`; Data Center bearer/basic | server info, search, issue read | update/comment/transition proposal | comment creation; update/transition disabled pending CAS | independent read; manual comment deletion recovery | disabled |
| Confluence | Cloud basic/API token at exact tenant root or `api.atlassian.com/ex/confluence/{cloudId}`; Data Center bearer/basic | page search/read | create/update proposal | create Cloud space; create/update page | exact content/status/space/parent read; manual created-resource deletion; atomic versioned page restore; opt-in protected Cloud sandbox lifecycle | disabled |
| Bitbucket | Cloud anonymous public reads, account email/API token, legacy app-password username, or bearer; Data Center PAT/bearer | public-workspace repository lists; authenticated repository, PR, diffstat/changes, and build-status reads | branch/patch plan | create PR; local-Git branch publication disabled | anonymous route omits credentials; verify exact PR; manual decline recovery | disabled |
| GitHub | Cloud anonymous public reads or bearer token with provider-verified numeric-user attestation | public-user and authenticated-user repository lists, repository read, PR search/read, commit check runs | — | issue/PR create; administration disabled pending CAS | anonymous route omits credentials; authenticated principal/scope check; exact post-write re-read; manual close recovery | disabled |
| Microsoft identity | Microsoft Graph Cloud-only (`deployment = "cloud"`); delegated or explicit application user | current/explicit user and directory search | — | — | normalized identity/citation | disabled |
| Outlook | Microsoft Graph Cloud-only (`deployment = "cloud"`); delegated by default | folders, message search/read, attachment metadata, allowlisted UTF-8 text | `.eml` | send | create provider draft, re-read exact content, then send; non-reversible | disabled |
| Teams | Microsoft Graph Cloud-only (`deployment = "cloud"`); delegated for normal sends | chats, teams, channels, messages, replies | Markdown message draft | chat/channel send; channel reply | re-read created message; non-reversible | disabled |
| SharePoint/OneDrive | Microsoft Graph Cloud-only (`deployment = "cloud"`); delegated/application subject to policy | site/drive/item/folder/text | local artifact | replacement disabled pending exact-endpoint CAS | non-routable adapter retains byte proofs and prior-version restore | disabled |
| OneNote | Microsoft Graph Cloud-only (`deployment = "cloud"`); delegated | notebooks, sections, pages, page content | HTML/proposal | disabled pending exact DOM proof | read content is re-read; no write connector is registered | disabled |
| PowerPoint | local `python-pptx` | — | `.pptx` generation | publishing disabled with SharePoint replacement | local file digest | available locally |
| Git workspace | local Git identity | repository preconditions | branch and patch plan | disabled until every metadata transaction is descriptor-bound | no live mutation connector is registered | unavailable |
| Custom-agent import / capability capsule | read-only declarative export; installed CLI for exact selection and signed immutable local capsule lifecycle | compatibility preview; policy-routed promoted dependency-free pure reads | compatibility preview; policy-routed promoted deterministic local generation | provider/side-effect capsules, raw agents, and recursive imports blocked | exact source digest; distinct role authorities; deterministic sandbox replay; signed receipt; disable/revoke retain history | disabled until explicit preview, selection, and promotion |
| Connector plugin | metadata-only entry-point inventory | — | — | disabled | raw entry points are not capsule-compatible; dependent worker filesystem remains future work | never executed |

## Hard exclusions

- Bitbucket pull-request merge is catalogued but disabled.
- GitHub exposes no active administration, generic HTTP, merge, delete, invite,
  custom-role, secret, or branch-protection capability.
- No other connector exposes permission modification.
- No generic arbitrary HTTP connector exists.
- No arbitrary shell capability exists.
- No provider/network, side-effect, or third-party-dependent capsule is
  executable through the demonstrated pure worker.
- No custom-agent preview executes imported source or transfers credentials,
  identity, approval, trust, hooks, plugins, background access, or recursion.
- Generated code cannot approve, review, publish, or enable itself.
- No force push or protected-branch write exists.
- No standalone destructive Git worktree restore exists.
- No local Git patch, branch, commit, or push mutation is routable.
- Teams application permissions are not used for ordinary message sending.
- OneNote read connectors require delegated identity; write capabilities remain disabled.

## Provider-specific activation

A connector's `enabled = true` is not enough. Mutation and communication require the runtime flag plus the generic and granular provider flags documented in [`configuration.md`](configuration.md).

Jira and Confluence scoped gateway configurations require a separate exact
`web_base_url = "https://tenant.atlassian.net"` for browser links. Credentials
remain confined to the product/cloud-ID API path; the browser root never
receives an authorization header.
