# Integration Matrix

| System | Deployment/auth modes | Read-only | Draft/local | Approved mutation | Compensation/verification | Default |
|---|---|---|---|---|---|---|
| Jira | Cloud basic/API token; Data Center bearer/basic | server info, search, issue read | update/comment/transition proposal | field update, comment, transition | independent read; restore fields; delete created comment; configured reverse transition | disabled |
| Confluence | Cloud basic/API token; Data Center bearer/basic | page search/read | create/update proposal | create Cloud space; create/update page | exact space/page read; remove created space/page; restore prior page version/body | disabled |
| Bitbucket | Cloud token/basic or bearer; Data Center PAT/bearer | repository, PR, diffstat/changes, build status | branch/patch plan | create PR; local-Git branch publication disabled | verify exact PR; decline created PR | disabled |
| GitHub | Cloud anonymous public reads or bearer token with provider-verified numeric-user attestation | public-user and authenticated-user repository lists, repository read, PR search/read, commit check runs | — | issue/PR create; allowlisted repository settings; existing-collaborator built-in role | anonymous route omits credentials; authenticated principal check; exact post-write re-read; close/restore compensation where safe | disabled |
| Microsoft identity | delegated or explicit application user | current/explicit user and directory search | — | — | normalized identity/citation | disabled |
| Outlook | Microsoft Graph delegated by default | folders, message search/read, attachment metadata, allowlisted UTF-8 text | `.eml` | send | create provider draft, re-read exact content, then send; non-reversible | disabled |
| Teams | Microsoft Graph delegated for normal sends | chats, teams, channels, messages, replies | Markdown message draft | chat/channel send; channel reply | re-read created message; non-reversible | disabled |
| SharePoint/OneDrive | Microsoft Graph delegated/application subject to policy | site/drive/item/folder/text | local artifact | bounded small-file upload | hash exact prior/uploaded/restored provider bytes; restore previous version | disabled |
| OneNote | Microsoft Graph delegated | notebooks, sections, pages, page content | HTML/proposal | disabled pending exact DOM proof | read content is re-read; no write connector is registered | disabled |
| PowerPoint | local `python-pptx` | — | `.pptx` generation | upload through SharePoint only | local file digest; SharePoint version verification after upload | available locally |
| Git workspace | local Git identity | repository preconditions | branch and patch plan | disabled until every metadata transaction is descriptor-bound | no live mutation connector is registered | unavailable |
| Connector plugin | metadata-only entry-point inventory | — | — | disabled | future isolated-worker contract | never executed |

## Hard exclusions

- Bitbucket pull-request merge is catalogued but disabled.
- GitHub exposes no generic HTTP, merge, delete, invite, custom-role, secret,
  or branch-protection capability. Its existing-collaborator role update is a
  separately gated, dual-approved exception to the general permission ban.
- No other connector exposes permission modification.
- No generic arbitrary HTTP connector exists.
- No arbitrary shell capability exists.
- No force push or protected-branch write exists.
- No standalone destructive Git worktree restore exists.
- No local Git patch, branch, commit, or push mutation is routable.
- Teams application permissions are not used for ordinary message sending.
- OneNote read connectors require delegated identity; write capabilities remain disabled.

## Provider-specific activation

A connector's `enabled = true` is not enough. Mutation and communication require the runtime flag plus the generic and granular provider flags documented in [`configuration.md`](configuration.md).
