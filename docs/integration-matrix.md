# Integration Matrix

| System | Deployment/auth modes | Read-only | Draft/local | Approved mutation | Compensation/verification | Default |
|---|---|---|---|---|---|---|
| Jira | Cloud basic/API token; Data Center bearer/basic | server info, search, issue read | update/comment/transition proposal | field update, comment, transition | independent read; restore fields; delete created comment; configured reverse transition | disabled |
| Confluence | Cloud basic/API token; Data Center bearer/basic | page search/read | create/update proposal | create/update page | version check; independent read; restore prior version/body or remove created page | disabled |
| Bitbucket | Cloud token/basic or bearer; Data Center PAT/bearer | repository, PR, diffstat/changes, build status | branch/patch plan | publish new agent branch; create PR | verify exact ref/PR; delete unchanged new ref; decline created PR | disabled |
| Microsoft identity | delegated or explicit application user | current/explicit user and directory search | — | — | normalized identity/citation | disabled |
| Outlook | Microsoft Graph delegated by default | folders, message search/read, attachment metadata, allowlisted UTF-8 text | `.eml` | send | create provider draft, re-read exact content, then send; non-reversible | disabled |
| Teams | Microsoft Graph delegated for normal sends | chats, teams, channels, messages, replies | Markdown message draft | chat/channel send; channel reply | re-read created message; non-reversible | disabled |
| SharePoint/OneDrive | Microsoft Graph delegated/application subject to policy | site/drive/item/folder/text | local artifact | bounded small-file upload | hash exact prior/uploaded/restored provider bytes; restore previous version | disabled |
| OneNote | Microsoft Graph delegated | notebooks, sections, pages, page content | HTML/proposal | disabled pending exact DOM proof | read content is re-read; no write connector is registered | disabled |
| PowerPoint | local `python-pptx` | — | `.pptx` generation | upload through SharePoint only | local file digest; SharePoint version verification after upload | available locally |
| Git workspace | local Git identity | repository preconditions | branch and patch plan | apply patch, create branch/commit, push | exact HEAD/ref checks; connector-managed reverse patch and compare-and-swap local ref rollback; remote push recovery is manual; no standalone worktree restore | requires explicit workspace root |
| Connector plugin | metadata-only entry-point inventory | — | — | disabled | future isolated-worker contract | never executed |

## Hard exclusions

- Bitbucket pull-request merge is catalogued but disabled.
- No connector exposes permission modification.
- No generic arbitrary HTTP connector exists.
- No arbitrary shell capability exists.
- No force push or protected-branch write exists.
- No standalone destructive Git worktree restore exists.
- Teams application permissions are not used for ordinary message sending.
- OneNote read connectors require delegated identity; write capabilities remain disabled.

## Provider-specific activation

A connector's `enabled = true` is not enough. Mutation and communication require the runtime flag plus the generic and granular provider flags documented in [`configuration.md`](configuration.md).
