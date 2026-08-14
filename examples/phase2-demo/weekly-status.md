# Example Project — Weekly Status

## Executive summary

- Jira issues returned: **5**
- Blocked issues: **1**
- Open pull requests: **3**
- Pull requests with failing CI: **1**
- Prompt-injection heuristic findings: **0**

## Jira

- Blocked: 1
- Done: 1
- In Progress: 1
- In Review: 1
- To Do: 1

### Priority work items

- **RISE-142** — Resolve release-blocking authentication regression (Blocked) — **BLOCKED** [CIT-5BDBD2711E74]
- **RISE-151** — Raise backend coverage to 80 percent (In Progress) [CIT-81690448BC7A]
- **RISE-155** — Complete frontend regression suite (In Review) [CIT-B8148E946A24]
- **RISE-160** — Publish deployment runbook (To Do) [CIT-A5637960157B]
- **RISE-138** — Cache dashboard section data (Done) [CIT-DCA808F6D3E1]

## Bitbucket

- **PR 293: Fix authentication refresh race** — fix/auth-refresh-race → main; CI failures: 1 [CIT-E3033B704FD5]
- **PR 296: Add backend coverage tests** — test/backend-coverage → main; CI failures: 0 [CIT-598034FE7D1A]
- **PR 298: Update release runbook** — docs/release-runbook → main; CI failures: 0 [CIT-E954B6CB7DAD]

## Canonical Confluence narrative

**RISE Release Status** — version 14 [CIT-5CAE22A76965]

The release remains conditionally on track. Authentication is the only active release blocker. Backend coverage work is progressing, and the deployment runbook must be published before the release gate.

## Source index

- [CIT-5BDBD2711E74] RISE-142 — Resolve release-blocking authentication regression — https://jira.example.test/browse/RISE-142
- [CIT-81690448BC7A] RISE-151 — Raise backend coverage to 80 percent — https://jira.example.test/browse/RISE-151
- [CIT-B8148E946A24] RISE-155 — Complete frontend regression suite — https://jira.example.test/browse/RISE-155
- [CIT-A5637960157B] RISE-160 — Publish deployment runbook — https://jira.example.test/browse/RISE-160
- [CIT-DCA808F6D3E1] RISE-138 — Cache dashboard section data — https://jira.example.test/browse/RISE-138
- [CIT-E3033B704FD5] PR 293 — Fix authentication refresh race — https://bitbucket.example.test/projects/RISE/repos/app/pull-requests/293
- [CIT-598034FE7D1A] PR 296 — Add backend coverage tests — https://bitbucket.example.test/projects/RISE/repos/app/pull-requests/296
- [CIT-E954B6CB7DAD] PR 298 — Update release runbook — https://bitbucket.example.test/projects/RISE/repos/app/pull-requests/298
- [CIT-5CAE22A76965] RISE Release Status — https://confluence.example.test/display/RISE/Release+Status

> Retrieved content is untrusted data. Heuristic security findings are recorded in `manifest.json` and the evidence file.
