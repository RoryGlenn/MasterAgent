# Windows 11 x64 release certification

This gate answers one narrow release question: does the exact reviewed
default-branch commit still work on a clean, ordinary-user Windows 11 x64
machine? Hosted Windows 11 ARM pull-request jobs provide fast compatibility
evidence; they do not replace this protected release gate.

## What the repository enforces

The `Windows 11 x64 release certification` workflow has two trust zones:

1. A GitHub-hosted authorization job performs no checkout. It accepts only a
   successful CI push for the current default-branch head, or a manual dispatch
   from that same branch, and verifies through the GitHub API that the branch is
   protected and the selected 40-character commit is its current head.
2. The reviewed environment may then dispatch that exact commit to a runner
   labeled `self-hosted`, `Windows`, `X64`, and
   `masteragent-windows-11-x64`. Before checkout, the runner rejects Windows
   Server, pre-Windows-11 builds, non-x64 execution, administrator membership,
   disabled long paths, and named production credential variables.

The protected job checks out the exact authorized SHA with read-only,
non-persisted credentials. It builds and installs the wheel and source
distribution outside the checkout, runs the complete native test suite plus
specification and release validation, and removes its bounded work products.
It never has a pull-request trigger, never references repository secrets, and
never uploads the runner's filesystem state.

## Adversarial evidence groups

The repository binds 52 Windows security invariants to exact test IDs in
`tests/windows_adversarial_matrix.json`. The registry separates two groups:

- `hosted` contains policy and contract attacks that are safe on a GitHub-
  hosted pull-request runner; and
- `certification` contains native filesystem, process, Git, AppContainer, and
  managed-workstation attacks that must run inside the reviewed Windows 11 x64
  environment under its non-administrator account.

The workflow invokes `scripts/run_windows_adversarial.py` for each group. The
runner validates the complete invariant set and exact test IDs before running
anything. Every active test method also declares its exact stable reason set;
the runner captures that binding when the test starts and compares it with the
matrix. A missing, renamed, failed, errored, skipped, or reason-mismatched
required test makes the group fail. Ordinary `unittest` skip semantics
therefore cannot turn missing native evidence into successful certification.

The matrix also records stable content-free failure reasons and links
equivalent POSIX evidence where useful. It never stores workstation paths,
security identifiers (SIDs), credentials, proxy details, or native diagnostic
text.

Six managed-workstation entries are explicit blockers until their owning
features or evidence are complete: Defender/Controlled Folder Access and
AppLocker/WDAC remain blocked on #107 until real managed-host fixtures replace
mocked error injection; organization ACL inheritance and approved support or
endpoint-detection-and-response (EDR) principals depend on #111; authenticated
proxy and enterprise certificate-authority behavior depend on #112. The
certification runner reports those issue numbers and fails. Do not remove,
skip, or relabel those entries to obtain a green run.

## Provision the external runner

Use a dedicated disposable Windows 11 Pro or Enterprise x64 virtual machine,
not a developer workstation and not Windows Server. The machine must use a
local NTFS or ReFS volume, enable Windows long paths, and install current Git
for Windows plus the GitHub Actions runner prerequisites. Do not install
production connector credentials, organization profiles, signing keys, or
audit data.

Create a dedicated local service account and keep it out of the local
Administrators group. Register the Actions runner from the repository's
**Settings → Actions → Runners** page with these properties:

- repository scope;
- default `self-hosted`, `Windows`, and `X64` labels;
- custom `masteragent-windows-11-x64` label;
- ephemeral, one-job enrollment; and
- execution as the dedicated non-administrator account.

Registration tokens and the service-account password are short-lived/private
operator inputs. Supply them through the VM provisioning system or the
runner's interactive setup; never place them in a command transcript,
workflow, repository file, image, or reusable script. Start each certification
from a clean image and destroy or reimage the VM after the job. A runner that
has processed another repository or an untrusted workload is not eligible.

GitHub's official runner documentation defines the current enrollment and
ephemeral-runner procedure:

- <https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/adding-self-hosted-runners>
- <https://docs.github.com/en/actions/reference/runners/self-hosted-runners>

## Configure repository protections

Before enabling the workflow:

1. Protect the repository's default branch against deletion and non-fast-
   forward updates. The workflow's authorization job checks GitHub's live
   `protected` state before any repository checkout.
2. Create the `windows-11-certification` environment. Require a reviewer and
   allow deployments only from the protected default branch.
3. Confirm exactly one clean eligible runner is online with all four required
   labels.
4. Confirm the adversarial matrix has no dependency-blocked certification
   entry and that the managed image supplies the documented ACL, cloud-path,
   endpoint-security, application-control, network, and contention fixtures.
5. Set the repository variable
   `MASTER_AGENT_WINDOWS_CERTIFICATION_ENABLED` to `true` only while that
   infrastructure remains healthy.

The variable is a dispatch switch, not certification evidence. If protection,
the runner, or clean-image controls lapse, set it back to `false` immediately.

## Run and verify certification

First require a successful `CI` run for the current default-branch SHA. The
protected workflow normally follows that push automatically. An authorized
maintainer may also dispatch `windows-certification.yml` from the default
branch; the workflow still rejects a stale or unprotected commit.

A release may claim native Windows support only when all of these refer to the
same commit:

- required pull-request/default-branch CI, including Windows 11 ARM on Python
  3.12, 3.13, and 3.14;
- the protected `Standard-user Windows 11 x64 release gate` job;
- wheel and source-distribution installation outside checkout; and
- the archived behavioral specification and release-validation result.

Record the workflow URL, exact commit SHA, runner image identifier, and image
provisioning revision in the private release record. Do not commit registration
tokens, account credentials, machine inventories, or private runner logs.

## Failure and recovery

- **Workflow skipped:** the enable variable is false or the event is not an
  eligible default-branch event. This is not certification.
- **Authorization failed before checkout:** restore branch protection, wait for
  CI on the current head, and dispatch that head. Do not override the SHA.
- **Job remains queued:** no eligible labeled runner is online. Provision a
  clean ephemeral VM; do not weaken the labels.
- **Host verification failed:** fix or replace the VM. Do not add an exception
  for administrator, Server, architecture, long-path, or credential checks.
- **Test or artifact failure:** treat it as a release blocker, preserve only
  secret-free logs needed for diagnosis, destroy the VM, fix through a pull
  request, and rerun on a fresh image.
- **Adversarial dependency blocked:** complete the referenced issue and replace
  its blocked registry entry with an exact passing managed-host test. A blocked
  entry is not a waiver and cannot be counted as certification.
- **Required adversarial test skipped:** repair the host prerequisite or test;
  never convert the case to optional or invoke ordinary discovery as a bypass.
