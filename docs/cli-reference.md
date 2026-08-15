# CLI Reference

`master-agent COMMAND --help` is the exact argument reference. The table below
documents every public command and, critically, whether it can perform network
or filesystem side effects.

| Command | Purpose | Side-effect boundary |
|---|---|---|
| `demo` | Run the credential-free Phase 3 demonstration | Creates a fresh private local workspace; no provider access |
| `sample-plan` | Write a synthetic weekly-status plan | Writes only the selected local JSON output |
| `inspect` | Validate and display a plan and fingerprint | Read-only local inspection |
| `bind-context` | Bind reviewed config, paths, connector identities, and gates into a plan | Writes the bound plan; live GitHub binding performs `GET /user`, while other supported identities are derived without provider mutation |
| `approve` | Sign selected action IDs for an exact plan fingerprint | Writes a local approval artifact; performs no provider request |
| `run` | Evaluate a plan or execute an approved, manifest-bound plan | No provider side effect without `--apply`; live apply is governed by every catalog, policy, approval, connector, and runtime gate |
| `plugins` | Inventory connector entry-point metadata without importing plugin code | Optional local JSON output; never executes plugin code |
| `readiness` | Validate governance, configuration, OAuth, permissions, and implemented production adapters | Offline; optional local JSON output |
| `oauth-device-code` | Run an enabled Microsoft delegated device-code flow | Performs Microsoft authentication requests and writes a mode-`0600` token file |
| `draft-package` | Generate the Phase 3 review package | Local create-only artifacts and audit state; no provider access |
| `compensation-plan` | Build a separately reviewable compensation plan from an original plan and run report | Writes only the selected local plan |
| `recurring-status` | Inspect registered schedules and due state | No provider access; may mark expired claims in an existing configured SQLite state database and can write optional local JSON output |
| `recurring-run` | Reserved recurring execution entry point | Disabled before config, credentials, connectors, or audit access |
| `discover` | Inspect connector configuration | Offline unless `--probe`; probing performs bounded read-only provider requests |
| `weekly-status-plan` | Build a read-only weekly-status plan | Writes only the selected local plan |
| `weekly-status` | Reserved direct weekly-status package entry point | Disabled before config, credentials, connectors, or audit access |
| `identity-resolve` | Resolve a configured person or provider identifier | Local identity-map read; optional local JSON output |
| `retain-evidence` | Persist evidence under the selected retention rule | Local create-only evidence and sidecar output; never contacts a provider |
| `evidence-prune` | Preview expired evidence | Read-only preview; `--apply` is disabled before traversal or deletion |
| `citations` | Extract resource citations from a result JSON file | Read-only local extraction; optional local JSON output |
| `communication-context-plan` | Build a read-only Outlook/Teams context plan | Writes only the selected local plan |
| `communication-context` | Reserved direct communication-context package entry point | Disabled before config, credentials, connectors, or audit access |
| `scan` | Scan supplied text or a local file for prompt-injection indicators | Local read/analysis only |
| `audit-verify` | Verify an existing SQLite audit hash chain | Read-only verification; missing or malformed state is rejected without creation |

Connector-aware `readiness`, `discover`, `bind-context`, and applied `run`
commands accept `--credentials-file /absolute/path/credentials.json` in a
development governance profile. Policy-only `run` commands do not read secrets.
The selected canonical path is part of the bound execution context.

## Configuration behavior

Commands that accept configuration paths use an explicit path first and the
wheel-packaged safe default otherwise. They never load configuration from the
current working directory implicitly. Explicit configuration and runtime paths
must satisfy the ownership, permission, and identity checks described in
[`configuration.md`](configuration.md).

Provider mutation is available only through an exact, manifest-bound
`run --apply`. The direct workflow commands retained for compatibility do not
offer an alternate execution path.
