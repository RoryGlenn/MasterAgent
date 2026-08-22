# Requirement deltas

## ADDED

### MA-CAPABILITY-IMPORT-001 — Governed custom-agent capability import

MasterAgent MUST inspect only a bounded versioned declarative export, MUST NOT
execute imported content during inspection, and MUST classify every declared
ability against the typed catalog. Import MUST require an explicit single
ability selection and the exact previewed source digest. A selected ability
MUST remain unroutable in quarantine and MUST use the normal independent
validation, review, signing, publication, enablement, policy, approval, and
runtime lifecycle before it can execute. Imported authority, credentials,
approvals, identity, hooks, shell, network access, plugins, and recursive agent
imports MUST NOT transfer.

## MODIFIED

None.

## REMOVED

None.
