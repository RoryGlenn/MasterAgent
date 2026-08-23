# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-LIVE-INTEGRATION-001 — Protected credentialed integration evidence

When the protected read matrix selects an authenticated managed-network
profile, the workflow MUST map its fixed proxy username and password broker
references from dedicated `connector-integration-read` environment secrets
only for the live read harness. Those privilege-specific secrets MUST NOT be
available to effect or administration jobs, and missing proxy setup MUST remain
a visible incomplete-integration result rather than falling back to direct or
ambient networking.

The repository MUST statically verify the exact protected proxy secret mapping
and its absence from other privilege zones.

## REMOVED

None.
