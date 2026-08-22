# Requirement deltas

## ADDED

None.

## MODIFIED

### MA-PLATFORM-001 — Platform runtime contracts

Linux MAY advertise the certified bubblewrap capsule-isolation backend only
after selecting a trusted absolute executable. Missing, relative, or unsafe
executables MUST report the contract unavailable with a bounded secret-free
reason. Status and worker execution MUST apply the same ownership, link,
permission, and executability trust conditions and use the same selected path.

## REMOVED

None.
