# Requirement deltas

## ADDED

### MA-WINDOWS-CAPSULES-001 — Native Windows capability capsule isolation

Add native Windows AppContainer isolation for dependency-free pure capsule
workers, including default-denied network and host access, one private writable
directory, Job Object quotas, typed protocol-only communication, exact identity
binding, adversarial probes, and fail-closed provider/side-effect behavior.

## MODIFIED

### MA-PLATFORM-001 — Platform runtime contracts

Permit native Windows to advertise `capsule_isolation` only when the
AppContainer and Job Object backend is fully available and native standard-user
evidence passes. Keep Linux bubblewrap and macOS behavior unchanged.

### MA-CAPABILITY-IMPORT-001 — Governed custom-agent capability import

Require promotion and activation worker identity to bind the selected native
isolation backend plus the exact security-relevant runtime, interpreter, and
worker artifacts, with component identity included in signed evidence.

## REMOVED

None.
