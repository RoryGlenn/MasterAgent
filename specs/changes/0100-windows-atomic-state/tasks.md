# Tasks

- [x] Extend the typed atomic-publication contract and implement protected
  Windows directory, lock, file, replace, delete, flush, ledger, and recovery
  primitives.
- [x] Advertise the native Windows atomic backend only after its bounded probes
  succeed, while preserving the remaining unavailable contracts.
- [x] Port SQLite create/read/update/recover/remove and audit/recurring callers
  to the Windows state transaction.
- [x] Port approval/readiness output, configuration, credential, OAuth,
  advisory, capsule, plugin, and draft persistence without POSIX fallback.
- [x] Port retained publication, preview/apply, repair, quarantine, and pair
  recovery to native Windows identity-bound transactions.
- [x] Add pure interruption, race, bound, redaction, and concurrency tests plus
  native Windows 11 standard-user persistence coverage.
- [x] Update semantic ownership, platform/runtime/retention specifications,
  architecture, operations, threat model, roadmap, release, and changelog
  documentation.
- [ ] Run focused/full tests, Ruff, mypy, specification, semantic, release,
  installed-artifact, native Windows, and immutable-range security validation.
- [ ] Apply the documentation completion gate and archive the verified change.
