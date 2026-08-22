# Tasks

- [x] Define the versioned POSIX/Windows object-identity and trust-policy binding.
- [x] Implement Win32 handle traversal, volume/path policy, ACL evaluation,
  retained pins, bounded reads, exclusive protected creation, bounded
  write/flush/readback, exact cleanup, and stable revalidation.
- [x] Implement `LockFileEx` shared/exclusive blocking and nonblocking behavior.
- [x] Select the partial Windows runtime without enabling incomplete contracts.
- [x] Port every secure-filesystem-only caller needed before advertising the
  backend and preserve POSIX behavior.
- [x] Admit the exact Windows `OWNER RIGHTS` SID only as an alias for a
  separately trusted owner and reject neighboring creator/owner aliases.
- [x] Add native Windows and platform-neutral adversarial regression coverage.
- [x] Release semantic ownership and update user, architecture, threat-model,
  CLI, roadmap, release, and changelog documentation.
- [x] Run focused/full tests, Ruff, mypy, specification, semantic, release, SBOM,
  archive, installed-artifact, and immutable-range security validation.
- [x] Apply the documentation completion gate and archive the verified change.
