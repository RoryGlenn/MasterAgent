"""POSIX cross-process whole-file locking."""

from __future__ import annotations

import fcntl
from dataclasses import dataclass

from master_agent.platform_runtime.contracts import LockMode


@dataclass(frozen=True, slots=True)
class PosixCrossProcessLockingBackend:
    """Preserve the runtime's existing ``flock`` semantics."""

    backend_id: str = "posix-flock"

    def acquire(
        self,
        descriptor: int,
        *,
        mode: LockMode,
        blocking: bool = True,
    ) -> None:
        """Acquire a shared or exclusive advisory lock."""

        if mode is LockMode.EXCLUSIVE:
            operation = fcntl.LOCK_EX
        elif mode is LockMode.SHARED:
            operation = fcntl.LOCK_SH
        else:
            raise ValueError("cross-process lock mode is invalid")
        if not isinstance(blocking, bool):
            raise TypeError("cross-process lock blocking flag must be a boolean")
        if not blocking:
            operation |= fcntl.LOCK_NB
        fcntl.flock(descriptor, operation)

    def release(self, descriptor: int) -> None:
        """Release an advisory lock."""

        fcntl.flock(descriptor, fcntl.LOCK_UN)
