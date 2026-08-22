"""POSIX process-supervision primitives."""

from __future__ import annotations

import resource
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PosixProcessSupervisionBackend:
    """Apply the established pure-capsule POSIX resource limits."""

    backend_id: str = "posix-rlimit"

    def apply_capsule_limits(
        self,
        *,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> None:
        """Apply the complete resource limit set with no partial fallback."""

        values = (cpu_seconds, memory_bytes, max_processes, max_output_bytes)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in values
        ):
            raise ValueError("capsule process limits must be positive integers")
        limits = (
            (resource.RLIMIT_CPU, cpu_seconds),
            (resource.RLIMIT_AS, memory_bytes),
            (resource.RLIMIT_NPROC, max_processes),
            (resource.RLIMIT_NOFILE, 16),
            (resource.RLIMIT_FSIZE, max_output_bytes + 4_096),
            (resource.RLIMIT_CORE, 0),
        )
        for kind, value in limits:
            resource.setrlimit(kind, (value, value))
