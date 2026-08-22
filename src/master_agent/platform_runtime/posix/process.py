"""POSIX process-supervision primitives."""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from master_agent.platform_runtime.contracts import (
    ProcessExecutionResult,
    ProcessExitReason,
    ProcessSupervisionError,
)


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

    def run(
        self,
        *,
        executable: Path,
        arguments: Sequence[str],
        cwd: Path,
        environment: Mapping[str, str],
        inherited_handles: Sequence[int] = (),
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Run a fixed POSIX command while preserving the established limits."""

        if inherited_handles:
            raise ProcessSupervisionError("inherited_handles_unsupported")
        _validate_run_inputs(
            executable=executable,
            arguments=arguments,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            max_processes=max_processes,
            max_output_bytes=max_output_bytes,
        )

        def apply_limits() -> None:
            self.apply_capsule_limits(
                cpu_seconds=cpu_seconds,
                memory_bytes=memory_bytes,
                max_processes=max_processes,
                max_output_bytes=max_output_bytes,
            )

        with tempfile.TemporaryFile() as output:
            try:
                process = subprocess.Popen(
                    (str(executable), *arguments),
                    executable=executable,
                    cwd=cwd,
                    env=dict(environment),
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=output,
                    shell=False,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=apply_limits,  # noqa: PLW1509
                )
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                raise ProcessSupervisionError("launch_failed") from error
            timed_out = False
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=30)
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(0)
            retained = output.read(max_output_bytes)
        return ProcessExecutionResult(
            reason=(
                ProcessExitReason.TIMED_OUT
                if timed_out
                else (
                    ProcessExitReason.EXITED
                    if process.returncode == 0
                    else ProcessExitReason.NONZERO_EXIT
                )
            ),
            exit_code=None if timed_out else process.returncode,
            stdout=retained,
            stderr=b"",
            output_truncated=size > max_output_bytes,
        )


def _validate_run_inputs(
    *,
    executable: Path,
    arguments: Sequence[str],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    cpu_seconds: int,
    memory_bytes: int,
    max_processes: int,
    max_output_bytes: int,
) -> None:
    """Validate the additive POSIX run surface without changing legacy limits."""

    if not executable.is_absolute() or not cwd.is_absolute():
        raise ValueError("process executable and cwd must be absolute")
    if any(not isinstance(item, str) or "\x00" in item for item in arguments):
        raise ValueError("process arguments are invalid")
    if any(
        not isinstance(key, str)
        or not key
        or "=" in key
        or "\x00" in key
        or not isinstance(value, str)
        or "\x00" in value
        for key, value in environment.items()
    ):
        raise ValueError("process environment is invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > 86_400
    ):
        raise ValueError("process timeout is invalid")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (cpu_seconds, memory_bytes, max_processes, max_output_bytes)
    ):
        raise ValueError("process limits must be positive integers")
