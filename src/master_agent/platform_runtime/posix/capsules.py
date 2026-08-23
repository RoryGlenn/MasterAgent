"""Linux capability-capsule isolation identity."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from master_agent.platform_runtime.contracts import (
    ProcessExecutionResult,
    ProcessExitReason,
    SecureFilesystemBackend,
)

LINUX_BUBBLEWRAP_UNAVAILABLE_REASON = (
    "native linux capsule_isolation backend is unavailable: "
    "trusted bubblewrap executable is unavailable"
)


@dataclass(frozen=True, slots=True)
class LinuxBubblewrapCapsuleIsolationBackend:
    """Identify the Linux bubblewrap namespace-isolation implementation."""

    executable: Path = field(repr=False)
    backend_id: str = field(default="linux-bubblewrap", init=False)

    @property
    def production_isolated(self) -> bool:
        """Return the certified namespace-isolation status."""

        return True

    def identity_components(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Mapping[str, str | None]:
        """Return the existing worker, interpreter, and bubblewrap identity."""

        return {
            "backend": self.backend_id,
            "worker_sha256": _sha256_file(worker),
            "interpreter_sha256": _sha256_file(interpreter),
            "sandbox_sha256": _sha256_file(self.executable),
        }

    def run_worker(
        self,
        *,
        worker: Path,
        interpreter: Path,
        request: bytes,
        environment: Mapping[str, str],
        timeout_seconds: float,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> ProcessExecutionResult:
        """Run the existing bubblewrap command and return bounded process data."""

        del cpu_seconds, memory_bytes, max_processes
        base_prefix = Path(sys.base_prefix).resolve()
        command = [
            str(self.executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--cap-drop",
            "ALL",
            "--clearenv",
        ]
        for key, value in environment.items():
            command.extend(("--setenv", key, value))
        command.extend(("--ro-bind", str(base_prefix), str(base_prefix)))
        for library_root in (Path("/lib"), Path("/lib64")):
            if library_root.exists():
                command.extend(("--ro-bind", str(library_root), str(library_root)))
        command.extend(
            (
                "--ro-bind",
                str(worker),
                "/capsule-worker.py",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",  # nosec B108 - private namespace tmpfs.
                "--dir",
                "/work",
                "--chdir",
                "/work",
                str(interpreter),
                "-I",
                "-S",
                "/capsule-worker.py",
            )
        )
        with tempfile.TemporaryDirectory(prefix="master-agent-capsule-") as directory:
            os.chmod(directory, 0o700)
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=errors,
                    cwd=directory,
                    env=dict(environment),
                    start_new_session=True,
                )
                try:
                    process.communicate(request, timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    _terminate_process(process)
                    return ProcessExecutionResult(
                        reason=ProcessExitReason.TIMED_OUT,
                        exit_code=None,
                        stdout=b"",
                        stderr=b"",
                        output_truncated=False,
                    )
                output.seek(0, os.SEEK_END)
                output_size = output.tell()
                output.seek(0)
                payload = output.read(min(output_size, max_output_bytes))
                errors.seek(0, os.SEEK_END)
                diagnostic_size = errors.tell()
                errors.seek(0)
                diagnostic = (
                    errors.read(4_096)
                    if diagnostic_size <= 4_096
                    else b"diagnostic_overflow"
                )
        return ProcessExecutionResult(
            reason=(
                ProcessExitReason.EXITED
                if process.returncode == 0
                else ProcessExitReason.NONZERO_EXIT
            ),
            exit_code=process.returncode,
            stdout=payload,
            stderr=diagnostic,
            output_truncated=output_size > max_output_bytes,
        )

    def denial_probes(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> tuple[Mapping[str, str], ...]:
        """Return no additional probes beyond the established namespace suite."""

        del worker, interpreter
        return ()


def select_linux_bubblewrap_backend(
    *,
    filesystem: SecureFilesystemBackend,
    executable: str | None = None,
) -> LinuxBubblewrapCapsuleIsolationBackend | None:
    """Return a trusted executable bubblewrap backend when one is usable."""

    candidate = executable if executable is not None else shutil.which("bwrap")
    if not candidate:
        return None
    unresolved = Path(candidate)
    if not unresolved.is_absolute():
        return None
    try:
        resolved = unresolved.resolve(strict=True)
        metadata = resolved.lstat()
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    if metadata.st_uid not in {0, filesystem.effective_user_id()}:
        return None
    if metadata.st_nlink != 1:
        return None
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions & stat.S_IWOTH:
        return None
    if permissions & stat.S_IWGRP:
        if metadata.st_uid != filesystem.effective_user_id():
            return None
        if not filesystem.group_is_private_to_owner(
            owner_id=metadata.st_uid,
            group_id=metadata.st_gid,
        ):
            return None
    if not os.access(resolved, os.X_OK):
        return None
    return LinuxBubblewrapCapsuleIsolationBackend(executable=resolved)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
