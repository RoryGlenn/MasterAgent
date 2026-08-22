"""POSIX trusted-Git inspection backend."""

from __future__ import annotations

import os
import selectors
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from master_agent.platform_runtime.contracts import (
    TrustedGitError,
    harden_trusted_git_command,
    validate_trusted_git_request,
)

_FIXED_GIT_PATH = "/usr/bin:/bin:/usr/local/bin"


@dataclass(frozen=True, slots=True)
class PosixTrustedGitBackend:
    """Preserve the existing bounded POSIX Git inspection behavior."""

    backend_id: str = "posix-trusted-git"

    def read(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> bytes:
        """Run one fixed Git read with bounded stdout and discarded diagnostics."""

        parsed = validate_trusted_git_request(
            repository,
            arguments,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        executable = shutil.which("git", path=_FIXED_GIT_PATH)
        if executable is None:
            raise TrustedGitError("executable_unavailable")
        command = (
            executable,
            "--no-pager",
            f"--work-tree={repository}",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            f"core.attributesFile={os.devnull}",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-c",
            "diff.external=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.ext.allow=never",
            *harden_trusted_git_command(parsed),
        )
        try:
            process = subprocess.Popen(
                command,
                cwd=repository,
                env=_environment(repository),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise TrustedGitError("launch_failed") from error
        selector = selectors.DefaultSelector()
        output = bytearray()
        deadline = time.monotonic() + timeout_seconds
        try:
            if process.stdout is None:
                raise TrustedGitError("output_unavailable")
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TrustedGitError("timed_out")
                chunk = os.read(
                    process.stdout.fileno(),
                    min(64 * 1024, max_output_bytes + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_output_bytes:
                    raise TrustedGitError("output_limit_exceeded")
            try:
                return_code = process.wait(
                    timeout=max(0.1, deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired as error:
                raise TrustedGitError("timed_out") from error
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise
        finally:
            selector.close()
            if process.stdout is not None:
                process.stdout.close()
        if return_code != 0:
            raise TrustedGitError("nonzero_exit")
        return bytes(output)


def _environment(root: Path) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": str(root.parent),
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment
