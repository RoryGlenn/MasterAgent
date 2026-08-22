"""Linux capability-capsule isolation identity."""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from master_agent.platform_runtime.contracts import SecureFilesystemBackend

LINUX_BUBBLEWRAP_UNAVAILABLE_REASON = (
    "native linux capsule_isolation backend is unavailable: "
    "trusted bubblewrap executable is unavailable"
)


@dataclass(frozen=True, slots=True)
class LinuxBubblewrapCapsuleIsolationBackend:
    """Identify the Linux bubblewrap namespace-isolation implementation."""

    executable: Path = field(repr=False)
    backend_id: str = field(default="linux-bubblewrap", init=False)


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
