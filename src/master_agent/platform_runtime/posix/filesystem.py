"""POSIX secure-filesystem primitives."""

from __future__ import annotations

import fcntl
import grp
import os
import pwd
from dataclasses import dataclass

from master_agent.platform_runtime.contracts import PlatformCapabilityUnavailable


@dataclass(frozen=True, slots=True)
class PosixSecureFilesystemBackend:
    """Descriptor and user-identity operations with existing POSIX semantics."""

    backend_id: str = "posix-descriptor-filesystem"

    def duplicate_descriptor(
        self,
        descriptor: int,
        *,
        minimum_descriptor: int,
    ) -> int:
        """Use ``F_DUPFD_CLOEXEC`` without a weaker duplication fallback."""

        command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
        if command is None:
            raise PlatformCapabilityUnavailable(
                "close-on-exec descriptor duplication is unavailable"
            )
        return int(fcntl.fcntl(descriptor, command, minimum_descriptor))

    def real_user_id(self) -> int:
        """Return the real POSIX user ID."""

        return os.getuid()

    def effective_user_id(self) -> int:
        """Return the effective POSIX user ID."""

        return os.geteuid()

    def group_is_private_to_owner(self, *, owner_id: int, group_id: int) -> bool:
        """Return whether every member of ``group_id`` is the owning account."""

        try:
            owner = pwd.getpwuid(owner_id).pw_name
            group = grp.getgrgid(group_id)
            members = set(group.gr_mem)
            members.update(
                account.pw_name
                for account in pwd.getpwall()
                if account.pw_gid == group_id
            )
        except (KeyError, OSError):
            return False
        return members <= {owner}
