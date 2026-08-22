"""Construct the complete native POSIX platform runtime."""

from __future__ import annotations

from master_agent.platform_runtime.contracts import (
    PlatformBackend,
    PlatformContract,
    PlatformContractStatus,
    PlatformRuntime,
    PlatformRuntimeStatus,
)
from master_agent.platform_runtime.posix.atomic import (
    PosixAtomicPublicationRecoveryBackend,
)
from master_agent.platform_runtime.posix.capsules import (
    LinuxBubblewrapCapsuleIsolationBackend,
)
from master_agent.platform_runtime.posix.filesystem import (
    PosixSecureFilesystemBackend,
)
from master_agent.platform_runtime.posix.git import PosixTrustedGitBackend
from master_agent.platform_runtime.posix.locking import (
    PosixCrossProcessLockingBackend,
)
from master_agent.platform_runtime.posix.process import (
    PosixProcessSupervisionBackend,
)


def build_posix_runtime(*, platform: str, backend: str) -> PlatformRuntime:
    """Return the immutable native POSIX runtime for Linux or macOS."""

    filesystem = PosixSecureFilesystemBackend()
    locking = PosixCrossProcessLockingBackend()
    atomic = PosixAtomicPublicationRecoveryBackend()
    process = PosixProcessSupervisionBackend()
    git = PosixTrustedGitBackend()
    capsules = LinuxBubblewrapCapsuleIsolationBackend() if platform == "linux" else None
    services: tuple[tuple[PlatformContract, PlatformBackend | None], ...] = (
        (PlatformContract.SECURE_FILESYSTEM, filesystem),
        (PlatformContract.CROSS_PROCESS_LOCKING, locking),
        (PlatformContract.ATOMIC_PUBLICATION_RECOVERY, atomic),
        (PlatformContract.PROCESS_SUPERVISION, process),
        (PlatformContract.TRUSTED_GIT, git),
        (PlatformContract.CAPSULE_ISOLATION, capsules),
    )
    statuses: list[PlatformContractStatus] = []
    for contract, service in services:
        if service is None:
            statuses.append(
                PlatformContractStatus(
                    contract=contract,
                    available=False,
                    backend=backend,
                    reason=(f"native {platform} {contract} backend is not implemented"),
                )
            )
        else:
            statuses.append(
                PlatformContractStatus(
                    contract=contract,
                    available=True,
                    backend=service.backend_id,
                )
            )
    status = PlatformRuntimeStatus(
        platform=platform,
        backend=backend,
        capabilities=tuple(statuses),
    )
    return PlatformRuntime(
        status=status,
        secure_filesystem=filesystem,
        cross_process_locking=locking,
        atomic_publication_recovery=atomic,
        process_supervision=process,
        trusted_git=git,
        capsule_isolation=capsules,
    )
