"""Construct the independently available native Windows runtime slice."""

from __future__ import annotations

import sys

from master_agent.platform_runtime.contracts import (
    PlatformBackend,
    PlatformCapabilityUnavailable,
    PlatformContract,
    PlatformContractStatus,
    PlatformRuntime,
    PlatformRuntimeStatus,
)
from master_agent.platform_runtime.windows.atomic import (
    WindowsAtomicPublicationRecoveryBackend,
    probe_windows_atomic_backend,
)
from master_agent.platform_runtime.windows.credentials import (
    WindowsCredentialStorageBackend,
    probe_windows_credential_storage_backend,
)
from master_agent.platform_runtime.windows.filesystem import (
    WindowsSecureFilesystemBackend,
    probe_windows_filesystem_backend,
)
from master_agent.platform_runtime.windows.git import (
    WINDOWS_GIT_UNAVAILABLE_REASON,
    probe_windows_git_backend,
)
from master_agent.platform_runtime.windows.locking import (
    WindowsCrossProcessLockingBackend,
    probe_windows_locking_backend,
)
from master_agent.platform_runtime.windows.process import (
    WindowsProcessSupervisionBackend,
    probe_windows_process_backend,
)

WINDOWS_RUNTIME_BACKEND_ID = "windows-native-partial"


def build_windows_runtime() -> PlatformRuntime:
    """Return the native partial runtime after bounded Win32 symbol probes."""

    if sys.platform != "win32":
        raise PlatformCapabilityUnavailable("native Windows runtime requires Windows")
    probe_windows_filesystem_backend()
    probe_windows_locking_backend()
    filesystem = WindowsSecureFilesystemBackend()
    locking = WindowsCrossProcessLockingBackend()
    probe_windows_atomic_backend(filesystem=filesystem, locking=locking)
    atomic = WindowsAtomicPublicationRecoveryBackend(
        filesystem=filesystem,
        locking=locking,
    )
    credential_api = probe_windows_credential_storage_backend(atomic=atomic)
    credentials = WindowsCredentialStorageBackend(
        atomic=atomic,
        api=credential_api,
    )
    process_api = probe_windows_process_backend()
    process = WindowsProcessSupervisionBackend(api=process_api)
    try:
        git = probe_windows_git_backend(filesystem=filesystem, process=process)
    except PlatformCapabilityUnavailable:
        git = None
    services: tuple[tuple[PlatformContract, PlatformBackend | None], ...] = (
        (PlatformContract.SECURE_FILESYSTEM, filesystem),
        (PlatformContract.CROSS_PROCESS_LOCKING, locking),
        (PlatformContract.ATOMIC_PUBLICATION_RECOVERY, atomic),
        (PlatformContract.CREDENTIAL_STORAGE, credentials),
        (PlatformContract.PROCESS_SUPERVISION, process),
        (PlatformContract.TRUSTED_GIT, git),
        (PlatformContract.CAPSULE_ISOLATION, None),
    )
    statuses = tuple(
        PlatformContractStatus(
            contract=contract,
            available=service is not None,
            backend=(
                service.backend_id
                if service is not None
                else WINDOWS_RUNTIME_BACKEND_ID
            ),
            reason=(
                None
                if service is not None
                else (
                    WINDOWS_GIT_UNAVAILABLE_REASON
                    if contract is PlatformContract.TRUSTED_GIT
                    else f"native windows {contract} backend is not implemented"
                )
            ),
        )
        for contract, service in services
    )
    return PlatformRuntime(
        status=PlatformRuntimeStatus(
            platform="windows",
            backend=WINDOWS_RUNTIME_BACKEND_ID,
            capabilities=statuses,
        ),
        secure_filesystem=filesystem,
        cross_process_locking=locking,
        atomic_publication_recovery=atomic,
        credential_storage=credentials,
        process_supervision=process,
        trusted_git=git,
    )
