"""Deterministic, lazy selection of native platform backends."""

from __future__ import annotations

import sys
from functools import cache

from master_agent.platform_runtime.contracts import (
    CapsuleIsolationBackend,
    CrossProcessLockingBackend,
    PlatformContract,
    PlatformContractStatus,
    PlatformRuntime,
    PlatformRuntimeStatus,
    ProcessSupervisionBackend,
    SecureFilesystemBackend,
)


def get_platform_runtime(platform: str | None = None) -> PlatformRuntime:
    """Return one immutable runtime selected from an explicit platform name."""

    selected = sys.platform if platform is None else platform
    identity = _normalize_platform(selected)
    return _runtime_for_identity(*identity)


def platform_runtime_status(platform: str | None = None) -> PlatformRuntimeStatus:
    """Return the complete secret-free backend status without using a backend."""

    return get_platform_runtime(platform).status


def require_platform_contract(
    contract: PlatformContract,
    platform: str | None = None,
) -> None:
    """Fail closed unless one exact native contract is implemented."""

    get_platform_runtime(platform).require_contract(contract)


def require_persistent_state_platform(platform: str | None = None) -> None:
    """Require the complete native contract set for persistent local state."""

    runtime = get_platform_runtime(platform)
    for contract in (
        PlatformContract.SECURE_FILESYSTEM,
        PlatformContract.CROSS_PROCESS_LOCKING,
        PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
    ):
        runtime.require_contract(contract)


def get_secure_filesystem_backend(
    platform: str | None = None,
) -> SecureFilesystemBackend:
    """Return the selected secure-filesystem backend."""

    return get_platform_runtime(platform).require_secure_filesystem()


def get_cross_process_locking_backend(
    platform: str | None = None,
) -> CrossProcessLockingBackend:
    """Return the selected cross-process-locking backend."""

    return get_platform_runtime(platform).require_cross_process_locking()


def get_process_supervision_backend(
    platform: str | None = None,
) -> ProcessSupervisionBackend:
    """Return the selected process-supervision backend."""

    return get_platform_runtime(platform).require_process_supervision()


def get_capsule_isolation_backend(
    platform: str | None = None,
) -> CapsuleIsolationBackend:
    """Return the selected capability-capsule isolation backend."""

    return get_platform_runtime(platform).require_capsule_isolation()


def _normalize_platform(value: str) -> tuple[str, str, bool]:
    """Return normalized identity, backend ID, and POSIX-selection flag."""

    normalized = (
        value.casefold() if isinstance(value, str) and value == value.strip() else ""
    )
    if normalized in {"linux", "linux2"}:
        return "linux", "posix-linux", True
    if normalized == "darwin":
        return "macos", "posix-macos", True
    if normalized in {"win32", "cygwin", "msys"}:
        return "windows", "windows-unavailable", False
    return "unsupported", "unsupported", False


@cache
def _runtime_for_identity(
    platform: str,
    backend: str,
    posix: bool,
) -> PlatformRuntime:
    """Load only the selected native backend and cache its immutable result."""

    if posix:
        try:
            from master_agent.platform_runtime.posix.runtime import (
                build_posix_runtime,
            )
        except ImportError:
            return _unavailable_runtime(
                platform=platform,
                backend=backend,
                reason=f"native {platform} platform backend is unavailable",
            )
        return build_posix_runtime(platform=platform, backend=backend)
    if platform == "windows":
        return _unavailable_runtime(
            platform=platform,
            backend=backend,
            reason_template="native windows {contract} backend is not implemented",
        )
    return _unavailable_runtime(
        platform=platform,
        backend=backend,
        reason_template="unsupported platform {contract} backend is unavailable",
    )


def _unavailable_runtime(
    *,
    platform: str,
    backend: str,
    reason: str | None = None,
    reason_template: str | None = None,
) -> PlatformRuntime:
    """Build a complete unavailable status without a generic fallback."""

    if (reason is None) == (reason_template is None):
        raise ValueError("exactly one unavailable platform reason is required")
    selected_reasons = {
        contract: (
            reason
            if reason is not None
            else _format_unavailable_reason(reason_template, contract)
        )
        for contract in PlatformContract
    }
    statuses = tuple(
        PlatformContractStatus(
            contract=contract,
            available=False,
            backend=backend,
            reason=selected_reasons[contract],
        )
        for contract in PlatformContract
    )
    return PlatformRuntime(
        status=PlatformRuntimeStatus(
            platform=platform,
            backend=backend,
            capabilities=statuses,
        )
    )


def _format_unavailable_reason(
    template: str | None,
    contract: PlatformContract,
) -> str:
    """Format one validated non-secret unavailability reason."""

    if template is None:  # pragma: no cover - guarded by caller invariant.
        raise ValueError("unavailable platform reason template is missing")
    return template.format(contract=str(contract))
