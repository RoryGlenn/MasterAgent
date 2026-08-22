"""Typed contracts for operating-system security backends.

The contracts in this module are intentionally narrow.  They identify the
security semantics a runtime route requires without assuming that every
supported Python platform has an implementation.  Platform-specific imports
belong in backend modules, never here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, cast, runtime_checkable

from master_agent.errors import ConfigurationError


class PlatformContract(StrEnum):
    """Security-sensitive runtime contracts selected as one native backend."""

    SECURE_FILESYSTEM = "secure_filesystem"
    CROSS_PROCESS_LOCKING = "cross_process_locking"
    ATOMIC_PUBLICATION_RECOVERY = "atomic_publication_recovery"
    PROCESS_SUPERVISION = "process_supervision"
    TRUSTED_GIT = "trusted_git"
    CAPSULE_ISOLATION = "capsule_isolation"


class PlatformCapabilityUnavailable(ConfigurationError):
    """A required native platform contract has no hardened implementation."""


class LockMode(StrEnum):
    """Portable intent for a whole-file advisory lock."""

    SHARED = "shared"
    EXCLUSIVE = "exclusive"


@runtime_checkable
class PlatformBackend(Protocol):
    """Common identity exposed by every native contract implementation."""

    @property
    def backend_id(self) -> str:
        """Return a stable, non-secret backend identity."""


@runtime_checkable
class SecureFilesystemBackend(PlatformBackend, Protocol):
    """Descriptor and account-identity primitives used by secure paths."""

    def duplicate_descriptor(
        self,
        descriptor: int,
        *,
        minimum_descriptor: int,
    ) -> int:
        """Duplicate a descriptor atomically with close-on-exec enabled."""

    def real_user_id(self) -> int:
        """Return the real account identifier used by persisted state."""

    def effective_user_id(self) -> int:
        """Return the effective account identifier used for execution checks."""

    def group_is_private_to_owner(self, *, owner_id: int, group_id: int) -> bool:
        """Return whether a group-writable artifact is private to its owner."""


@runtime_checkable
class CrossProcessLockingBackend(PlatformBackend, Protocol):
    """Whole-file cross-process advisory locking primitives."""

    def acquire(
        self,
        descriptor: int,
        *,
        mode: LockMode,
        blocking: bool = True,
    ) -> None:
        """Acquire the requested lock, optionally without blocking."""

    def release(self, descriptor: int) -> None:
        """Release a previously acquired lock."""


@runtime_checkable
class AtomicPublicationRecoveryBackend(PlatformBackend, Protocol):
    """Identity for atomic publication and crash-recovery semantics.

    The existing POSIX implementation remains in its established callers for
    issue #98.  Later platform work can extend this protocol without treating
    a generic rename as a safe fallback.
    """


@runtime_checkable
class ProcessSupervisionBackend(PlatformBackend, Protocol):
    """Native process limits and supervision required by capsule workers."""

    def apply_capsule_limits(
        self,
        *,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
        max_output_bytes: int,
    ) -> None:
        """Apply the complete fail-closed pure-capsule resource-limit set."""


@runtime_checkable
class TrustedGitBackend(PlatformBackend, Protocol):
    """Identity for native trusted-Git execution semantics.

    Issue #98 exposes backend selection only.  Native execution remains in the
    existing POSIX Git path until its dedicated platform tranche is complete.
    """


@runtime_checkable
class CapsuleIsolationBackend(PlatformBackend, Protocol):
    """Native OS containment for executable capability-capsule workers."""


@dataclass(frozen=True, slots=True)
class PlatformContractStatus:
    """Secret-free availability for one platform contract."""

    contract: PlatformContract
    available: bool
    backend: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.backend or self.backend != self.backend.strip():
            raise ValueError("platform contract backend identity is invalid")
        if self.available and self.reason is not None:
            raise ValueError("available platform contract must not report a reason")
        if not self.available and not self.reason:
            raise ValueError("unavailable platform contract requires a reason")

    def to_dict(self) -> dict[str, object]:
        """Return the stable readiness representation."""

        value: dict[str, object] = {
            "available": self.available,
            "backend": self.backend,
        }
        if self.reason is not None:
            value["reason"] = self.reason
        return value


@dataclass(frozen=True, slots=True)
class PlatformRuntimeStatus:
    """Complete, deterministic native-backend availability report."""

    platform: str
    backend: str
    capabilities: tuple[PlatformContractStatus, ...]

    def __post_init__(self) -> None:
        expected = tuple(PlatformContract)
        observed = tuple(item.contract for item in self.capabilities)
        if observed != expected:
            raise ValueError("platform runtime status contract order is incomplete")
        if not self.platform or not self.backend:
            raise ValueError("platform runtime identity is invalid")

    def contract_status(self, contract: PlatformContract) -> PlatformContractStatus:
        """Return one exact contract status."""

        return self.capabilities[tuple(PlatformContract).index(contract)]

    def supports(self, *contracts: PlatformContract) -> bool:
        """Return whether every requested contract is available."""

        return not self.unavailable(contracts)

    def unavailable(
        self,
        contracts: Iterable[PlatformContract],
    ) -> tuple[PlatformContractStatus, ...]:
        """Return unavailable requested contracts in canonical order."""

        required = frozenset(contracts)
        return tuple(
            item
            for item in self.capabilities
            if item.contract in required and not item.available
        )

    def to_dict(self) -> dict[str, object]:
        """Return the additive readiness payload used by CLI reports."""

        return {
            "platform": self.platform,
            "backend": self.backend,
            "capabilities": {
                str(item.contract): item.to_dict() for item in self.capabilities
            },
        }


@dataclass(frozen=True, slots=True)
class PlatformRuntime:
    """One deterministically selected set of native platform backends."""

    status: PlatformRuntimeStatus
    secure_filesystem: SecureFilesystemBackend | None = None
    cross_process_locking: CrossProcessLockingBackend | None = None
    atomic_publication_recovery: AtomicPublicationRecoveryBackend | None = None
    process_supervision: ProcessSupervisionBackend | None = None
    trusted_git: TrustedGitBackend | None = None
    capsule_isolation: CapsuleIsolationBackend | None = None

    def __post_init__(self) -> None:
        services = self._services()
        for item in self.status.capabilities:
            service = services[item.contract]
            if item.available != (service is not None):
                raise ValueError("platform runtime service availability drifted")
            if service is not None and item.backend != service.backend_id:
                raise ValueError("platform runtime service identity drifted")

    def supports(self, *contracts: PlatformContract) -> bool:
        """Return whether every requested native contract is available."""

        return self.status.supports(*contracts)

    def require_contract(self, contract: PlatformContract) -> PlatformBackend:
        """Return a required backend or fail with its non-secret reason."""

        service = self._services()[contract]
        if service is None:
            status = self.status.contract_status(contract)
            raise PlatformCapabilityUnavailable(cast(str, status.reason))
        return service

    def require_secure_filesystem(self) -> SecureFilesystemBackend:
        """Return the secure-filesystem backend or fail closed."""

        return cast(
            SecureFilesystemBackend,
            self.require_contract(PlatformContract.SECURE_FILESYSTEM),
        )

    def require_cross_process_locking(self) -> CrossProcessLockingBackend:
        """Return the cross-process-locking backend or fail closed."""

        return cast(
            CrossProcessLockingBackend,
            self.require_contract(PlatformContract.CROSS_PROCESS_LOCKING),
        )

    def require_process_supervision(self) -> ProcessSupervisionBackend:
        """Return the process-supervision backend or fail closed."""

        return cast(
            ProcessSupervisionBackend,
            self.require_contract(PlatformContract.PROCESS_SUPERVISION),
        )

    def require_capsule_isolation(self) -> CapsuleIsolationBackend:
        """Return the capsule-isolation backend or fail closed."""

        return self.require_contract(PlatformContract.CAPSULE_ISOLATION)

    def _services(self) -> Mapping[PlatformContract, PlatformBackend | None]:
        return MappingProxyType(
            {
                PlatformContract.SECURE_FILESYSTEM: self.secure_filesystem,
                PlatformContract.CROSS_PROCESS_LOCKING: self.cross_process_locking,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY: (
                    self.atomic_publication_recovery
                ),
                PlatformContract.PROCESS_SUPERVISION: self.process_supervision,
                PlatformContract.TRUSTED_GIT: self.trusted_git,
                PlatformContract.CAPSULE_ISOLATION: self.capsule_isolation,
            }
        )
