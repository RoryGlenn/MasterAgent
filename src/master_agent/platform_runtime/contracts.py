"""Typed contracts for operating-system security backends.

The contracts in this module are intentionally narrow.  They identify the
security semantics a runtime route requires without assuming that every
supported Python platform has an implementation.  Platform-specific imports
belong in backend modules, never here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Any, Protocol, Self, cast, runtime_checkable

from master_agent.errors import ConfigurationError


class PlatformContract(StrEnum):
    """Security-sensitive runtime contracts selected as one native backend."""

    SECURE_FILESYSTEM = "secure_filesystem"
    CROSS_PROCESS_LOCKING = "cross_process_locking"
    ATOMIC_PUBLICATION_RECOVERY = "atomic_publication_recovery"
    CREDENTIAL_STORAGE = "credential_storage"
    PROCESS_SUPERVISION = "process_supervision"
    TRUSTED_GIT = "trusted_git"
    CAPSULE_ISOLATION = "capsule_isolation"


class PlatformCapabilityUnavailable(ConfigurationError):
    """A required native platform contract has no hardened implementation."""


class ProcessExitReason(StrEnum):
    """Secret-free terminal reason for one supervised process."""

    EXITED = "exited"
    NONZERO_EXIT = "nonzero_exit"
    TIMED_OUT = "timed_out"


class ProcessSupervisionError(ConfigurationError):
    """A supervised process could not be launched or controlled safely."""

    def __init__(self, reason: str, *, native_error_code: int | None = None) -> None:
        if not reason or reason != reason.strip() or len(reason) > 80:
            raise ValueError("process supervision reason is invalid")
        if native_error_code is not None and (
            isinstance(native_error_code, bool)
            or not isinstance(native_error_code, int)
            or native_error_code < 0
        ):
            raise ValueError("native process error code is invalid")
        self.reason = reason
        self.native_error_code = native_error_code
        super().__init__(f"process supervision failed: {reason}")


class TrustedGitError(ConfigurationError):
    """A trusted Git inspection could not be completed safely."""

    def __init__(self, reason: str) -> None:
        if not reason or reason != reason.strip() or len(reason) > 80:
            raise ValueError("trusted Git failure reason is invalid")
        self.reason = reason
        super().__init__(f"trusted Git inspection failed: {reason}")


_TRUSTED_GIT_MAX_ARGUMENTS = 256
_TRUSTED_GIT_MAX_ARGUMENT_BYTES = 256 * 1024
_TRUSTED_GIT_MAX_OUTPUT_BYTES = 128 * 1024 * 1024
_TRUSTED_GIT_OBJECT_TYPES = frozenset({"blob", "commit", "tree"})
_TRUSTED_GIT_LS_FILES_OPTIONS = frozenset(
    {"--cached", "--exclude-standard", "--others", "--stage", "-z"}
)
_TRUSTED_GIT_STATUS_OPTIONS = frozenset(
    {"--porcelain=v1", "--untracked-files=all", "--untracked-files=no", "-z"}
)
_TRUSTED_GIT_DIFF_OPTIONS = frozenset(
    {
        "--binary",
        "--cached",
        "--ignore-submodules=all",
        "--name-only",
        "--name-status",
        "--no-ext-diff",
        "--no-textconv",
        "--staged",
        "--stat",
        "-z",
    }
)


def validate_trusted_git_request(
    repository: Path,
    arguments: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[str, ...]:
    """Return one strictly parsed, fixed read-only Git command vector."""

    if not isinstance(repository, Path) or not repository.is_absolute():
        raise ValueError("trusted Git repository must be an absolute path")
    if isinstance(arguments, (str, bytes)):
        raise TypeError("trusted Git arguments must be a sequence of strings")
    parsed = tuple(arguments)
    if (
        not parsed
        or len(parsed) > _TRUSTED_GIT_MAX_ARGUMENTS
        or any(
            not isinstance(item, str) or "\x00" in item or "\r" in item or "\n" in item
            for item in parsed
        )
        or sum(len(item.encode("utf-8")) for item in parsed)
        > _TRUSTED_GIT_MAX_ARGUMENT_BYTES
    ):
        raise ValueError("trusted Git arguments are invalid or not read-only")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 60
    ):
        raise ValueError("trusted Git timeout is invalid")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or not 0 < max_output_bytes <= _TRUSTED_GIT_MAX_OUTPUT_BYTES
    ):
        raise ValueError("trusted Git output limit is invalid")
    command = parsed[0]
    if command == "cat-file":
        if (
            len(parsed) != 3
            or parsed[1] not in _TRUSTED_GIT_OBJECT_TYPES
            or not _trusted_git_object_id_is_safe(parsed[2])
        ):
            raise ValueError("trusted Git cat-file request is invalid")
    elif command == "rev-parse":
        if parsed != ("rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"):
            raise ValueError("trusted Git revision request is invalid")
    elif command == "ls-files":
        _validate_trusted_git_options(parsed[1:], _TRUSTED_GIT_LS_FILES_OPTIONS)
    elif command == "status":
        if any(value not in _TRUSTED_GIT_STATUS_OPTIONS for value in parsed[1:]):
            raise ValueError("trusted Git status request is invalid")
    elif command == "diff":
        _validate_trusted_git_options(parsed[1:], _TRUSTED_GIT_DIFF_OPTIONS)
    else:
        raise ValueError("trusted Git command is invalid or not read-only")
    return parsed


def harden_trusted_git_command(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """Add non-overridable safety options to one validated Git command."""

    if arguments[0] == "diff":
        separator = arguments.index("--") if "--" in arguments else len(arguments)
        return (
            "diff",
            *arguments[1:separator],
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=all",
            *arguments[separator:],
        )
    if arguments[0] == "status":
        return ("status", *arguments[1:], "--ignore-submodules=all")
    return arguments


def _validate_trusted_git_options(
    arguments: tuple[str, ...],
    allowed: frozenset[str],
) -> None:
    separator = arguments.index("--") if "--" in arguments else len(arguments)
    if any(value not in allowed for value in arguments[:separator]):
        raise ValueError("trusted Git command options are invalid")
    if separator == len(arguments):
        return
    if "--" in arguments[separator + 1 :]:
        raise ValueError("trusted Git pathspec separator is duplicated")
    if any(
        not _trusted_git_literal_pathspec_is_safe(value)
        for value in arguments[separator + 1 :]
    ):
        raise ValueError("trusted Git pathspec is invalid")


def _trusted_git_literal_pathspec_is_safe(value: str) -> bool:
    prefix = ":(literal)"
    if not value.startswith(prefix):
        return False
    relative = value[len(prefix) :]
    if not relative or relative.startswith(("/", "\\")) or "\\" in relative:
        return False
    return all(component not in {"", ".", ".."} for component in relative.split("/"))


def _trusted_git_object_id_is_safe(value: str) -> bool:
    return len(value) in (40, 64) and all(
        character in "0123456789abcdef" for character in value
    )


@dataclass(frozen=True, slots=True)
class ProcessExecutionResult:
    """Bounded terminal state returned by a native process supervisor."""

    reason: ProcessExitReason
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    output_truncated: bool

    def __post_init__(self) -> None:
        if self.reason is ProcessExitReason.TIMED_OUT:
            if self.exit_code is not None:
                raise ValueError("timed-out process must not report an exit code")
        elif isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise TypeError("completed process exit code must be an integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise TypeError("process output must be bytes")
        if not isinstance(self.output_truncated, bool):
            raise TypeError("process output truncation flag must be a boolean")


class LockMode(StrEnum):
    """Portable intent for a whole-file advisory lock."""

    SHARED = "shared"
    EXCLUSIVE = "exclusive"


@dataclass(frozen=True, slots=True)
class AtomicStateIdentity:
    """Exact native object and content identity for one protected generation."""

    object_identity: PlatformObjectIdentity
    content_sha256: str
    size: int

    def __post_init__(self) -> None:
        if self.object_identity.kind is not FilesystemObjectKind.FILE:
            raise ValueError("atomic state identity must describe a file")
        if not _lower_hex(self.content_sha256, minimum=64, maximum=64):
            raise ValueError("atomic state content digest is invalid")
        if isinstance(self.size, bool) or not isinstance(self.size, int):
            raise TypeError("atomic state size must be an integer")
        if self.size < 0:
            raise ValueError("atomic state size is invalid")


@runtime_checkable
class AtomicStateTransaction(Protocol):
    """One serialized protected-file transaction held across caller work."""

    @property
    def path(self) -> Path:
        """Return the validated display path for the selected state file."""

    @property
    def identity(self) -> AtomicStateIdentity | None:
        """Return the current recovered identity, or ``None`` when absent."""

    def read_bytes(self) -> bytes | None:
        """Return bounded current bytes after recovery and revalidation."""

    def publish_bytes(
        self,
        payload: bytes,
        *,
        expected: AtomicStateIdentity | None,
    ) -> AtomicStateIdentity:
        """Publish one exact replacement or create-only generation."""

    def remove(self, *, expected: AtomicStateIdentity) -> bool:
        """Remove only the exact current generation."""

    def __enter__(self) -> Self:
        """Acquire and return this transaction."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release the transaction and all retained native resources."""


class FilesystemObjectKind(StrEnum):
    """Portable filesystem object kinds admitted by native backends."""

    DIRECTORY = "directory"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class PlatformObjectIdentity:
    """Versioned native identity bound into approval and execution context.

    The discriminated payload deliberately retains native facts. POSIX object
    identity is not projected into Windows fields and Windows SID/DACL facts
    are never approximated with Unix owner or mode values.
    """

    platform: str
    kind: FilesystemObjectKind
    device: int | None = None
    inode: int | None = None
    owner: int | None = None
    mode: int | None = None
    volume_serial: str | None = None
    file_id: str | None = None
    owner_sid: str | None = None
    dacl_sha256: str | None = None
    trust_policy_sha256: str | None = None
    schema: str = "master-agent/platform-object-identity@1"

    def __post_init__(self) -> None:
        if self.schema != "master-agent/platform-object-identity@1":
            raise ValueError("unsupported platform object identity schema")
        if self.platform == "posix":
            self._validate_posix()
        elif self.platform == "windows":
            self._validate_windows()
        else:
            raise ValueError("platform object identity platform is invalid")

    @classmethod
    def from_posix(
        cls,
        *,
        kind: FilesystemObjectKind,
        device: int,
        inode: int,
        owner: int,
        mode: int,
    ) -> PlatformObjectIdentity:
        """Build an exact POSIX identity without changing legacy semantics."""

        return cls(
            platform="posix",
            kind=kind,
            device=device,
            inode=inode,
            owner=owner,
            mode=mode,
        )

    @classmethod
    def from_windows(
        cls,
        *,
        kind: FilesystemObjectKind,
        volume_serial: str,
        file_id: str,
        owner_sid: str,
        dacl_sha256: str,
        trust_policy_sha256: str,
    ) -> PlatformObjectIdentity:
        """Build an exact Windows handle, SID, DACL, and policy identity."""

        return cls(
            platform="windows",
            kind=kind,
            volume_serial=volume_serial,
            file_id=file_id,
            owner_sid=owner_sid,
            dacl_sha256=dacl_sha256,
            trust_policy_sha256=trust_policy_sha256,
        )

    @property
    def object_key(self) -> tuple[str, str, str]:
        """Return the native volume/object key used for alias detection."""

        if self.platform == "posix":
            return self.platform, str(self.device), str(self.inode)
        return self.platform, cast(str, self.volume_serial), cast(str, self.file_id)

    def to_dict(self) -> dict[str, object]:
        """Serialize the exact discriminated identity payload."""

        payload: dict[str, object] = {
            "schema": self.schema,
            "platform": self.platform,
            "kind": str(self.kind),
        }
        if self.platform == "posix":
            payload["posix"] = {
                "device": self.device,
                "inode": self.inode,
                "owner": self.owner,
                "mode": self.mode,
            }
        else:
            payload["windows"] = {
                "volume_serial": self.volume_serial,
                "file_id": self.file_id,
                "owner_sid": self.owner_sid,
                "dacl_sha256": self.dacl_sha256,
                "trust_policy_sha256": self.trust_policy_sha256,
            }
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PlatformObjectIdentity:
        """Parse one exact versioned identity without cross-platform coercion."""

        platform = str(data.get("platform", ""))
        try:
            kind = FilesystemObjectKind(str(data.get("kind", "")))
        except (TypeError, ValueError) as error:
            raise ValueError("platform object identity kind is invalid") from error
        schema = str(data.get("schema", ""))
        if platform == "posix":
            if set(data) != {"schema", "platform", "kind", "posix"}:
                raise ValueError("POSIX platform object identity shape is invalid")
            native = data.get("posix")
            if not isinstance(native, Mapping):
                raise ValueError("POSIX platform object identity payload is invalid")
            if set(native) != {"device", "inode", "owner", "mode"}:
                raise ValueError("POSIX platform object identity shape is invalid")
            return cls(
                schema=schema,
                platform=platform,
                kind=kind,
                device=_identity_int(native, "device"),
                inode=_identity_int(native, "inode"),
                owner=_identity_int(native, "owner"),
                mode=_identity_int(native, "mode"),
            )
        if platform == "windows":
            if set(data) != {"schema", "platform", "kind", "windows"}:
                raise ValueError("Windows platform object identity shape is invalid")
            native = data.get("windows")
            if not isinstance(native, Mapping):
                raise ValueError("Windows platform object identity payload is invalid")
            if set(native) != {
                "volume_serial",
                "file_id",
                "owner_sid",
                "dacl_sha256",
                "trust_policy_sha256",
            }:
                raise ValueError("Windows platform object identity shape is invalid")
            return cls(
                schema=schema,
                platform=platform,
                kind=kind,
                volume_serial=str(native.get("volume_serial", "")),
                file_id=str(native.get("file_id", "")),
                owner_sid=str(native.get("owner_sid", "")),
                dacl_sha256=str(native.get("dacl_sha256", "")),
                trust_policy_sha256=str(native.get("trust_policy_sha256", "")),
            )
        return cls(schema=schema, platform=platform, kind=kind)

    def _validate_posix(self) -> None:
        values = (self.device, self.inode, self.owner, self.mode)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in values
        ):
            raise ValueError("POSIX platform object identity payload is invalid")
        if cast(int, self.mode) > 0o7777:
            raise ValueError("POSIX platform object identity mode is invalid")
        if any(
            value is not None
            for value in (
                self.volume_serial,
                self.file_id,
                self.owner_sid,
                self.dacl_sha256,
                self.trust_policy_sha256,
            )
        ):
            raise ValueError("POSIX platform object identity mixes native payloads")

    def _validate_windows(self) -> None:
        if any(
            value is not None
            for value in (self.device, self.inode, self.owner, self.mode)
        ):
            raise ValueError("Windows platform object identity mixes native payloads")
        if not _lower_hex(self.volume_serial, minimum=1, maximum=16):
            raise ValueError("Windows platform volume identity is invalid")
        if not _lower_hex(self.file_id, minimum=32, maximum=32):
            raise ValueError("Windows platform file identity is invalid")
        if (
            not isinstance(self.owner_sid, str)
            or not self.owner_sid.startswith("S-")
            or not 3 <= len(self.owner_sid) <= 184
            or any(
                ord(character) < 33 or ord(character) > 126
                for character in self.owner_sid
            )
        ):
            raise ValueError("Windows platform owner SID is invalid")
        for label, value in (
            ("DACL", self.dacl_sha256),
            ("trust policy", self.trust_policy_sha256),
        ):
            if not _lower_hex(value, minimum=64, maximum=64):
                raise ValueError(f"Windows platform {label} digest is invalid")


def _identity_int(data: Mapping[str, Any], name: str) -> int:
    value = data.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"platform object identity {name} is invalid")
    return value


def _lower_hex(value: object, *, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and minimum <= len(value) <= maximum
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


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
    """Bounded native publication and deterministic recovery semantics."""

    def ensure_private_directory(self, path: Path) -> Path:
        """Create or validate one account-private native state directory."""

    def open_transaction(
        self,
        path: Path,
        *,
        max_bytes: int,
        create: bool,
    ) -> AtomicStateTransaction:
        """Return an unentered serialized transaction for one protected file."""


@runtime_checkable
class CredentialStorageBackend(PlatformBackend, Protocol):
    """Native, non-ambient credential storage selected by reviewed metadata."""

    def load_credentials(
        self,
        *,
        provider: str,
        target: str,
        allowed_names: Sequence[str],
    ) -> Mapping[str, str]:
        """Load a bounded subset of exact declared credential names."""

    def store_credentials(
        self,
        *,
        provider: str,
        target: str,
        credentials: Mapping[str, str],
    ) -> None:
        """Persist one bounded exact credential mapping for trusted setup."""

    def remove_credentials(
        self,
        *,
        provider: str,
        target: str,
        credential_names: Sequence[str],
    ) -> None:
        """Remove only the selected credential names or protected document."""


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
        """Run one fixed command with native tree and resource supervision."""


@runtime_checkable
class TrustedGitBackend(PlatformBackend, Protocol):
    """Native fixed-command, configuration-isolated Git inspection."""

    def read(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> bytes:
        """Return bounded stdout from one read-only Git inspection."""


@runtime_checkable
class CapsuleIsolationBackend(PlatformBackend, Protocol):
    """Native OS containment for executable capability-capsule workers."""

    @property
    def executable(self) -> Path | None:
        """Return an external containment executable when the backend uses one."""

    @property
    def production_isolated(self) -> bool:
        """Return whether the backend enforces the production OS boundary."""

    def identity_components(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Mapping[str, str | None]:
        """Return exact secret-free artifact digests for promotion binding."""

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
        """Run one bounded request through the backend's isolated worker."""

    def denial_probes(
        self,
        *,
        worker: Path,
        interpreter: Path,
    ) -> Sequence[Mapping[str, str]]:
        """Return OS-enforced denial evidence required by this backend."""


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
    credential_storage: CredentialStorageBackend | None = None
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

    def require_atomic_publication_recovery(
        self,
    ) -> AtomicPublicationRecoveryBackend:
        """Return the atomic-publication backend or fail closed."""

        return cast(
            AtomicPublicationRecoveryBackend,
            self.require_contract(PlatformContract.ATOMIC_PUBLICATION_RECOVERY),
        )

    def require_credential_storage(self) -> CredentialStorageBackend:
        """Return the native credential-storage backend or fail closed."""

        return cast(
            CredentialStorageBackend,
            self.require_contract(PlatformContract.CREDENTIAL_STORAGE),
        )

    def require_process_supervision(self) -> ProcessSupervisionBackend:
        """Return the process-supervision backend or fail closed."""

        return cast(
            ProcessSupervisionBackend,
            self.require_contract(PlatformContract.PROCESS_SUPERVISION),
        )

    def require_trusted_git(self) -> TrustedGitBackend:
        """Return the trusted-Git backend or fail closed."""

        return cast(
            TrustedGitBackend,
            self.require_contract(PlatformContract.TRUSTED_GIT),
        )

    def require_capsule_isolation(self) -> CapsuleIsolationBackend:
        """Return the capsule-isolation backend or fail closed."""

        return cast(
            CapsuleIsolationBackend,
            self.require_contract(PlatformContract.CAPSULE_ISOLATION),
        )

    def _services(self) -> Mapping[PlatformContract, PlatformBackend | None]:
        return MappingProxyType(
            {
                PlatformContract.SECURE_FILESYSTEM: self.secure_filesystem,
                PlatformContract.CROSS_PROCESS_LOCKING: self.cross_process_locking,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY: (
                    self.atomic_publication_recovery
                ),
                PlatformContract.CREDENTIAL_STORAGE: self.credential_storage,
                PlatformContract.PROCESS_SUPERVISION: self.process_supervision,
                PlatformContract.TRUSTED_GIT: self.trusted_git,
                PlatformContract.CAPSULE_ISOLATION: self.capsule_isolation,
            }
        )
