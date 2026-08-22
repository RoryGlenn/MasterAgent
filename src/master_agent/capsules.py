"""Immutable capability-capsule manifests, promotion, and storage.

Generated code is data until a trusted authority signs every deterministic
promotion transition.  This module never imports capsule code.  Execution is
implemented by :mod:`master_agent.capsule_runtime` in a separate, restricted
worker process.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from master_agent.capabilities import CapabilityDefinition
from master_agent.config_sources import ConfigSource
from master_agent.directory_safety import DirectoryIdentity, PinnedDirectory
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import (
    CapabilityCapsuleExecutionBinding,
    DataClassification,
    RiskLevel,
    freeze_json_mapping,
)
from master_agent.platform_runtime import (
    LockMode,
    PlatformContract,
    get_cross_process_locking_backend,
    get_secure_filesystem_backend,
    require_platform_contract,
)
from master_agent.resource_limits import measure_json_resources

if TYPE_CHECKING:
    from master_agent.platform_runtime.windows.filesystem import PinnedWindowsPath

CAPSULE_SCHEMA = "master-agent/capability-capsule@1"
CAPSULE_SPEC_SCHEMA = "master-agent/capability-capsule-spec@1"
DEPENDENCY_LOCK_SCHEMA = "master-agent/capsule-dependency-lock@1"
TEST_SUITE_SCHEMA = "master-agent/capsule-tests@1"
VERIFICATION_SCHEMA = "master-agent/capsule-verification@1"
COMPENSATION_SCHEMA = "master-agent/capsule-compensation@1"
SBOM_FORMAT = "CycloneDX"
SBOM_SPEC_VERSION = "1.5"
ZERO_SHA256 = "0" * 64

_CAPABILITY_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9][a-z0-9_-]*)+")
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")
_SCHEMA_TYPES = frozenset(
    {"array", "boolean", "integer", "number", "object", "string", "string_list"}
)
_HTTP_METHODS = frozenset({"DELETE", "GET", "PATCH", "POST", "PUT"})
_MAX_BUNDLE_FILE_BYTES = 2 * 1024 * 1024
_MAX_MANIFESTS = 16
_MAX_CAPSULE_INPUT_BYTES = 1024 * 1024
_MAX_CAPSULE_OUTPUT_BYTES = 1024 * 1024
_MAX_CAPSULE_MEMORY_BYTES = 512 * 1024 * 1024
_MIN_CAPSULE_MEMORY_BYTES = 32 * 1024 * 1024


class CapsuleState(StrEnum):
    """Authorized lifecycle states for one immutable capsule version."""

    QUARANTINED = "quarantined"
    TESTED = "tested"
    SANDBOX_VALIDATED = "sandbox_validated"
    REVIEWED = "reviewed"
    PUBLISHED = "published"
    ENABLED = "enabled"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class CapsuleRole(StrEnum):
    """Trust roles permitted to sign a capsule transition."""

    GENERATOR = "generator"
    VALIDATOR = "validator"
    SANDBOX_VALIDATOR = "sandbox_validator"
    REVIEWER = "reviewer"
    PUBLISHER = "publisher"
    REVOKER = "revoker"


_STATE_ROLE: dict[CapsuleState, CapsuleRole] = {
    CapsuleState.QUARANTINED: CapsuleRole.GENERATOR,
    CapsuleState.TESTED: CapsuleRole.VALIDATOR,
    CapsuleState.SANDBOX_VALIDATED: CapsuleRole.SANDBOX_VALIDATOR,
    CapsuleState.REVIEWED: CapsuleRole.REVIEWER,
    CapsuleState.PUBLISHED: CapsuleRole.PUBLISHER,
    CapsuleState.ENABLED: CapsuleRole.PUBLISHER,
    CapsuleState.DEPRECATED: CapsuleRole.PUBLISHER,
    CapsuleState.REVOKED: CapsuleRole.REVOKER,
}
_ALLOWED_TRANSITIONS: dict[CapsuleState, frozenset[CapsuleState]] = {
    CapsuleState.QUARANTINED: frozenset({CapsuleState.TESTED, CapsuleState.REVOKED}),
    CapsuleState.TESTED: frozenset(
        {CapsuleState.SANDBOX_VALIDATED, CapsuleState.REVOKED}
    ),
    CapsuleState.SANDBOX_VALIDATED: frozenset(
        {CapsuleState.REVIEWED, CapsuleState.REVOKED}
    ),
    CapsuleState.REVIEWED: frozenset({CapsuleState.PUBLISHED, CapsuleState.REVOKED}),
    CapsuleState.PUBLISHED: frozenset({CapsuleState.ENABLED, CapsuleState.REVOKED}),
    CapsuleState.ENABLED: frozenset({CapsuleState.DEPRECATED, CapsuleState.REVOKED}),
    CapsuleState.DEPRECATED: frozenset({CapsuleState.REVOKED}),
    CapsuleState.REVOKED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class CapsuleSpec:
    """Typed, secret-free contract for one generated capability version."""

    capability_id: str
    version: str
    system: str
    risk: RiskLevel
    input_schema: Mapping[str, str]
    output_schema: Mapping[str, str]
    source_provenance: str
    source_license: str
    publisher: str
    side_effects: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = ()
    allowed_path_prefixes: tuple[str, ...] = ()
    credential_names: tuple[str, ...] = ()
    credential_scopes: tuple[str, ...] = ()
    intents: tuple[str, ...] = ()
    negative_intents: tuple[str, ...] = ()
    data_classification: DataClassification = DataClassification.INTERNAL
    retention_class: str = "ephemeral"
    max_input_bytes: int = 65_536
    max_output_bytes: int = 65_536
    timeout_seconds: int = 5
    cpu_seconds: int = 2
    memory_bytes: int = 134_217_728
    max_processes: int = 1
    schema: str = CAPSULE_SPEC_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CAPSULE_SPEC_SCHEMA:
            raise ValidationError("unsupported capability capsule spec schema")
        if not isinstance(self.risk, RiskLevel) or not isinstance(
            self.data_classification, DataClassification
        ):
            raise ValidationError("capsule risk or classification is malformed")
        if (
            not self.capability_id.isascii()
            or _CAPABILITY_PATTERN.fullmatch(self.capability_id) is None
        ):
            raise ValidationError("capsule capability_id is malformed")
        if _VERSION_PATTERN.fullmatch(self.version) is None:
            raise ValidationError("capsule version must be semantic")
        for name, value in (
            ("system", self.system),
            ("source_provenance", self.source_provenance),
            ("source_license", self.source_license),
            ("publisher", self.publisher),
            ("retention_class", self.retention_class),
        ):
            if not value or value != value.strip() or not value.isascii():
                raise ValidationError(f"capsule {name} is empty or malformed")
        if self.system != self.capability_id.split(".", 1)[0]:
            raise ValidationError("capsule system must match its capability prefix")
        input_schema = _validated_schema(self.input_schema, "input")
        output_schema = _validated_schema(self.output_schema, "output")
        if not input_schema or not output_schema:
            raise ValidationError("capsule input and output schemas must be non-empty")
        object.__setattr__(self, "input_schema", MappingProxyType(input_schema))
        object.__setattr__(self, "output_schema", MappingProxyType(output_schema))
        for name, values in (
            ("side_effects", self.side_effects),
            ("credential_names", self.credential_names),
            ("credential_scopes", self.credential_scopes),
            ("intents", self.intents),
            ("negative_intents", self.negative_intents),
        ):
            _validate_unique_strings(values, f"capsule {name}")
        if not self.intents:
            raise ValidationError("capsule intents must not be empty")
        origins = tuple(
            sorted(_canonical_origin(item) for item in self.allowed_origins)
        )
        methods = tuple(sorted(self.allowed_methods))
        paths = tuple(sorted(self.allowed_path_prefixes))
        _validate_unique_strings(origins, "capsule allowed_origins")
        _validate_unique_strings(methods, "capsule allowed_methods")
        _validate_unique_strings(paths, "capsule allowed_path_prefixes")
        if any(method not in _HTTP_METHODS for method in methods):
            raise ValidationError("capsule allowed_methods contains an unsafe method")
        if any(
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
            for path in paths
        ):
            raise ValidationError("capsule allowed_path_prefixes is malformed")
        if bool(origins) != bool(methods) or bool(origins) != bool(paths):
            raise ValidationError(
                "capsule provider origins, methods, and paths must be declared together"
            )
        if not origins and (self.credential_names or self.credential_scopes):
            raise ValidationError("a network-free capsule cannot request credentials")
        if self.risk in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}:
            if self.side_effects:
                raise ValidationError("read/local capsules cannot declare side effects")
        elif not self.side_effects:
            raise ValidationError("side-effecting capsules must declare exact effects")
        for limit_name, limit_value, minimum, maximum in (
            ("max_input_bytes", self.max_input_bytes, 1, _MAX_CAPSULE_INPUT_BYTES),
            ("max_output_bytes", self.max_output_bytes, 1, _MAX_CAPSULE_OUTPUT_BYTES),
            ("timeout_seconds", self.timeout_seconds, 1, 30),
            ("cpu_seconds", self.cpu_seconds, 1, 10),
            (
                "memory_bytes",
                self.memory_bytes,
                _MIN_CAPSULE_MEMORY_BYTES,
                _MAX_CAPSULE_MEMORY_BYTES,
            ),
            ("max_processes", self.max_processes, 1, 4),
        ):
            if (
                not isinstance(limit_value, int)
                or isinstance(limit_value, bool)
                or not minimum <= limit_value <= maximum
            ):
                raise ValidationError(f"capsule {limit_name} is outside its safe bound")
        object.__setattr__(self, "allowed_origins", origins)
        object.__setattr__(self, "allowed_methods", methods)
        object.__setattr__(self, "allowed_path_prefixes", paths)

    @property
    def policy_contract_sha256(self) -> str:
        """Digest every execution-affecting typed policy field."""

        policy = {
            "capability_id": self.capability_id,
            "version": self.version,
            "system": self.system,
            "risk": str(self.risk),
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema),
            "side_effects": list(self.side_effects),
            "allowed_origins": list(self.allowed_origins),
            "allowed_methods": list(self.allowed_methods),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "credential_names": list(self.credential_names),
            "credential_scopes": list(self.credential_scopes),
            "intents": list(self.intents),
            "negative_intents": list(self.negative_intents),
            "data_classification": str(self.data_classification),
            "retention_class": self.retention_class,
            "source_provenance": self.source_provenance,
            "source_license": self.source_license,
            "publisher": self.publisher,
            "limits": self.limits_dict(),
        }
        return _sha256_json(policy)

    def limits_dict(self) -> dict[str, int]:
        """Return worker limits in canonical form."""

        return {
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "timeout_seconds": self.timeout_seconds,
            "cpu_seconds": self.cpu_seconds,
            "memory_bytes": self.memory_bytes,
            "max_processes": self.max_processes,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete typed capsule contract."""

        return {
            "schema": self.schema,
            "capability_id": self.capability_id,
            "version": self.version,
            "system": self.system,
            "risk": str(self.risk),
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema),
            "source_provenance": self.source_provenance,
            "source_license": self.source_license,
            "publisher": self.publisher,
            "side_effects": list(self.side_effects),
            "allowed_origins": list(self.allowed_origins),
            "allowed_methods": list(self.allowed_methods),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "credential_names": list(self.credential_names),
            "credential_scopes": list(self.credential_scopes),
            "intents": list(self.intents),
            "negative_intents": list(self.negative_intents),
            "data_classification": str(self.data_classification),
            "retention_class": self.retention_class,
            **self.limits_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CapsuleSpec:
        """Parse one strict capsule contract."""

        return cls(
            schema=str(data.get("schema", "")),
            capability_id=_required_string(data, "capability_id"),
            version=_required_string(data, "version"),
            system=_required_string(data, "system"),
            risk=RiskLevel(_required_string(data, "risk")),
            input_schema=_string_mapping(data, "input_schema"),
            output_schema=_string_mapping(data, "output_schema"),
            source_provenance=_required_string(data, "source_provenance"),
            source_license=_required_string(data, "source_license"),
            publisher=_required_string(data, "publisher"),
            side_effects=_string_tuple(data, "side_effects"),
            allowed_origins=_string_tuple(data, "allowed_origins"),
            allowed_methods=_string_tuple(data, "allowed_methods"),
            allowed_path_prefixes=_string_tuple(data, "allowed_path_prefixes"),
            credential_names=_string_tuple(data, "credential_names"),
            credential_scopes=_string_tuple(data, "credential_scopes"),
            intents=_string_tuple(data, "intents"),
            negative_intents=_string_tuple(data, "negative_intents"),
            data_classification=DataClassification(
                _required_string(data, "data_classification")
            ),
            retention_class=_required_string(data, "retention_class"),
            max_input_bytes=_positive_int(data, "max_input_bytes"),
            max_output_bytes=_positive_int(data, "max_output_bytes"),
            timeout_seconds=_positive_int(data, "timeout_seconds"),
            cpu_seconds=_positive_int(data, "cpu_seconds"),
            memory_bytes=_positive_int(data, "memory_bytes"),
            max_processes=_positive_int(data, "max_processes"),
        )


@dataclass(frozen=True, slots=True)
class CapsuleBundle:
    """Bounded generated source and its complete validation artifacts."""

    spec: CapsuleSpec
    source: bytes
    dependency_lock: Mapping[str, Any]
    sbom: Mapping[str, Any]
    test_suite: Mapping[str, Any]
    verification_contract: Mapping[str, Any]
    compensation_contract: Mapping[str, Any]
    third_party_notices: str

    def __post_init__(self) -> None:
        if not self.source or len(self.source) > _MAX_BUNDLE_FILE_BYTES:
            raise ValidationError("capsule source is empty or exceeds 2 MiB")
        try:
            self.source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValidationError("capsule source must be UTF-8") from error
        for name, value in (
            ("dependency_lock", self.dependency_lock),
            ("sbom", self.sbom),
            ("test_suite", self.test_suite),
            ("verification_contract", self.verification_contract),
            ("compensation_contract", self.compensation_contract),
        ):
            measure_json_resources(
                value,
                context=f"capsule {name}",
                max_bytes=_MAX_BUNDLE_FILE_BYTES,
            )
            encoded = _canonical_json(value)
            if len(encoded) > _MAX_BUNDLE_FILE_BYTES:
                raise ValidationError(f"capsule {name} exceeds 2 MiB")
            object.__setattr__(self, name, freeze_json_mapping(value))
        if len(self.third_party_notices.encode("utf-8")) > _MAX_BUNDLE_FILE_BYTES:
            raise ValidationError("capsule third-party notices exceed 2 MiB")

    @property
    def source_sha256(self) -> str:
        return hashlib.sha256(self.source).hexdigest()

    @property
    def dependency_lock_sha256(self) -> str:
        return _sha256_json(self.dependency_lock)

    @property
    def sbom_sha256(self) -> str:
        return _sha256_json(self.sbom)

    @property
    def test_suite_sha256(self) -> str:
        return _sha256_json(self.test_suite)

    @property
    def verification_contract_sha256(self) -> str:
        return _sha256_json(self.verification_contract)

    @property
    def compensation_contract_sha256(self) -> str:
        return _sha256_json(self.compensation_contract)

    @property
    def notices_sha256(self) -> str:
        return hashlib.sha256(self.third_party_notices.encode("utf-8")).hexdigest()

    @property
    def artifact_sha256(self) -> str:
        return _sha256_json(
            {
                "capsule.json": _sha256_json(self.spec.to_dict()),
                "program.py": self.source_sha256,
                "dependencies.lock.json": self.dependency_lock_sha256,
                "sbom.cdx.json": self.sbom_sha256,
                "tests.json": self.test_suite_sha256,
                "verification.json": self.verification_contract_sha256,
                "compensation.json": self.compensation_contract_sha256,
                "THIRD_PARTY_NOTICES.md": self.notices_sha256,
            }
        )

    @classmethod
    def from_directory(cls, root: Path) -> CapsuleBundle:
        """Read an owner-controlled, symlink-free generated bundle."""

        require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
        if os.name == "nt":
            from master_agent.platform_runtime.windows.filesystem import (
                WindowsSecureFilesystemBackend,
            )

            backend = get_secure_filesystem_backend()
            if not isinstance(backend, WindowsSecureFilesystemBackend):
                raise ConfigurationError(
                    "native Windows secure filesystem is unavailable"
                )
            try:
                with backend.pin_directory(root, require_private=True) as pinned:
                    return cls._from_windows_directory(pinned)
            except ConfigurationError:
                raise
            except OSError as error:
                raise ConfigurationError("capsule directory is unavailable") from error
        descriptor = _open_private_directory(root)
        try:
            return cls._from_descriptor(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def _from_windows_directory(
        cls,
        directory: PinnedWindowsPath,
    ) -> CapsuleBundle:
        """Read the fixed artifact set from one retained native Windows pin."""

        spec = CapsuleSpec.from_dict(
            _decode_json(_read_windows_regular(directory, "capsule.json"))
        )
        return cls(
            spec=spec,
            source=_read_windows_regular(directory, "program.py"),
            dependency_lock=_decode_json(
                _read_windows_regular(directory, "dependencies.lock.json")
            ),
            sbom=_decode_json(_read_windows_regular(directory, "sbom.cdx.json")),
            test_suite=_decode_json(_read_windows_regular(directory, "tests.json")),
            verification_contract=_decode_json(
                _read_windows_regular(directory, "verification.json")
            ),
            compensation_contract=_decode_json(
                _read_windows_regular(directory, "compensation.json")
            ),
            third_party_notices=_read_windows_regular(
                directory,
                "THIRD_PARTY_NOTICES.md",
            ).decode("utf-8"),
        )

    @classmethod
    def _from_descriptor(cls, descriptor: int) -> CapsuleBundle:
        """Read the fixed artifact set relative to one already-pinned directory."""

        spec = CapsuleSpec.from_dict(
            _decode_json(_read_regular_at(descriptor, "capsule.json"))
        )
        return cls(
            spec=spec,
            source=_read_regular_at(descriptor, "program.py"),
            dependency_lock=_decode_json(
                _read_regular_at(descriptor, "dependencies.lock.json")
            ),
            sbom=_decode_json(_read_regular_at(descriptor, "sbom.cdx.json")),
            test_suite=_decode_json(_read_regular_at(descriptor, "tests.json")),
            verification_contract=_decode_json(
                _read_regular_at(descriptor, "verification.json")
            ),
            compensation_contract=_decode_json(
                _read_regular_at(descriptor, "compensation.json")
            ),
            third_party_notices=_read_regular_at(
                descriptor, "THIRD_PARTY_NOTICES.md"
            ).decode("utf-8"),
        )


@dataclass(frozen=True, slots=True)
class CapsuleManifest:
    """One signed immutable state in a capsule promotion chain."""

    spec: CapsuleSpec
    state: CapsuleState
    sequence: int
    source_sha256: str
    artifact_sha256: str
    dependency_lock_sha256: str
    sbom_sha256: str
    test_suite_sha256: str
    validation_result_sha256: str
    sandbox_validation_sha256: str
    verification_contract_sha256: str
    compensation_contract_sha256: str
    notices_sha256: str
    policy_contract_sha256: str
    worker_sha256: str
    environment: str
    created_at: str
    transitioned_at: str
    actor: str
    role: CapsuleRole
    reviewer: str
    previous_manifest_sha256: str | None
    signer_key_id: str
    signature: str = ""
    schema: str = CAPSULE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CAPSULE_SCHEMA:
            raise ValidationError("unsupported capability capsule schema")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool):
            raise ValidationError("capsule sequence must be an integer")
        if self.sequence < 0:
            raise ValidationError("capsule sequence must not be negative")
        if _STATE_ROLE[self.state] is not self.role:
            raise ValidationError("capsule state was signed with the wrong role")
        for name, value in (
            ("environment", self.environment),
            ("actor", self.actor),
            ("signer_key_id", self.signer_key_id),
        ):
            if not value or value != value.strip():
                raise ValidationError(f"capsule {name} is empty or malformed")
        created_at = _parse_timestamp(self.created_at, "capsule created_at")
        transitioned_at = _parse_timestamp(
            self.transitioned_at, "capsule transitioned_at"
        )
        if transitioned_at < created_at:
            raise ValidationError("capsule transition predates capsule creation")
        if self.sequence == 0:
            if self.state is not CapsuleState.QUARANTINED:
                raise ValidationError("the first capsule state must be quarantined")
            if self.previous_manifest_sha256 is not None:
                raise ValidationError(
                    "the first capsule state cannot have a predecessor"
                )
        else:
            if self.previous_manifest_sha256 is None:
                raise ValidationError("a promoted capsule state requires a predecessor")
            _validate_sha256(self.previous_manifest_sha256, "previous manifest")
        for name, value in (
            ("source_sha256", self.source_sha256),
            ("artifact_sha256", self.artifact_sha256),
            ("dependency_lock_sha256", self.dependency_lock_sha256),
            ("sbom_sha256", self.sbom_sha256),
            ("test_suite_sha256", self.test_suite_sha256),
            ("validation_result_sha256", self.validation_result_sha256),
            ("sandbox_validation_sha256", self.sandbox_validation_sha256),
            ("verification_contract_sha256", self.verification_contract_sha256),
            ("compensation_contract_sha256", self.compensation_contract_sha256),
            ("notices_sha256", self.notices_sha256),
            ("policy_contract_sha256", self.policy_contract_sha256),
            ("worker_sha256", self.worker_sha256),
        ):
            _validate_sha256(value, f"capsule {name}")
        if (
            self.state
            in {
                CapsuleState.TESTED,
                CapsuleState.SANDBOX_VALIDATED,
                CapsuleState.REVIEWED,
                CapsuleState.PUBLISHED,
                CapsuleState.ENABLED,
                CapsuleState.DEPRECATED,
            }
            and self.validation_result_sha256 == ZERO_SHA256
        ):
            raise ValidationError("tested capsule state requires validation evidence")
        if (
            self.state
            in {
                CapsuleState.SANDBOX_VALIDATED,
                CapsuleState.REVIEWED,
                CapsuleState.PUBLISHED,
                CapsuleState.ENABLED,
                CapsuleState.DEPRECATED,
            }
            and self.sandbox_validation_sha256 == ZERO_SHA256
        ):
            raise ValidationError("promoted capsule requires sandbox evidence")
        if self.state in {
            CapsuleState.REVIEWED,
            CapsuleState.PUBLISHED,
            CapsuleState.ENABLED,
            CapsuleState.DEPRECATED,
        } or (self.state is CapsuleState.REVOKED and bool(self.reviewer)):
            if not self.reviewer or (
                self.reviewer.casefold() == self.spec.publisher.casefold()
            ):
                raise ValidationError(
                    "reviewed capsule requires a distinct reviewer identity"
                )
        elif self.reviewer:
            raise ValidationError("capsule reviewer cannot appear before review")
        if self.signature:
            _validate_sha256(self.signature, "capsule signature")

    @property
    def manifest_sha256(self) -> str:
        """Digest the signed immutable manifest."""

        if not self.signature:
            raise ValidationError("unsigned capsule has no manifest identity")
        return _sha256_json(self.to_dict())

    def unsigned_dict(self) -> dict[str, Any]:
        """Return canonical signature material without the signature field."""

        return {
            "schema": self.schema,
            "spec": self.spec.to_dict(),
            "state": str(self.state),
            "sequence": self.sequence,
            "source_sha256": self.source_sha256,
            "artifact_sha256": self.artifact_sha256,
            "dependency_lock_sha256": self.dependency_lock_sha256,
            "sbom_sha256": self.sbom_sha256,
            "test_suite_sha256": self.test_suite_sha256,
            "validation_result_sha256": self.validation_result_sha256,
            "sandbox_validation_sha256": self.sandbox_validation_sha256,
            "verification_contract_sha256": self.verification_contract_sha256,
            "compensation_contract_sha256": self.compensation_contract_sha256,
            "notices_sha256": self.notices_sha256,
            "policy_contract_sha256": self.policy_contract_sha256,
            "worker_sha256": self.worker_sha256,
            "environment": self.environment,
            "created_at": self.created_at,
            "transitioned_at": self.transitioned_at,
            "actor": self.actor,
            "role": str(self.role),
            "reviewer": self.reviewer,
            "previous_manifest_sha256": self.previous_manifest_sha256,
            "signer_key_id": self.signer_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the signed capsule manifest."""

        return {**self.unsigned_dict(), "signature": self.signature}

    def binding(
        self,
        *,
        authenticated_principal: str = "local:operator",
        agent_identity: str = "master-agent",
        tenant_id: str = "local",
        provider_account_id: str = "none",
        credential_provider_id: str = "none",
    ) -> CapabilityCapsuleExecutionBinding:
        """Return the complete plan/approval execution binding."""

        if self.state is not CapsuleState.ENABLED:
            raise ValidationError("only an enabled capsule can bind to a plan")
        return CapabilityCapsuleExecutionBinding(
            capability_id=self.spec.capability_id,
            version=self.spec.version,
            risk=self.spec.risk,
            manifest_sha256=self.manifest_sha256,
            source_sha256=self.source_sha256,
            artifact_sha256=self.artifact_sha256,
            dependency_lock_sha256=self.dependency_lock_sha256,
            sbom_sha256=self.sbom_sha256,
            test_suite_sha256=self.test_suite_sha256,
            validation_result_sha256=self.validation_result_sha256,
            sandbox_validation_sha256=self.sandbox_validation_sha256,
            verification_contract_sha256=self.verification_contract_sha256,
            compensation_contract_sha256=self.compensation_contract_sha256,
            policy_contract_sha256=self.policy_contract_sha256,
            worker_sha256=self.worker_sha256,
            publisher=self.spec.publisher,
            reviewer=self.reviewer,
            signer_key_id=self.signer_key_id,
            authenticated_principal=authenticated_principal,
            agent_identity=agent_identity,
            tenant_id=tenant_id,
            provider_account_id=provider_account_id,
            credential_provider_id=credential_provider_id,
            allowed_origins=self.spec.allowed_origins,
            allowed_methods=self.spec.allowed_methods,
            allowed_path_prefixes=self.spec.allowed_path_prefixes,
            credential_names=self.spec.credential_names,
            credential_scopes=self.spec.credential_scopes,
            data_classification=self.spec.data_classification,
            retention_class=self.spec.retention_class,
            max_input_bytes=self.spec.max_input_bytes,
            max_output_bytes=self.spec.max_output_bytes,
            timeout_seconds=self.spec.timeout_seconds,
            cpu_seconds=self.spec.cpu_seconds,
            memory_bytes=self.spec.memory_bytes,
            max_processes=self.spec.max_processes,
        )

    def capability_definition(self) -> CapabilityDefinition:
        """Translate the enabled capsule into the normal typed catalog contract."""

        if self.state is not CapsuleState.ENABLED:
            raise ValidationError("unpromoted capsule cannot enter the catalog")
        return CapabilityDefinition(
            name=self.spec.capability_id,
            enabled=True,
            authentication="local",
            risk=self.spec.risk,
            reversible=bool(self.spec.side_effects),
            target_system=self.spec.system,
            target_resource_types=("capsule_request",),
            parameter_schema=self.spec.input_schema,
            max_input_bytes=(
                self.spec.max_input_bytes
                if self.spec.risk is RiskLevel.LOCAL_GENERATION
                else None
            ),
            max_output_bytes=(
                self.spec.max_output_bytes
                if self.spec.risk is RiskLevel.LOCAL_GENERATION
                else None
            ),
            description=(
                f"Promoted capability capsule {self.spec.capability_id} "
                f"version {self.spec.version}"
            ),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CapsuleManifest:
        """Parse one signed immutable manifest."""

        return cls(
            schema=_required_string(data, "schema"),
            spec=CapsuleSpec.from_dict(_mapping(data, "spec")),
            state=CapsuleState(_required_string(data, "state")),
            sequence=_nonnegative_int(data, "sequence"),
            source_sha256=_required_string(data, "source_sha256"),
            artifact_sha256=_required_string(data, "artifact_sha256"),
            dependency_lock_sha256=_required_string(data, "dependency_lock_sha256"),
            sbom_sha256=_required_string(data, "sbom_sha256"),
            test_suite_sha256=_required_string(data, "test_suite_sha256"),
            validation_result_sha256=_required_string(data, "validation_result_sha256"),
            sandbox_validation_sha256=_required_string(
                data, "sandbox_validation_sha256"
            ),
            verification_contract_sha256=_required_string(
                data, "verification_contract_sha256"
            ),
            compensation_contract_sha256=_required_string(
                data, "compensation_contract_sha256"
            ),
            notices_sha256=_required_string(data, "notices_sha256"),
            policy_contract_sha256=_required_string(data, "policy_contract_sha256"),
            worker_sha256=_required_string(data, "worker_sha256"),
            environment=_required_string(data, "environment"),
            created_at=_required_string(data, "created_at"),
            transitioned_at=_required_string(data, "transitioned_at"),
            actor=_required_string(data, "actor"),
            role=CapsuleRole(_required_string(data, "role")),
            reviewer=str(data.get("reviewer", "")),
            previous_manifest_sha256=(
                str(data["previous_manifest_sha256"])
                if data.get("previous_manifest_sha256") is not None
                else None
            ),
            signer_key_id=_required_string(data, "signer_key_id"),
            signature=_required_string(data, "signature"),
        )


@dataclass(frozen=True, slots=True)
class CapsuleAuthority:
    """Authenticated promotion identity; secret values never serialize."""

    key_id: str
    subject: str
    roles: frozenset[CapsuleRole]
    environments: frozenset[str]
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if _IDENTIFIER_PATTERN.fullmatch(self.key_id) is None:
            raise ConfigurationError("capsule authority key_id is malformed")
        if not self.subject or self.subject != self.subject.strip():
            raise ConfigurationError("capsule authority subject is malformed")
        if not self.roles or not self.environments:
            raise ConfigurationError(
                "capsule authority roles/environments are required"
            )
        if len(self.secret) < 32:
            raise ConfigurationError("capsule authority secret requires 32 bytes")

    def sign(self, manifest: CapsuleManifest) -> CapsuleManifest:
        """Sign one state only when this authority owns the required role."""

        required = _STATE_ROLE[manifest.state]
        if required not in self.roles:
            raise ConfigurationError(
                f"capsule authority {self.key_id} lacks role {required}"
            )
        if manifest.environment not in self.environments:
            raise ConfigurationError(
                "capsule authority is not valid in this environment"
            )
        if manifest.actor != self.subject or manifest.signer_key_id != self.key_id:
            raise ConfigurationError("capsule manifest actor does not match its signer")
        signature = hmac.new(
            self.secret,
            _canonical_json(manifest.unsigned_dict()),
            hashlib.sha256,
        ).hexdigest()
        return replace(manifest, signature=signature)


@dataclass(frozen=True, slots=True)
class CapsuleTrustStore:
    """Explicit trusted promotion authorities."""

    authorities: Mapping[str, CapsuleAuthority]

    def __post_init__(self) -> None:
        selected = dict(self.authorities)
        if not selected or any(key != item.key_id for key, item in selected.items()):
            raise ConfigurationError(
                "capsule trust authorities are empty or inconsistent"
            )
        object.__setattr__(self, "authorities", MappingProxyType(selected))

    def verify(self, manifest: CapsuleManifest) -> None:
        """Authenticate a manifest's signature, role, actor, and environment."""

        try:
            authority = self.authorities[manifest.signer_key_id]
        except KeyError as error:
            raise ConfigurationError("capsule signer is not trusted") from error
        expected = authority.sign(replace(manifest, signature="")).signature
        if not hmac.compare_digest(expected, manifest.signature):
            raise ConfigurationError("capsule signature is invalid")


@dataclass(frozen=True, slots=True)
class LicensePolicy:
    """Allowed dependency licenses and notice requirements."""

    allowed_spdx: frozenset[str]
    denied_spdx: frozenset[str]
    deny_unknown: bool = True
    require_notices: bool = True

    def __post_init__(self) -> None:
        """Reject ambiguous or unusable admission policy."""

        if not self.allowed_spdx:
            raise ConfigurationError("dependency license allowlist is empty")
        overlap = self.allowed_spdx & self.denied_spdx
        if overlap:
            raise ConfigurationError(
                "dependency license policy both allows and denies: "
                + ", ".join(sorted(overlap))
            )
        for license_id in self.allowed_spdx | self.denied_spdx:
            if not license_id or license_id != license_id.strip():
                raise ConfigurationError("dependency license identifier is malformed")

    @classmethod
    def from_toml(cls, source: ConfigSource) -> LicensePolicy:
        """Load the repository dependency-license policy."""

        with source.open("rb") as handle:
            raw = tomllib.load(handle)
        policy = raw.get("policy")
        if not isinstance(policy, Mapping):
            raise ConfigurationError("dependency license policy is absent")
        return cls(
            allowed_spdx=frozenset(_toml_string_list(policy, "allowed_spdx")),
            denied_spdx=frozenset(_toml_string_list(policy, "denied_spdx")),
            deny_unknown=_strict_bool(policy.get("deny_unknown"), "deny_unknown"),
            require_notices=_strict_bool(
                policy.get("require_notices"), "require_notices"
            ),
        )

    def permits(self, license_id: str) -> bool:
        """Return whether one exact SPDX/license reference is allowed."""

        if license_id in self.denied_spdx:
            return False
        if license_id in self.allowed_spdx:
            return True
        return not self.deny_unknown


def create_quarantined_manifest(
    bundle: CapsuleBundle,
    *,
    authority: CapsuleAuthority,
    environment: str,
    worker_sha256: str,
    now: datetime | None = None,
) -> CapsuleManifest:
    """Create and sign the first immutable quarantine state."""

    _validate_sha256(worker_sha256, "capsule worker identity")
    timestamp = _timestamp(now)
    manifest = CapsuleManifest(
        spec=bundle.spec,
        state=CapsuleState.QUARANTINED,
        sequence=0,
        source_sha256=bundle.source_sha256,
        artifact_sha256=bundle.artifact_sha256,
        dependency_lock_sha256=bundle.dependency_lock_sha256,
        sbom_sha256=bundle.sbom_sha256,
        test_suite_sha256=bundle.test_suite_sha256,
        validation_result_sha256=ZERO_SHA256,
        sandbox_validation_sha256=ZERO_SHA256,
        verification_contract_sha256=bundle.verification_contract_sha256,
        compensation_contract_sha256=bundle.compensation_contract_sha256,
        notices_sha256=bundle.notices_sha256,
        policy_contract_sha256=bundle.spec.policy_contract_sha256,
        worker_sha256=worker_sha256,
        environment=environment,
        created_at=timestamp,
        transitioned_at=timestamp,
        actor=authority.subject,
        role=CapsuleRole.GENERATOR,
        reviewer="",
        previous_manifest_sha256=None,
        signer_key_id=authority.key_id,
    )
    return authority.sign(manifest)


def advance_manifest(
    current: CapsuleManifest,
    target: CapsuleState,
    *,
    authority: CapsuleAuthority,
    trust: CapsuleTrustStore,
    validation_result_sha256: str | None = None,
    sandbox_validation_sha256: str | None = None,
    reviewer: str | None = None,
    now: datetime | None = None,
) -> CapsuleManifest:
    """Authorize one deterministic promotion, deprecation, or revocation."""

    trust.verify(current)
    if target not in _ALLOWED_TRANSITIONS[current.state]:
        raise ConfigurationError(
            f"capsule transition {current.state} -> {target} is not allowed"
        )
    validation_digest = validation_result_sha256 or current.validation_result_sha256
    sandbox_digest = sandbox_validation_sha256 or current.sandbox_validation_sha256
    _validate_sha256(validation_digest, "capsule validation evidence")
    _validate_sha256(sandbox_digest, "capsule sandbox evidence")
    selected_reviewer = current.reviewer
    if target is CapsuleState.REVIEWED:
        selected_reviewer = (reviewer or authority.subject).strip()
    elif reviewer is not None and reviewer != current.reviewer:
        raise ConfigurationError("capsule reviewer can change only during review")
    transitioned_at = _timestamp(now)
    if _parse_timestamp(transitioned_at, "capsule transitioned_at") < _parse_timestamp(
        current.transitioned_at, "current capsule transitioned_at"
    ):
        raise ConfigurationError("capsule transition timestamp moved backwards")
    manifest = replace(
        current,
        state=target,
        sequence=current.sequence + 1,
        validation_result_sha256=validation_digest,
        sandbox_validation_sha256=sandbox_digest,
        transitioned_at=transitioned_at,
        actor=authority.subject,
        role=_STATE_ROLE[target],
        reviewer=selected_reviewer,
        previous_manifest_sha256=current.manifest_sha256,
        signer_key_id=authority.key_id,
        signature="",
    )
    return authority.sign(manifest)


def _require_capsule_store_platform() -> None:
    """Require every native contract used by persistent capsule storage."""

    get_secure_filesystem_backend()
    get_cross_process_locking_backend()
    require_platform_contract(PlatformContract.ATOMIC_PUBLICATION_RECOVERY)


class CapsuleStore:
    """Owner-private append-only capsule artifacts and signed state chains."""

    def __init__(self, root: Path) -> None:
        _require_capsule_store_platform()
        self._root_anchor = _private_root(root)
        self.root = self._root_anchor.path

    def install(
        self,
        bundle: CapsuleBundle,
        manifest: CapsuleManifest,
        *,
        trust: CapsuleTrustStore,
    ) -> Path:
        """Install one quarantined immutable bundle without overwriting files."""

        _require_capsule_store_platform()
        trust.verify(manifest)
        if manifest.state is not CapsuleState.QUARANTINED:
            raise ConfigurationError("capsule install requires quarantined state")
        _verify_bundle_identity(bundle, manifest)
        identity = self._capsule_name(
            manifest.spec.capability_id, manifest.spec.version
        )
        root_descriptor = self._root_anchor.duplicate_fd()
        try:
            try:
                os.mkdir(identity, mode=0o700, dir_fd=root_descriptor)
            except FileExistsError:
                raise ConfigurationError(
                    "capability capsule version is already installed"
                ) from None
            descriptor = _open_private_directory_at(root_descriptor, identity)
        finally:
            os.close(root_descriptor)
        try:
            get_cross_process_locking_backend().acquire(
                descriptor,
                mode=LockMode.EXCLUSIVE,
            )
            artifacts = {
                "capsule.json": _canonical_json(bundle.spec.to_dict()),
                "program.py": bundle.source,
                "dependencies.lock.json": _canonical_json(bundle.dependency_lock),
                "sbom.cdx.json": _canonical_json(bundle.sbom),
                "tests.json": _canonical_json(bundle.test_suite),
                "verification.json": _canonical_json(bundle.verification_contract),
                "compensation.json": _canonical_json(bundle.compensation_contract),
                "THIRD_PARTY_NOTICES.md": bundle.third_party_notices.encode("utf-8"),
            }
            for name, payload in artifacts.items():
                _write_private_at(descriptor, name, payload)
            filename = self._append_manifest_at(
                descriptor,
                manifest,
                trust=trust,
                existing=(),
            )
        finally:
            os.close(descriptor)
        return (
            self._capsule_directory(manifest.spec.capability_id, manifest.spec.version)
            / filename
        )

    def append_manifest(
        self,
        manifest: CapsuleManifest,
        *,
        trust: CapsuleTrustStore,
    ) -> Path:
        """Append one authenticated transition after verifying the entire chain."""

        _require_capsule_store_platform()
        trust.verify(manifest)
        descriptor = self._open_capsule(
            manifest.spec.capability_id, manifest.spec.version
        )
        try:
            get_cross_process_locking_backend().acquire(
                descriptor,
                mode=LockMode.EXCLUSIVE,
            )
            bundle = CapsuleBundle._from_descriptor(descriptor)
            _verify_bundle_identity(bundle, manifest)
            existing = self._manifests_at(
                descriptor,
                manifest.spec.capability_id,
                manifest.spec.version,
                trust=trust,
            )
            filename = self._append_manifest_at(
                descriptor,
                manifest,
                trust=trust,
                existing=existing,
            )
        finally:
            os.close(descriptor)
        return (
            self._capsule_directory(manifest.spec.capability_id, manifest.spec.version)
            / filename
        )

    def load_bundle(self, capability_id: str, version: str) -> CapsuleBundle:
        """Re-read and authenticate the fixed artifact set without following links."""

        _require_capsule_store_platform()
        descriptor = self._open_capsule(capability_id, version)
        try:
            get_cross_process_locking_backend().acquire(
                descriptor,
                mode=LockMode.SHARED,
            )
            return CapsuleBundle._from_descriptor(descriptor)
        finally:
            os.close(descriptor)

    def manifests(
        self,
        capability_id: str,
        version: str,
        *,
        trust: CapsuleTrustStore,
    ) -> tuple[CapsuleManifest, ...]:
        """Load and authenticate a complete bounded promotion chain."""

        _require_capsule_store_platform()
        descriptor = self._open_capsule(capability_id, version)
        try:
            get_cross_process_locking_backend().acquire(
                descriptor,
                mode=LockMode.SHARED,
            )
            return self._manifests_at(
                descriptor,
                capability_id,
                version,
                trust=trust,
            )
        finally:
            os.close(descriptor)

    def resolve_enabled(
        self,
        capability_id: str,
        version: str,
        manifest_sha256: str,
        *,
        trust: CapsuleTrustStore,
    ) -> tuple[CapsuleManifest, CapsuleBundle]:
        """Resolve only the exact latest enabled immutable manifest."""

        _require_capsule_store_platform()
        _validate_sha256(manifest_sha256, "requested capsule manifest")
        descriptor = self._open_capsule(capability_id, version)
        try:
            get_cross_process_locking_backend().acquire(
                descriptor,
                mode=LockMode.SHARED,
            )
            manifests = self._manifests_at(
                descriptor,
                capability_id,
                version,
                trust=trust,
            )
            if not manifests:
                raise ConfigurationError("capability capsule is not installed")
            current = manifests[-1]
            if current.state in {CapsuleState.DEPRECATED, CapsuleState.REVOKED}:
                raise ConfigurationError(f"capability capsule is {current.state}")
            if current.state is not CapsuleState.ENABLED:
                raise ConfigurationError(
                    "capability capsule is not promoted and enabled"
                )
            if current.manifest_sha256 != manifest_sha256:
                raise ConfigurationError(
                    "requested capsule digest is not the enabled version"
                )
            bundle = CapsuleBundle._from_descriptor(descriptor)
            _verify_bundle_identity(bundle, current)
            return current, bundle
        finally:
            os.close(descriptor)

    def _open_capsule(self, capability_id: str, version: str) -> int:
        root_descriptor = self._root_anchor.duplicate_fd()
        try:
            return _open_private_directory_at(
                root_descriptor,
                self._capsule_name(capability_id, version),
            )
        finally:
            os.close(root_descriptor)

    def _manifests_at(
        self,
        descriptor: int,
        capability_id: str,
        version: str,
        *,
        trust: CapsuleTrustStore,
    ) -> tuple[CapsuleManifest, ...]:
        try:
            names = sorted(
                name
                for name in os.listdir(descriptor)
                if name.endswith(".manifest.json")
            )
        except OSError as error:
            raise ConfigurationError(
                "capsule manifest directory is unavailable"
            ) from error
        if len(names) > _MAX_MANIFESTS:
            raise ConfigurationError("capsule promotion chain exceeds 16 states")
        manifests: list[CapsuleManifest] = []
        for name in names:
            manifest = CapsuleManifest.from_dict(
                _decode_json(_read_regular_at(descriptor, name))
            )
            trust.verify(manifest)
            if name != self._manifest_filename(manifest):
                raise ConfigurationError("capsule manifest filename digest drifted")
            if (
                manifest.spec.capability_id != capability_id
                or manifest.spec.version != version
            ):
                raise ConfigurationError("capsule manifest identity drifted")
            if manifests:
                previous = manifests[-1]
                if (
                    manifest.sequence != previous.sequence + 1
                    or manifest.previous_manifest_sha256 != previous.manifest_sha256
                    or manifest.state not in _ALLOWED_TRANSITIONS[previous.state]
                ):
                    raise ConfigurationError("capsule promotion chain is invalid")
            elif manifest.sequence != 0:
                raise ConfigurationError("capsule promotion chain starts after zero")
            manifests.append(manifest)
        return tuple(manifests)

    def _append_manifest_at(
        self,
        descriptor: int,
        manifest: CapsuleManifest,
        *,
        trust: CapsuleTrustStore,
        existing: Sequence[CapsuleManifest],
    ) -> str:
        trust.verify(manifest)
        if existing:
            current = existing[-1]
            if (
                manifest.sequence != current.sequence + 1
                or manifest.previous_manifest_sha256 != current.manifest_sha256
                or manifest.state not in _ALLOWED_TRANSITIONS[current.state]
            ):
                raise ConfigurationError("capsule promotion chain is not contiguous")
        elif manifest.sequence != 0:
            raise ConfigurationError(
                "capsule promotion chain is missing its first state"
            )
        filename = self._manifest_filename(manifest)
        _write_private_at(descriptor, filename, _canonical_json(manifest.to_dict()))
        return filename

    @staticmethod
    def _manifest_filename(manifest: CapsuleManifest) -> str:
        return (
            f"{manifest.sequence:02d}-{manifest.state}-"
            f"{manifest.manifest_sha256}.manifest.json"
        )

    def _capsule_name(self, capability_id: str, version: str) -> str:
        if (
            _CAPABILITY_PATTERN.fullmatch(capability_id) is None
            or _VERSION_PATTERN.fullmatch(version) is None
        ):
            raise ConfigurationError("capsule store identity is malformed")
        return hashlib.sha256(f"{capability_id}\n{version}".encode()).hexdigest()

    def _capsule_directory(self, capability_id: str, version: str) -> Path:
        return self.root / self._capsule_name(capability_id, version)


def validate_dependency_metadata(
    bundle: CapsuleBundle,
    *,
    policy: LicensePolicy,
) -> tuple[dict[str, str], ...]:
    """Validate complete lock, license, notice, and SBOM agreement."""

    if not policy.permits(bundle.spec.source_license):
        raise ValidationError(
            "capsule source license is not permitted by dependency policy"
        )

    lock = bundle.dependency_lock
    if lock.get("schema") != DEPENDENCY_LOCK_SCHEMA:
        raise ValidationError("capsule dependency lock schema is unsupported")
    raw_dependencies = lock.get("dependencies")
    if not isinstance(raw_dependencies, tuple) or len(raw_dependencies) > 128:
        raise ValidationError("capsule dependency lock is malformed or unbounded")
    dependencies: list[dict[str, str]] = []
    for raw in raw_dependencies:
        if not isinstance(raw, Mapping):
            raise ValidationError("capsule dependency entry must be an object")
        dependency = {
            key: _required_string(raw, key)
            for key in ("name", "version", "artifact_sha256", "license")
        }
        if _IDENTIFIER_PATTERN.fullmatch(dependency["name"]) is None:
            raise ValidationError("capsule dependency name is malformed")
        _validate_sha256(dependency["artifact_sha256"], "capsule dependency artifact")
        if not policy.permits(dependency["license"]):
            raise ValidationError(
                f"capsule dependency license is not permitted: {dependency['license']}"
            )
        dependencies.append(dependency)
    identities = [(item["name"].casefold(), item["version"]) for item in dependencies]
    if len(identities) != len(set(identities)):
        raise ValidationError("capsule dependency lock contains duplicates")
    if (
        bundle.sbom.get("bomFormat") != SBOM_FORMAT
        or str(bundle.sbom.get("specVersion", "")) != SBOM_SPEC_VERSION
    ):
        raise ValidationError("capsule SBOM must be CycloneDX 1.5")
    raw_components = bundle.sbom.get("components")
    if not isinstance(raw_components, tuple):
        raise ValidationError("capsule SBOM components must be an immutable sequence")
    observed: list[tuple[str, str, str]] = []
    for raw in raw_components:
        if not isinstance(raw, Mapping):
            raise ValidationError("capsule SBOM component must be an object")
        observed.append(
            (
                _required_string(raw, "name").casefold(),
                _required_string(raw, "version"),
                _required_string(raw, "license"),
            )
        )
    expected = [
        (item["name"].casefold(), item["version"], item["license"])
        for item in dependencies
    ]
    if sorted(observed) != sorted(expected):
        raise ValidationError(
            "capsule SBOM does not match its complete dependency lock"
        )
    if policy.require_notices:
        notice = bundle.third_party_notices.casefold()
        for dependency in dependencies:
            if (
                dependency["name"].casefold() not in notice
                or dependency["license"].casefold() not in notice
            ):
                raise ValidationError(
                    "capsule third-party notices omit a dependency or license"
                )
    return tuple(dependencies)


def validate_bundle_contracts(bundle: CapsuleBundle) -> None:
    """Validate test, verification, and compensation document schemas."""

    if bundle.test_suite.get("schema") != TEST_SUITE_SCHEMA:
        raise ValidationError("capsule test-suite schema is unsupported")
    cases = bundle.test_suite.get("cases")
    if not isinstance(cases, tuple) or not 1 <= len(cases) <= 32:
        raise ValidationError("capsule test suite must contain 1..32 cases")
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValidationError("capsule test case must be an object")
        _mapping(case, "input")
        _mapping(case, "expected")
    if bundle.verification_contract.get("schema") != VERIFICATION_SCHEMA:
        raise ValidationError("capsule verification schema is unsupported")
    verification_mode = str(bundle.verification_contract.get("mode", ""))
    if verification_mode not in {"deterministic_replay", "provider_readback"}:
        raise ValidationError("capsule verification mode is unsupported")
    if bundle.compensation_contract.get("schema") != COMPENSATION_SCHEMA:
        raise ValidationError("capsule compensation schema is unsupported")
    compensation_mode = str(bundle.compensation_contract.get("mode", ""))
    if bundle.spec.side_effects:
        if verification_mode != "provider_readback" or compensation_mode != "verified":
            raise ValidationError(
                "side-effect capsule requires provider readback and verified compensation"
            )
    elif compensation_mode != "not_applicable":
        raise ValidationError("pure capsule compensation must be not_applicable")


def _verify_bundle_identity(bundle: CapsuleBundle, manifest: CapsuleManifest) -> None:
    if bundle.spec != manifest.spec:
        raise ConfigurationError("capsule spec differs from its signed manifest")
    expected = {
        "source_sha256": bundle.source_sha256,
        "artifact_sha256": bundle.artifact_sha256,
        "dependency_lock_sha256": bundle.dependency_lock_sha256,
        "sbom_sha256": bundle.sbom_sha256,
        "test_suite_sha256": bundle.test_suite_sha256,
        "verification_contract_sha256": bundle.verification_contract_sha256,
        "compensation_contract_sha256": bundle.compensation_contract_sha256,
        "notices_sha256": bundle.notices_sha256,
        "policy_contract_sha256": bundle.spec.policy_contract_sha256,
    }
    for name, value in expected.items():
        if getattr(manifest, name) != value:
            raise ConfigurationError(f"capsule artifact digest drifted: {name}")


def _validated_schema(value: Mapping[str, str], label: str) -> dict[str, str]:
    result = dict(value)
    if len(result) > 64:
        raise ValidationError(f"capsule {label} schema exceeds 64 fields")
    for name, descriptor in result.items():
        if _IDENTIFIER_PATTERN.fullmatch(name) is None:
            raise ValidationError(f"capsule {label} schema name is malformed")
        base = descriptor.removesuffix("?")
        if base not in _SCHEMA_TYPES:
            raise ValidationError(f"capsule {label} schema type is unsupported")
    return result


def _canonical_origin(value: str) -> str:
    if value != value.strip() or not value:
        raise ValidationError("capsule provider origin is malformed")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValidationError("capsule provider origin has an invalid port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValidationError("capsule provider origin must be an exact HTTPS origin")
    hostname = parsed.hostname.casefold().rstrip(".")
    rendered = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != 443:
        rendered = f"{rendered}:{port}"
    return urlunsplit(("https", rendered, "", "", ""))


def _private_root(path: Path) -> PinnedDirectory:
    selected = path.expanduser()
    if not selected.is_absolute():
        raise ConfigurationError("capsule store root must be absolute")
    selected.mkdir(mode=0o700, parents=False, exist_ok=True)
    metadata = selected.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != get_secure_filesystem_backend().effective_user_id()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ConfigurationError("capsule store root must be owner-private mode 0700")
    expected = DirectoryIdentity.from_stat(metadata)
    return PinnedDirectory.open(selected, expected_identity=expected)


def _open_private_directory(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise ConfigurationError("capsule directory is unavailable") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != get_secure_filesystem_backend().effective_user_id()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise ConfigurationError("capsule directory must be owner-private mode 0700")
    return descriptor


def _open_private_directory_at(parent_descriptor: int, name: str) -> int:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ConfigurationError("capsule directory name is unsafe")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise ConfigurationError("capsule directory is unavailable") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != get_secure_filesystem_backend().effective_user_id()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise ConfigurationError("capsule directory must be owner-private mode 0700")
    return descriptor


def _read_regular_at(directory_fd: int, name: str) -> bytes:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ConfigurationError("capsule artifact name is unsafe")
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != get_secure_filesystem_backend().effective_user_id()
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_BUNDLE_FILE_BYTES
        ):
            raise ConfigurationError("capsule artifact is not a bounded owned file")
        payload = bytearray()
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 64 * 1024))
            if not block:
                raise ConfigurationError("capsule artifact changed during read")
            payload.extend(block)
            remaining -= len(block)
        current = os.fstat(descriptor)
        if os.read(descriptor, 1) or _file_identity(current) != _file_identity(
            metadata
        ):
            raise ConfigurationError("capsule artifact changed during read")
        return bytes(payload)
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError("capsule artifact could not be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_windows_regular(directory: PinnedWindowsPath, name: str) -> bytes:
    """Read one fixed bundle artifact through its retained Windows handle."""

    from master_agent.platform_runtime.windows.filesystem import WindowsObjectKind

    try:
        with directory.pin_child(
            name,
            kind=WindowsObjectKind.FILE,
            require_private=True,
        ) as artifact:
            return artifact.read_bytes(_MAX_BUNDLE_FILE_BYTES)
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError("capsule artifact could not be read safely") from error


def _write_private_at(directory_fd: int, name: str, payload: bytes) -> None:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ConfigurationError("capsule artifact name is unsafe")
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _decode_json(payload: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("capsule JSON artifact is malformed") from error
    if not isinstance(value, Mapping):
        raise ConfigurationError("capsule JSON artifact must be an object")
    return value


def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValidationError(f"capsule {key} must be an object")
    return value


def _string_mapping(data: Mapping[str, Any], key: str) -> dict[str, str]:
    value = _mapping(data, key)
    if not all(
        isinstance(name, str) and isinstance(item, str) for name, item in value.items()
    ):
        raise ValidationError(f"capsule {key} must map strings to strings")
    return {str(name): str(item) for name, item in value.items()}


def _required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValidationError(f"capsule {key} must be a string")
    return value


def _string_tuple(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"capsule {key} must be a string list")
    return tuple(value)


def _positive_int(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValidationError(f"capsule {key} must be a positive integer")
    return value


def _nonnegative_int(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"capsule {key} must be a nonnegative integer")
    return value


def _validate_unique_strings(values: Sequence[str], label: str) -> None:
    if len(values) != len(set(values)) or any(
        not value or value != value.strip() for value in values
    ):
        raise ValidationError(f"{label} must contain unique normalized strings")


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValidationError(f"{label} must be a lowercase SHA-256 digest")


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValidationError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise ValidationError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime | None) -> str:
    selected = (value or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    return selected.isoformat().replace("+00:00", "Z")


def _toml_string_list(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ConfigurationError(f"dependency license {key} must be a string list")
    return tuple(value)


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"dependency license {label} must be a boolean")
    return value
