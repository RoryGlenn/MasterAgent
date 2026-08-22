"""Quarantine validation and governed execution for capability capsules.

Only dependency-free, pure capsules execute in the demonstrated local/test
runtime.  Provider and side-effect capsules remain fail closed until a typed
provider broker supplies destination-bound calls, independent readback, and
verified compensation.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from master_agent.capabilities import CapabilityCatalog
from master_agent.capsules import (
    CapsuleBundle,
    CapsuleManifest,
    CapsuleState,
    CapsuleStore,
    CapsuleTrustStore,
    LicensePolicy,
    validate_bundle_contracts,
    validate_dependency_metadata,
)
from master_agent.errors import ConfigurationError, ConnectorError, ValidationError
from master_agent.models import (
    ActionState,
    AgentAction,
    CapabilityCapsuleExecutionBinding,
    ExecutionContext,
    ExecutionResult,
    ResourceRef,
    RiskLevel,
    VerificationResult,
    freeze_json_mapping,
)
from master_agent.platform_runtime import (
    SecureFilesystemBackend,
    get_platform_runtime,
    get_secure_filesystem_backend,
)
from master_agent.resource_limits import measure_json_resources

WORKER_PROTOCOL = "master-agent/capsule-worker@1"
VALIDATION_SCHEMA = "master-agent/capsule-validation@1"
SANDBOX_VALIDATION_SCHEMA = "master-agent/capsule-sandbox-validation@1"
_WORKER_PATH = (
    Path(__file__).with_name("platform_runtime") / "posix" / "capsule_worker.py"
)
_MAX_WORKER_RESPONSE_OVERHEAD = 4_096


@dataclass(frozen=True, slots=True)
class CapsuleValidation:
    """Deterministic, content-free validation and sandbox evidence."""

    validation: Mapping[str, Any]
    sandbox: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "validation", freeze_json_mapping(self.validation))
        object.__setattr__(self, "sandbox", freeze_json_mapping(self.sandbox))

    @property
    def validation_sha256(self) -> str:
        return _sha256_json(self.validation)

    @property
    def sandbox_sha256(self) -> str:
        return _sha256_json(self.sandbox)


class CapsuleWorker:
    """Run one pure capsule in a bounded process and optional Linux namespace."""

    def __init__(
        self,
        *,
        require_os_sandbox: bool = True,
        bubblewrap: str | None = None,
    ) -> None:
        explicit_bubblewrap = bubblewrap is not None
        runtime = get_platform_runtime(
            capsule_executable=(
                bubblewrap if explicit_bubblewrap or require_os_sandbox else ""
            )
        )
        runtime.require_process_supervision()
        self._filesystem = runtime.require_secure_filesystem()
        isolation_backend = None
        if require_os_sandbox or explicit_bubblewrap:
            isolation_backend = runtime.require_capsule_isolation()
        self._bubblewrap = (
            isolation_backend.executable if isolation_backend is not None else None
        )
        self._require_os_sandbox = require_os_sandbox
        if require_os_sandbox and self._bubblewrap is None:
            raise ConfigurationError(
                "capability capsule execution requires the bubblewrap OS sandbox"
            )
        _validate_worker_artifact(
            _WORKER_PATH,
            executable=False,
            filesystem=self._filesystem,
        )
        _validate_worker_artifact(
            Path(sys.executable).resolve(),
            executable=True,
            filesystem=self._filesystem,
        )
        if self._bubblewrap is not None:
            _validate_worker_artifact(
                self._bubblewrap,
                executable=True,
                filesystem=self._filesystem,
            )

    @property
    def backend(self) -> str:
        """Return the exact isolation backend identity."""

        return "linux-bubblewrap" if self._bubblewrap is not None else "test-subprocess"

    @property
    def production_isolated(self) -> bool:
        """Return whether an OS-enforced no-network/mount namespace is active."""

        return self._bubblewrap is not None and sys.platform.startswith("linux")

    @property
    def identity_sha256(self) -> str:
        """Bind worker source, interpreter, and sandbox binary into promotion."""

        interpreter = Path(sys.executable).resolve()
        _validate_worker_artifact(
            _WORKER_PATH,
            executable=False,
            filesystem=self._filesystem,
        )
        _validate_worker_artifact(
            interpreter,
            executable=True,
            filesystem=self._filesystem,
        )
        if self._bubblewrap is not None:
            _validate_worker_artifact(
                self._bubblewrap,
                executable=True,
                filesystem=self._filesystem,
            )
        payload = {
            "backend": self.backend,
            "worker_sha256": _sha256_file(_WORKER_PATH),
            "interpreter_sha256": _sha256_file(interpreter),
            "sandbox_sha256": (
                _sha256_file(self._bubblewrap) if self._bubblewrap is not None else None
            ),
        }
        return _sha256_json(payload)

    def execute(
        self, bundle: CapsuleBundle, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Execute an authenticated bundle's pure program in the worker."""

        return self.execute_program(
            source=bundle.source,
            request=request,
            max_input_bytes=bundle.spec.max_input_bytes,
            max_output_bytes=bundle.spec.max_output_bytes,
            timeout_seconds=bundle.spec.timeout_seconds,
            cpu_seconds=bundle.spec.cpu_seconds,
            memory_bytes=bundle.spec.memory_bytes,
            max_processes=bundle.spec.max_processes,
        )

    def execute_program(
        self,
        *,
        source: bytes,
        request: Mapping[str, Any],
        max_input_bytes: int,
        max_output_bytes: int,
        timeout_seconds: int,
        cpu_seconds: int,
        memory_bytes: int,
        max_processes: int,
    ) -> dict[str, Any]:
        """Execute source through the bounded protocol; useful for sandbox probes."""

        measure_json_resources(
            request,
            context="capsule worker request",
            max_bytes=max_input_bytes,
        )
        try:
            decoded_source = source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ConnectorError("capability capsule source is not UTF-8") from error
        envelope = {
            "schema": WORKER_PROTOCOL,
            "source": decoded_source,
            "request": dict(request),
            "limits": {
                "cpu_seconds": cpu_seconds,
                "memory_bytes": memory_bytes,
                "max_processes": max_processes,
                "max_output_bytes": max_output_bytes,
            },
        }
        encoded = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > 2 * 1024 * 1024:
            raise ConnectorError("capability capsule worker envelope is too large")
        command = self._command()
        safe_environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
        }
        with tempfile.TemporaryDirectory(prefix="master-agent-capsule-") as directory:
            os.chmod(directory, 0o700)
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=errors,
                    cwd=directory,
                    env=safe_environment,
                    start_new_session=True,
                )
                try:
                    process.communicate(encoded, timeout=timeout_seconds + 1)
                except subprocess.TimeoutExpired as error:
                    _terminate_process(process)
                    raise ConnectorError(
                        "capability capsule worker timed out"
                    ) from error
                output.seek(0, os.SEEK_END)
                size = output.tell()
                if size > max_output_bytes + _MAX_WORKER_RESPONSE_OVERHEAD:
                    raise ConnectorError(
                        "capability capsule worker output exceeded quota"
                    )
                output.seek(0)
                payload = output.read()
                errors.seek(0, os.SEEK_END)
                error_size = errors.tell()
                errors.seek(0)
                diagnostic = errors.read(4_096) if error_size <= 4_096 else b""
        try:
            response = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ConnectorError(
                "capability capsule worker response is malformed: "
                + _classify_worker_launch_failure(
                    process.returncode,
                    diagnostic,
                    diagnostic_overflow=error_size > 4_096,
                )
            ) from error
        if (
            not isinstance(response, Mapping)
            or response.get("schema") != WORKER_PROTOCOL
        ):
            raise ConnectorError("capability capsule worker protocol drifted")
        if process.returncode != 0 or response.get("ok") is not True:
            error_code = response.get("error")
            rendered = error_code if isinstance(error_code, str) else "worker_failed"
            raise ConnectorError(f"capability capsule rejected: {rendered}")
        result = response.get("output")
        if not isinstance(result, Mapping):
            raise ConnectorError("capability capsule output must be an object")
        measure_json_resources(
            result,
            context="capsule worker output",
            max_bytes=max_output_bytes,
        )
        return deepcopy(dict(result))

    def _command(self) -> list[str]:
        interpreter = Path(sys.executable).resolve()
        if self._bubblewrap is None:
            if self._require_os_sandbox:
                raise ConfigurationError("capability capsule OS sandbox is unavailable")
            return [str(interpreter), "-I", "-S", str(_WORKER_PATH)]
        if not sys.platform.startswith("linux"):
            raise ConfigurationError("bubblewrap capsules require Linux")
        base_prefix = Path(sys.base_prefix).resolve()
        command = [
            str(self._bubblewrap),
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "PYTHONHASHSEED",
            "0",
            "--ro-bind",
            str(base_prefix),
            str(base_prefix),
        ]
        for library_root in (Path("/lib"), Path("/lib64")):
            if library_root.exists():
                command.extend(["--ro-bind", str(library_root), str(library_root)])
        command.extend(
            [
                "--ro-bind",
                str(_WORKER_PATH),
                "/capsule-worker.py",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                # This is a private tmpfs inside the new mount namespace.
                "/tmp",  # nosec B108
                "--dir",
                "/work",
                "--chdir",
                "/work",
                str(interpreter),
                "-I",
                "-S",
                "/capsule-worker.py",
            ]
        )
        return command


class CapsuleValidator:
    """Validate dependency closure, contracts, tests, and isolation controls."""

    def __init__(self, *, worker: CapsuleWorker, license_policy: LicensePolicy) -> None:
        self._worker = worker
        self._license_policy = license_policy

    def validate(self, bundle: CapsuleBundle) -> CapsuleValidation:
        """Return deterministic evidence only after every validation passes."""

        dependencies = validate_dependency_metadata(
            bundle,
            policy=self._license_policy,
        )
        validate_bundle_contracts(bundle)
        if dependencies:
            raise ValidationError(
                "the pure capsule worker rejects third-party runtime dependencies"
            )
        raw_cases = bundle.test_suite["cases"]
        if not isinstance(raw_cases, tuple):  # pragma: no cover - validated above.
            raise ValidationError("capsule test cases are malformed")
        case_digests: list[str] = []
        for raw_case in raw_cases:
            if not isinstance(raw_case, Mapping):  # pragma: no cover - validated above.
                raise ValidationError("capsule test case is malformed")
            request = _mapping(raw_case, "input")
            expected = _mapping(raw_case, "expected")
            _validate_typed_mapping(request, bundle.spec.input_schema, "capsule input")
            _validate_typed_mapping(
                expected, bundle.spec.output_schema, "capsule output"
            )
            observed = self._worker.execute(bundle, request)
            _validate_typed_mapping(
                observed, bundle.spec.output_schema, "capsule output"
            )
            if observed != dict(expected):
                raise ValidationError("capability capsule test result did not match")
            case_digests.append(
                _sha256_json({"input": dict(request), "expected": dict(expected)})
            )
        validation = {
            "schema": VALIDATION_SCHEMA,
            "artifact_sha256": bundle.artifact_sha256,
            "dependency_count": len(dependencies),
            "case_count": len(case_digests),
            "case_sha256": case_digests,
            "worker_sha256": self._worker.identity_sha256,
            "status": "passed",
        }
        probes = self._sandbox_probes()
        sandbox = {
            "schema": SANDBOX_VALIDATION_SCHEMA,
            "artifact_sha256": bundle.artifact_sha256,
            "backend": self._worker.backend,
            "os_isolated": self._worker.production_isolated,
            "worker_sha256": self._worker.identity_sha256,
            "probes": probes,
            "status": "passed",
        }
        return CapsuleValidation(validation=validation, sandbox=sandbox)

    def _sandbox_probes(self) -> list[dict[str, str]]:
        probes = {
            "host_file": b'def run(request):\n    return {"value": open(request["path"]).read()}\n',
            "ambient_secret": b'def run(request):\n    return {"value": __import__("os").environ}\n',
            "network": b'def run(request):\n    return {"value": __import__("socket").socket()}\n',
            "subprocess": b'def run(request):\n    return {"value": __import__("subprocess").run(["id"])}\n',
            "private_introspection": b'def run(request):\n    return {"value": request.__class__.__mro__}\n',
        }
        results: list[dict[str, str]] = []
        for name, source in probes.items():
            try:
                self._worker.execute_program(
                    source=source,
                    request={"path": "/etc/passwd"},
                    max_input_bytes=4_096,
                    max_output_bytes=4_096,
                    timeout_seconds=1,
                    cpu_seconds=1,
                    memory_bytes=64 * 1024 * 1024,
                    max_processes=1,
                )
            except ConnectorError:
                results.append({"name": name, "status": "denied"})
            else:
                raise ValidationError(
                    f"capsule isolation probe unexpectedly ran: {name}"
                )
        return results


class CapsuleConnector:
    """Typed connector facade for one exact enabled pure capsule."""

    def __init__(
        self,
        *,
        manifest: CapsuleManifest,
        bundle: CapsuleBundle,
        binding: CapabilityCapsuleExecutionBinding,
        worker: CapsuleWorker,
    ) -> None:
        if manifest.state is not CapsuleState.ENABLED:
            raise ConfigurationError("capsule connector requires an enabled manifest")
        if _binding_for_runtime(manifest, binding) != binding:
            raise ConfigurationError(
                "capsule connector identity differs from plan binding"
            )
        if manifest.worker_sha256 != worker.identity_sha256:
            raise ConfigurationError("capsule worker identity differs from promotion")
        if (
            manifest.spec.side_effects
            or manifest.spec.allowed_origins
            or manifest.spec.credential_names
            or manifest.spec.risk
            not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
        ):
            raise ConfigurationError(
                "provider and side-effect capsules require a typed provider broker"
            )
        self._manifest = manifest
        self._bundle = bundle
        self._binding = binding
        self._worker = worker
        self._last_results: dict[str, dict[str, Any]] = {}

    @property
    def system(self) -> str:
        return self._manifest.spec.system

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({self._manifest.spec.capability_id})

    @property
    def capsule_binding(self) -> CapabilityCapsuleExecutionBinding:
        return self._binding

    def execute(self, action: AgentAction) -> ExecutionResult:
        self._validate_action(action)
        output = self._worker.execute(self._bundle, action.parameters)
        _validate_typed_mapping(
            output,
            self._manifest.spec.output_schema,
            "capsule output",
        )
        self._last_results[action.target.resource_id] = deepcopy(output)
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=output,
            after=output,
            connector_reference=(
                f"capsule:{self._manifest.spec.capability_id}:"
                f"{self._manifest.spec.version}:{self._manifest.manifest_sha256}"
            ),
            message="promoted capability capsule executed in isolation",
        )

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        value = self._last_results.get(resource.resource_id)
        return deepcopy(value) if value is not None else None

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        self._validate_action(action)
        observed = self._worker.execute(self._bundle, action.parameters)
        _validate_typed_mapping(
            observed,
            self._manifest.spec.output_schema,
            "capsule output",
        )
        verified = _sha256_json(observed) == _sha256_json(result.after or {})
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified by independent deterministic sandbox replay"
                if verified
                else "independent deterministic sandbox replay differed"
            ),
        )

    def _validate_action(self, action: AgentAction) -> None:
        spec = self._manifest.spec
        if self._worker.identity_sha256 != self._binding.worker_sha256:
            raise ConnectorError("capsule worker identity drifted after activation")
        if (
            action.capability != spec.capability_id
            or action.target.system != spec.system
        ):
            raise ConnectorError("capsule connector received a different capability")
        if action.target.resource_type != "capsule_request":
            raise ConnectorError("capsule target must be capsule_request")
        if action.risk is not spec.risk:
            raise ConnectorError("capsule action risk differs from its manifest")
        if action.data_classification is not spec.data_classification:
            raise ConnectorError(
                "capsule action classification differs from its manifest"
            )
        _validate_typed_mapping(action.parameters, spec.input_schema, "capsule input")


@dataclass(frozen=True, slots=True)
class ActivatedCapsule:
    """Exact artifacts permitted to enter the normal governed runtime."""

    manifest: CapsuleManifest
    bundle: CapsuleBundle
    connector: CapsuleConnector
    catalog: CapabilityCatalog


def activate_capsule(
    *,
    store: CapsuleStore,
    trust: CapsuleTrustStore,
    binding: CapabilityCapsuleExecutionBinding,
    worker: CapsuleWorker,
    base_catalog: CapabilityCatalog,
) -> ActivatedCapsule:
    """Resolve and authenticate an exact plan binding before construction."""

    manifest, bundle = store.resolve_enabled(
        binding.capability_id,
        binding.version,
        binding.manifest_sha256,
        trust=trust,
    )
    if _binding_for_runtime(manifest, binding) != binding:
        raise ConfigurationError("enabled capsule differs from the approved binding")
    if manifest.worker_sha256 != worker.identity_sha256:
        raise ConfigurationError("enabled capsule was validated by another worker")
    catalog = catalog_with_capsule(base_catalog, manifest)
    connector = CapsuleConnector(
        manifest=manifest,
        bundle=bundle,
        binding=binding,
        worker=worker,
    )
    return ActivatedCapsule(
        manifest=manifest,
        bundle=bundle,
        connector=connector,
        catalog=catalog,
    )


def catalog_with_capsule(
    base: CapabilityCatalog,
    manifest: CapsuleManifest,
) -> CapabilityCatalog:
    """Add one enabled capsule definition without shadowing first-party code."""

    definition = manifest.capability_definition()
    if definition.name in base.definitions:
        raise ConfigurationError(
            "capability capsule cannot shadow an existing catalog capability"
        )
    return CapabilityCatalog({**base.definitions, definition.name: definition})


def context_with_capsules(
    context: ExecutionContext,
    manifests: Sequence[CapsuleManifest],
    *,
    authenticated_principal: str = "local:operator",
    agent_identity: str = "master-agent",
    tenant_id: str = "local",
    provider_account_id: str = "none",
    credential_provider_id: str = "none",
) -> ExecutionContext:
    """Bind exact enabled capsule identities into a plan execution context."""

    bindings = tuple(
        manifest.binding(
            authenticated_principal=authenticated_principal,
            agent_identity=agent_identity,
            tenant_id=tenant_id,
            provider_account_id=provider_account_id,
            credential_provider_id=credential_provider_id,
        )
        for manifest in manifests
    )
    return replace(context, capsules=bindings)


def _binding_for_runtime(
    manifest: CapsuleManifest,
    binding: CapabilityCapsuleExecutionBinding,
) -> CapabilityCapsuleExecutionBinding:
    return manifest.binding(
        authenticated_principal=binding.authenticated_principal,
        agent_identity=binding.agent_identity,
        tenant_id=binding.tenant_id,
        provider_account_id=binding.provider_account_id,
        credential_provider_id=binding.credential_provider_id,
    )


def _validate_typed_mapping(
    value: Mapping[str, Any],
    schema: Mapping[str, str],
    label: str,
) -> None:
    unknown = sorted(set(value) - set(schema))
    if unknown:
        raise ValidationError(f"{label} has unexpected fields: {', '.join(unknown)}")
    for name, descriptor in schema.items():
        optional = descriptor.endswith("?")
        if name not in value:
            if optional:
                continue
            raise ValidationError(f"{label} is missing required field: {name}")
        item = value[name]
        if optional and item is None:
            continue
        expected = descriptor.removesuffix("?")
        if not _matches_type(item, expected):
            raise ValidationError(f"{label} field {name} must be {expected}")


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, (list, tuple))
    if expected == "string_list":
        return isinstance(value, (list, tuple)) and all(
            isinstance(item, str) for item in value
        )
    return False


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ValidationError(f"capsule test {key} must be an object")
    return selected


def _sha256_json(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _validate_worker_artifact(
    path: Path,
    *,
    executable: bool,
    filesystem: SecureFilesystemBackend | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ConfigurationError(
            "capability capsule worker artifact is unavailable"
        ) from error
    failures: list[str] = []
    if not stat.S_ISREG(metadata.st_mode):
        failures.append("not_regular")
    filesystem = filesystem or get_secure_filesystem_backend()
    if metadata.st_uid not in {0, filesystem.effective_user_id()}:
        failures.append("untrusted_owner")
    if metadata.st_nlink != 1:
        failures.append("multiple_links")
    if stat.S_IMODE(metadata.st_mode) & stat.S_IWOTH:
        failures.append("world_writable")
    if not _group_write_is_owner_private(metadata, filesystem=filesystem):
        failures.append("shared_group_writable")
    if executable and not os.access(path, os.X_OK):
        failures.append("not_executable")
    if failures:
        raise ConfigurationError(
            "capability capsule worker artifact is not trusted: " + ",".join(failures)
        )


def _group_write_is_owner_private(
    metadata: os.stat_result,
    *,
    filesystem: SecureFilesystemBackend,
) -> bool:
    """Allow group writes only when that group represents the file owner alone."""

    if not stat.S_IMODE(metadata.st_mode) & stat.S_IWGRP:
        return True
    if metadata.st_uid != filesystem.effective_user_id():
        return False
    return filesystem.group_is_private_to_owner(
        owner_id=metadata.st_uid,
        group_id=metadata.st_gid,
    )


def _classify_worker_launch_failure(
    returncode: int,
    diagnostic: bytes,
    *,
    diagnostic_overflow: bool = False,
) -> str:
    """Return a content-free reason for a pre-protocol worker failure."""

    if diagnostic_overflow:
        return "launch_diagnostic_overflow"
    normalized = diagnostic.lower()
    if b"operation not permitted" in normalized or (
        b"permission denied" in normalized
        and (b"namespace" in normalized or b"bwrap" in normalized)
    ):
        return "sandbox_permission_denied"
    if b"no such file or directory" in normalized:
        return "sandbox_runtime_missing"
    if b"error while loading shared libraries" in normalized:
        return "interpreter_dependency_missing"
    if returncode < 0:
        return "worker_terminated_by_signal"
    return "worker_failed_before_protocol"


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
