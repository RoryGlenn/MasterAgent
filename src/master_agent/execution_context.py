"""Build and enforce approval-bound live execution identities."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Self, cast
from urllib.parse import urlsplit

from master_agent.config import (
    ConnectorConfig,
    IntegrationConfig,
    PrincipalAttestationAdapter,
    ResolvedConnectorConfig,
    ResolvedExecutionTarget,
)
from master_agent.config_sources import ConfigSource
from master_agent.connectors.github import GitHubConnector
from master_agent.connectors.microsoft import MicrosoftIdentityConnector
from master_agent.connectors.reddit import RedditConnector
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError
from master_agent.http import HttpTransport
from master_agent.models import (
    CapabilityCapsuleExecutionBinding,
    ChangePlan,
    ConfigurationExecutionBinding,
    ConnectorExecutionBinding,
    ExecutionContext,
    PluginExecutionBinding,
    RuntimeExecutionBinding,
    RuntimePathExecutionBinding,
)
from master_agent.oauth import StaticTokenProvider
from master_agent.platform_runtime import (
    PlatformContract,
    PlatformObjectIdentity,
    require_platform_contract,
)
from master_agent.plugins import PluginDescriptor


@dataclass(frozen=True, slots=True)
class CapturedConnectorExecution:
    """Immutable runtime material plus its secret-free approval binding."""

    config: ConnectorConfig
    target: ResolvedExecutionTarget
    binding: ConnectorExecutionBinding
    resolved: ResolvedConnectorConfig | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class CredentialAttestation:
    """Secret-free principal and effective scope facts for approval binding."""

    identity: str | None
    scopes: tuple[str, ...] = ()


@dataclass(slots=True)
class CapturedRuntimePath:
    """One exact manifest-bound directory pin retained across an applied run."""

    binding: RuntimePathExecutionBinding
    publication: bool
    _anchor: PinnedDirectory

    def validate(self) -> None:
        """Fail closed unless the captured ancestor remains exact."""

        self._anchor.validate()

    def open_target(self) -> PinnedDirectory:
        """Return an owned duplicate of the exact approved directory."""

        self.validate()
        return self._anchor.duplicate()

    def close(self) -> None:
        """Release the captured ancestor chain."""

        self._anchor.close()

    def __enter__(self) -> Self:
        self.validate()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def capture_connector_executions(
    integrations: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    systems: set[str] | None = None,
    require_trusted_principal: bool = True,
    include_resolved_credentials: bool = True,
    principal_transport: HttpTransport | None = None,
    approved_execution_context: ExecutionContext | None = None,
) -> tuple[CapturedConnectorExecution, ...]:
    """Capture selected enabled destinations and trusted principals."""

    source = dict(environ if environ is not None else os.environ)
    approved_connectors: dict[str, ConnectorExecutionBinding] | None = None
    if approved_execution_context is not None:
        if (
            not integrations.source_sha256
            or integrations.source_sha256
            != approved_execution_context.integrations_sha256
        ):
            raise ConfigurationError(
                "captured integrations bundle differs from the approved "
                "execution context"
            )
        approved_connectors = {
            item.system: item for item in approved_execution_context.connectors
        }
        selected_systems = {
            config.system
            for config in integrations.connectors.values()
            if config.enabled and _connector_is_selected(config.system, systems)
        }
        if selected_systems != set(approved_connectors):
            raise ConfigurationError(
                "captured connector set differs from the approved execution context"
            )
    captured: list[CapturedConnectorExecution] = []
    for config in integrations.connectors.values():
        if not config.enabled or not _connector_is_selected(config.system, systems):
            continue
        target = config.capture_execution_target(source)
        if approved_connectors is not None:
            _verify_approved_connector_target(
                config,
                target,
                approved_connectors[config.system],
            )
        ca_bundle = target.ca_bundle
        needs_resolved = include_resolved_credentials or (
            require_trusted_principal
            and config.principal_attestation_adapter is not None
        )
        resolved = (
            config.resolve(
                source,
                auth_transport=principal_transport,
                execution_target=target,
            )
            if needs_resolved
            else None
        )
        if require_trusted_principal and resolved is not None:
            resolved = _pin_resolved_authentication(resolved)
        attestation = (
            _credential_attestation(
                config,
                resolved=resolved,
                environ=source,
                transport=principal_transport,
            )
            if require_trusted_principal
            else CredentialAttestation(identity=None)
        )
        captured.append(
            CapturedConnectorExecution(
                config=config,
                target=target,
                resolved=resolved,
                binding=ConnectorExecutionBinding(
                    system=config.system,
                    deployment=str(config.deployment),
                    config_identity_sha256=target.config_identity,
                    resolved_base_url=target.base_url,
                    resolved_origin=_origin(target.base_url, system=config.system),
                    authentication_mode=str(config.auth_mode),
                    credential_scopes=attestation.scopes,
                    credential_identity=attestation.identity,
                    ca_bundle_path=(
                        str(ca_bundle.path) if ca_bundle is not None else None
                    ),
                    ca_bundle_sha256=(
                        ca_bundle.sha256 if ca_bundle is not None else None
                    ),
                    network_profile_name=target.network_profile_name,
                    network_profile_sha256=target.network_profile_sha256,
                    proxy_origin=target.proxy_url,
                ),
            )
        )
    return tuple(sorted(captured, key=lambda item: item.binding.system))


def _verify_approved_connector_target(
    config: ConnectorConfig,
    target: ResolvedExecutionTarget,
    approved: ConnectorExecutionBinding,
) -> None:
    """Reject destination or trust drift before any credential is resolved."""

    observed_origin = _origin(target.base_url, system=config.system)
    ca_bundle = target.ca_bundle
    comparisons = [
        ("deployment", str(config.deployment), approved.deployment),
        ("config identity", target.config_identity, approved.config_identity_sha256),
        ("base URL", target.base_url, approved.resolved_base_url),
        ("origin", observed_origin, approved.resolved_origin),
        (
            "CA path",
            str(ca_bundle.path) if ca_bundle is not None else None,
            approved.ca_bundle_path,
        ),
        (
            "CA digest",
            ca_bundle.sha256 if ca_bundle is not None else None,
            approved.ca_bundle_sha256,
        ),
    ]
    legacy_direct = (
        approved.network_profile_name == "direct"
        and approved.network_profile_sha256 is None
        and approved.proxy_origin is None
    )
    if legacy_direct:
        comparisons.extend(
            (
                ("network profile", target.network_profile_name, "direct"),
                ("proxy origin", target.proxy_url, None),
            )
        )
    else:
        comparisons.extend(
            (
                (
                    "network profile",
                    target.network_profile_name,
                    approved.network_profile_name,
                ),
                (
                    "network profile digest",
                    target.network_profile_sha256,
                    approved.network_profile_sha256,
                ),
                ("proxy origin", target.proxy_url, approved.proxy_origin),
            )
        )
    for detail, observed, expected in comparisons:
        if observed != expected:
            raise ConfigurationError(
                "applied execution context differs from the approved plan: "
                "connector origin or CA identity; "
                f"captured connector {config.system} {detail} differs from the "
                "approved execution context"
            )


def build_execution_context(
    integrations: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    plugin_descriptors: Sequence[PluginDescriptor] = (),
    runtime: RuntimeExecutionBinding | None = None,
    include_connectors: bool = True,
    systems: set[str] | None = None,
    principal_transport: HttpTransport | None = None,
    capsule_bindings: Sequence[CapabilityCapsuleExecutionBinding] = (),
    approved_execution_context: ExecutionContext | None = None,
) -> ExecutionContext:
    """Resolve a secret-free snapshot suitable for plan approval binding."""

    if not integrations.source_sha256:
        raise ConfigurationError(
            "applied execution context requires a hashed integrations bundle"
        )
    connector_bindings = (
        tuple(
            item.binding
            for item in capture_connector_executions(
                integrations,
                environ=environ,
                systems=systems,
                principal_transport=principal_transport,
                include_resolved_credentials=False,
                approved_execution_context=approved_execution_context,
            )
        )
        if include_connectors
        else ()
    )

    plugin_bindings: list[PluginExecutionBinding] = []
    for descriptor in plugin_descriptors:
        if not (
            descriptor.distribution
            and descriptor.distribution_version
            and descriptor.artifact_sha256
        ):
            raise ConfigurationError(
                f"connector plugin {descriptor.name} lacks an exact artifact identity"
            )
        plugin_bindings.append(
            PluginExecutionBinding(
                name=descriptor.name,
                group=descriptor.group,
                entry_point=descriptor.value,
                distribution=descriptor.distribution,
                distribution_version=descriptor.distribution_version,
                artifact_sha256=descriptor.artifact_sha256,
                identity_sha256=descriptor.identity_sha256,
            )
        )

    return ExecutionContext(
        integrations_sha256=integrations.source_sha256,
        connectors=connector_bindings,
        plugins=tuple(plugin_bindings),
        capsules=tuple(capsule_bindings),
        runtime=runtime,
    )


def _connector_is_selected(system: str, systems: set[str] | None) -> bool:
    """Return whether one configured provider backs a requested runtime system."""

    if systems is None:
        return True
    if system == "microsoft":
        return bool(
            systems & {"microsoft", "sharepoint", "outlook", "teams", "onenote"}
        )
    return system in systems


def _credential_attestation(
    config: ConnectorConfig,
    *,
    resolved: ResolvedConnectorConfig | None,
    environ: Mapping[str, str],
    transport: HttpTransport | None,
) -> CredentialAttestation:
    """Capture a flow-enforced or provider-verified principal and scopes."""

    adapter = config.principal_attestation_adapter
    if adapter is PrincipalAttestationAdapter.GITHUB_AUTHENTICATED_USER:
        if resolved is None:  # pragma: no cover - capture invariant.
            raise ConfigurationError(
                "GitHub principal attestation requires credentials"
            )
        github_attested = GitHubConnector(
            resolved,
            transport=transport,
        ).attest_principal()
        return CredentialAttestation(
            identity=github_attested.identity,
            scopes=github_attested.scopes,
        )
    if adapter is PrincipalAttestationAdapter.MICROSOFT_DELEGATED_USER:
        if resolved is None:  # pragma: no cover - capture invariant.
            raise ConfigurationError(
                "Microsoft principal attestation requires credentials"
            )
        microsoft_attested = MicrosoftIdentityConnector(
            resolved,
            transport=transport,
        ).attest_principal()
        return CredentialAttestation(
            identity=microsoft_attested.identity,
            scopes=microsoft_attested.scopes,
        )
    if adapter is PrincipalAttestationAdapter.REDDIT_AUTHENTICATED_USER:
        if resolved is None:  # pragma: no cover - capture invariant.
            raise ConfigurationError(
                "Reddit principal attestation requires credentials"
            )
        reddit_attested = RedditConnector(
            resolved,
            transport=transport,
        ).attest_principal()
        return CredentialAttestation(
            identity=reddit_attested.identity,
            scopes=reddit_attested.scopes,
        )
    if adapter is not None:  # pragma: no cover - adapter registry invariant.
        raise ConfigurationError(
            f"connector {config.system} has an unsupported principal adapter"
        )
    return CredentialAttestation(identity=config.credential_identity(environ))


def _pin_resolved_authentication(
    resolved: ResolvedConnectorConfig,
) -> ResolvedConnectorConfig:
    """Freeze one token value for attestation and subsequent provider I/O."""

    provider = resolved.auth.token_provider
    if provider is None:
        return resolved
    token = provider.get_token()
    return replace(
        resolved,
        auth=replace(
            resolved.auth,
            token_provider=StaticTokenProvider(token),
        ),
    )


def build_runtime_execution_binding(
    integrations: IntegrationConfig,
    *,
    connector_mode: str,
    include_writes: bool,
    include_communications: bool,
    audit_database: Path,
    artifact_root: Path,
    workspace_root: Path | None,
    result_json: Path | None,
    evidence_type: str,
    configuration_sources: Mapping[str, ConfigSource],
    credential_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
    captured_paths: Sequence[CapturedRuntimePath] | None = None,
) -> RuntimeExecutionBinding:
    """Capture every non-secret runtime input that can alter an applied run."""

    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    source = environ if environ is not None else os.environ
    normalized_workspace = _canonical_path(workspace_root)
    owned_paths: tuple[CapturedRuntimePath, ...] = ()
    if captured_paths is None:
        owned_paths = capture_runtime_execution_paths(
            integrations,
            connector_mode=connector_mode,
            include_writes=include_writes,
            audit_database=audit_database,
            artifact_root=artifact_root,
            workspace_root=workspace_root,
            result_json=result_json,
            environ=source,
        )
        selected_paths = owned_paths
    else:
        selected_paths = tuple(captured_paths)
    expected_specs = _runtime_path_specs(
        integrations,
        connector_mode=connector_mode,
        include_writes=include_writes,
        audit_database=audit_database,
        artifact_root=artifact_root,
        workspace_root=workspace_root,
        result_json=result_json,
        environ=source,
    )
    expected = {
        name: (_canonical_path(path) or "", publication)
        for name, path, publication in expected_specs
    }
    observed = {
        item.binding.name: (item.binding.path, item.publication)
        for item in selected_paths
    }
    if len(observed) != len(selected_paths) or observed != expected:
        for item in owned_paths:
            item.close()
        raise ConfigurationError(
            "captured runtime directory set differs from selected runtime paths"
        )

    configurations = tuple(
        ConfigurationExecutionBinding(
            name=name,
            sha256=_config_source_sha256(config_source),
        )
        for name, config_source in configuration_sources.items()
    )
    normalized_result = _canonical_path(result_json)
    normalized_credential_file = _canonical_path(credential_file)
    try:
        return RuntimeExecutionBinding(
            connector_mode=connector_mode,
            include_writes=include_writes,
            include_communications=include_communications,
            audit_database=_canonical_path(audit_database) or "",
            artifact_root=_canonical_path(artifact_root) or "",
            workspace_root=normalized_workspace,
            result_json=normalized_result,
            credential_file=normalized_credential_file,
            evidence_type=evidence_type if normalized_result is not None else None,
            configurations=configurations,
            runtime_paths=tuple(
                item.binding for item in selected_paths if not item.publication
            ),
            publication_roots=tuple(
                item.binding for item in selected_paths if item.publication
            ),
        )
    finally:
        for item in owned_paths:
            item.close()


def capture_runtime_execution_paths(
    integrations: IntegrationConfig,
    *,
    connector_mode: str,
    include_writes: bool,
    audit_database: Path,
    artifact_root: Path,
    workspace_root: Path | None,
    result_json: Path | None,
    environ: Mapping[str, str] | None = None,
    approved_bindings: Sequence[RuntimePathExecutionBinding] | None = None,
) -> tuple[CapturedRuntimePath, ...]:
    """Capture and retain exact ancestor identities for every writable root."""

    require_platform_contract(PlatformContract.SECURE_FILESYSTEM)
    source = environ if environ is not None else os.environ
    captured: list[CapturedRuntimePath] = []
    try:
        specifications = _runtime_path_specs(
            integrations,
            connector_mode=connector_mode,
            include_writes=include_writes,
            audit_database=audit_database,
            artifact_root=artifact_root,
            workspace_root=workspace_root,
            result_json=result_json,
            environ=source,
        )
        if approved_bindings is None:
            approved = None
        else:
            approved = {item.name: item for item in approved_bindings}
            if len(approved) != len(approved_bindings):
                raise ConfigurationError("approved runtime path names are not unique")
        if approved is not None and set(approved) != {
            name for name, _, _ in specifications
        }:
            raise ConfigurationError(
                "applied execution context differs from the approved plan: "
                "runtime policy, principal, gate, or path binding"
            )
        for name, path, publication in specifications:
            if approved is not None:
                captured.append(
                    _capture_approved_runtime_path(
                        name,
                        path,
                        publication=publication,
                        approved=approved[name],
                    )
                )
                continue
            captured.append(
                _capture_runtime_path(
                    name,
                    path,
                    publication=publication,
                )
            )
        return tuple(captured)
    except BaseException:
        for item in captured:
            item.close()
        raise


def enforce_execution_context(plan: ChangePlan, observed: ExecutionContext) -> None:
    """Reject live execution unless the observed context is exactly approved."""

    approved = plan.execution_context
    if approved is None:
        raise ConfigurationError(
            "applied execution requires an approval-bound execution context; "
            "run bind-context before approval"
        )
    if approved != observed:
        changed: list[str] = []
        if approved.integrations_sha256 != observed.integrations_sha256:
            changed.append("integrations bundle")
        if approved.connectors != observed.connectors:
            changed.append("connector origin or CA identity")
        if approved.plugins != observed.plugins:
            changed.append("connector plugin identity")
        if approved.capsules != observed.capsules:
            changed.append("promoted capability capsule identity")
        if approved.runtime != observed.runtime:
            changed.append("runtime policy, principal, gate, or path binding")
        rendered = ", ".join(changed) or "execution context"
        raise ConfigurationError(
            f"applied execution context differs from the approved plan: {rendered}"
        )


def _origin(base_url: str, *, system: str) -> str:
    parsed = urlsplit(base_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            f"connector {system} has an invalid base URL port"
        ) from error
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and not (parsed.scheme == "https" and port == 443):
        rendered_host = f"{rendered_host}:{port}"
    return f"{parsed.scheme.lower()}://{rendered_host}"


def _config_source_sha256(source: ConfigSource) -> str:
    """Hash one already trusted configuration snapshot without interpreting it."""

    with source.open("rb") as handle:
        payload = handle.read()
    return hashlib.sha256(payload).hexdigest()


def _canonical_path(path: Path | None) -> str | None:
    if path is None:
        return None
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if os.name == "nt":
        from master_agent.platform_runtime.windows.filesystem import (
            validate_windows_drive_path,
        )

        return validate_windows_drive_path(selected).canonical
    return str(selected.resolve(strict=False))


def _runtime_path_specs(
    integrations: IntegrationConfig,
    *,
    connector_mode: str,
    include_writes: bool,
    audit_database: Path,
    artifact_root: Path,
    workspace_root: Path | None,
    result_json: Path | None,
    environ: Mapping[str, str],
) -> tuple[tuple[str, Path, bool], ...]:
    """Return named writable directories and publication-root requirements."""

    specifications: list[tuple[str, Path, bool]] = [
        ("audit.parent", audit_database.parent, False),
        ("artifact.root", artifact_root, False),
    ]
    if workspace_root is not None:
        specifications.append(("workspace.root", workspace_root, False))
    if result_json is not None:
        specifications.append(("result.parent", result_json.parent, False))
    if connector_mode == "live" and include_writes:
        for config in integrations.connectors.values():
            if not config.enabled or config.system != "bitbucket":
                continue
            if not (
                _strict_extra_bool(config.extra, "write_enabled")
                and _strict_extra_bool(config.extra, "branch_push_enabled")
            ):
                continue
            variable = str(config.extra.get("repository_root_env", "")).strip()
            if variable:
                raw_root = environ.get(variable, "").strip()
                if not raw_root:
                    raise ConfigurationError(
                        "Bitbucket branch publication requires environment variable "
                        f"{variable}"
                    )
                selected_root = Path(raw_root)
            elif workspace_root is not None:
                selected_root = workspace_root
            else:
                raise ConfigurationError(
                    "Bitbucket branch publication requires workspace_root or "
                    "repository_root_env"
                )
            specifications.append(
                (
                    f"{config.system}.branch_publication",
                    selected_root,
                    True,
                )
            )
    return tuple(specifications)


def _capture_runtime_path(
    name: str,
    path: Path,
    *,
    publication: bool,
) -> CapturedRuntimePath:
    """Pin an exact pre-existing canonical runtime directory."""

    canonical_value = _canonical_path(path)
    if canonical_value is None:  # pragma: no cover - non-optional invariant.
        raise ConfigurationError("runtime directory path is missing")
    target = Path(canonical_value)
    try:
        anchor = PinnedDirectory.open(target)
    except ConfigurationError as error:
        raise ConfigurationError(
            f"runtime directory must already exist and be private: {name}"
        ) from error
    try:
        object_identity = anchor.object_identity
        device, inode, owner, mode = _legacy_runtime_identity(object_identity)
        return CapturedRuntimePath(
            binding=RuntimePathExecutionBinding(
                name=name,
                path=str(target),
                anchor_path=str(anchor.path),
                device=device,
                inode=inode,
                owner=owner,
                mode=mode,
                object_identity=object_identity,
            ),
            publication=publication,
            _anchor=anchor,
        )
    except BaseException:
        anchor.close()
        raise


def _capture_approved_runtime_path(
    name: str,
    path: Path,
    *,
    publication: bool,
    approved: RuntimePathExecutionBinding,
) -> CapturedRuntimePath:
    """Reopen the plan's exact ancestor rather than selecting a newer leaf."""

    target_value = _canonical_path(path)
    if target_value is None:  # pragma: no cover - non-optional invariant.
        raise ConfigurationError("runtime directory path is missing")
    if approved.name != name or approved.path != target_value:
        raise ConfigurationError(
            "applied execution context differs from the approved plan: "
            "runtime policy, principal, gate, or path binding"
        )
    if approved.anchor_path != approved.path:
        raise ConfigurationError(
            f"approved runtime directory does not pin its exact path: {name}"
        )
    expected = approved.platform_identity
    anchor = PinnedDirectory.open(
        Path(approved.path),
        expected_identity=expected,
    )
    try:
        observed = anchor.object_identity
        if observed != expected:
            raise ConfigurationError(
                f"approved runtime directory identity changed: {name}"
            )
        device, inode, owner, mode = _legacy_runtime_identity(observed)
        return CapturedRuntimePath(
            binding=RuntimePathExecutionBinding(
                name=name,
                path=target_value,
                anchor_path=str(anchor.path),
                device=device,
                inode=inode,
                owner=owner,
                mode=mode,
                # Preserve the approved wire shape so pre-native POSIX plans
                # remain byte-for-byte comparable after their identities have
                # still been checked through the current platform contract.
                object_identity=(
                    observed if approved.object_identity is not None else None
                ),
            ),
            publication=publication,
            _anchor=anchor,
        )
    except BaseException:
        anchor.close()
        raise


def _legacy_runtime_identity(
    identity: PlatformObjectIdentity,
) -> tuple[int, int, int, int]:
    """Return legacy POSIX fields or zero placeholders for native Windows."""

    if identity.platform == "windows":
        return 0, 0, 0, 0
    return (
        cast(int, identity.device),
        cast(int, identity.inode),
        cast(int, identity.owner),
        cast(int, identity.mode),
    )


def _strict_extra_bool(extra: Mapping[str, object], key: str) -> bool:
    value = extra.get(key, False)
    if not isinstance(value, bool):
        raise ConfigurationError(f"connector setting {key} must be a boolean")
    return value
