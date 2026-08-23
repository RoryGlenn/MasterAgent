"""Configuration and connectivity discovery for live integrations."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TypedDict
from urllib.parse import urlsplit

from master_agent.capabilities import (
    CapabilityDefinition,
    validate_connector_execution_binding,
)
from master_agent.config import IntegrationConfig
from master_agent.connectors.base import Connector
from master_agent.connectors.factory import build_live_connectors
from master_agent.errors import ConfigurationError, MasterAgentError
from master_agent.execution_context import capture_connector_executions
from master_agent.governance import GovernanceProfile
from master_agent.http import HttpTransport
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    DataClassification,
    ResourceRef,
    RiskLevel,
)
from master_agent.provider_egress import (
    ProviderDataEgressBinding,
    ProviderDataRoute,
    bind_provider_data_egress,
    minimize_probe_result,
    preflight_provider_data_egress,
)

_DEFAULT_DISCOVERY_SYSTEMS = frozenset(
    {
        "jira",
        "confluence",
        "bitbucket",
        "github",
        "microsoft",
        "sharepoint",
        "outlook",
        "teams",
        "reddit",
    }
)


class DiscoveryStatus(StrEnum):
    """State of one runtime connector during discovery."""

    DISABLED = "disabled"
    MISSING_ENVIRONMENT = "missing_environment"
    READY = "ready"
    REACHABLE = "reachable"
    FAILED = "failed"


class _DiscoveryCommon(TypedDict):
    configuration: str
    enabled: bool
    deployment: str
    auth_mode: str
    base_url: str | None
    required_environment: tuple[str, ...]
    missing_environment: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiscoveryRecord:
    """Audit-safe integration discovery result."""

    configuration: str
    system: str
    status: DiscoveryStatus
    enabled: bool
    deployment: str
    auth_mode: str
    base_url: str | None
    required_environment: tuple[str, ...]
    missing_environment: tuple[str, ...]
    capabilities: tuple[str, ...] = ()
    probe: Mapping[str, Any] | None = None
    egress: Mapping[str, Any] | None = None
    error_type: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record without authentication material."""

        value = asdict(self)
        value["status"] = str(self.status)
        return value


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """Complete audit-safe integration discovery report."""

    generated_at: str
    connectors: tuple[DiscoveryRecord, ...]

    @property
    def ready(self) -> bool:
        """Return whether at least one enabled connector is ready."""

        enabled = tuple(
            item
            for item in self.connectors
            if item.status is not DiscoveryStatus.DISABLED
        )
        return bool(enabled) and all(
            item.status in {DiscoveryStatus.READY, DiscoveryStatus.REACHABLE}
            for item in enabled
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "generated_at": self.generated_at,
            "ready": self.ready,
            "connectors": [item.to_dict() for item in self.connectors],
        }


class EnvironmentDiscovery:
    """Object-oriented facade used by the command-line interface."""

    def __init__(
        self,
        config: IntegrationConfig,
        *,
        environ: Mapping[str, str] | None = None,
        transport: HttpTransport | None = None,
        systems: set[str] | None = None,
        governance: GovernanceProfile | None = None,
        data_classification: DataClassification | None = None,
    ) -> None:
        self._config = config
        self._environ = environ
        self._transport = transport
        self._systems = systems
        self._governance = governance
        self._data_classification = data_classification

    def inspect(self, *, probe: bool = False) -> DiscoveryReport:
        """Inspect configuration and optionally call read-only probes."""

        return DiscoveryReport(
            generated_at=datetime.now(UTC).isoformat(),
            connectors=discover_integrations(
                self._config,
                environ=self._environ,
                probe=probe,
                transport=self._transport,
                systems=self._systems,
                governance=self._governance,
                data_classification=self._data_classification,
            ),
        )


def discover_integrations(
    config: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    probe: bool = False,
    transport: HttpTransport | None = None,
    systems: set[str] | None = None,
    governance: GovernanceProfile | None = None,
    data_classification: DataClassification | None = None,
) -> tuple[DiscoveryRecord, ...]:
    """Inspect integration configuration and optionally probe live APIs.

    Parameters
    ----------
    config
        Parsed integration configuration.
    environ
        Environment mapping containing credential values.
    probe
        When true, perform bounded read-only connectivity checks.
    transport
        Optional transport injected by tests.
    systems
        Optional runtime-system allowlist.
    governance
        Required model-context policy for live probes.
    data_classification
        Explicit provider-data class for a probe. Development may use only the
        configured nonproduction default when this is omitted.

    Returns
    -------
    tuple[DiscoveryRecord, ...]
        One record per runtime connector. Secret values are never included.
    """

    selected = set(_DEFAULT_DISCOVERY_SYSTEMS) if systems is None else set(systems)
    probe_classification: DataClassification | None = None
    probe_denials: dict[str, str] = {}
    if probe:
        if systems is not None:
            _validate_probe_system_selection(config, selected)
        probe_classification, probe_denials = _probe_policy_state(
            config,
            governance=governance,
            systems=selected,
            data_classification=data_classification,
        )
    source = environ if environ is not None else os.environ
    records: list[DiscoveryRecord] = []

    for configuration in sorted(config.connectors):
        unresolved = config.connectors[configuration]
        runtime_systems = tuple(
            system for system in _runtime_systems(configuration) if system in selected
        )
        if not runtime_systems:
            continue

        # Policy-denied systems are reported without consulting environment
        # values, credential readiness, principal attestation, or connector
        # construction. A configured secret can never turn a denied probe into
        # an attempted one.
        denied_systems = tuple(
            system for system in runtime_systems if system in probe_denials
        )
        if denied_systems:
            denied_common = _policy_denied_common(configuration, unresolved)
            records.extend(
                DiscoveryRecord(
                    system=system,
                    status=DiscoveryStatus.FAILED,
                    error_type="ConfigurationError",
                    error_message=probe_denials[system],
                    **denied_common,
                )
                for system in denied_systems
            )
            runtime_systems = tuple(
                system for system in runtime_systems if system not in probe_denials
            )
            if not runtime_systems:
                continue

        configuration_errors = unresolved.configuration_errors(source)
        configured_base_url = unresolved.base_url or (
            source.get(unresolved.base_url_env) if unresolved.base_url_env else None
        )
        common: _DiscoveryCommon = {
            "configuration": configuration,
            "enabled": unresolved.enabled,
            "deployment": str(unresolved.deployment),
            "auth_mode": str(unresolved.auth_mode),
            "base_url": _safe_discovery_base_url(configured_base_url),
            "required_environment": unresolved.required_environment_variables(),
            "missing_environment": unresolved.missing_environment_variables(source),
        }

        if not unresolved.enabled:
            records.extend(
                DiscoveryRecord(
                    system=system,
                    status=DiscoveryStatus.DISABLED,
                    **common,
                )
                for system in runtime_systems
            )
            continue

        if configuration_errors:
            status = (
                DiscoveryStatus.MISSING_ENVIRONMENT
                if common["missing_environment"]
                else DiscoveryStatus.FAILED
            )
            records.extend(
                DiscoveryRecord(
                    system=system,
                    status=status,
                    error_type="ConfigurationError",
                    error_message="; ".join(configuration_errors),
                    **common,
                )
                for system in runtime_systems
            )
            continue

        probe_bindings: dict[str, ProviderDataEgressBinding] = {}
        try:
            scoped_config = IntegrationConfig(
                connectors={configuration: unresolved},
                network_profiles=config.network_profiles,
                source_sha256=config.source_sha256,
            )
            captured = (
                capture_connector_executions(
                    scoped_config,
                    environ=source,
                    systems=set(runtime_systems),
                    principal_transport=transport,
                )
                if probe
                else ()
            )
            captured_binding = captured[0].binding if captured else None
            live = build_live_connectors(
                scoped_config,
                environ=source,
                transport=transport,
                systems=set(runtime_systems),
                captured_executions=captured if probe else None,
            )
            by_system = {connector.system: connector for connector in live}
            if probe:
                assert governance is not None
                assert governance.model_context is not None
                assert probe_classification is not None
                assert captured_binding is not None
                for system in runtime_systems:
                    action, definition = _probe_contract(
                        system,
                        probe_classification,
                    )
                    probe_bindings[system] = bind_provider_data_egress(
                        policy=governance.model_context,
                        action=action,
                        definition=definition,
                        connector_binding=captured_binding,
                        route=ProviderDataRoute.EPHEMERAL,
                        audit_available=False,
                    )
        except (
            KeyError,
            MasterAgentError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as error:
            records.extend(
                DiscoveryRecord(
                    system=system,
                    status=DiscoveryStatus.FAILED,
                    error_type=type(error).__name__,
                    error_message=(
                        "provider connection setup failed after egress preflight"
                        if probe
                        else str(error)
                    ),
                    **common,
                )
                for system in runtime_systems
            )
            continue

        for system in runtime_systems:
            connector = by_system.get(system)
            if connector is None:
                records.append(
                    DiscoveryRecord(
                        system=system,
                        status=DiscoveryStatus.FAILED,
                        error_type="ConfigurationError",
                        error_message="no connector was constructed",
                        **common,
                    )
                )
                continue
            capabilities = _capabilities(connector)
            if not probe:
                records.append(
                    DiscoveryRecord(
                        system=system,
                        status=DiscoveryStatus.READY,
                        capabilities=capabilities,
                        **common,
                    )
                )
                continue
            binding = probe_bindings.get(system)
            if binding is None:
                records.append(
                    DiscoveryRecord(
                        system=system,
                        status=DiscoveryStatus.FAILED,
                        capabilities=capabilities,
                        error_type="ConfigurationError",
                        error_message="provider probe is missing its egress binding",
                        **common,
                    )
                )
                continue
            assert probe_classification is not None
            try:
                assert captured_binding is not None
                endpoint_allowed, endpoint_reason = (
                    validate_connector_execution_binding(connector, captured_binding)
                )
                if not endpoint_allowed:
                    raise ConfigurationError(endpoint_reason)
                raw_probe = _probe(connector)
                action, definition = _probe_contract(
                    system,
                    probe_classification,
                )
                assert governance is not None
                assert governance.model_context is not None
                rebound = bind_provider_data_egress(
                    policy=governance.model_context,
                    action=action,
                    definition=definition,
                    connector_binding=captured_binding,
                    route=ProviderDataRoute.EPHEMERAL,
                    audit_available=False,
                )
                if rebound.fingerprint != binding.fingerprint:
                    raise ConfigurationError(
                        "provider-data egress binding changed before probe return"
                    )
                endpoint_allowed, endpoint_reason = (
                    validate_connector_execution_binding(connector, captured_binding)
                )
                if not endpoint_allowed:
                    raise ConfigurationError(endpoint_reason)
                probe_result = minimize_probe_result(raw_probe, binding)
                records.append(
                    DiscoveryRecord(
                        system=system,
                        status=DiscoveryStatus.REACHABLE,
                        capabilities=capabilities,
                        probe=probe_result,
                        egress=binding.to_dict(),
                        **common,
                    )
                )
            except (
                KeyError,
                MasterAgentError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as error:
                records.append(
                    DiscoveryRecord(
                        system=system,
                        status=DiscoveryStatus.FAILED,
                        capabilities=capabilities,
                        egress=binding.to_dict(),
                        error_type=type(error).__name__,
                        error_message="provider probe failed after egress authorization",
                        **common,
                    )
                )

    return tuple(records)


def preflight_probe_provider_egress(
    config: IntegrationConfig,
    *,
    governance: GovernanceProfile,
    systems: set[str] | None = None,
    data_classification: DataClassification | None = None,
) -> DataClassification:
    """Authorize selected live probes without reading credential material.

    The command-line routes call this before loading an explicit credential
    file or overlaying ambient credential variables. ``discover_integrations``
    performs the same preflight internally for direct library callers.
    """

    selected = set(_DEFAULT_DISCOVERY_SYSTEMS) if systems is None else set(systems)
    if systems is not None:
        _validate_probe_system_selection(config, selected)
    classification, denials = _probe_policy_state(
        config,
        governance=governance,
        systems=selected,
        data_classification=data_classification,
    )
    if denials:
        first_system = min(denials)
        raise ConfigurationError(denials[first_system])
    return classification


def _validate_probe_system_selection(
    config: IntegrationConfig,
    systems: set[str],
) -> None:
    """Reject empty or unconfigured explicit probe allowlists."""

    if not systems:
        raise ConfigurationError("live provider probes require a selected system")
    configured = {
        system
        for configuration in config.connectors
        for system in _runtime_systems(configuration)
    }
    unknown = sorted(systems - configured)
    if unknown:
        raise ConfigurationError(
            "live provider probes select unconfigured systems: " + ", ".join(unknown)
        )


def _probe_policy_state(
    config: IntegrationConfig,
    *,
    governance: GovernanceProfile | None,
    systems: set[str],
    data_classification: DataClassification | None,
) -> tuple[DataClassification, dict[str, str]]:
    """Resolve one probe class and content-free per-system policy denials."""

    if governance is None or governance.model_context is None:
        raise ConfigurationError(
            "live provider probes require configured model-context policy"
        )
    classification = governance.model_context.resolve_probe_classification(
        data_classification,
        environment=str(governance.environment),
    )
    selected_runtime_systems = {
        system
        for configuration in config.connectors
        for system in _runtime_systems(configuration)
        if system in systems
    }
    denials: dict[str, str] = {}
    for system in sorted(selected_runtime_systems):
        reason = _probe_policy_preflight(
            governance,
            systems=(system,),
            data_classification=classification,
        )
        if reason is not None:
            denials[system] = reason
    return classification, denials


def _policy_denied_common(
    configuration: str,
    connector: Any,
) -> _DiscoveryCommon:
    """Build a denial record solely from non-secret static configuration."""

    return {
        "configuration": configuration,
        "enabled": connector.enabled,
        "deployment": str(connector.deployment),
        "auth_mode": str(connector.auth_mode),
        "base_url": _safe_discovery_base_url(connector.base_url),
        "required_environment": connector.required_environment_variables(),
        "missing_environment": (),
    }


def _runtime_systems(configuration: str) -> tuple[str, ...]:
    if configuration == "microsoft":
        return ("microsoft", "sharepoint", "outlook", "teams", "onenote")
    return (configuration,)


def _safe_discovery_base_url(value: str | None) -> str | None:
    """Return only a normalized credential- and query-free configured endpoint."""

    if value is None:
        return None
    selected = value.strip()
    try:
        parsed = urlsplit(selected)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    return selected


def _capabilities(connector: Connector) -> tuple[str, ...]:
    value = getattr(connector, "capabilities", ())
    return tuple(sorted(str(item) for item in value))


def _probe(connector: Connector) -> Mapping[str, Any]:
    probe_method = getattr(connector, "probe", None)
    if not callable(probe_method):
        return {"reachable": True, "note": "connector has no dedicated probe"}
    result = probe_method()
    if not isinstance(result, Mapping):
        return {"reachable": True, "result": str(result)}
    return dict(result)


def _probe_policy_preflight(
    governance: GovernanceProfile,
    *,
    systems: tuple[str, ...],
    data_classification: DataClassification,
) -> str | None:
    """Reject a probe before principal attestation or connector construction."""

    assert governance.model_context is not None
    for system in systems:
        action, definition = _probe_contract(system, data_classification)
        try:
            preflight_provider_data_egress(
                policy=governance.model_context,
                action=action,
                definition=definition,
                route=ProviderDataRoute.EPHEMERAL,
                audit_available=False,
            )
        except ConfigurationError as error:
            return str(error)
    return None


def _probe_contract(
    system: str,
    data_classification: DataClassification,
) -> tuple[AgentAction, CapabilityDefinition]:
    """Return a fixed, versioned control-plane probe contract."""

    capability = f"{system}.connection.probe"
    action = AgentAction(
        capability=capability,
        target=ResourceRef(system, "connection", "configured-provider"),
        parameters={},
        risk=RiskLevel.READ_ONLY,
        data_classification=data_classification,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"{system}:connection-probe",
        justification="Verify the configured provider connection.",
    )
    definition = CapabilityDefinition(
        name=capability,
        enabled=True,
        authentication="anonymous_or_configured_connector",
        risk=RiskLevel.READ_ONLY,
        target_system=system,
        target_resource_types=("connection",),
        parameter_schema={},
        read_result_schema="master-agent/provider-probe@1",
        read_result_resources={
            "reachable": "value",
            "result_sha256": "value",
        },
        description="Fixed-field provider connectivity probe.",
    )
    return action, definition
