"""Configuration and connectivity discovery for live integrations."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TypedDict

from master_agent.config import IntegrationConfig
from master_agent.connectors.base import Connector
from master_agent.connectors.factory import build_live_connectors
from master_agent.errors import MasterAgentError
from master_agent.http import HttpTransport


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
    ) -> None:
        self._config = config
        self._environ = environ
        self._transport = transport
        self._systems = systems

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
            ),
        )


def discover_integrations(
    config: IntegrationConfig,
    *,
    environ: Mapping[str, str] | None = None,
    probe: bool = False,
    transport: HttpTransport | None = None,
    systems: set[str] | None = None,
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

    Returns
    -------
    tuple[DiscoveryRecord, ...]
        One record per runtime connector. Secret values are never included.
    """

    source = environ if environ is not None else os.environ
    selected = systems or {
        "jira",
        "confluence",
        "bitbucket",
        "github",
        "microsoft",
        "sharepoint",
        "outlook",
        "teams",
    }
    records: list[DiscoveryRecord] = []

    for configuration in sorted(config.connectors):
        unresolved = config.connectors[configuration]
        runtime_systems = tuple(
            system for system in _runtime_systems(configuration) if system in selected
        )
        if not runtime_systems:
            continue

        configuration_errors = unresolved.configuration_errors(source)
        common: _DiscoveryCommon = {
            "configuration": configuration,
            "enabled": unresolved.enabled,
            "deployment": str(unresolved.deployment),
            "auth_mode": str(unresolved.auth_mode),
            "base_url": unresolved.base_url
            or (
                source.get(unresolved.base_url_env) if unresolved.base_url_env else None
            ),
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

        try:
            live = build_live_connectors(
                IntegrationConfig(connectors={configuration: unresolved}),
                environ=source,
                transport=transport,
                systems=set(runtime_systems),
            )
            by_system = {connector.system: connector for connector in live}
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
                    error_message=str(error),
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
            try:
                probe_result = _probe(connector)
                records.append(
                    DiscoveryRecord(
                        system=system,
                        status=DiscoveryStatus.REACHABLE,
                        capabilities=capabilities,
                        probe=probe_result,
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
                        error_type=type(error).__name__,
                        error_message=str(error),
                        **common,
                    )
                )

    return tuple(records)


def _runtime_systems(configuration: str) -> tuple[str, ...]:
    if configuration == "microsoft":
        return ("microsoft", "sharepoint", "outlook", "teams")
    return (configuration,)


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
