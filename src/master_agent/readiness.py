"""Phase 0 and Phase 2C deployment-readiness assessment."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from master_agent.audit import implemented_audit_sink
from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.errors import ConfigurationError
from master_agent.governance import EnvironmentKind, GovernanceProfile
from master_agent.identity import IdentityRegistry
from master_agent.models import DataClassification, RiskLevel
from master_agent.oauth import AccessToken, inspect_jwt_claims
from master_agent.oauth_config import OAuthProfiles
from master_agent.platform_runtime import PlatformRuntimeStatus, platform_runtime_status
from master_agent.provider_egress import (
    ProviderDataRoute,
    implemented_dlp_adapter,
)


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """Secret-free deployment readiness result."""

    ready: bool
    environment: str
    checks: tuple[Mapping[str, Any], ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    platform_runtime: PlatformRuntimeStatus

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "schema": "master-agent/readiness@1",
            "ready": self.ready,
            "environment": self.environment,
            "checks": [dict(item) for item in self.checks],
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "platform_runtime": self.platform_runtime.to_dict(),
        }


def provider_data_egress_policy_denials(
    *,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    integrations: IntegrationConfig,
    egress_checks: Sequence[tuple[str, DataClassification]],
) -> tuple[str, ...]:
    """Return selected egress denials without consulting credential state."""

    if not egress_checks:
        return ()
    model_context = governance.model_context
    if model_context is None:
        return ("governance has no configured model-context provider-data policy",)
    audit_available = implemented_audit_sink(governance.audit_sink) is not None
    denials: list[str] = []
    for provider, data_classification in egress_checks:
        configuration = _provider_configuration(provider)
        connector = integrations.connectors.get(configuration)
        if connector is None:
            denials.append(f"{provider}: selected provider is not configured")
            continue
        if not connector.enabled:
            denials.append(f"{provider}: selected provider connector is disabled")
            continue
        if not _provider_feature_ready(connector, provider):
            denials.append(f"{provider}: selected provider feature is not enabled")
            continue
        capabilities = _provider_readiness_capabilities(catalog, provider)
        decisions = tuple(
            model_context.evaluate(
                provider=provider,
                capability=capability,
                data_classification=data_classification,
                route=route,
                audit_available=(
                    audit_available if route is ProviderDataRoute.AUDITED else False
                ),
            )
            for capability in capabilities
            for route in (ProviderDataRoute.EPHEMERAL, ProviderDataRoute.AUDITED)
        )
        if any(decision.permitted for decision in decisions):
            continue
        reasons = tuple(dict.fromkeys(decision.reason for decision in decisions))
        reason = reasons[0] if reasons else "model-context policy is unavailable"
        denials.append(f"{provider}:{data_classification}: {reason}")
    return tuple(denials)


def assess_readiness(
    *,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    integrations: IntegrationConfig,
    oauth_profiles: OAuthProfiles | None = None,
    identities: IdentityRegistry | None = None,
    environ: Mapping[str, str] | None = None,
    tokens: Mapping[str, AccessToken] | None = None,
    egress_checks: Sequence[tuple[str, DataClassification]] = (),
) -> ReadinessReport:
    """Assess configuration, governance, authentication, and scope coverage.

    This function does not perform network requests. Real contract probes are a
    separate operator action so readiness inspection is safe in CI and during
    installation.
    """

    checks: list[Mapping[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    selected_platform_status = platform_runtime_status()
    static_egress_denials = provider_data_egress_policy_denials(
        catalog=catalog,
        governance=governance,
        integrations=integrations,
        egress_checks=egress_checks,
    )
    readiness_environ: Mapping[str, str] | None = (
        {} if static_egress_denials else environ
    )
    readiness_tokens: Mapping[str, AccessToken] = (
        {} if static_egress_denials else (tokens or {})
    )

    model_context = governance.model_context
    model_context_errors: list[str] = []
    if egress_checks:
        if model_context is None:
            model_context_errors.append(
                "governance has no configured model-context provider-data policy"
            )
        elif (
            governance.environment is EnvironmentKind.DEVELOPMENT
            and model_context.source_data_environment != "nonproduction"
        ):
            model_context_errors.append(
                "development model-context policy must use explicitly nonproduction data"
            )
        checks.append(
            {
                "name": "model_context_policy",
                "passed": model_context is not None and not model_context_errors,
                "destination": (
                    model_context.destination if model_context is not None else None
                ),
                "model_tenancy": (
                    model_context.model_tenancy if model_context is not None else None
                ),
                "source_data_environment": (
                    model_context.source_data_environment
                    if model_context is not None
                    else None
                ),
                "dlp_adapter": (
                    model_context.dlp_adapter if model_context is not None else None
                ),
                "dlp_adapter_implemented": bool(
                    model_context is not None
                    and implemented_dlp_adapter(model_context.dlp_adapter) is not None
                ),
                "policy_fingerprint": (
                    model_context.fingerprint if model_context is not None else None
                ),
                "errors": list(model_context_errors),
            }
        )
        errors.extend(model_context_errors)

    audit_sink = implemented_audit_sink(governance.audit_sink)
    audit_sink_ready = audit_sink is not None
    checks.append(
        {
            "name": "audit_sink",
            "passed": audit_sink_ready,
            "configured": governance.audit_sink,
            "kind": str(audit_sink.kind) if audit_sink is not None else None,
            "external": audit_sink.external if audit_sink is not None else None,
            "tamper_resistant": (
                audit_sink.tamper_resistant if audit_sink is not None else None
            ),
        }
    )
    if audit_sink is None:
        errors.append(
            "configured audit sink has no implemented typed adapter: "
            f"{governance.audit_sink}"
        )

    coverage = governance.coverage_report(catalog)
    checks.append(
        {
            "name": "governance_coverage",
            "passed": bool(coverage["ready"]),
            "covered_capabilities": len(coverage["covered"]),
        }
    )
    errors.extend(str(item) for item in coverage["errors"])

    enabled_connectors = 0
    for name, connector in sorted(integrations.connectors.items()):
        if not connector.enabled:
            continue
        enabled_connectors += 1
        missing_environment = connector.missing_environment_variables(readiness_environ)
        missing_errors = {
            f"environment variable {variable} is missing"
            for variable in missing_environment
        }
        static_errors = tuple(
            item
            for item in connector.configuration_errors(readiness_environ)
            if item not in missing_errors
        )
        network_variables = frozenset(
            connector.network_profile.required_environment_variables()
        )
        missing_network_environment = tuple(
            variable
            for variable in missing_environment
            if variable in network_variables
        )
        network_errors: tuple[str, ...] = ()
        if not missing_network_environment and not static_errors:
            try:
                connector.capture_execution_target(readiness_environ)
            except ConfigurationError:
                network_errors = (
                    "selected network profile or enterprise CA bundle is invalid",
                )
        attestation_error = (
            connector.principal_attestation_error() if not missing_environment else None
        )
        connector_errors = tuple(
            dict.fromkeys(
                (
                    *static_errors,
                    *network_errors,
                    *((attestation_error,) if attestation_error is not None else ()),
                )
            )
        )
        checks.append(
            {
                "name": f"connector:{name}",
                "passed": not connector_errors,
                "deployment": str(connector.deployment),
                "credential_ready": not missing_environment,
                "network_ready": not missing_network_environment and not network_errors,
                "network_profile": connector.network_profile.name,
                "network_mode": str(connector.network_profile.mode),
                "proxy_configured": connector.network_profile.mode.value != "direct",
                "enterprise_ca_configured": bool(
                    connector.network_profile.ca_bundle_env or connector.ca_bundle_env
                ),
                "missing_environment": list(missing_environment),
                "principal_attestation": (
                    str(connector.principal_attestation_adapter)
                    if connector.principal_attestation_adapter is not None
                    else "flow_enforced"
                ),
                "errors": list(connector_errors),
            }
        )
        errors.extend(f"{name}: {item}" for item in connector_errors)
        if missing_environment:
            warnings.append(
                f"{name}: connector is available but inactive until its "
                "credentials are supplied"
            )
    if enabled_connectors == 0:
        warnings.append("no live connectors are available")

    for provider, data_classification in egress_checks:
        configuration = _provider_configuration(provider)
        selected_connector = integrations.connectors.get(configuration)
        missing_environment = (
            selected_connector.missing_environment_variables(readiness_environ)
            if selected_connector is not None and selected_connector.enabled
            else ()
        )
        attestation_error = (
            selected_connector.principal_attestation_error()
            if selected_connector is not None
            and selected_connector.enabled
            and not missing_environment
            else None
        )
        feature_ready = bool(
            selected_connector is not None
            and _provider_feature_ready(selected_connector, provider)
        )
        connector_usable = bool(
            selected_connector is not None
            and selected_connector.enabled
            and not selected_connector.configuration_errors(readiness_environ)
            and attestation_error is None
            and feature_ready
        )
        candidate_capabilities = _provider_readiness_capabilities(catalog, provider)
        ephemeral_decisions = tuple(
            (
                capability,
                model_context.evaluate(
                    provider=provider,
                    capability=capability,
                    data_classification=data_classification,
                    route=ProviderDataRoute.EPHEMERAL,
                    audit_available=False,
                ),
            )
            for capability in candidate_capabilities
            if model_context is not None
        )
        audited_decisions = tuple(
            (
                capability,
                model_context.evaluate(
                    provider=provider,
                    capability=capability,
                    data_classification=data_classification,
                    route=ProviderDataRoute.AUDITED,
                    audit_available=audit_sink_ready,
                ),
            )
            for capability in candidate_capabilities
            if model_context is not None
        )
        ephemeral_allowed = tuple(
            capability
            for capability, decision in ephemeral_decisions
            if decision.permitted
        )
        audited_allowed = tuple(
            capability
            for capability, decision in audited_decisions
            if decision.permitted
        )
        policy_usable = bool(ephemeral_allowed or audited_allowed)
        passed = connector_usable and policy_usable
        check_name = f"provider_data_egress:{provider}:{data_classification}"
        reason = (
            "provider configuration and model-context policy are usable"
            if passed
            else _egress_readiness_reason(
                connector_exists=selected_connector is not None,
                connector_enabled=bool(
                    selected_connector is not None and selected_connector.enabled
                ),
                missing_environment=missing_environment,
                attestation_error=attestation_error,
                feature_ready=feature_ready,
                policy_reasons=_policy_denial_reasons(
                    ephemeral_decisions,
                    audited_decisions,
                ),
            )
        )
        checks.append(
            {
                "name": check_name,
                "passed": passed,
                "provider": provider,
                "data_classification": str(data_classification),
                "destination": (
                    model_context.destination if model_context is not None else None
                ),
                "model_tenancy": (
                    model_context.model_tenancy if model_context is not None else None
                ),
                "connector_configuration": configuration,
                "credential_ready": not missing_environment,
                "connector_ready": connector_usable,
                "ephemeral_allowed": bool(ephemeral_allowed),
                "audited_allowed": bool(audited_allowed),
                "approved_capabilities": sorted(
                    set(ephemeral_allowed) | set(audited_allowed)
                ),
                "ephemeral_policy": _approved_route_summaries(ephemeral_decisions),
                "audited_policy": _approved_route_summaries(audited_decisions),
                "dlp_adapter_implemented": bool(
                    model_context is not None
                    and implemented_dlp_adapter(model_context.dlp_adapter) is not None
                ),
                "reason": reason,
            }
        )
        if not passed:
            errors.append(f"{check_name}: {reason}")

    if governance.environment is not EnvironmentKind.DEVELOPMENT:
        deployment_errors = _non_development_placeholder_errors(
            governance=governance,
            integrations=integrations,
            identities=identities,
            enabled_connectors=enabled_connectors,
        )
        checks.append(
            {
                "name": "non_development_placeholders",
                "passed": not deployment_errors,
                "errors": list(deployment_errors),
            }
        )
        errors.extend(deployment_errors)

    if oauth_profiles is not None:
        for name, profile in sorted(oauth_profiles.profiles.items()):
            if not profile.enabled:
                continue
            profile_errors = profile.readiness_errors(
                readiness_environ,
                platform_status=selected_platform_status,
            )
            checks.append(
                {
                    "name": f"oauth:{name}",
                    "passed": not profile_errors,
                    "flow": str(profile.flow),
                    "provider": profile.provider,
                    "required_scopes": list(profile.scopes),
                    "errors": list(profile_errors),
                }
            )
            errors.extend(f"oauth {name}: {item}" for item in profile_errors)

    for name, token in sorted(readiness_tokens.items()):
        token_profile = oauth_profiles.profiles.get(name) if oauth_profiles else None
        required = set(token_profile.scopes if token_profile else ())
        granted = {item.casefold() for item in token.scopes}
        claims = inspect_jwt_claims(token.value)
        claim_scopes = str(claims.get("scp", "")).split()
        claim_roles = claims.get("roles", [])
        granted.update(item.casefold() for item in claim_scopes)
        if isinstance(claim_roles, list):
            granted.update(str(item).casefold() for item in claim_roles)
        missing = sorted(item for item in required if item.casefold() not in granted)
        valid = token.is_valid() and not missing
        checks.append(
            {
                "name": f"token:{name}",
                "passed": valid,
                "source": token.source,
                "expires_at": token.expires_at.isoformat(),
                "missing_permissions": missing,
                "tenant_id": claims.get("tid"),
                "audience": claims.get("aud"),
            }
        )
        if not token.is_valid():
            errors.append(f"token {name} is expired or too close to expiry")
        if missing:
            errors.append(
                f"token {name} lacks required permissions: {', '.join(missing)}"
            )

    if governance.environment is EnvironmentKind.PRODUCTION:
        approval_value = governance.metadata.get("production_approved", False)
        if not isinstance(approval_value, bool):
            errors.append("production_approved must be a boolean")
            approved = False
        else:
            approved = approval_value
        if not approved:
            errors.append("production governance has not been explicitly approved")
        if audit_sink is None:
            errors.append(
                "production requires an implemented external, tamper-resistant "
                "audit sink"
            )
        elif not audit_sink.external or not audit_sink.tamper_resistant:
            errors.append("production audit sink must be external and tamper-resistant")
        if "environment" in governance.secret_manager.casefold():
            warnings.append(
                "production should use an approved secret manager rather than "
                "long-lived environment secrets"
            )

    return ReadinessReport(
        ready=not errors,
        environment=str(governance.environment),
        checks=tuple(checks),
        errors=tuple(dict.fromkeys(errors)),
        warnings=tuple(dict.fromkeys(warnings)),
        platform_runtime=selected_platform_status,
    )


def _non_development_placeholder_errors(
    *,
    governance: GovernanceProfile,
    integrations: IntegrationConfig,
    identities: IdentityRegistry | None,
    enabled_connectors: int,
) -> tuple[str, ...]:
    """Reject packaged example facts outside the development environment."""

    errors: list[str] = []
    placeholders = {
        "unassigned",
        "example",
        "example-organization",
        "platform-owner",
        "system-owner",
        "source-control-owner",
        "communications-owner",
        "local-operator-or-approved-agent",
        "nonproduction-development",
    }
    if governance.organization.strip().casefold() in placeholders:
        errors.append("non-development organization must not be a placeholder")
    if governance.model_context is not None:
        if governance.model_context.destination.strip().casefold() in placeholders:
            errors.append("non-development model-context destination is a placeholder")
        if governance.model_context.model_tenancy.strip().casefold() in placeholders:
            errors.append("non-development model tenancy is a placeholder")
    for key, value in governance.metadata.items():
        if key.endswith("_owner") and str(value).strip().casefold() in placeholders:
            errors.append(f"non-development governance owner is a placeholder: {key}")
    for rule in governance.rules:
        if rule.owner.strip().casefold() in placeholders:
            errors.append(
                f"non-development governance rule owner is a placeholder: "
                f"{rule.pattern}"
            )
    if enabled_connectors == 0:
        errors.append("non-development deployment requires an enabled connector")
    for name, connector in integrations.connectors.items():
        if not connector.enabled or not connector.base_url:
            continue
        hostname = (urlparse(connector.base_url).hostname or "").casefold()
        if hostname in {"localhost", "127.0.0.1", "::1"} or any(
            label == "example" or label.startswith("example-")
            for label in hostname.split(".")
        ):
            errors.append(
                f"non-development connector uses a placeholder endpoint: {name}"
            )
    if identities is None or not identities.people:
        errors.append(
            "non-development deployment requires a reviewed identity registry"
        )
    else:
        for person in identities.people.values():
            for system, value in person.identifiers.items():
                normalized = value.strip().casefold()
                if normalized == "me" or "@example." in normalized:
                    errors.append(
                        f"non-development identity is a placeholder: "
                        f"{person.key}.{system}"
                    )
    return tuple(dict.fromkeys(errors))


def _provider_configuration(provider: str) -> str:
    if provider in {"microsoft", "sharepoint", "outlook", "teams", "onenote"}:
        return "microsoft"
    return provider


def _egress_readiness_reason(
    *,
    connector_exists: bool,
    connector_enabled: bool,
    missing_environment: tuple[str, ...],
    attestation_error: str | None,
    feature_ready: bool,
    policy_reasons: tuple[str, ...],
) -> str:
    if not connector_exists:
        return "selected provider has no connector configuration"
    if not connector_enabled:
        return "selected provider connector is disabled"
    if missing_environment:
        return "selected provider credentials are not ready: " + ", ".join(
            missing_environment
        )
    if attestation_error is not None:
        return "selected provider has no implemented principal attestation"
    if not feature_ready:
        return "selected provider feature is not enabled"
    if not policy_reasons:
        return "model-context policy is unavailable"
    return "; ".join(policy_reasons[:4])


def _provider_readiness_capabilities(
    catalog: CapabilityCatalog,
    provider: str,
) -> tuple[str, ...]:
    capabilities = [f"{provider}.connection.probe"]
    capabilities.extend(
        name
        for name in catalog.enabled_names()
        if catalog.definition(name).risk is RiskLevel.READ_ONLY
        and catalog.definition(name).target_system == provider
        and catalog.definition(name).authentication != "local"
        and bool(catalog.definition(name).read_result_schema)
        and bool(catalog.definition(name).read_result_resources)
    )
    return tuple(dict.fromkeys(capabilities))


def _provider_feature_ready(connector: Any, provider: str) -> bool:
    if provider == "onenote":
        return bool(connector.extra.get("onenote_read_enabled", False))
    return True


def _approved_route_summaries(
    decisions: tuple[tuple[str, Any], ...],
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for capability, decision in decisions:
        rule = decision.rule
        if not decision.permitted or rule is None:
            continue
        summary = grouped.setdefault(
            rule.name,
            {
                "rule": rule.name,
                "handling": str(rule.handling),
                "audit_required": rule.audit_required,
                "dlp_required": rule.dlp_required,
                "allowed_fields": sorted(rule.allowed_fields),
                "max_items": rule.max_items,
                "max_output_bytes": rule.max_output_bytes,
                "capabilities": [],
            },
        )
        summary["capabilities"].append(capability)
    return [grouped[name] for name in sorted(grouped)]


def _policy_denial_reasons(
    *decision_groups: tuple[tuple[str, Any], ...],
) -> tuple[str, ...]:
    reasons = [
        decision.reason
        for group in decision_groups
        for _, decision in group
        if not decision.permitted
    ]
    return tuple(dict.fromkeys(reasons))
