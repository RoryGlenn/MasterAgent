"""Phase 0 and Phase 2C deployment-readiness assessment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from master_agent.audit import implemented_audit_sink
from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.governance import EnvironmentKind, GovernanceProfile
from master_agent.identity import IdentityRegistry
from master_agent.oauth import AccessToken, inspect_jwt_claims
from master_agent.oauth_config import OAuthProfiles


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """Secret-free deployment readiness result."""

    ready: bool
    environment: str
    checks: tuple[Mapping[str, Any], ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "schema": "master-agent/readiness@1",
            "ready": self.ready,
            "environment": self.environment,
            "checks": [dict(item) for item in self.checks],
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def assess_readiness(
    *,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    integrations: IntegrationConfig,
    oauth_profiles: OAuthProfiles | None = None,
    identities: IdentityRegistry | None = None,
    environ: Mapping[str, str] | None = None,
    tokens: Mapping[str, AccessToken] | None = None,
) -> ReadinessReport:
    """Assess configuration, governance, authentication, and scope coverage.

    This function does not perform network requests. Real contract probes are a
    separate operator action so readiness inspection is safe in CI and during
    installation.
    """

    checks: list[Mapping[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []

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
        attestation_error = connector.principal_attestation_error()
        connector_errors = tuple(
            dict.fromkeys(
                (
                    *connector.configuration_errors(environ),
                    *((attestation_error,) if attestation_error is not None else ()),
                )
            )
        )
        checks.append(
            {
                "name": f"connector:{name}",
                "passed": not connector_errors,
                "deployment": str(connector.deployment),
                "principal_attestation": (
                    str(connector.principal_attestation_adapter)
                    if connector.principal_attestation_adapter is not None
                    else "flow_enforced"
                ),
                "errors": list(connector_errors),
            }
        )
        errors.extend(f"{name}: {item}" for item in connector_errors)
    if enabled_connectors == 0:
        warnings.append(
            "no live connectors are enabled; runtime is safe but not connected"
        )

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
            profile_errors = profile.readiness_errors(environ)
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

    for name, token in sorted((tokens or {}).items()):
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
    }
    if governance.organization.strip().casefold() in placeholders:
        errors.append("non-development organization must not be a placeholder")
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
