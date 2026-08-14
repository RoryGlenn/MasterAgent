"""Phase 0 and Phase 2C deployment-readiness assessment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from master_agent.capabilities import CapabilityCatalog
from master_agent.config import IntegrationConfig
from master_agent.governance import EnvironmentKind, GovernanceProfile
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
        connector_errors = connector.configuration_errors(environ)
        checks.append(
            {
                "name": f"connector:{name}",
                "passed": not connector_errors,
                "deployment": str(connector.deployment),
                "errors": list(connector_errors),
            }
        )
        errors.extend(f"{name}: {item}" for item in connector_errors)
    if enabled_connectors == 0:
        warnings.append(
            "no live connectors are enabled; runtime is safe but not connected"
        )

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
        profile = oauth_profiles.profiles.get(name) if oauth_profiles else None
        required = set(profile.scopes if profile else ())
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
        if "local" in governance.audit_sink.casefold():
            errors.append("production audit sink must not be local-only")
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
