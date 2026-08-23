"""Ephemeral, policy-gated sessions for typed provider reads.

This module deliberately does not use :class:`~master_agent.audit.AuditLog`,
runtime path bindings, idempotency state, or result publication.  It is the
narrow execution path for a direct user asking to read one configured provider
through an existing typed ``ReadOnlyConnector``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.connectors.read_only import ReadOnlyConnector
from master_agent.errors import (
    ConfigurationError,
    ConnectorError,
    MasterAgentError,
    VerificationError,
)
from master_agent.governance import GovernanceProfile
from master_agent.http import (
    activate_http_action_budget,
    connector_http_action_budget,
)
from master_agent.models import (
    ActionState,
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    ExecutionResult,
    RiskLevel,
    VerificationResult,
    freeze_json_mapping,
)
from master_agent.planners.base import enforce_systems_governance
from master_agent.policy import PolicyEngine
from master_agent.provider_egress import (
    ProviderDataEgressBinding,
    ProviderDataRoute,
    bind_provider_data_egress,
    preflight_provider_data_egress,
    sanitize_provider_result,
    verification_metadata,
)

_MICROSOFT_PROVIDER_SYSTEMS = frozenset(
    {"microsoft", "sharepoint", "outlook", "teams", "onenote"}
)

__all__ = (
    "DirectReadActionReport",
    "DirectReadExecutor",
    "DirectReadPayload",
    "DirectReadReport",
    "DirectReadSession",
    "DirectReadVerification",
    "preflight_direct_read_plan",
)


@dataclass(frozen=True, slots=True)
class DirectReadPayload:
    """Verified provider content held only in the caller's memory.

    Parameters
    ----------
    data
        Normalized read data returned by the typed connector after a successful
        independent verification.
    connector_reference
        Provider reference returned by the connector, when available.
    """

    data: Mapping[str, Any]
    connector_reference: str | None

    def __post_init__(self) -> None:
        """Freeze the JSON-compatible provider payload for the report."""

        object.__setattr__(self, "data", freeze_json_mapping(self.data))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible in-memory payload representation."""

        return {
            "data": _thaw_json(self.data),
            "connector_reference": self.connector_reference,
        }


@dataclass(frozen=True, slots=True)
class DirectReadVerification:
    """Immutable independent verification evidence for one direct read."""

    verified: bool
    observed: Mapping[str, Any] | None
    message: str

    def __post_init__(self) -> None:
        """Freeze verification evidence before it leaves the session."""

        if self.observed is not None:
            object.__setattr__(
                self,
                "observed",
                freeze_json_mapping(self.observed),
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible verification representation."""

        return {
            "verified": self.verified,
            "observed": (
                _thaw_json(self.observed) if self.observed is not None else None
            ),
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class DirectReadActionReport:
    """Verified in-memory outcome for one direct read action."""

    action_id: UUID
    capability: str
    state: ActionState
    message: str
    payload: DirectReadPayload
    verification: DirectReadVerification
    egress: ProviderDataEgressBinding

    def __post_init__(self) -> None:
        """Keep the direct-report terminal state unambiguous."""

        if self.state is not ActionState.VERIFIED:
            raise ValueError("direct read action reports must be verified")
        if not self.verification.verified:
            raise ValueError("direct read action reports require verified evidence")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible direct-read action report."""

        return {
            "action_id": str(self.action_id),
            "capability": self.capability,
            "state": str(self.state),
            "message": self.message,
            "payload": self.payload.to_dict(),
            "verification": self.verification.to_dict(),
            "egress": self.egress.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class DirectReadReport:
    """Complete, non-persistent report for one direct provider read session."""

    plan_id: UUID
    plan_fingerprint: str
    provider: str
    actions: tuple[DirectReadActionReport, ...]
    schema: str = "master-agent/direct-read-report@1"

    def __post_init__(self) -> None:
        """Validate that the report has one provider and verified actions."""

        if self.schema != "master-agent/direct-read-report@1":
            raise ValueError("unsupported direct read report schema")
        if not self.provider.strip():
            raise ValueError("direct read report provider must not be empty")
        if not self.actions:
            raise ValueError("direct read report must contain at least one action")

    @property
    def successful(self) -> bool:
        """Return whether every returned payload was independently verified."""

        return all(
            action.state is ActionState.VERIFIED and action.verification.verified
            for action in self.actions
        )

    @property
    def payloads(self) -> tuple[DirectReadPayload, ...]:
        """Return verified payloads in the requested action order."""

        return tuple(action.payload for action in self.actions)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible report without writing it anywhere."""

        return {
            "schema": self.schema,
            "plan_id": str(self.plan_id),
            "plan_fingerprint": self.plan_fingerprint,
            "provider": self.provider,
            "successful": self.successful,
            "actions": [action.to_dict() for action in self.actions],
        }


class DirectReadSession:
    """Execute one direct-user, one-provider read plan without durable state.

    The caller supplies exactly one already constructed typed read connector and
    its fresh secret-free execution binding.  The binding is intentionally not
    placed on the plan: direct sessions reject any persisted execution context.
    """

    def __init__(
        self,
        *,
        catalog: CapabilityCatalog,
        governance: GovernanceProfile,
        policy: PolicyEngine,
        sources: SourceOfTruthRegistry,
        connector: ReadOnlyConnector,
        execution_binding: ConnectorExecutionBinding,
    ) -> None:
        """Create an in-memory direct read session.

        Parameters
        ----------
        catalog, governance, policy, sources
            The normal typed runtime validators.  Direct reads retain these
            checks rather than inheriting write-oriented persistence.
        connector
            The sole built-in typed read connector selected by the caller.
        execution_binding
            A fresh, secret-free binding for that connector's configuration,
            credential identity, scopes, and fixed provider endpoint.
        """

        if not isinstance(connector, ReadOnlyConnector):
            raise ConfigurationError(
                "direct read sessions require a typed ReadOnlyConnector"
            )
        if not _is_builtin_direct_read_connector(connector):
            raise ConfigurationError(
                "direct read sessions require a factory-issued built-in connector"
            )
        if not isinstance(execution_binding, ConnectorExecutionBinding):
            raise ConfigurationError(
                "direct read sessions require a typed connector execution binding"
            )
        self._catalog = catalog
        self._governance = governance
        self._policy = policy
        self._sources = sources
        self._connector = connector
        self._execution_binding = execution_binding

    def execute(self, plan: ChangePlan) -> DirectReadReport:
        """Preflight and execute a direct provider-read plan in memory.

        All actions are validated before the first provider request.  Each
        action then executes and independently re-reads under one retained HTTP
        request/response budget.  A failed verification raises instead of
        returning unverified provider content.
        """

        provider = preflight_direct_read_plan(
            plan=plan,
            catalog=self._catalog,
            governance=self._governance,
            policy=self._policy,
            sources=self._sources,
        )
        self._validate_connector_shape(plan, provider)
        egress_bindings = tuple(
            self._validate_execution_contract(action) for action in plan.actions
        )

        reports = tuple(
            self._execute_action(action, egress)
            for action, egress in zip(plan.actions, egress_bindings, strict=True)
        )
        return DirectReadReport(
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            provider=self._connector.system,
            actions=reports,
        )

    def run(self, plan: ChangePlan) -> DirectReadReport:
        """Alias :meth:`execute` for orchestration-style callers."""

        return self.execute(plan)

    def _validate_connector_shape(self, plan: ChangePlan, provider: str) -> None:
        """Bind an already preflighted plan to one typed read connector."""

        if provider != self._connector.system:
            raise ConfigurationError(
                "direct read plan provider does not match the selected connector"
            )
        expected_binding_system = _binding_system_for(self._connector.system)
        if self._execution_binding.system != expected_binding_system:
            raise ConfigurationError(
                "direct read execution binding does not match the selected provider"
            )
        _validate_binding_endpoint(self._execution_binding)

        for action in plan.actions:
            if action.capability not in self._connector.capabilities:
                raise ConfigurationError(
                    f"selected read connector does not support {action.capability}"
                )

    def _validate_execution_contract(
        self,
        action: AgentAction,
    ) -> ProviderDataEgressBinding:
        """Validate the live connector binding after no-I/O plan preflight."""

        execution_ok, execution_reason = self._catalog.validate_execution(
            action,
            self._connector,
            self._execution_binding,
            connector_mode="live",
        )
        if not execution_ok:
            raise ConfigurationError(execution_reason)
        _validate_connector_endpoint(self._connector, self._execution_binding)
        if self._governance.model_context is None:
            raise ConfigurationError(
                "provider reads require configured model-context policy"
            )
        return bind_provider_data_egress(
            policy=self._governance.model_context,
            action=action,
            definition=self._catalog.definition(action.capability),
            connector_binding=self._execution_binding,
            route=ProviderDataRoute.EPHEMERAL,
            audit_available=False,
        )

    def _execute_action(
        self,
        action: AgentAction,
        egress: ProviderDataEgressBinding,
    ) -> DirectReadActionReport:
        """Execute and independently verify one preflighted read action."""

        budget = connector_http_action_budget(self._connector)
        if budget is None:
            raise ConfigurationError(
                "direct read connector is missing a live HTTP action budget"
            )
        snapshot: ExecutionResult | None = None
        verification: VerificationResult | None = None
        provider_failed = False
        try:
            with activate_http_action_budget(budget):
                result = self._connector.execute(action)
                _validate_read_result(action, result)
                snapshot = _copy_execution_result(result)
                verification = self._connector.verify(
                    action,
                    _copy_execution_result(snapshot),
                )
                _validate_verification(action, verification)
        except (
            KeyError,
            MasterAgentError,
            OSError,
            OverflowError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            provider_failed = True
        if provider_failed or snapshot is None or verification is None:
            # Raise outside the provider exception handler so neither __cause__ nor
            # __context__ retains attacker-controlled provider content.
            raise ConnectorError("provider read failed after egress authorization")

        if not verification.verified:
            raise VerificationError(
                f"direct read did not independently verify {action.capability}"
            )
        if snapshot.after is None:
            raise ConnectorError("direct read connector returned no payload")
        rechecked = self._validate_execution_contract(action)
        if rechecked.fingerprint != egress.fingerprint:
            raise ConfigurationError(
                "provider-data egress binding changed before result return"
            )
        sanitized: ExecutionResult | None = None
        sanitized_verification: Mapping[str, Any] | None = None
        sanitization_failed = False
        try:
            sanitized = sanitize_provider_result(snapshot, egress)
            sanitized_verification = verification_metadata(
                verification.observed,
                egress,
            )
        except (
            KeyError,
            MasterAgentError,
            OSError,
            OverflowError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            sanitization_failed = True
        if sanitization_failed or sanitized is None:
            # Raise outside the sanitization exception handler so provider-controlled
            # values cannot survive in exception chaining or caller-visible text.
            raise ConnectorError("provider read failed after egress authorization")
        if sanitized.after is None:  # pragma: no cover - snapshot invariant.
            raise ConnectorError("direct read connector returned no sanitized payload")

        return DirectReadActionReport(
            action_id=action.action_id,
            capability=action.capability,
            state=ActionState.VERIFIED,
            message="provider read independently verified",
            payload=DirectReadPayload(
                data=sanitized.after,
                connector_reference=sanitized.connector_reference,
            ),
            verification=DirectReadVerification(
                verified=verification.verified,
                observed=sanitized_verification,
                message="provider read independently verified",
            ),
            egress=egress,
        )


def preflight_direct_read_plan(
    *,
    plan: ChangePlan,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    policy: PolicyEngine,
    sources: SourceOfTruthRegistry,
) -> str:
    """Validate a direct read plan before credentials or a connector are resolved.

    This no-I/O phase lets a CLI reject an invalid plan before provider
    principal attestation or connector construction.  It intentionally leaves
    the fresh connector execution binding for :class:`DirectReadSession`,
    which validates it immediately before dispatch.

    Returns
    -------
    str
        The one provider system selected by the preflighted plan.
    """

    enforce_systems_governance(plan)
    provider = _validate_unbound_session_shape(plan)
    governance_ok, governance_reason = governance.allows_direct_read_session(plan)
    if not governance_ok:
        raise ConfigurationError(governance_reason)
    for action in plan.actions:
        _validate_unbound_action(
            plan=plan,
            action=action,
            catalog=catalog,
            governance=governance,
            policy=policy,
            sources=sources,
        )
    return provider


# ``DirectReadExecutor`` is intentionally an alias instead of another runtime
# layer: both names identify the same stateless, one-provider execution type.
DirectReadExecutor = DirectReadSession


def _validate_unbound_session_shape(plan: ChangePlan) -> str:
    """Reject stateful, indirect, cross-provider, and effect-bearing plans."""

    context = plan.execution_context
    if context is not None:
        if context.plugins:
            raise ConfigurationError("direct read sessions cannot execute plugins")
        if context.capsules:
            raise ConfigurationError(
                "direct read sessions cannot execute capability capsules"
            )
        raise ConfigurationError(
            "direct read sessions must not use a persisted execution context"
        )
    if plan.workflow_id is not None or plan.workflow_fingerprint is not None:
        raise ConfigurationError(
            "direct read sessions cannot execute a registered workflow"
        )
    if plan.compensate_on_failure:
        raise ConfigurationError("direct read sessions cannot request compensation")

    systems = {action.target.system for action in plan.actions}
    if len(systems) != 1:
        raise ConfigurationError("direct read sessions require exactly one provider")
    provider = next(iter(systems))
    for action in plan.actions:
        if action.risk is not RiskLevel.READ_ONLY:
            raise ConfigurationError(
                "direct read sessions permit read-only actions only"
            )
        if action.authority_source is not AuthoritySource.DIRECT_USER:
            raise ConfigurationError(
                "direct read sessions require direct-user authority"
            )
        if action.requires_approval:
            raise ConfigurationError(
                "direct read sessions cannot carry approval-required actions"
            )
    return provider


def _is_builtin_direct_read_connector(connector: ReadOnlyConnector) -> bool:
    """Return whether the connector is an exact repository-owned implementation."""

    # Import lazily to keep connector construction out of module initialization.
    from master_agent.connectors.bitbucket import BitbucketConnector
    from master_agent.connectors.confluence import ConfluenceConnector
    from master_agent.connectors.github import GitHubConnector
    from master_agent.connectors.jira import JiraConnector
    from master_agent.connectors.microsoft import (
        MicrosoftIdentityConnector,
        SharePointConnector,
    )
    from master_agent.connectors.onenote import OneNoteReadConnector
    from master_agent.connectors.outlook import OutlookConnector
    from master_agent.connectors.reddit import RedditConnector
    from master_agent.connectors.teams import TeamsConnector

    return type(connector) in {
        BitbucketConnector,
        ConfluenceConnector,
        GitHubConnector,
        JiraConnector,
        MicrosoftIdentityConnector,
        OneNoteReadConnector,
        OutlookConnector,
        RedditConnector,
        SharePointConnector,
        TeamsConnector,
    }


def _validate_unbound_action(
    *,
    plan: ChangePlan,
    action: AgentAction,
    catalog: CapabilityCatalog,
    governance: GovernanceProfile,
    policy: PolicyEngine,
    sources: SourceOfTruthRegistry,
) -> None:
    """Apply catalog, governance, source, and policy before connector setup."""

    catalog_ok, catalog_reason = catalog.validate_action(action)
    if not catalog_ok:
        raise ConfigurationError(catalog_reason)

    governance_ok, governance_reason = governance.validate_action(action)
    if not governance_ok:
        raise ConfigurationError(governance_reason)
    definition = catalog.definition(action.capability)
    if governance.model_context is None:
        raise ConfigurationError(
            "provider reads require configured model-context policy"
        )
    preflight_provider_data_egress(
        policy=governance.model_context,
        action=action,
        definition=definition,
        route=ProviderDataRoute.EPHEMERAL,
        audit_available=False,
    )
    external_model_ok, external_model_reason = governance.validate_external_model(
        action,
        definition,
    )
    if not external_model_ok:
        raise ConfigurationError(external_model_reason)

    source_ok, source_reason = sources.validate(plan, action)
    if not source_ok:
        raise ConfigurationError(source_reason)

    minimum_approvers = governance.minimum_approvers(action.capability)
    decision = policy.evaluate(
        plan=plan,
        action=action,
        minimum_distinct_approvers=minimum_approvers,
    )
    if not decision.permitted or decision.approval_required:
        raise ConfigurationError(
            f"direct read policy does not permit {action.capability}: {decision.reason}"
        )


def _binding_system_for(system: str) -> str:
    """Return the configuration owner for a connector-facing provider system."""

    return "microsoft" if system in _MICROSOFT_PROVIDER_SYSTEMS else system


def _validate_binding_endpoint(binding: ConnectorExecutionBinding) -> None:
    """Confirm that the binding's declared origin matches its fixed base URL."""

    parsed = urlsplit(binding.resolved_base_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError(
            "direct read execution binding must use an HTTPS provider endpoint"
        )
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            "direct read execution binding has an invalid provider endpoint port"
        ) from error
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != 443:
        rendered_host = f"{rendered_host}:{port}"
    expected_origin = f"https://{rendered_host}"
    if binding.resolved_origin != expected_origin:
        raise ConfigurationError(
            "direct read execution binding origin does not match its provider endpoint"
        )


def _validate_connector_endpoint(
    connector: ReadOnlyConnector,
    binding: ConnectorExecutionBinding,
) -> None:
    """Reject a resolved connector whose endpoint or CA identity drifted."""

    config = getattr(connector, "_config", None)
    if config is None:
        raise ConfigurationError("direct read connector has no resolved configuration")
    base_url = getattr(config, "base_url", None)
    if not isinstance(base_url, str) or not base_url:
        raise ConfigurationError(
            "direct read connector has no resolved provider endpoint"
        )
    if base_url != binding.resolved_base_url:
        raise ConfigurationError(
            "resolved connector endpoint drifted from the direct read binding"
        )
    ca_bundle = getattr(config, "ca_bundle", None)
    ca_bundle_sha256 = getattr(config, "ca_bundle_sha256", None)
    if (
        ca_bundle is not None
        or ca_bundle_sha256 is not None
        or binding.ca_bundle_path is not None
        or binding.ca_bundle_sha256 is not None
    ) and (
        (str(ca_bundle) if ca_bundle is not None else None) != binding.ca_bundle_path
        or ca_bundle_sha256 != binding.ca_bundle_sha256
    ):
        raise ConfigurationError(
            "resolved connector CA identity drifted from the direct read binding"
        )
    runtime_network_name = getattr(config, "network_profile_name", "direct")
    runtime_network_sha256 = getattr(config, "network_profile_sha256", None)
    runtime_proxy = getattr(config, "proxy_url", None)
    legacy_direct = (
        binding.network_profile_name == "direct"
        and binding.network_profile_sha256 is None
        and binding.proxy_origin is None
    )
    network_drifted = (
        runtime_network_name != "direct" or runtime_proxy is not None
        if legacy_direct
        else (
            runtime_network_name != binding.network_profile_name
            or runtime_network_sha256 != binding.network_profile_sha256
            or runtime_proxy != binding.proxy_origin
        )
    )
    if network_drifted:
        raise ConfigurationError(
            "resolved connector network profile drifted from the direct read binding"
        )


def _validate_read_result(action: AgentAction, result: object) -> None:
    """Bind a connector result to a successful read-only action."""

    if not isinstance(result, ExecutionResult):
        raise ConnectorError("connector returned an invalid direct read result")
    if result.action_id != action.action_id:
        raise ConnectorError("connector result action ID did not match the action")
    result.validate_integrity()
    if result.state is not ActionState.SUCCEEDED:
        raise ConnectorError(
            "direct read connector result must report succeeded before verification"
        )


def _validate_verification(action: AgentAction, verification: object) -> None:
    """Ensure a connector returned typed verification for the same action."""

    if not isinstance(verification, VerificationResult):
        raise ConnectorError("connector returned an invalid direct read verification")
    if verification.action_id != action.action_id:
        raise ConnectorError(
            "connector verification action ID did not match the action"
        )


def _copy_execution_result(result: ExecutionResult) -> ExecutionResult:
    """Return a private copy before passing connector evidence to verification."""

    result.validate_integrity()
    return ExecutionResult(
        action_id=result.action_id,
        state=result.state,
        before=result.before,
        after=result.after,
        connector_reference=result.connector_reference,
        message=result.message,
        compensation=result.compensation,
    )


def _thaw_json(value: Any) -> Any:
    """Render recursively frozen JSON-compatible values for report output."""

    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value
