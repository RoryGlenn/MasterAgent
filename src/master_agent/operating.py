"""Progressive employee and developer operating-mode contracts.

This module is intentionally an offline boundary.  It loads one immutable
organization profile, provisions only private local directories, validates an
unbound :class:`~master_agent.models.ChangePlan`, and reports capability-scoped
readiness without constructing connectors or executing actions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tomllib
import unicodedata
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Self

from master_agent.auth import AuthMode
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.config import (
    DeploymentType,
    IntegrationConfig,
    is_placeholder_provider_url,
)
from master_agent.config_sources import (
    ConfigSnapshot,
    ConfigSource,
    resolve_config_source,
)
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import ChangePlan, RiskLevel
from master_agent.platform_runtime import (
    PlatformContract,
    PlatformRuntimeStatus,
    platform_runtime_status,
    require_persistent_state_platform,
)
from master_agent.trust_store import capture_ca_bundle, create_ssl_context

ORGANIZATION_PROFILE_SCHEMA = "master-agent/organization-profile@1"
OPERATING_PLAN_VALIDATION_SCHEMA = "master-agent/operating-plan-validation@1"
OPERATING_READINESS_SCHEMA = "master-agent/operating-readiness@1"
ORGANIZATION_SETUP_SCHEMA = "master-agent/organization-setup@1"

_PROFILE_FILENAME = "organization-profile.toml"
_MAX_PROFILE_BYTES = 256 * 1024
_MAX_PROFILE_CAPABILITIES = 512
_MAX_CONFIGURATION_PATHS = 32
_MAX_PATH_CHARACTERS = 4096
_MAX_REPORT_BYTES = 1024 * 1024
_MAX_DIRECTORY_DEPTH = 64
_RUN_ID_PATTERN = re.compile(r"[a-f0-9]{32}")
_CAPABILITY_PATTERN = re.compile(r"[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+")
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "organization",
        "mode",
        "state_root",
        "connector_mode",
        "writes_enabled",
        "communications_enabled",
        "capabilities",
        "configuration",
    }
)
_REQUIRED_TOP_LEVEL_KEYS = _TOP_LEVEL_KEYS - {"configuration"}
_CONFIGURATION_NAMES = frozenset(
    {
        "approval_authorities",
        "capabilities",
        "communication_context",
        "draft_package",
        "governance",
        "identities",
        "integrations",
        "oauth",
        "policy",
        "recurring",
        "retention",
        "sources_of_truth",
        "weekly_status",
    }
)
_LOCAL_AUTHENTICATION_CONTRACTS = frozenset({"local", "local_git"})
_ANONYMOUS_AUTHENTICATION_CONTRACTS = frozenset({"anonymous_or_configured_connector"})
_ANONYMOUS_CAPABILITIES = frozenset(
    {
        "bitbucket.public_repository.list",
        "github.public_repository.list",
    }
)
_EMPLOYEE_RISKS = frozenset(
    {
        RiskLevel.READ_ONLY,
        RiskLevel.LOCAL_GENERATION,
        RiskLevel.REVERSIBLE_WRITE,
        RiskLevel.EXTERNAL_COMMUNICATION,
    }
)


class OperatingMode(StrEnum):
    """Supported user-facing operating modes."""

    EMPLOYEE = "employee"
    DEVELOPER = "developer"


class ConnectorMode(StrEnum):
    """Connector family selected by an organization profile."""

    LIVE = "live"
    MOCK = "mock"


class ReadinessLevel(StrEnum):
    """Progressive, capability-scoped readiness levels."""

    INSTALL = "install_ready"
    READ = "read_ready"
    DRAFT = "draft_ready"
    EFFECT = "effect_ready"
    ENTERPRISE = "enterprise_ready"


class OperatingFailureCategory(StrEnum):
    """Stable categories suitable for employee-facing remediation."""

    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    MISSING_ORGANIZATION_SETUP = "missing_organization_setup"
    MISSING_USER_AUTHENTICATION = "missing_user_authentication"
    BLOCKED_POLICY = "blocked_policy"
    RUNTIME_DEFECT = "runtime_defect"


@dataclass(frozen=True, slots=True)
class OperatingIssue:
    """One bounded operating-mode failure.

    Parameters
    ----------
    category
        Stable remediation category.
    message
        Secret-free explanation suitable for terminal or JSON output.
    capability
        Exact capability affected by the issue, when applicable.
    """

    category: OperatingFailureCategory
    message: str
    capability: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.category, OperatingFailureCategory):
            raise TypeError("operating issue category must be typed")
        _validate_bounded_text(self.message, "operating issue message", maximum=1024)
        if self.capability is not None:
            _validate_capability_name(self.capability)

    def to_dict(self) -> dict[str, str]:
        """Serialize the issue without provider content or credentials."""

        result = {
            "category": str(self.category),
            "message": self.message,
        }
        if self.capability is not None:
            result["capability"] = self.capability
        return result


class OperatingValidationError(ValidationError):
    """Raised when an operating-mode validation result is rejected."""

    def __init__(self, issues: Sequence[OperatingIssue]) -> None:
        bounded = tuple(issues)
        if not bounded:
            raise ValueError("an operating validation error requires an issue")
        self.issues = bounded
        self.category = bounded[0].category
        super().__init__(bounded[0].message)

    def to_dict(self) -> dict[str, Any]:
        """Return a bounded employee-facing error payload."""

        return {
            "category": str(self.category),
            "message": str(self),
            "issues": [item.to_dict() for item in self.issues],
        }


@dataclass(frozen=True, slots=True)
class OrganizationProfile:
    """Immutable organization-owned operating profile.

    Paths are secret-free references only.  Relative paths are bound to the
    profile file's parent rather than the current working directory.
    """

    organization: str
    mode: OperatingMode
    state_root: Path
    connector_mode: ConnectorMode
    writes_enabled: bool
    communications_enabled: bool
    capabilities: tuple[str, ...]
    configuration: Mapping[str, Path]
    fingerprint: str
    source_path: Path
    schema: str = ORGANIZATION_PROFILE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ORGANIZATION_PROFILE_SCHEMA:
            raise ConfigurationError("unsupported organization profile schema")
        _validate_bounded_text(self.organization, "organization", maximum=256)
        if not isinstance(self.mode, OperatingMode):
            raise ConfigurationError("organization profile mode must be typed")
        if not isinstance(self.connector_mode, ConnectorMode):
            raise ConfigurationError(
                "organization profile connector_mode must be typed"
            )
        if not isinstance(self.writes_enabled, bool):
            raise ConfigurationError("writes_enabled must be a boolean")
        if not isinstance(self.communications_enabled, bool):
            raise ConfigurationError("communications_enabled must be a boolean")
        if not self.state_root.is_absolute():
            raise ConfigurationError("organization profile state_root must be absolute")
        _validate_path_length(self.state_root, "state_root")
        source_path = _absolute_path(self.source_path)
        _validate_path_length(source_path, "profile source path")
        capabilities = tuple(sorted(set(self.capabilities)))
        if len(capabilities) != len(self.capabilities):
            raise ConfigurationError("organization profile capabilities must be unique")
        if len(capabilities) > _MAX_PROFILE_CAPABILITIES:
            raise ConfigurationError(
                "organization profile capability allowlist exceeds 512 items"
            )
        for capability in capabilities:
            _validate_capability_name(capability)
        configuration = dict(self.configuration)
        if len(configuration) > _MAX_CONFIGURATION_PATHS:
            raise ConfigurationError(
                "organization profile configuration path count is too large"
            )
        unknown = sorted(set(configuration) - _CONFIGURATION_NAMES)
        if unknown:
            raise ConfigurationError(
                "organization profile has unknown configuration paths: "
                + ", ".join(unknown)
            )
        for name, path in configuration.items():
            if not isinstance(name, str) or not isinstance(path, Path):
                raise ConfigurationError(
                    "organization profile configuration paths must be named paths"
                )
            if not path.is_absolute():
                raise ConfigurationError(
                    f"organization profile configuration path is not absolute: {name}"
                )
            _validate_path_length(path, f"configuration path {name}")
        if re.fullmatch(r"[0-9a-f]{64}", self.fingerprint) is None:
            raise ConfigurationError("organization profile fingerprint is malformed")
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "configuration", MappingProxyType(configuration))
        object.__setattr__(self, "source_path", source_path)

    @classmethod
    def from_toml(cls, source: ConfigSource) -> Self:
        """Load one bounded organization profile snapshot.

        Parameters
        ----------
        source
            Trusted path, packaged resource, or pre-captured configuration
            snapshot.

        Returns
        -------
        OrganizationProfile
            Strict immutable profile with exact source fingerprint.
        """

        snapshot = _profile_snapshot(source)
        return cls.from_snapshot(snapshot)

    @classmethod
    def from_snapshot(
        cls,
        snapshot: ConfigSnapshot,
        *,
        installed_path: Path | None = None,
    ) -> Self:
        """Parse one already-captured profile, optionally at its installed path."""

        payload = snapshot.payload
        if len(payload) > _MAX_PROFILE_BYTES:
            raise ConfigurationError("organization profile exceeds the 256 KiB limit")
        source_path = installed_path or snapshot.display_path
        return cls._from_payload(payload, source_path=source_path)

    @classmethod
    def _from_payload(cls, payload: bytes, *, source_path: Path) -> Self:
        try:
            decoded = payload.decode("utf-8")
            raw = tomllib.loads(decoded)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise ConfigurationError(
                "organization profile is not valid UTF-8 TOML"
            ) from error
        if not isinstance(raw, Mapping):  # pragma: no cover - tomllib invariant.
            raise ConfigurationError("organization profile must be a TOML document")
        unknown = sorted(str(key) for key in raw if key not in _TOP_LEVEL_KEYS)
        if unknown:
            raise ConfigurationError(
                "organization profile has unknown keys: " + ", ".join(unknown)
            )
        missing = sorted(_REQUIRED_TOP_LEVEL_KEYS - set(raw))
        if missing:
            raise ConfigurationError(
                "organization profile is missing required keys: " + ", ".join(missing)
            )
        schema = _required_string(raw, "schema")
        if schema != ORGANIZATION_PROFILE_SCHEMA:
            raise ConfigurationError("unsupported organization profile schema")
        try:
            mode = OperatingMode(_required_string(raw, "mode"))
        except ValueError as error:
            raise ConfigurationError(
                "organization profile mode must be employee or developer"
            ) from error
        try:
            connector_mode = ConnectorMode(_required_string(raw, "connector_mode"))
        except ValueError as error:
            raise ConfigurationError(
                "organization profile connector_mode must be live or mock"
            ) from error
        capabilities = _required_string_list(raw, "capabilities")
        raw_configuration = raw.get("configuration", {})
        if not isinstance(raw_configuration, Mapping):
            raise ConfigurationError("[configuration] must be a TOML table")
        if not all(isinstance(key, str) for key in raw_configuration):
            raise ConfigurationError("configuration path names must be strings")
        unknown_paths = sorted(set(raw_configuration) - _CONFIGURATION_NAMES)
        if unknown_paths:
            raise ConfigurationError(
                "organization profile has unknown configuration paths: "
                + ", ".join(unknown_paths)
            )
        if not all(isinstance(value, str) for value in raw_configuration.values()):
            raise ConfigurationError("configuration paths must be strings")
        source_path = _absolute_path(source_path)
        base = source_path.parent
        state_root = _profile_relative_path(
            _required_string(raw, "state_root"),
            base=base,
            name="state_root",
        )
        configuration = {
            str(name): _profile_relative_path(
                str(value),
                base=base,
                name=f"configuration.{name}",
            )
            for name, value in raw_configuration.items()
        }
        return cls(
            schema=schema,
            organization=_required_string(raw, "organization"),
            mode=mode,
            state_root=state_root,
            connector_mode=connector_mode,
            writes_enabled=_required_bool(raw, "writes_enabled"),
            communications_enabled=_required_bool(raw, "communications_enabled"),
            capabilities=capabilities,
            configuration=configuration,
            fingerprint=hashlib.sha256(payload).hexdigest(),
            source_path=source_path,
        )

    def configuration_path(self, name: str) -> Path | None:
        """Return one explicit normal configuration path, if configured."""

        if name not in _CONFIGURATION_NAMES:
            raise ConfigurationError(f"unknown organization configuration path: {name}")
        return self.configuration.get(name)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the secret-free profile identity and gates."""

        return {
            "schema": self.schema,
            "organization": self.organization,
            "mode": str(self.mode),
            "state_root": os.fspath(self.state_root),
            "connector_mode": str(self.connector_mode),
            "writes_enabled": self.writes_enabled,
            "communications_enabled": self.communications_enabled,
            "capabilities": list(self.capabilities),
            "configuration": {
                name: os.fspath(path)
                for name, path in sorted(self.configuration.items())
            },
            "fingerprint": self.fingerprint,
            "source_path": os.fspath(self.source_path),
        }


@dataclass(frozen=True, slots=True)
class OperatingStatePaths:
    """Private organization state roots created during setup."""

    state_root: Path
    runs_root: Path

    def to_dict(self) -> dict[str, str]:
        """Serialize the two directory paths."""

        return {
            "state_root": os.fspath(self.state_root),
            "runs_root": os.fspath(self.runs_root),
        }


@dataclass(frozen=True, slots=True)
class OperatingRunPaths:
    """Private paths allocated for one unexecuted operating run."""

    run_id: str
    run_root: Path
    plan: Path
    bound_plan: Path
    audit_database: Path
    artifacts: Path
    result: Path
    workspace: Path

    def to_dict(self) -> dict[str, str]:
        """Serialize path identities; none of the file paths must yet exist."""

        return {
            "run_id": self.run_id,
            "run_root": os.fspath(self.run_root),
            "plan": os.fspath(self.plan),
            "bound_plan": os.fspath(self.bound_plan),
            "audit_database": os.fspath(self.audit_database),
            "artifacts": os.fspath(self.artifacts),
            "result": os.fspath(self.result),
            "workspace": os.fspath(self.workspace),
        }


@dataclass(frozen=True, slots=True)
class OrganizationSetupResult:
    """Result of installing one immutable profile and private state roots."""

    profile: OrganizationProfile
    state: OperatingStatePaths
    profile_created: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize setup evidence without creating runtime files."""

        return {
            "schema": ORGANIZATION_SETUP_SCHEMA,
            "profile": self.profile.to_dict(),
            "state": self.state.to_dict(),
            "profile_created": self.profile_created,
        }


@dataclass(frozen=True, slots=True)
class OperatingPlanValidation:
    """Pure pre-runtime validation result for one change plan."""

    mode: OperatingMode
    plan_fingerprint: str
    profile_fingerprint: str
    issues: tuple[OperatingIssue, ...] = ()

    @property
    def allowed(self) -> bool:
        """Return whether runtime construction may continue."""

        return not self.issues

    def require_valid(self) -> None:
        """Raise a typed error unless validation allowed the plan."""

        if self.issues:
            raise OperatingValidationError(self.issues)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the bounded validation result."""

        return {
            "schema": OPERATING_PLAN_VALIDATION_SCHEMA,
            "allowed": self.allowed,
            "mode": str(self.mode),
            "plan_fingerprint": self.plan_fingerprint,
            "profile_fingerprint": self.profile_fingerprint,
            "issues": [item.to_dict() for item in self.issues],
        }

    def to_json(self) -> str:
        """Return canonical JSON under the operating report byte ceiling."""

        return _bounded_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class CapabilityReadiness:
    """Readiness state for one exact allowlisted capability."""

    capability: str
    risk: RiskLevel | None
    install_ready: bool
    read_ready: bool
    draft_ready: bool
    effect_ready: bool
    enterprise_ready: bool = False
    issues: tuple[OperatingIssue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize one capability's progressive readiness."""

        return {
            "capability": self.capability,
            "risk": str(self.risk) if self.risk is not None else None,
            "install_ready": self.install_ready,
            "read_ready": self.read_ready,
            "draft_ready": self.draft_ready,
            "effect_ready": self.effect_ready,
            "enterprise_ready": self.enterprise_ready,
            "issues": [item.to_dict() for item in self.issues],
        }


@dataclass(frozen=True, slots=True)
class OperatingReadinessReport:
    """Bounded offline readiness report for an organization profile."""

    mode: OperatingMode
    profile_fingerprint: str
    profile_source: Path
    capabilities: tuple[CapabilityReadiness, ...]
    platform_runtime: PlatformRuntimeStatus
    enterprise_blocker: str = (
        "enterprise readiness requires the organization trust controls tracked by #113"
    )
    schema: str = OPERATING_READINESS_SCHEMA

    @property
    def install_ready(self) -> bool:
        """Return whether the core package/profile diagnostic path is healthy.

        Individual optional capability dependencies remain visible on each
        capability record without making a usable core installation appear
        broken.
        """

        return True

    @property
    def read_ready(self) -> bool:
        """Return whether at least one requested read capability is ready."""

        selected = tuple(
            item for item in self.capabilities if item.risk is RiskLevel.READ_ONLY
        )
        return self.install_ready and any(item.read_ready for item in selected)

    @property
    def draft_ready(self) -> bool:
        """Return whether at least one requested draft capability is ready."""

        selected = tuple(
            item
            for item in self.capabilities
            if item.risk is RiskLevel.LOCAL_GENERATION
        )
        return self.install_ready and any(item.draft_ready for item in selected)

    @property
    def effect_ready(self) -> bool:
        """Return whether at least one requested effect capability is ready."""

        selected = tuple(
            item
            for item in self.capabilities
            if item.risk not in {None, RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
        )
        return self.install_ready and any(item.effect_ready for item in selected)

    @property
    def enterprise_ready(self) -> bool:
        """Remain fail closed until the organization trust milestone lands."""

        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize a bounded doctor/readiness payload."""

        return {
            "schema": self.schema,
            "mode": str(self.mode),
            "profile_fingerprint": self.profile_fingerprint,
            "profile_source": os.fspath(self.profile_source),
            "platform_runtime": self.platform_runtime.to_dict(),
            "levels": {
                str(ReadinessLevel.INSTALL): self.install_ready,
                str(ReadinessLevel.READ): self.read_ready,
                str(ReadinessLevel.DRAFT): self.draft_ready,
                str(ReadinessLevel.EFFECT): self.effect_ready,
                str(ReadinessLevel.ENTERPRISE): self.enterprise_ready,
            },
            "enterprise_blocker": self.enterprise_blocker,
            "capabilities": [item.to_dict() for item in self.capabilities],
        }

    def to_json(self) -> str:
        """Return canonical JSON under the operating report byte ceiling."""

        return _bounded_json(self.to_dict())


def default_organization_profile_path(*, home: Path | None = None) -> Path:
    """Return the safe current-user default profile path.

    Parameters
    ----------
    home
        Explicit home directory for tests or embedding.  Defaults to
        :meth:`pathlib.Path.home` and never consults the current directory.
    """

    selected_home = _absolute_path(home or Path.home())
    if selected_home == Path(selected_home.anchor):
        raise ConfigurationError("organization profile home directory is invalid")
    return selected_home / ".master-agent" / "MasterAgent" / _PROFILE_FILENAME


def load_organization_profile(source: ConfigSource) -> OrganizationProfile:
    """Load a profile with stable setup-aware error categorization."""

    try:
        return OrganizationProfile.from_toml(source)
    except FileNotFoundError as error:  # pragma: no cover - normalized by resolver.
        raise _setup_error("organization profile is not installed") from error
    except ConfigurationError as error:
        if "not found" in str(error) or "unavailable" in str(error):
            raise _setup_error("organization profile is not installed") from error
        raise OperatingValidationError(
            (
                OperatingIssue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    f"organization profile is invalid: {error}",
                ),
            )
        ) from error


def install_organization_profile(
    source: ConfigSource,
    *,
    destination: Path | None = None,
) -> OrganizationSetupResult:
    """Install an exact mode-0600 profile and provision private state roots.

    Setup creates only the destination parent, ``state_root``, and
    ``state_root/runs``.  It deliberately creates no plan, audit database,
    result, workspace, or artifact.
    """

    require_persistent_state_platform()
    snapshot = _profile_snapshot(source)
    target = _absolute_path(destination or default_organization_profile_path())
    if target.name in {"", ".", ".."} or target == Path(target.anchor):
        raise ConfigurationError("organization profile destination is invalid")
    _validate_path_length(target, "organization profile destination")
    # Validate all bytes before mutating the local state namespace. Relative
    # paths intentionally bind to the installed profile location.
    installed_profile = OrganizationProfile.from_snapshot(
        snapshot,
        installed_path=target,
    )
    target_key = _portable_path_key(target)
    state_aliases = (
        installed_profile.state_root,
        *installed_profile.state_root.parents,
    )
    if any(_portable_path_key(candidate) == target_key for candidate in state_aliases):
        raise ConfigurationError(
            "organization profile state_root must not occupy the profile file path"
        )
    _ensure_private_directory(target.parent)
    destination_exists = os.path.lexists(target)
    if destination_exists:
        # Validate existing bytes before provisioning any paths selected by a
        # replacement profile. Identical setup remains idempotent.
        _validate_existing_profile_file(target, snapshot.payload)
    state = provision_organization_state(installed_profile)
    created = (
        False
        if destination_exists
        else _install_private_file(
            target,
            snapshot.payload,
        )
    )
    if destination_exists:
        _validate_existing_profile_file(target, snapshot.payload)
    profile = OrganizationProfile.from_snapshot(
        ConfigSnapshot(display_path=target, payload=snapshot.payload),
    )
    return OrganizationSetupResult(
        profile=profile,
        state=state,
        profile_created=created,
    )


def _validate_existing_profile_file(path: Path, expected: bytes) -> None:
    """Validate existing installed bytes without creating a raced destination."""

    parent = _ensure_private_directory(path.parent)
    descriptor = os.open(parent, _directory_flags())
    try:
        if _read_private_file(descriptor, path.name) != expected:
            raise ConfigurationError(
                "organization profile destination already contains different bytes"
            )
    finally:
        os.close(descriptor)


def provision_organization_state(profile: OrganizationProfile) -> OperatingStatePaths:
    """Create only the private state and run-container directories."""

    require_persistent_state_platform()
    state_root = _ensure_private_directory(profile.state_root)
    runs_root = _ensure_private_directory(state_root / "runs")
    return OperatingStatePaths(state_root=state_root, runs_root=runs_root)


def allocate_operating_run(
    profile: OrganizationProfile,
    *,
    run_id: str | None = None,
) -> OperatingRunPaths:
    """Allocate one opaque private run root without creating runtime files.

    The allocation creates the run root plus distinct empty ``state``,
    ``artifacts``, ``results``, and ``workspace`` directories. Returned file
    paths remain absent until their owning runtime component explicitly creates
    them.
    """

    require_persistent_state_platform()
    state = provision_organization_state(profile)
    attempts = 1 if run_id is not None else 8
    selected: str | None = None
    run_root: Path | None = None
    for _ in range(attempts):
        candidate = run_id or secrets.token_hex(16)
        if _RUN_ID_PATTERN.fullmatch(candidate) is None:
            raise ConfigurationError("operating run ID must be 32 lowercase hex digits")
        try:
            run_root = _create_private_child(state.runs_root, candidate)
        except FileExistsError:
            if run_id is not None:
                raise ConfigurationError("operating run ID already exists") from None
            continue
        selected = candidate
        break
    if selected is None or run_root is None:
        raise ConfigurationError("could not allocate a unique operating run ID")
    state_directory = _create_private_child(run_root, "state")
    artifacts = _create_private_child(run_root, "artifacts")
    results = _create_private_child(run_root, "results")
    workspace = _create_private_child(run_root, "workspace")
    return OperatingRunPaths(
        run_id=selected,
        run_root=run_root,
        plan=run_root / "plan.json",
        bound_plan=run_root / "bound-plan.json",
        audit_database=state_directory / "audit.sqlite3",
        artifacts=artifacts,
        result=results / "result.json",
        workspace=workspace,
    )


def validate_operating_plan(
    plan: ChangePlan,
    *,
    profile: OrganizationProfile,
    catalog: CapabilityCatalog,
    integrations: IntegrationConfig | None = None,
    environ: Mapping[str, str] | None = None,
    authenticated_capabilities: AbstractSet[str] = frozenset(),
    policy_blocked_capabilities: AbstractSet[str] = frozenset(),
    runtime_capabilities: AbstractSet[str] | None = None,
) -> OperatingPlanValidation:
    """Validate a plan before connector or runtime construction.

    This function is pure: it does not import plugins, construct connectors,
    open a database, allocate a run directory, or execute any action.
    """

    issues: list[OperatingIssue] = []
    selected_platform_status = platform_runtime_status()
    if plan.execution_context is not None:
        if plan.execution_context.plugins:
            issues.append(
                _issue(
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    "pre-bound connector plugins are not accepted by the operating workflow",
                )
            )
        if plan.execution_context.capsules:
            issues.append(
                _issue(
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    "pre-bound capability capsules are not accepted by the operating workflow",
                )
            )
        issues.append(
            _issue(
                OperatingFailureCategory.BLOCKED_POLICY,
                "the operating workflow accepts only unbound plans",
            )
        )
    for action in plan.actions:
        capability = action.capability
        if capability not in profile.capabilities:
            issues.append(
                _issue(
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    "capability is outside the organization profile allowlist",
                    capability,
                )
            )
            continue
        definition = catalog.definitions.get(capability)
        if definition is None:
            issues.append(
                _issue(
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    "capability is not present in the installed catalog",
                    capability,
                )
            )
            continue
        issues.extend(
            _definition_availability_issues(
                definition,
                profile=profile,
                integrations=integrations,
                environ=environ,
                authenticated_capabilities=authenticated_capabilities,
                policy_blocked_capabilities=policy_blocked_capabilities,
                runtime_capabilities=runtime_capabilities,
                token_files_are_unverified=False,
                platform_status=selected_platform_status,
            )
        )
        allowed, reason = catalog.validate_action(action)
        if not allowed and definition.enabled:
            issues.append(
                _issue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    f"plan action does not match the capability contract: {reason}",
                    capability,
                )
            )
    return OperatingPlanValidation(
        mode=profile.mode,
        plan_fingerprint=plan.fingerprint,
        profile_fingerprint=profile.fingerprint,
        issues=_deduplicate_issues(issues),
    )


def require_operating_plan(
    plan: ChangePlan,
    *,
    profile: OrganizationProfile,
    catalog: CapabilityCatalog,
    integrations: IntegrationConfig | None = None,
    environ: Mapping[str, str] | None = None,
    authenticated_capabilities: AbstractSet[str] = frozenset(),
    policy_blocked_capabilities: AbstractSet[str] = frozenset(),
    runtime_capabilities: AbstractSet[str] | None = None,
) -> OperatingPlanValidation:
    """Return a valid result or raise :class:`OperatingValidationError`."""

    result = validate_operating_plan(
        plan,
        profile=profile,
        catalog=catalog,
        integrations=integrations,
        environ=environ,
        authenticated_capabilities=authenticated_capabilities,
        policy_blocked_capabilities=policy_blocked_capabilities,
        runtime_capabilities=runtime_capabilities,
    )
    result.require_valid()
    return result


def assess_operating_readiness(
    *,
    profile: OrganizationProfile,
    catalog: CapabilityCatalog,
    integrations: IntegrationConfig | None = None,
    environ: Mapping[str, str] | None = None,
    capabilities: Sequence[str] | None = None,
    authenticated_capabilities: AbstractSet[str] = frozenset(),
    policy_blocked_capabilities: AbstractSet[str] = frozenset(),
    runtime_capabilities: AbstractSet[str] | None = None,
    state_backed_read_capabilities: AbstractSet[str] = frozenset(),
    filesystem_backed_read_capabilities: AbstractSet[str] = frozenset(),
    platform_status: PlatformRuntimeStatus | None = None,
) -> OperatingReadinessReport:
    """Assess offline capability readiness without probing providers."""

    requested = (
        tuple(capabilities) if capabilities is not None else profile.capabilities
    )
    if len(requested) > _MAX_PROFILE_CAPABILITIES:
        raise ConfigurationError("operating readiness request exceeds 512 capabilities")
    if len(requested) != len(set(requested)):
        raise ConfigurationError("operating readiness capabilities must be unique")
    selected_platform_status = platform_status or platform_runtime_status()
    readiness: list[CapabilityReadiness] = []
    for capability in sorted(requested):
        _validate_capability_name(capability)
        issues: list[OperatingIssue] = []
        definition = catalog.definitions.get(capability)
        if capability not in profile.capabilities:
            issues.append(
                _issue(
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    "capability is outside the organization profile allowlist",
                    capability,
                )
            )
        if definition is None:
            issues.append(
                _issue(
                    OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                    "capability is not present in the installed catalog",
                    capability,
                )
            )
            readiness.append(
                CapabilityReadiness(
                    capability=capability,
                    risk=None,
                    install_ready=False,
                    read_ready=False,
                    draft_ready=False,
                    effect_ready=False,
                    issues=_deduplicate_issues(issues),
                )
            )
            continue
        filesystem_backed_read = capability in filesystem_backed_read_capabilities or (
            definition.risk is RiskLevel.READ_ONLY
            and _definition_uses_filesystem_trust(
                definition,
                integrations=integrations,
                environ=environ,
            )
        )
        availability = _definition_availability_issues(
            definition,
            profile=profile,
            integrations=integrations,
            environ=environ,
            authenticated_capabilities=authenticated_capabilities,
            policy_blocked_capabilities=policy_blocked_capabilities,
            runtime_capabilities=runtime_capabilities,
            token_files_are_unverified=True,
            platform_status=selected_platform_status,
        )
        issues.extend(availability)
        required_platform_contracts = _readiness_platform_contracts(
            definition,
            state_backed_read=capability in state_backed_read_capabilities,
            filesystem_backed_read=filesystem_backed_read,
        )
        unavailable_platform_contracts = selected_platform_status.unavailable(
            required_platform_contracts
        )
        if unavailable_platform_contracts:
            unavailable = ", ".join(
                f"{item.contract} ({item.reason})"
                for item in unavailable_platform_contracts
            )
            issues.append(
                _issue(
                    OperatingFailureCategory.RUNTIME_DEFECT,
                    "required native platform runtime contracts are unavailable: "
                    f"{unavailable}",
                    capability,
                )
            )
        install_ready = bool(
            runtime_capabilities is None or capability in runtime_capabilities
        )
        operational_ready = not issues
        readiness.append(
            CapabilityReadiness(
                capability=capability,
                risk=definition.risk,
                install_ready=install_ready,
                read_ready=(
                    operational_ready and definition.risk is RiskLevel.READ_ONLY
                ),
                draft_ready=(
                    operational_ready and definition.risk is RiskLevel.LOCAL_GENERATION
                ),
                effect_ready=(
                    operational_ready
                    and definition.risk
                    not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
                ),
                enterprise_ready=False,
                issues=_deduplicate_issues(issues),
            )
        )
    return OperatingReadinessReport(
        mode=profile.mode,
        profile_fingerprint=profile.fingerprint,
        profile_source=profile.source_path,
        capabilities=tuple(readiness),
        platform_runtime=selected_platform_status,
    )


def _readiness_platform_contracts(
    definition: CapabilityDefinition,
    *,
    state_backed_read: bool,
    filesystem_backed_read: bool,
) -> tuple[PlatformContract, ...]:
    """Return native contracts needed by one capability's operating route."""

    required: set[PlatformContract] = set()
    if filesystem_backed_read:
        required.add(PlatformContract.SECURE_FILESYSTEM)
    if (
        state_backed_read
        or definition.risk is RiskLevel.LOCAL_GENERATION
        or definition.risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
    ):
        required.update(
            {
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.ATOMIC_PUBLICATION_RECOVERY,
            }
        )
    if definition.authentication == "local_git":
        required.update(
            {
                PlatformContract.SECURE_FILESYSTEM,
                PlatformContract.CROSS_PROCESS_LOCKING,
                PlatformContract.PROCESS_SUPERVISION,
                PlatformContract.TRUSTED_GIT,
            }
        )
    return tuple(contract for contract in PlatformContract if contract in required)


def _definition_availability_issues(
    definition: CapabilityDefinition,
    *,
    profile: OrganizationProfile,
    integrations: IntegrationConfig | None,
    environ: Mapping[str, str] | None,
    authenticated_capabilities: AbstractSet[str],
    policy_blocked_capabilities: AbstractSet[str],
    runtime_capabilities: AbstractSet[str] | None,
    token_files_are_unverified: bool,
    platform_status: PlatformRuntimeStatus,
) -> tuple[OperatingIssue, ...]:
    capability = definition.name
    issues: list[OperatingIssue] = []
    if not definition.enabled:
        issues.append(
            _issue(
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                "capability is disabled in the installed catalog",
                capability,
            )
        )
    if runtime_capabilities is not None and capability not in runtime_capabilities:
        issues.append(
            _issue(
                OperatingFailureCategory.RUNTIME_DEFECT,
                "capability has no installed runtime implementation",
                capability,
            )
        )
    if capability in policy_blocked_capabilities:
        issues.append(
            _issue(
                OperatingFailureCategory.BLOCKED_POLICY,
                "capability is blocked by the active organization policy",
                capability,
            )
        )
    if (
        profile.mode is OperatingMode.EMPLOYEE
        and definition.risk not in _EMPLOYEE_RISKS
    ):
        issues.append(
            _issue(
                OperatingFailureCategory.BLOCKED_POLICY,
                "capability risk is available only in developer mode",
                capability,
            )
        )
    if (
        profile.mode is OperatingMode.EMPLOYEE
        and profile.connector_mode is ConnectorMode.MOCK
        and definition.authentication not in _LOCAL_AUTHENTICATION_CONTRACTS
    ):
        issues.append(
            _issue(
                OperatingFailureCategory.BLOCKED_POLICY,
                "mock connector mode is available only in developer mode",
                capability,
            )
        )
    if definition.risk is RiskLevel.EXTERNAL_COMMUNICATION:
        if not profile.communications_enabled:
            issues.append(
                _issue(
                    OperatingFailureCategory.BLOCKED_POLICY,
                    "external communications are disabled by the organization profile",
                    capability,
                )
            )
    elif (
        definition.risk not in {RiskLevel.READ_ONLY, RiskLevel.LOCAL_GENERATION}
        and not profile.writes_enabled
    ):
        issues.append(
            _issue(
                OperatingFailureCategory.BLOCKED_POLICY,
                "provider writes are disabled by the organization profile",
                capability,
            )
        )
    if (
        definition.authentication in _LOCAL_AUTHENTICATION_CONTRACTS
        or profile.connector_mode is ConnectorMode.MOCK
    ):
        return _deduplicate_issues(issues)
    connector_system = _connector_system(definition.target_system)
    if integrations is None:
        issues.append(
            _issue(
                OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                "live capability requires the organization integrations configuration",
                capability,
            )
        )
        return _deduplicate_issues(issues)
    connector = integrations.connectors.get(connector_system)
    if connector is None or not connector.enabled:
        issues.append(
            _issue(
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                "live capability has no enabled typed connector configuration",
                capability,
            )
        )
        return _deduplicate_issues(issues)
    source = environ if environ is not None else {}
    selected_endpoint = connector.effective_base_url(source)
    if is_placeholder_provider_url(selected_endpoint):
        issues.append(
            _issue(
                OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                "provider endpoint is still the packaged placeholder",
                capability,
            )
        )
        return _deduplicate_issues(issues)
    cloud_only_reason: str | None = None
    if (
        connector_system == "github"
        and connector.deployment is not DeploymentType.CLOUD
    ):
        cloud_only_reason = "GitHub capabilities require GitHub Cloud"
    elif (
        connector_system == "microsoft"
        and connector.deployment is not DeploymentType.CLOUD
    ):
        cloud_only_reason = "Microsoft capabilities require Microsoft Graph Cloud"
    elif (
        capability == "bitbucket.public_repository.list"
        and connector.deployment is not DeploymentType.CLOUD
    ):
        cloud_only_reason = (
            "Bitbucket public workspace repositories require Bitbucket Cloud"
        )
    elif (
        capability == "confluence.space.create"
        and connector.deployment is not DeploymentType.CLOUD
    ):
        cloud_only_reason = "Confluence space creation requires Confluence Cloud"
    if cloud_only_reason is not None:
        issues.append(
            _issue(
                OperatingFailureCategory.UNSUPPORTED_CAPABILITY,
                cloud_only_reason,
                capability,
            )
        )
        return _deduplicate_issues(issues)
    ca_bundle_selected = bool(
        connector.ca_bundle_env and source.get(connector.ca_bundle_env, "")
    )
    secure_filesystem_available = platform_status.supports(
        PlatformContract.SECURE_FILESYSTEM
    )
    readiness_target = (
        replace(connector, ca_bundle_env=None)
        if ca_bundle_selected and not secure_filesystem_available
        else connector
    )
    try:
        _base_url, ca_bundle = readiness_target.resolve_execution_target(source)
        if ca_bundle is not None:
            create_ssl_context(capture_ca_bundle(ca_bundle).data)
    except ConfigurationError as error:
        ca_error = "CA bundle" in str(error)
        category = (
            OperatingFailureCategory.MISSING_ORGANIZATION_SETUP
            if ca_error
            or "does not exist" in str(error)
            or "requires a base URL" in str(error)
            else OperatingFailureCategory.RUNTIME_DEFECT
        )
        issues.append(
            _issue(
                category,
                "provider destination or trust configuration is missing or invalid",
                capability,
            )
        )
        return _deduplicate_issues(issues)
    authentication_required = not (
        definition.authentication in _ANONYMOUS_AUTHENTICATION_CONTRACTS
        and capability in _ANONYMOUS_CAPABILITIES
    )
    readiness_connector = (
        connector
        if authentication_required
        else replace(
            connector,
            auth_mode=AuthMode.NONE,
            username_env=None,
            secret_env=None,
        )
    )
    missing = readiness_connector.missing_environment_variables(source)
    endpoint_missing = bool(
        not connector.base_url
        and connector.base_url_env
        and not source.get(connector.base_url_env)
    )
    if endpoint_missing:
        issues.append(
            _issue(
                OperatingFailureCategory.MISSING_ORGANIZATION_SETUP,
                "provider endpoint configuration is missing for the selected capability",
                capability,
            )
        )
    credential_missing = tuple(
        name for name in missing if name != connector.base_url_env
    )
    if (
        credential_missing
        and authentication_required
        and capability not in authenticated_capabilities
    ):
        issues.append(
            _issue(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                "user authentication is missing for the selected capability",
                capability,
            )
        )
    if (
        authentication_required
        and capability not in authenticated_capabilities
        and not credential_missing
        and token_files_are_unverified
        and _token_file_authentication_unavailable(connector, source)
    ):
        issues.append(
            _issue(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                "delegated token-file authentication must be verified at execution time",
                capability,
            )
        )
    missing_messages = {f"environment variable {name} is missing" for name in missing}
    static_errors = tuple(
        item
        for item in readiness_connector.configuration_errors(source)
        if item not in missing_messages
    )
    if static_errors:
        issues.append(
            _issue(
                OperatingFailureCategory.RUNTIME_DEFECT,
                "typed connector configuration is invalid for the selected capability",
                capability,
            )
        )
    if (
        authentication_required
        and str(connector.auth_mode) == "none"
        and capability not in authenticated_capabilities
    ):
        issues.append(
            _issue(
                OperatingFailureCategory.MISSING_USER_AUTHENTICATION,
                "user authentication is not configured for the selected capability",
                capability,
            )
        )
    return _deduplicate_issues(issues)


def _definition_uses_filesystem_trust(
    definition: CapabilityDefinition,
    *,
    integrations: IntegrationConfig | None,
    environ: Mapping[str, str] | None,
) -> bool:
    """Return whether a read consumes a configured file-backed trust input."""

    if integrations is None:
        return False
    connector = integrations.connectors.get(_connector_system(definition.target_system))
    if connector is None:
        return False
    source = environ if environ is not None else {}
    ca_bundle_selected = bool(
        connector.ca_bundle_env and source.get(connector.ca_bundle_env, "")
    )
    oauth_flow = str(connector.extra.get("oauth_flow", "environment")).strip()
    return ca_bundle_selected or oauth_flow == "token_file"


def _token_file_authentication_unavailable(
    connector: object,
    environ: Mapping[str, str],
) -> bool:
    """Keep content-free readiness conservative for delegated token files."""

    del environ
    auth_mode = getattr(connector, "auth_mode", None)
    extra = getattr(connector, "extra", {})
    if auth_mode is not AuthMode.OAUTH_DELEGATED or not isinstance(extra, Mapping):
        return False
    return str(extra.get("oauth_flow", "environment")).strip() == "token_file"


def _profile_snapshot(source: ConfigSource) -> ConfigSnapshot:
    if isinstance(source, ConfigSnapshot):
        payload = source.payload
        display_path = source.display_path
    elif isinstance(source, Path):
        snapshot = resolve_config_source(source, _PROFILE_FILENAME)
        payload = snapshot.payload
        display_path = snapshot.display_path
    else:
        try:
            with source.open("rb") as handle:
                payload = handle.read(_MAX_PROFILE_BYTES + 1)
        except FileNotFoundError:
            raise
        except OSError as error:
            raise ConfigurationError(
                "organization profile could not be read"
            ) from error
        display_path = Path(str(source))
    if len(payload) > _MAX_PROFILE_BYTES:
        raise ConfigurationError("organization profile exceeds the 256 KiB limit")
    return ConfigSnapshot(display_path=_absolute_path(display_path), payload=payload)


def _required_string(raw: Mapping[str, Any], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str):
        raise ConfigurationError(f"organization profile {name} must be a string")
    _validate_bounded_text(value, f"organization profile {name}", maximum=4096)
    return value


def _required_bool(raw: Mapping[str, Any], name: str) -> bool:
    value = raw.get(name)
    if not isinstance(value, bool):
        raise ConfigurationError(f"organization profile {name} must be a boolean")
    return value


def _required_string_list(raw: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = raw.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(
            f"organization profile {name} must be a list of strings"
        )
    if len(value) > _MAX_PROFILE_CAPABILITIES:
        raise ConfigurationError(
            "organization profile capability allowlist exceeds 512 items"
        )
    return tuple(value)


def _profile_relative_path(
    value: str,
    *,
    base: Path,
    name: str,
) -> Path:
    _validate_bounded_text(value, name, maximum=_MAX_PATH_CHARACTERS)
    selected = Path(value).expanduser()
    if not selected.is_absolute():
        selected = base / selected
    return _absolute_path(selected)


def _absolute_path(path: Path) -> Path:
    selected = path.expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    return Path(os.path.abspath(os.fspath(selected)))


def _portable_path_key(path: Path) -> tuple[str, ...]:
    """Conservatively identify case-folded and Unicode-normalized path aliases."""

    return tuple(
        unicodedata.normalize("NFD", component).casefold()
        for component in _absolute_path(path).parts
    )


def _validate_path_length(path: Path, name: str) -> None:
    rendered = os.fspath(path)
    if len(rendered) > _MAX_PATH_CHARACTERS or "\x00" in rendered:
        raise ConfigurationError(f"organization profile {name} is invalid")


def _validate_bounded_text(value: str, name: str, *, maximum: int) -> None:
    if not value or value != value.strip() or len(value) > maximum:
        raise ConfigurationError(f"{name} is empty, padded, or too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ConfigurationError(f"{name} contains control characters")


def _validate_capability_name(value: str) -> None:
    if len(value) > 256 or _CAPABILITY_PATTERN.fullmatch(value) is None:
        raise ConfigurationError(
            "organization profile capability names must be bounded dotted names"
        )


def _issue(
    category: OperatingFailureCategory,
    message: str,
    capability: str | None = None,
) -> OperatingIssue:
    return OperatingIssue(category=category, message=message, capability=capability)


def _setup_error(message: str) -> OperatingValidationError:
    return OperatingValidationError(
        (OperatingIssue(OperatingFailureCategory.MISSING_ORGANIZATION_SETUP, message),)
    )


def _deduplicate_issues(issues: Sequence[OperatingIssue]) -> tuple[OperatingIssue, ...]:
    unique: dict[tuple[str, str, str | None], OperatingIssue] = {}
    for issue in issues:
        key = (str(issue.category), issue.message, issue.capability)
        unique.setdefault(key, issue)
    return tuple(unique.values())


def _connector_system(system: str) -> str:
    if system in {"microsoft", "sharepoint", "outlook", "teams", "onenote"}:
        return "microsoft"
    return system


def _bounded_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    if len(encoded.encode("utf-8")) > _MAX_REPORT_BYTES:
        raise ConfigurationError("operating report exceeds the 1 MiB limit")
    return encoded


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not no_follow:
        raise ConfigurationError(
            "secure descriptor-backed state provisioning is unavailable"
        )
    return os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)


def _ensure_private_directory(path: Path) -> Path:
    selected = _absolute_path(path)
    if selected == Path(selected.anchor):
        raise ConfigurationError("private state directory path is invalid")
    components = selected.parts[1:]
    if not components or len(components) > _MAX_DIRECTORY_DEPTH:
        raise ConfigurationError("private state directory path is too deep")
    descriptor = os.open(os.sep, _directory_flags())
    try:
        for index, component in enumerate(components):
            created = False
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            try:
                observed = os.fstat(child)
                public = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if not _same_directory(observed, public):
                    raise ConfigurationError(
                        "private state directory changed during provisioning"
                    )
                if created:
                    os.fchmod(child, 0o700)
                    os.fsync(child)
                    observed = os.fstat(child)
                if index == len(components) - 1:
                    _validate_private_directory(observed, exact_mode=True)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        raise ConfigurationError(
            "private state path must contain only no-follow directories"
        ) from error
    finally:
        os.close(descriptor)
    return selected


def _create_private_child(parent: Path, name: str) -> Path:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ConfigurationError("private state child name is invalid")
    parent_path = _ensure_private_directory(parent)
    descriptor = os.open(parent_path, _directory_flags())
    child = -1
    try:
        os.mkdir(name, 0o700, dir_fd=descriptor)
        os.fsync(descriptor)
        child = os.open(name, _directory_flags(), dir_fd=descriptor)
        os.fchmod(child, 0o700)
        observed = os.fstat(child)
        public = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if not _same_directory(observed, public):
            raise ConfigurationError("private state child changed during creation")
        _validate_private_directory(observed, exact_mode=True)
        os.fsync(child)
    except FileExistsError:
        raise
    except OSError as error:
        raise ConfigurationError("private state child could not be created") from error
    finally:
        if child >= 0:
            os.close(child)
        os.close(descriptor)
    return parent_path / name


def _validate_private_directory(
    value: os.stat_result,
    *,
    exact_mode: bool,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise ConfigurationError("private state object is not a directory")
    if value.st_uid != os.geteuid():
        raise ConfigurationError("private state directory is not owned by this user")
    mode = stat.S_IMODE(value.st_mode)
    if (exact_mode and mode != 0o700) or (not exact_mode and mode & 0o077):
        raise ConfigurationError("private state directory must have mode 0700")


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_uid == right.st_uid
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
    )


def _install_private_file(path: Path, payload: bytes) -> bool:
    parent = _ensure_private_directory(path.parent)
    descriptor = os.open(parent, _directory_flags())
    file_descriptor = -1
    owned_identity: tuple[int, int, int] | None = None
    completed = False
    try:
        try:
            file_descriptor = os.open(
                path.name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=descriptor,
            )
        except FileExistsError:
            existing = _read_private_file(descriptor, path.name)
            if existing != payload:
                raise ConfigurationError(
                    "organization profile destination already contains different bytes"
                ) from None
            return False
        os.fchmod(file_descriptor, 0o600)
        initial = os.fstat(file_descriptor)
        _validate_private_file(initial, size=0)
        owned_identity = (initial.st_dev, initial.st_ino, initial.st_uid)
        _write_all(file_descriptor, payload)
        os.fsync(file_descriptor)
        final = os.fstat(file_descriptor)
        _validate_private_file(final, size=len(payload))
        published = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if _file_identity(final) != _file_identity(published):
            raise ConfigurationError("organization profile publication was replaced")
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        observed_payload = bytearray()
        while len(observed_payload) <= _MAX_PROFILE_BYTES:
            block = os.read(
                file_descriptor,
                min(64 * 1024, _MAX_PROFILE_BYTES + 1 - len(observed_payload)),
            )
            if not block:
                break
            observed_payload.extend(block)
        after_read = os.fstat(file_descriptor)
        published_after = os.stat(
            path.name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        if (
            bytes(observed_payload) != payload
            or _file_identity(final) != _file_identity(after_read)
            or _file_identity(after_read) != _file_identity(published_after)
        ):
            raise ConfigurationError(
                "organization profile bytes changed during publication"
            )
        os.fsync(descriptor)
        parent_public = os.stat(parent, follow_symlinks=False)
        if not _same_directory(os.fstat(descriptor), parent_public):
            raise ConfigurationError(
                "organization profile parent changed during publication"
            )
        completed = True
        return True
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if not completed and owned_identity is not None:
            _unlink_private_file_if_owned(descriptor, path.name, owned_identity)
        os.close(descriptor)


def _unlink_private_file_if_owned(
    parent_descriptor: int,
    name: str,
    expected: tuple[int, int, int],
) -> None:
    """Remove only the exact private profile inode created by this call."""

    try:
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    observed = (current.st_dev, current.st_ino, current.st_uid)
    if (
        observed != expected
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) != 0o600
    ):
        raise ConfigurationError(
            "organization profile rollback refused after identity change"
        )
    try:
        os.unlink(name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as error:
        raise ConfigurationError(
            "organization profile rollback was incomplete"
        ) from error


def _read_private_file(parent_descriptor: int, name: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        _validate_private_file(before)
        if before.st_size > _MAX_PROFILE_BYTES:
            raise ConfigurationError("installed organization profile is too large")
        payload = bytearray()
        while len(payload) <= _MAX_PROFILE_BYTES:
            block = os.read(
                descriptor, min(64 * 1024, _MAX_PROFILE_BYTES + 1 - len(payload))
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if os.read(descriptor, 1) or _file_identity(before) != _file_identity(after):
            raise ConfigurationError(
                "installed organization profile changed during read"
            )
        public = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if _file_identity(after) != _file_identity(public):
            raise ConfigurationError("installed organization profile path was replaced")
        return bytes(payload)
    except OSError as error:
        raise ConfigurationError(
            "installed organization profile must be a no-follow private file"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_private_file(value: os.stat_result, *, size: int | None = None) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
        or (size is not None and value.st_size != size)
    ):
        raise ConfigurationError(
            "organization profile must be a current-user mode-0600 regular file"
        )


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("organization profile write made no progress")
        offset += written


__all__ = [
    "CapabilityReadiness",
    "ConnectorMode",
    "OperatingFailureCategory",
    "OperatingIssue",
    "OperatingMode",
    "OperatingPlanValidation",
    "OperatingReadinessReport",
    "OperatingRunPaths",
    "OperatingStatePaths",
    "OperatingValidationError",
    "OrganizationProfile",
    "OrganizationSetupResult",
    "ReadinessLevel",
    "allocate_operating_run",
    "assess_operating_readiness",
    "default_organization_profile_path",
    "install_organization_profile",
    "load_organization_profile",
    "provision_organization_state",
    "require_operating_plan",
    "validate_operating_plan",
]
