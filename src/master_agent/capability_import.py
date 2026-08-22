"""Read-only inspection and quarantine for foreign agent capabilities.

Foreign agent exports are untrusted data. This module parses one bounded,
self-contained JSON snapshot, but it never imports or executes embedded source.
Only an explicitly selected, statically compatible ability can enter the
existing signed capsule lifecycle, and it enters in the quarantined state.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from master_agent.capabilities import CapabilityCatalog
from master_agent.capsules import (
    CapsuleAuthority,
    CapsuleBundle,
    CapsuleManifest,
    CapsuleSpec,
    CapsuleStore,
    CapsuleTrustStore,
    LicensePolicy,
    create_quarantined_manifest,
    validate_bundle_contracts,
    validate_dependency_metadata,
)
from master_agent.config_sources import ConfigSnapshot, snapshot_explicit_file
from master_agent.errors import ConfigurationError, ValidationError
from master_agent.models import RiskLevel
from master_agent.resource_limits import measure_json_resources

AGENT_IMPORT_SCHEMA = "master-agent/custom-agent-capabilities@1"
AGENT_IMPORT_PREVIEW_SCHEMA = "master-agent/capability-import-preview@1"

_MAX_IMPORT_BYTES = 4 * 1024 * 1024
_MAX_ABILITIES = 64
_MAX_DEPENDENCIES = 128
_MAX_DESCRIPTION_CHARACTERS = 1_024
_MAX_SOURCE_CHARACTERS = 256 * 1024
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_CAPABILITY_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9][a-z0-9_-]*)+")
_FORBIDDEN_REQUIREMENTS = frozenset(
    {
        "approval",
        "background_access",
        "credential",
        "hook",
        "identity",
        "network",
        "plugin",
        "recursive_agent",
        "shell",
    }
)
_SAFE_REQUIREMENTS = frozenset({"deterministic", "pure_local"})
_SAFE_CONSTRAINTS = frozenset(
    {"deterministic", "network-free", "single-request", "stateless"}
)
_TOP_LEVEL_KEYS = frozenset(
    {"schema", "agent_id", "agent_version", "publisher", "abilities"}
)
_ABILITY_KEYS = frozenset(
    {
        "name",
        "kind",
        "description",
        "proposed_mapping",
        "dependencies",
        "constraints",
        "requirements",
        "capsule",
    }
)
_DEPENDENCY_KEYS = frozenset({"name", "version", "artifact_sha256", "license"})
_CAPSULE_SPEC_KEYS = frozenset(
    {
        "schema",
        "capability_id",
        "version",
        "system",
        "risk",
        "input_schema",
        "output_schema",
        "source_provenance",
        "source_license",
        "publisher",
        "side_effects",
        "allowed_origins",
        "allowed_methods",
        "allowed_path_prefixes",
        "credential_names",
        "credential_scopes",
        "intents",
        "negative_intents",
        "data_classification",
        "retention_class",
        "max_input_bytes",
        "max_output_bytes",
        "timeout_seconds",
        "cpu_seconds",
        "memory_bytes",
        "max_processes",
    }
)
_BUNDLE_KEYS = frozenset(
    {
        "spec",
        "source",
        "dependency_lock",
        "sbom",
        "test_suite",
        "verification_contract",
        "compensation_contract",
        "third_party_notices",
    }
)
_STATIC_FORBIDDEN_NODES = (
    ast.AsyncFor,
    ast.AsyncFunctionDef,
    ast.AsyncWith,
    ast.Await,
    ast.ClassDef,
    ast.Delete,
    ast.Global,
    ast.Import,
    ast.ImportFrom,
    ast.Lambda,
    ast.NamedExpr,
    ast.Nonlocal,
    ast.Raise,
    ast.Try,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)
_STATIC_FORBIDDEN_CALLS = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "input",
        "locals",
        "open",
        "setattr",
        "vars",
    }
)


class AgentAbilityKind(StrEnum):
    """Declarative ability kinds accepted by the import format."""

    CAPABILITY = "capability"
    REFERENCE = "reference"
    SKILL = "skill"
    TOOL = "tool"
    WORKFLOW = "workflow"
    AGENT = "agent"


class ImportClassification(StrEnum):
    """Compatibility result for one foreign ability."""

    ALREADY_SUPPORTED = "already_supported"
    SAFELY_IMPORTABLE = "safely_importable"
    CONFLICTING = "conflicting"
    UNSUPPORTED = "unsupported"
    UNSAFE = "unsafe"


@dataclass(frozen=True, slots=True)
class AgentDependency:
    """One exact dependency declared by a foreign ability."""

    name: str
    version: str
    artifact_sha256: str
    license: str

    def __post_init__(self) -> None:
        if _IDENTIFIER_PATTERN.fullmatch(self.name) is None:
            raise ValidationError("agent ability dependency name is malformed")
        if not self.version or self.version != self.version.strip():
            raise ValidationError("agent ability dependency version is malformed")
        _validate_bounded_ascii(self.version, "agent ability dependency version")
        _validate_sha256(self.artifact_sha256, "agent ability dependency artifact")
        if not self.license or self.license != self.license.strip():
            raise ValidationError("agent ability dependency license is malformed")
        _validate_bounded_ascii(self.license, "agent ability dependency license")

    def to_dict(self) -> dict[str, str]:
        """Serialize the exact dependency identity."""

        return {
            "name": self.name,
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "license": self.license,
        }


@dataclass(frozen=True, slots=True)
class AgentAbility:
    """One bounded ability parsed from an untrusted agent export."""

    name: str
    kind: AgentAbilityKind
    description: str
    proposed_mapping: str
    dependencies: tuple[AgentDependency, ...]
    constraints: tuple[str, ...]
    requirements: tuple[str, ...]
    bundle: CapsuleBundle | None

    def __post_init__(self) -> None:
        if _IDENTIFIER_PATTERN.fullmatch(self.name) is None:
            raise ValidationError("agent ability name is malformed")
        _validate_display_text(self.description, "agent ability description")
        if self.proposed_mapping and (
            not self.proposed_mapping.isascii()
            or _CAPABILITY_PATTERN.fullmatch(self.proposed_mapping) is None
        ):
            raise ValidationError("agent ability proposed mapping is malformed")
        _validate_unique_text(self.constraints, "agent ability constraints")
        _validate_unique_text(self.requirements, "agent ability requirements")
        if any(
            not value.isascii() or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) is None
            for value in self.requirements
        ):
            raise ValidationError("agent ability requirements must be canonical tokens")
        dependency_ids = [
            (item.name.casefold(), item.version) for item in self.dependencies
        ]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ValidationError(
                "agent ability dependency declarations are duplicated"
            )
        if self.kind in {AgentAbilityKind.CAPABILITY, AgentAbilityKind.REFERENCE}:
            if not self.proposed_mapping:
                raise ValidationError(
                    "capability and reference abilities require a proposed mapping"
                )
        elif self.proposed_mapping:
            raise ValidationError(
                "non-capability agent abilities cannot propose a capability mapping"
            )
        if self.kind is AgentAbilityKind.CAPABILITY:
            if self.bundle is None:
                raise ValidationError("capability ability requires an embedded capsule")
        elif self.bundle is not None:
            raise ValidationError(
                "only a capability ability may contain executable capsule source"
            )


@dataclass(frozen=True, slots=True)
class AgentCapabilityPackage:
    """Immutable parsed view of one exact custom-agent export."""

    agent_id: str
    agent_version: str
    publisher: str
    source_sha256: str
    abilities: tuple[AgentAbility, ...]

    def __post_init__(self) -> None:
        if _IDENTIFIER_PATTERN.fullmatch(self.agent_id) is None:
            raise ValidationError("custom agent ID is malformed")
        if _VERSION_PATTERN.fullmatch(self.agent_version) is None:
            raise ValidationError("custom agent version must be semantic")
        if (
            not self.publisher
            or self.publisher != self.publisher.strip()
            or not self.publisher.isascii()
            or len(self.publisher) > 256
            or any(not character.isprintable() for character in self.publisher)
        ):
            raise ValidationError("custom agent publisher is malformed")
        if not 1 <= len(self.abilities) <= _MAX_ABILITIES:
            raise ValidationError("custom agent export must contain 1..64 abilities")
        names = [item.name.casefold() for item in self.abilities]
        if len(names) != len(set(names)):
            raise ValidationError(
                "custom agent export contains duplicate ability names"
            )
        mappings = [
            item.proposed_mapping.casefold()
            for item in self.abilities
            if item.proposed_mapping
        ]
        if len(mappings) != len(set(mappings)):
            raise ValidationError(
                "custom agent export contains duplicate proposed capability mappings"
            )
        _validate_sha256(self.source_sha256, "custom agent source")


@dataclass(frozen=True, slots=True)
class AbilityPreview:
    """Bounded compatibility result for one declared ability."""

    name: str
    kind: AgentAbilityKind
    description: str
    classification: ImportClassification
    proposed_mapping: str
    dependencies: tuple[AgentDependency, ...]
    constraints: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize a human-readable, secret-free preview row."""

        return {
            "name": self.name,
            "kind": str(self.kind),
            "description": self.description,
            "classification": str(self.classification),
            "proposed_mapping": self.proposed_mapping or None,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "constraints": list(self.constraints),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class AgentImportPreview:
    """Read-only compatibility report for one exact source snapshot."""

    package: AgentCapabilityPackage
    abilities: tuple[AbilityPreview, ...]
    schema: str = AGENT_IMPORT_PREVIEW_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete preview without imported source code."""

        counts = {
            str(classification): sum(
                item.classification is classification for item in self.abilities
            )
            for classification in ImportClassification
        }
        return {
            "schema": self.schema,
            "agent": {
                "id": self.package.agent_id,
                "version": self.package.agent_version,
                "publisher": self.package.publisher,
                "source_sha256": self.package.source_sha256,
            },
            "summary": counts,
            "abilities": [item.to_dict() for item in self.abilities],
            "activation": (
                "preview only; select one safely_importable ability by name and "
                "source digest, then complete the independent capsule lifecycle"
            ),
        }

    def ability(self, name: str) -> AbilityPreview:
        """Resolve one exact previewed ability name."""

        matches = [item for item in self.abilities if item.name == name]
        if len(matches) != 1:
            raise ValidationError(f"preview does not contain ability: {name}")
        return matches[0]


@dataclass(frozen=True, slots=True)
class ImportedQuarantine:
    """One explicitly selected foreign ability installed in quarantine."""

    source_sha256: str
    ability_name: str
    bundle: CapsuleBundle
    manifest: CapsuleManifest


def inspect_agent_capabilities(
    source: ConfigSnapshot,
    *,
    catalog: CapabilityCatalog,
    license_policy: LicensePolicy,
) -> AgentImportPreview:
    """Inspect one custom-agent export without executing imported content."""

    package = _load_package(source)
    previews = tuple(
        _classify_ability(
            package,
            ability,
            catalog=catalog,
            license_policy=license_policy,
        )
        for ability in package.abilities
    )
    return AgentImportPreview(package=package, abilities=previews)


def quarantine_selected_ability(
    source_path: Path,
    *,
    expected_source_sha256: str,
    ability_name: str,
    catalog: CapabilityCatalog,
    license_policy: LicensePolicy,
    store: CapsuleStore,
    authority: CapsuleAuthority,
    trust: CapsuleTrustStore,
    environment: str,
    worker_sha256: str,
    now: datetime | None = None,
) -> ImportedQuarantine:
    """Reinspect and quarantine exactly one explicitly selected safe ability."""

    _validate_sha256(expected_source_sha256, "expected custom agent source")
    source = snapshot_explicit_file(source_path)
    preview = inspect_agent_capabilities(
        source,
        catalog=catalog,
        license_policy=license_policy,
    )
    if preview.package.source_sha256 != expected_source_sha256:
        raise ConfigurationError(
            "custom agent source drifted after preview; inspect the updated source"
        )
    selected = preview.ability(ability_name)
    if selected.classification is not ImportClassification.SAFELY_IMPORTABLE:
        detail = "; ".join(selected.reasons) or str(selected.classification)
        raise ConfigurationError(
            f"agent ability is not safely importable: {ability_name}: {detail}"
        )
    ability = next(
        item for item in preview.package.abilities if item.name == ability_name
    )
    if ability.bundle is None:  # pragma: no cover - classification invariant.
        raise RuntimeError("safely importable ability has no capsule bundle")
    provenance = (
        "agent-import:sha256:"
        f"{preview.package.source_sha256}:"
        f"{preview.package.agent_id}@{preview.package.agent_version}:"
        f"{ability.name}"
    )
    imported_spec = replace(ability.bundle.spec, source_provenance=provenance)
    imported_bundle = replace(ability.bundle, spec=imported_spec)
    manifest = create_quarantined_manifest(
        imported_bundle,
        authority=authority,
        environment=environment,
        worker_sha256=worker_sha256,
        now=now,
    )
    store.install(imported_bundle, manifest, trust=trust)
    return ImportedQuarantine(
        source_sha256=preview.package.source_sha256,
        ability_name=ability.name,
        bundle=imported_bundle,
        manifest=manifest,
    )


def _load_package(source: ConfigSnapshot) -> AgentCapabilityPackage:
    with source.open("rb") as handle:
        payload = handle.read(_MAX_IMPORT_BYTES + 1)
    if len(payload) > _MAX_IMPORT_BYTES:
        raise ValidationError("custom agent export exceeds the 4 MiB limit")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("custom agent export must be UTF-8") from error
    try:
        raw = json.loads(
            decoded,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValidationError("custom agent export is malformed JSON") from error
    if not isinstance(raw, Mapping):
        raise ValidationError("custom agent export must be a JSON object")
    measure_json_resources(
        raw,
        context="custom agent export",
        max_bytes=_MAX_IMPORT_BYTES,
    )
    _require_exact_keys(raw, _TOP_LEVEL_KEYS, "custom agent export")
    if _required_string(raw, "schema") != AGENT_IMPORT_SCHEMA:
        raise ValidationError("custom agent export schema is unsupported")
    raw_abilities = raw.get("abilities")
    if not isinstance(raw_abilities, list):
        raise ValidationError("custom agent abilities must be a list")
    abilities = tuple(_parse_ability(item) for item in raw_abilities)
    return AgentCapabilityPackage(
        agent_id=_required_string(raw, "agent_id"),
        agent_version=_required_string(raw, "agent_version"),
        publisher=_required_string(raw, "publisher"),
        source_sha256=hashlib.sha256(payload).hexdigest(),
        abilities=abilities,
    )


def _parse_ability(value: object) -> AgentAbility:
    if not isinstance(value, Mapping):
        raise ValidationError("custom agent ability must be an object")
    _require_exact_keys(value, _ABILITY_KEYS, "custom agent ability")
    raw_dependencies = value.get("dependencies")
    if (
        not isinstance(raw_dependencies, list)
        or len(raw_dependencies) > _MAX_DEPENDENCIES
    ):
        raise ValidationError("agent ability dependencies must be a bounded list")
    dependencies = tuple(_parse_dependency(item) for item in raw_dependencies)
    raw_capsule = value.get("capsule")
    bundle = _parse_bundle(raw_capsule) if raw_capsule is not None else None
    return AgentAbility(
        name=_required_string(value, "name"),
        kind=AgentAbilityKind(_required_string(value, "kind")),
        description=_required_string(value, "description"),
        proposed_mapping=_optional_string(value, "proposed_mapping"),
        dependencies=dependencies,
        constraints=_string_tuple(value, "constraints"),
        requirements=_string_tuple(value, "requirements"),
        bundle=bundle,
    )


def _parse_dependency(value: object) -> AgentDependency:
    if not isinstance(value, Mapping):
        raise ValidationError("agent ability dependency must be an object")
    _require_exact_keys(value, _DEPENDENCY_KEYS, "agent ability dependency")
    return AgentDependency(
        name=_required_string(value, "name"),
        version=_required_string(value, "version"),
        artifact_sha256=_required_string(value, "artifact_sha256"),
        license=_required_string(value, "license"),
    )


def _parse_bundle(value: object) -> CapsuleBundle:
    if not isinstance(value, Mapping):
        raise ValidationError("agent capability capsule must be an object")
    _require_exact_keys(value, _BUNDLE_KEYS, "agent capability capsule")
    source = _source_string(value, "source")
    if len(source) > _MAX_SOURCE_CHARACTERS:
        raise ValidationError("agent capability source exceeds 256 KiB")
    dependency_lock = _required_mapping(value, "dependency_lock")
    sbom = _required_mapping(value, "sbom")
    test_suite = _required_mapping(value, "test_suite")
    verification = _required_mapping(value, "verification_contract")
    compensation = _required_mapping(value, "compensation_contract")
    _validate_embedded_document_shape(
        dependency_lock=dependency_lock,
        sbom=sbom,
        test_suite=test_suite,
        verification=verification,
        compensation=compensation,
    )
    return CapsuleBundle(
        spec=_capsule_spec(value),
        source=source.encode("utf-8"),
        dependency_lock=dependency_lock,
        sbom=sbom,
        test_suite=test_suite,
        verification_contract=verification,
        compensation_contract=compensation,
        third_party_notices=_optional_string(value, "third_party_notices"),
    )


def _capsule_spec(value: Mapping[str, object]) -> CapsuleSpec:
    spec = _required_mapping(value, "spec")
    _require_exact_keys(spec, _CAPSULE_SPEC_KEYS, "agent capsule spec")
    return CapsuleSpec.from_dict(spec)


def _validate_embedded_document_shape(
    *,
    dependency_lock: Mapping[str, object],
    sbom: Mapping[str, object],
    test_suite: Mapping[str, object],
    verification: Mapping[str, object],
    compensation: Mapping[str, object],
) -> None:
    """Reject hidden executable or authority fields in embedded documents."""

    _require_exact_keys(
        dependency_lock,
        frozenset({"schema", "dependencies"}),
        "agent capsule dependency lock",
    )
    raw_dependencies = dependency_lock.get("dependencies")
    if isinstance(raw_dependencies, list):
        for dependency in raw_dependencies:
            if not isinstance(dependency, Mapping):
                raise ValidationError("agent capsule dependency must be an object")
            _require_exact_keys(
                dependency,
                _DEPENDENCY_KEYS,
                "agent capsule dependency",
            )
    _require_exact_keys(
        sbom,
        frozenset({"bomFormat", "specVersion", "components"}),
        "agent capsule SBOM",
    )
    raw_components = sbom.get("components")
    if isinstance(raw_components, list):
        for component in raw_components:
            if not isinstance(component, Mapping):
                raise ValidationError("agent capsule SBOM component must be an object")
            _require_exact_keys(
                component,
                frozenset({"name", "version", "license"}),
                "agent capsule SBOM component",
            )
    _require_exact_keys(
        test_suite,
        frozenset({"schema", "cases"}),
        "agent capsule test suite",
    )
    raw_cases = test_suite.get("cases")
    if isinstance(raw_cases, list):
        for case in raw_cases:
            if not isinstance(case, Mapping):
                raise ValidationError("agent capsule test case must be an object")
            _require_exact_keys(
                case,
                frozenset({"input", "expected"}),
                "agent capsule test case",
            )
    _require_exact_keys(
        verification,
        frozenset({"schema", "mode"}),
        "agent capsule verification",
    )
    _require_exact_keys(
        compensation,
        frozenset({"schema", "mode"}),
        "agent capsule compensation",
    )


def _classify_ability(
    package: AgentCapabilityPackage,
    ability: AgentAbility,
    *,
    catalog: CapabilityCatalog,
    license_policy: LicensePolicy,
) -> AbilityPreview:
    unsafe: list[str] = []
    unsupported: list[str] = []
    forbidden = sorted(set(ability.requirements) & _FORBIDDEN_REQUIREMENTS)
    if forbidden:
        unsafe.append(
            "imported authority or executable requirements are prohibited: "
            + ", ".join(forbidden)
        )
    unknown_requirements = sorted(
        set(ability.requirements) - _FORBIDDEN_REQUIREMENTS - _SAFE_REQUIREMENTS
    )
    if unknown_requirements:
        unsafe.append(
            "unrecognized ability requirements fail closed: "
            + ", ".join(unknown_requirements)
        )
    unknown_constraints = sorted(set(ability.constraints) - _SAFE_CONSTRAINTS)
    if unknown_constraints:
        unsafe.append(
            "unrecognized ability constraints fail closed: "
            + ", ".join(unknown_constraints)
        )
    if ability.kind is AgentAbilityKind.AGENT:
        unsafe.append("recursive agent imports are prohibited")
    bundle = ability.bundle
    if bundle is not None:
        if bundle.spec.publisher != package.publisher:
            unsafe.append("capsule publisher differs from the declared agent publisher")
        if bundle.spec.capability_id != ability.proposed_mapping:
            unsafe.append("capsule capability ID differs from the proposed mapping")
        locked = _locked_dependencies(bundle)
        if locked != ability.dependencies:
            unsafe.append(
                "declared dependencies differ from the locked capsule dependency closure"
            )
        try:
            dependencies = validate_dependency_metadata(
                bundle,
                policy=license_policy,
            )
            validate_bundle_contracts(bundle)
        except ValidationError as error:
            unsafe.append(f"capsule contract is invalid: {error}")
        else:
            if dependencies:
                unsupported.append(
                    "third-party runtime dependencies are not supported by the pure worker"
                )
        source_reason = _static_source_rejection(bundle.source)
        if source_reason is not None:
            unsafe.append(
                "capsule source is outside the statically safe preview subset: "
                + source_reason
            )
        if (
            bundle.spec.allowed_origins
            or bundle.spec.credential_names
            or bundle.spec.credential_scopes
            or bundle.spec.side_effects
        ):
            unsupported.append(
                "provider, credential, and side-effect abilities require a reviewed "
                "first-party connector"
            )
        if bundle.spec.risk not in {
            RiskLevel.READ_ONLY,
            RiskLevel.LOCAL_GENERATION,
        }:
            unsupported.append(
                "only pure read-only or local-generation capsules are importable"
            )

    if unsafe:
        classification = ImportClassification.UNSAFE
        reasons = unsafe + unsupported
    elif ability.kind is AgentAbilityKind.REFERENCE:
        if ability.proposed_mapping in catalog.definitions:
            classification = ImportClassification.ALREADY_SUPPORTED
            reasons = ["the proposed typed capability already exists in the catalog"]
        else:
            classification = ImportClassification.UNSUPPORTED
            reasons = ["the referenced typed capability is not installed"]
    elif ability.kind is not AgentAbilityKind.CAPABILITY:
        classification = ImportClassification.UNSUPPORTED
        reasons = [
            "version 1 imports one typed capability, not raw skills, tools, or workflows"
        ]
    elif ability.proposed_mapping in catalog.definitions:
        classification = ImportClassification.CONFLICTING
        reasons = [
            "the proposed capability name would shadow an existing catalog capability"
        ]
    elif unsupported:
        classification = ImportClassification.UNSUPPORTED
        reasons = unsupported
    else:
        classification = ImportClassification.SAFELY_IMPORTABLE
        reasons = [
            "eligible for explicit quarantine; independent promotion is still required"
        ]
    return AbilityPreview(
        name=ability.name,
        kind=ability.kind,
        description=ability.description,
        classification=classification,
        proposed_mapping=ability.proposed_mapping,
        dependencies=ability.dependencies,
        constraints=ability.constraints,
        reasons=tuple(reasons),
    )


def _locked_dependencies(bundle: CapsuleBundle) -> tuple[AgentDependency, ...]:
    raw = bundle.dependency_lock.get("dependencies")
    if not isinstance(raw, tuple):
        return ()
    parsed: list[AgentDependency] = []
    for item in raw:
        if not isinstance(item, Mapping):
            return ()
        try:
            parsed.append(
                AgentDependency(
                    name=_required_string(item, "name"),
                    version=_required_string(item, "version"),
                    artifact_sha256=_required_string(item, "artifact_sha256"),
                    license=_required_string(item, "license"),
                )
            )
        except ValidationError:
            return ()
    return tuple(parsed)


def _static_source_rejection(source: bytes) -> str | None:
    """Return a bounded static warning without compiling or executing source."""

    try:
        decoded = source.decode("utf-8")
        tree = ast.parse(decoded, filename="<import-preview>", mode="exec")
    except (UnicodeDecodeError, SyntaxError):
        return "source_syntax"
    if len(tuple(ast.walk(tree))) > 8_192:
        return "source_too_complex"
    for node in ast.walk(tree):
        if isinstance(node, _STATIC_FORBIDDEN_NODES):
            return "forbidden_syntax"
        if isinstance(node, ast.Name) and node.id.startswith("_"):
            return "private_name"
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            return "private_attribute"
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _STATIC_FORBIDDEN_CALLS
        ):
            return "forbidden_call"
    for item in tree.body:
        is_docstring = (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        )
        if not is_docstring and not isinstance(item, ast.FunctionDef):
            return "top_level_statement"
    functions = {item.name for item in tree.body if isinstance(item, ast.FunctionDef)}
    if "run" not in functions:
        return "missing_run"
    return None


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _require_exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    observed = set(value)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    if missing:
        raise ValidationError(f"{label} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ValidationError(f"{label} has unsupported fields: {', '.join(unknown)}")


def _required_mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ValidationError(f"agent import {key} must be an object")
    return MappingProxyType(dict(selected))


def _required_string(value: Mapping[str, object], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected or selected != selected.strip():
        raise ValidationError(f"agent import {key} must be a non-empty string")
    return selected


def _optional_string(value: Mapping[str, object], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or selected != selected.strip():
        raise ValidationError(f"agent import {key} must be a string")
    return selected


def _source_string(value: Mapping[str, object], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ValidationError(f"agent import {key} must be a non-empty string")
    return selected


def _string_tuple(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    selected = value.get(key)
    if not isinstance(selected, list) or not all(
        isinstance(item, str) and item and item == item.strip() for item in selected
    ):
        raise ValidationError(f"agent import {key} must be a string list")
    return tuple(selected)


def _validate_display_text(value: str, label: str) -> None:
    if len(value) > _MAX_DESCRIPTION_CHARACTERS or any(
        not character.isprintable() for character in value
    ):
        raise ValidationError(f"{label} is unbounded or contains controls")


def _validate_bounded_ascii(value: str, label: str) -> None:
    if (
        len(value) > 128
        or not value.isascii()
        or any(not character.isprintable() for character in value)
    ):
        raise ValidationError(f"{label} is unbounded or malformed")


def _validate_unique_text(values: Sequence[str], label: str) -> None:
    if len(values) > 64:
        raise ValidationError(f"{label} exceeds 64 entries")
    if len(values) != len(set(values)):
        raise ValidationError(f"{label} contains duplicates")
    for value in values:
        _validate_display_text(value, label)


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64:
        raise ValidationError(f"{label} digest is malformed")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValidationError(f"{label} digest is malformed") from error
