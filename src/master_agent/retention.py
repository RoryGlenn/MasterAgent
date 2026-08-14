"""Retention metadata and restricted evidence-file handling."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from fnmatch import fnmatchcase
import json
from pathlib import Path
import tomllib
from typing import Any, Mapping

from master_agent.config_sources import ConfigSource
from master_agent.errors import ConfigurationError
from master_agent.evidence import content_digest


class PersistenceMode(StrEnum):
    """How retrieved content may be persisted by the runtime."""

    METADATA_ONLY = "metadata_only"
    EXPLICIT_CONTENT = "explicit_content"
    PROHIBITED = "prohibited"


@dataclass(frozen=True, slots=True)
class RetentionRule:
    """Retention decision for matching evidence."""

    pattern: str
    ttl_hours: int
    persistence: PersistenceMode

    def __post_init__(self) -> None:
        if not self.pattern.strip():
            raise ConfigurationError("retention rule pattern must not be empty")
        if self.ttl_hours <= 0:
            raise ConfigurationError("retention ttl_hours must be positive")


@dataclass(frozen=True, slots=True)
class RetentionConfig:
    """Ordered retention rules with a fail-closed default."""

    default: RetentionRule
    rules: tuple[RetentionRule, ...]

    @classmethod
    def from_toml(cls, path: ConfigSource) -> RetentionConfig:
        """Load retention rules from TOML."""

        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as error:
            raise ConfigurationError(
                f"retention configuration not found: {path}"
            ) from error
        root = raw.get("retention", {})
        if not isinstance(root, Mapping):
            raise ConfigurationError("[retention] must be a TOML table")
        default = RetentionRule(
            pattern="*",
            ttl_hours=int(root.get("default_ttl_hours", 24)),
            persistence=PersistenceMode(
                str(root.get("default_persistence", "metadata_only"))
            ),
        )
        values = raw.get("rules", [])
        if not isinstance(values, list):
            raise ConfigurationError("[[rules]] must be an array of tables")
        rules = tuple(
            RetentionRule(
                pattern=str(value.get("pattern", "")),
                ttl_hours=int(value.get("ttl_hours", default.ttl_hours)),
                persistence=PersistenceMode(
                    str(value.get("persistence", default.persistence))
                ),
            )
            for value in values
            if isinstance(value, Mapping)
        )
        return cls(default=default, rules=rules)

    def decide(self, evidence_type: str) -> RetentionRule:
        """Return the first rule matching ``evidence_type``."""

        for rule in self.rules:
            if fnmatchcase(evidence_type, rule.pattern):
                return rule
        return self.default


@dataclass(frozen=True, slots=True)
class RetentionManifest:
    """Sidecar metadata for one explicitly persisted evidence file."""

    evidence_path: str
    evidence_type: str
    created_at: str
    expires_at: str
    persistence: str
    content_included: bool
    content_digest: str
    citation_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the manifest."""

        value = asdict(self)
        value["citation_ids"] = list(self.citation_ids)
        return value


@dataclass(frozen=True, slots=True)
class RetentionPurgeResult:
    """Summary of one bounded expiration cleanup pass."""

    scanned_manifests: int
    expired_manifests: int
    removed_files: tuple[str, ...]
    errors: tuple[str, ...]
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize the cleanup result."""

        return {
            "scanned_manifests": self.scanned_manifests,
            "expired_manifests": self.expired_manifests,
            "removed_files": list(self.removed_files),
            "errors": list(self.errors),
            "dry_run": self.dry_run,
        }


def write_retained_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    evidence_type: str,
    config: RetentionConfig,
    include_content: bool,
    now: datetime | None = None,
) -> tuple[Path, Path]:
    """Write a restricted JSON evidence file and expiration sidecar.

    The caller must explicitly opt into content persistence. Rules marked
    ``metadata_only`` or ``prohibited`` reject such writes.
    """

    rule = _permitted_rule(
        config,
        evidence_type=evidence_type,
        include_content=include_content,
    )
    created = _aware_utc(now)
    output = dict(payload) if include_content else _metadata_only(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    _restrict(path)
    citations = output.get("citations", [])
    citation_ids = tuple(
        str(item.get("citation_id"))
        for item in citations
        if isinstance(item, Mapping) and item.get("citation_id")
    )
    return path, _write_manifest(
        path,
        evidence_type=evidence_type,
        rule=rule,
        created=created,
        content_included=include_content,
        digest=content_digest(output),
        citation_ids=citation_ids,
    )


def write_retained_text(
    path: Path,
    content: str,
    *,
    evidence_type: str,
    config: RetentionConfig,
    citation_ids: tuple[str, ...] = (),
    now: datetime | None = None,
) -> tuple[Path, Path]:
    """Write restricted text when an explicit-content rule permits it."""

    rule = _permitted_rule(
        config,
        evidence_type=evidence_type,
        include_content=True,
    )
    created = _aware_utc(now)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _restrict(path)
    return path, _write_manifest(
        path,
        evidence_type=evidence_type,
        rule=rule,
        created=created,
        content_included=True,
        digest=content_digest(content),
        citation_ids=citation_ids,
    )


def purge_expired_evidence(
    root: Path,
    *,
    now: datetime | None = None,
    dry_run: bool = True,
    max_manifests: int = 10_000,
) -> RetentionPurgeResult:
    """Remove expired evidence and sidecars without following external paths.

    Only sidecars below ``root`` are considered. Each sidecar may name only a
    sibling evidence file, preventing path traversal or deletion outside the
    selected evidence directory.
    """

    if max_manifests <= 0:
        raise ValueError("max_manifests must be positive")
    current = _aware_utc(now)
    resolved_root = root.resolve()
    manifests = sorted(root.rglob("*.retention.json"))[:max_manifests]
    removed: list[str] = []
    errors: list[str] = []
    expired = 0

    for sidecar in manifests:
        try:
            raw = json.loads(sidecar.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise ValueError("retention sidecar must be a JSON object")
            expires_at = datetime.fromisoformat(str(raw["expires_at"]))
            expires_at = _aware_utc(expires_at)
            if expires_at > current:
                continue
            expired += 1
            evidence_name = str(raw.get("evidence_path", ""))
            if not evidence_name or Path(evidence_name).name != evidence_name:
                raise ValueError("retention evidence_path must be a sibling filename")
            evidence = (sidecar.parent / evidence_name).resolve()
            if evidence.parent != sidecar.parent.resolve():
                raise ValueError("retention evidence path escapes its sidecar directory")
            if resolved_root not in (sidecar.resolve(), *sidecar.resolve().parents):
                raise ValueError("retention sidecar escapes selected root")
            for candidate in (evidence, sidecar.resolve()):
                if candidate.exists():
                    removed.append(str(candidate))
                    if not dry_run:
                        candidate.unlink()
        except Exception as error:  # Corrupt sidecars must not stop other cleanup.
            errors.append(f"{sidecar}: {type(error).__name__}: {error}")

    return RetentionPurgeResult(
        scanned_manifests=len(manifests),
        expired_manifests=expired,
        removed_files=tuple(removed),
        errors=tuple(errors),
        dry_run=dry_run,
    )


def _permitted_rule(
    config: RetentionConfig,
    *,
    evidence_type: str,
    include_content: bool,
) -> RetentionRule:
    rule = config.decide(evidence_type)
    if rule.persistence is PersistenceMode.PROHIBITED:
        raise ConfigurationError(
            f"retention policy prohibits persistence for {evidence_type}"
        )
    if include_content and rule.persistence is not PersistenceMode.EXPLICIT_CONTENT:
        raise ConfigurationError(
            f"retention policy does not permit content persistence for {evidence_type}"
        )
    return rule


def _write_manifest(
    path: Path,
    *,
    evidence_type: str,
    rule: RetentionRule,
    created: datetime,
    content_included: bool,
    digest: str,
    citation_ids: tuple[str, ...],
) -> Path:
    manifest = RetentionManifest(
        evidence_path=path.name,
        evidence_type=evidence_type,
        created_at=created.isoformat(),
        expires_at=(created + timedelta(hours=rule.ttl_hours)).isoformat(),
        persistence=str(rule.persistence),
        content_included=content_included,
        content_digest=digest,
        citation_ids=tuple(dict.fromkeys(citation_ids)),
    )
    sidecar = path.with_suffix(path.suffix + ".retention.json")
    sidecar.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _restrict(sidecar)
    return sidecar


def _metadata_only(payload: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema",
        "system",
        "deployment",
        "returned",
        "total",
        "citation_ids",
        "citations",
        "evidence",
        "retention",
        "security",
    }
    return {key: value for key, value in payload.items() if key in allowed}


def _aware_utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _restrict(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
