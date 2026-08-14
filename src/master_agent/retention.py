"""Retention metadata and restricted evidence-file handling."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

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

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.pattern in seen:
                raise ConfigurationError(
                    f"duplicate retention rule pattern: {rule.pattern}"
                )
            seen.add(rule.pattern)
        restriction = {
            PersistenceMode.EXPLICIT_CONTENT: 0,
            PersistenceMode.METADATA_ONLY: 1,
            PersistenceMode.PROHIBITED: 2,
        }
        for candidate in self.rules:
            for blocker in self.rules:
                if blocker is candidate:
                    continue
                if (
                    restriction[blocker.persistence]
                    <= restriction[candidate.persistence]
                ):
                    continue
                if _pattern_definitely_covers(blocker.pattern, candidate.pattern):
                    raise ConfigurationError(
                        f"retention rule {candidate.pattern} is shadowed by "
                        f"more restrictive rule {blocker.pattern}"
                    )

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
        """Return the most restrictive rule matching ``evidence_type``.

        Retention is a confidentiality boundary, so configuration order cannot
        weaken it.  A prohibited match overrides every other match and a
        metadata-only match overrides explicit-content persistence.  Ties use
        the shortest TTL and then the most specific pattern.
        """

        matches = [
            rule for rule in self.rules if fnmatchcase(evidence_type, rule.pattern)
        ]
        if not matches:
            return self.default
        restriction = {
            PersistenceMode.EXPLICIT_CONTENT: 0,
            PersistenceMode.METADATA_ONLY: 1,
            PersistenceMode.PROHIBITED: 2,
        }
        return max(
            matches,
            key=lambda rule: (
                restriction[rule.persistence],
                -rule.ttl_hours,
                _pattern_specificity(rule.pattern),
            ),
        )


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


@dataclass(frozen=True, slots=True)
class RetentionRepairResult:
    """Result of detecting and optionally quarantining orphaned evidence."""

    scanned_files: int
    orphaned_files: tuple[str, ...]
    quarantined_files: tuple[str, ...]
    errors: tuple[str, ...]
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize the repair result."""

        return {
            "scanned_files": self.scanned_files,
            "orphaned_files": list(self.orphaned_files),
            "quarantined_files": list(self.quarantined_files),
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
    citations = output.get("citations", [])
    citation_ids = tuple(
        str(item.get("citation_id"))
        for item in citations
        if isinstance(item, Mapping) and item.get("citation_id")
    )
    sidecar, manifest = _build_manifest(
        path,
        evidence_type=evidence_type,
        rule=rule,
        created=created,
        content_included=include_content,
        digest=content_digest(output),
        citation_ids=citation_ids,
    )
    _atomic_write_files(
        {
            path: (
                json.dumps(output, indent=2, ensure_ascii=False, default=str) + "\n"
            ).encode("utf-8"),
            sidecar: (
                json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8"),
        }
    )
    return path, sidecar


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
    sidecar, manifest = _build_manifest(
        path,
        evidence_type=evidence_type,
        rule=rule,
        created=created,
        content_included=True,
        digest=content_digest(content),
        citation_ids=citation_ids,
    )
    _atomic_write_files(
        {
            path: content.encode("utf-8"),
            sidecar: (
                json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8"),
        }
    )
    return path, sidecar


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
                raise TypeError("retention sidecar must be a JSON object")
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
                raise ValueError(
                    "retention evidence path escapes its sidecar directory"
                )
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


def repair_orphaned_evidence(
    root: Path,
    *,
    dry_run: bool = True,
    max_files: int = 10_000,
) -> RetentionRepairResult:
    """Detect and quarantine unpaired evidence in a dedicated evidence root.

    An evidence file without its retention sidecar, or a sidecar without its
    named sibling, is not treated as valid retained evidence. Applied repairs
    move such files into a same-filesystem ``.retention-quarantine`` directory
    so the operation remains recoverable.
    """

    if max_files <= 0:
        raise ValueError("max_files must be positive")
    resolved_root = root.resolve()
    quarantine = resolved_root / ".retention-quarantine"
    files = [
        path
        for path in sorted(root.rglob("*"))
        if (path.is_file() or path.is_symlink())
        and quarantine not in (path.resolve(), *path.resolve().parents)
    ][:max_files]
    paired_evidence: set[Path] = set()
    orphans: set[Path] = set()
    errors: list[str] = []

    for sidecar in (path for path in files if path.name.endswith(".retention.json")):
        try:
            if sidecar.is_symlink():
                raise OSError("retention sidecar must not be a symbolic link")
            raw = json.loads(sidecar.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise ValueError("retention sidecar must be a JSON object")
            evidence_name = str(raw.get("evidence_path", ""))
            if not evidence_name or Path(evidence_name).name != evidence_name:
                raise ValueError("retention evidence_path must be a sibling filename")
            evidence = sidecar.parent / evidence_name
            if evidence.is_symlink() or not evidence.is_file():
                orphans.add(sidecar)
            else:
                paired_evidence.add(evidence.resolve())
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            orphans.add(sidecar)
            errors.append(f"{sidecar}: {type(error).__name__}")

    for evidence in (
        path for path in files if not path.name.endswith(".retention.json")
    ):
        if evidence.is_symlink() or evidence.resolve() not in paired_evidence:
            orphans.add(evidence)

    quarantined: list[str] = []
    if not dry_run and orphans:
        quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
        _reject_symlink(quarantine)
        for orphan in sorted(orphans):
            try:
                relative = orphan.resolve().relative_to(resolved_root)
                destination = quarantine / relative
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _reject_symlink(destination.parent)
                if destination.exists() or destination.is_symlink():
                    raise FileExistsError("quarantine destination already exists")
                os.replace(orphan, destination)
                quarantined.append(str(destination))
            except (OSError, ValueError) as error:
                errors.append(f"{orphan}: quarantine failed: {type(error).__name__}")
        _fsync_directory(quarantine)

    return RetentionRepairResult(
        scanned_files=len(files),
        orphaned_files=tuple(str(path) for path in sorted(orphans)),
        quarantined_files=tuple(quarantined),
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


def _build_manifest(
    path: Path,
    *,
    evidence_type: str,
    rule: RetentionRule,
    created: datetime,
    content_included: bool,
    digest: str,
    citation_ids: tuple[str, ...],
) -> tuple[Path, RetentionManifest]:
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
    return sidecar, manifest


def _metadata_only(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project a payload onto a fixed, content-free metadata schema.

    Top-level allowlisting is insufficient because retrieved content can be
    nested beneath otherwise legitimate fields such as ``evidence`` or
    ``security``.  Keep only scalar structural facts, digests, citation
    identifiers, and prompt-injection finding categories.  In particular,
    finding excerpts and arbitrary nested values are never retained.
    """

    output: dict[str, Any] = {}
    for key in ("schema", "system", "deployment", "returned", "total"):
        value = payload.get(key)
        if key in payload and (
            isinstance(value, (str, int, float, bool)) or value is None
        ):
            output[key] = value

    citation_ids = payload.get("citation_ids")
    if isinstance(citation_ids, (list, tuple)):
        output["citation_ids"] = [
            item for item in citation_ids if isinstance(item, str)
        ]

    citations = payload.get("citations")
    if isinstance(citations, (list, tuple)):
        projected_citations = [
            projected
            for item in citations
            if isinstance(item, Mapping)
            if (projected := _project_citation(item))
        ]
        output["citations"] = projected_citations

    evidence = payload.get("evidence")
    if isinstance(evidence, Mapping):
        projected_evidence = _project_scalars(
            evidence,
            {
                "content_digest",
                "retrieved_at",
                "version",
                "etag",
                "count",
                "returned",
                "total",
            },
        )
        if projected_evidence:
            output["evidence"] = projected_evidence

    retention = payload.get("retention")
    if isinstance(retention, Mapping):
        projected_retention = _project_scalars(
            retention,
            {"persistence", "created_at", "expires_at", "content_included"},
        )
        if projected_retention:
            output["retention"] = projected_retention

    security = payload.get("security")
    if isinstance(security, Mapping):
        projected_security = _project_security(security)
        if projected_security:
            output["security"] = projected_security
    return output


def _project_citation(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return content-free citation identity and provenance metadata."""

    return _project_scalars(
        value,
        {
            "citation_id",
            "system",
            "resource_type",
            "resource_id",
            "retrieved_at",
            "content_digest",
        },
    )


def _project_security(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return finding classifications without retrieved-content excerpts."""

    output = _project_scalars(value, {"content_is_untrusted"})
    findings = value.get("prompt_injection_findings")
    if isinstance(findings, (list, tuple)):
        output["prompt_injection_findings"] = [
            _project_scalars(item, {"path", "category", "severity"})
            for item in findings
            if isinstance(item, Mapping)
        ]
    return output


def _project_scalars(
    value: Mapping[str, Any],
    allowed: set[str],
) -> dict[str, Any]:
    """Select only JSON scalar values for explicitly allowed keys."""

    return {
        key: item
        for key, item in value.items()
        if key in allowed and isinstance(item, (str, int, float, bool))
    }


def _pattern_specificity(pattern: str) -> tuple[int, int, int]:
    """Return deterministic precedence within one persistence mode."""

    wildcards = pattern.count("*") + pattern.count("?")
    return (len(pattern) - wildcards, -wildcards, len(pattern))


def _pattern_definitely_covers(broad: str, narrow: str) -> bool:
    """Recognize simple glob containment used to reject unreachable allows."""

    if broad == "*":
        return True
    if "?" in broad or "[" in broad:
        return False
    if broad.endswith("*") and "*" not in broad[:-1]:
        broad_prefix = broad[:-1]
        narrow_prefix = narrow.split("*", 1)[0].split("?", 1)[0]
        return narrow_prefix.startswith(broad_prefix)
    return broad == narrow


def _aware_utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _atomic_write_files(files: Mapping[Path, bytes]) -> None:
    """Commit same-directory retained files with rollback on partial failure."""

    if not files:
        raise ValueError("at least one retained file is required")
    targets = tuple(files)
    parent = targets[0].parent
    if any(target.parent != parent for target in targets):
        raise ConfigurationError("retained evidence and sidecar must be siblings")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_symlink(parent)

    snapshots: dict[Path, bytes | None] = {}
    temporary: dict[Path, Path] = {}
    committed: list[Path] = []
    try:
        for target, content in files.items():
            snapshots[target] = _read_existing_regular_file(target)
            temporary[target] = _prepare_restricted_temp(parent, target.name, content)
        for target in targets:
            os.replace(temporary[target], target)
            committed.append(target)
        _fsync_directory(parent)
    except Exception as error:
        rollback_errors: list[str] = []
        for target in reversed(committed):
            try:
                previous = snapshots[target]
                if previous is None:
                    target.unlink(missing_ok=True)
                else:
                    restored = _prepare_restricted_temp(
                        parent,
                        target.name,
                        previous,
                    )
                    os.replace(restored, target)
            except (OSError, ConfigurationError) as rollback_error:
                rollback_errors.append(type(rollback_error).__name__)
        for temp_path in temporary.values():
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            _fsync_directory(parent)
        except OSError as rollback_error:
            rollback_errors.append(type(rollback_error).__name__)
        if rollback_errors:
            raise ConfigurationError(
                "retained evidence commit failed and rollback was incomplete: "
                + ", ".join(rollback_errors)
            ) from error
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError(
            f"retained evidence commit failed: {type(error).__name__}"
        ) from error


def _read_existing_regular_file(path: Path) -> bytes | None:
    """Read an existing destination without following a final symlink."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ConfigurationError(
            f"retained evidence destination is unsafe: {path.name}"
        ) from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ConfigurationError(
                f"retained evidence destination is not a regular file: {path.name}"
            )
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _prepare_restricted_temp(parent: Path, name: str, content: bytes) -> Path:
    """Write and fsync a mode-0600 no-follow temporary file."""

    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{name}.retention-txn-",
        dir=parent,
    )
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short retained evidence write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    return path


def _reject_symlink(path: Path) -> None:
    """Reject a symlink at a retention transaction boundary."""

    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ConfigurationError(
            f"retention transaction path does not exist: {path}"
        ) from error
    if stat.S_ISLNK(mode):
        raise ConfigurationError(f"retention transaction path is a symlink: {path}")


def _fsync_directory(path: Path) -> None:
    """Persist directory entry changes for a completed transaction."""

    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
