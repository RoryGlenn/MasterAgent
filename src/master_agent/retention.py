"""Retention metadata and restricted evidence-file handling."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Self

from master_agent.config_sources import ConfigSource
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConfigurationError, StructuredDataTypeError
from master_agent.evidence import content_digest

_SECURITY_CATEGORIES = frozenset(
    {
        "authority_claim",
        "credential_request",
        "external_action_request",
        "instruction_override",
    }
)
_SECURITY_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_RETENTION_FLOCK_NAME = ".master-agent-retention.flock"
_RETENTION_QUARANTINE_NAME = ".retention-quarantine"
_MAX_REPAIR_FILE_BYTES = 64 * 1024 * 1024
_MAX_REPAIR_DEPTH = 64


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


@dataclass(frozen=True, slots=True)
class _RetainedFileRecord:
    """Descriptor-discovered file identity beneath one pinned evidence root."""

    relative_parts: tuple[str, ...]
    identity: tuple[int, int]
    mode: int
    size: int

    @property
    def name(self) -> str:
        return self.relative_parts[-1]

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.mode)


class RetainedJSONReservation:
    """Create-only retained JSON names held across an external operation.

    The persistent retention lock is acquired and both final names are proven
    absent before an effect. This prevents a stale destination or a cooperating
    concurrent writer from turning a successful effect into a false-failure.
    Commit creates both final names once, keeps their exact descriptors through
    write/readback, and removes only transaction-owned files on failure.
    """

    def __init__(
        self,
        path: Path,
        *,
        evidence_type: str,
        config: RetentionConfig,
        include_content: bool,
        now: datetime | None = None,
        parent_directory: PinnedDirectory | None = None,
    ) -> None:
        self._rule = _permitted_rule(
            config,
            evidence_type=evidence_type,
            include_content=include_content,
        )
        self._evidence_type = evidence_type
        self._include_content = include_content
        self._created_at = _aware_utc(now)
        self._pinned = (
            parent_directory.duplicate()
            if parent_directory is not None
            else PinnedDirectory.open(path.parent)
        )
        self._parent_descriptor = self._pinned.fileno()
        absolute = Path(os.path.abspath(os.fspath(path)))
        if (
            Path(os.path.realpath(absolute.parent)) != self._pinned.path
            or absolute.name in {"", ".", ".."}
            or Path(absolute.name).name != absolute.name
        ):
            self._pinned.close()
            raise ConfigurationError(
                "retained evidence must be an immediate child of its pinned parent"
            )
        self._path = self._pinned.path / absolute.name
        self._sidecar = self._path.with_suffix(self._path.suffix + ".retention.json")
        if self._sidecar.name == self._path.name:
            self._pinned.close()
            raise ConfigurationError("retained evidence names must be distinct")
        self._lock_descriptor = -1
        self._lock_identity: tuple[int, int] | None = None
        self._files: list[tuple[str, tuple[int, int]]] = []
        self._committed = False
        self._closed = False
        try:
            self._lock_descriptor, self._lock_identity = _open_retention_lock(
                self._parent_descriptor
            )
            fcntl.flock(self._lock_descriptor, fcntl.LOCK_EX)
            _validate_restricted_file_at(
                self._parent_descriptor,
                _RETENTION_FLOCK_NAME,
                self._lock_identity,
            )
            self._pinned.validate()
            _require_retained_names_absent(
                self._parent_descriptor,
                (self._path.name, self._sidecar.name),
            )
            self._validate()
        except BaseException:
            self._rollback_and_close()
            raise

    @property
    def path(self) -> Path:
        """Return the canonical reserved evidence path."""

        return self._path

    @property
    def sidecar(self) -> Path:
        """Return the canonical reserved retention-sidecar path."""

        return self._sidecar

    def commit(self, payload: Mapping[str, Any]) -> tuple[Path, Path]:
        """Write, verify, and durably commit the reserved result pair."""

        if self._closed or self._committed:
            raise ConfigurationError("retained evidence reservation is not active")
        output = dict(payload) if self._include_content else _metadata_only(payload)
        citations = output.get("citations", [])
        citation_ids = tuple(
            str(item.get("citation_id"))
            for item in citations
            if isinstance(item, Mapping) and item.get("citation_id")
        )
        _, manifest = _build_manifest(
            self._path,
            evidence_type=self._evidence_type,
            rule=self._rule,
            created=self._created_at,
            content_included=self._include_content,
            digest=content_digest(output),
            citation_ids=citation_ids,
        )
        content_by_name = {
            self._path.name: (
                json.dumps(output, indent=2, ensure_ascii=False, default=str) + "\n"
            ).encode("utf-8"),
            self._sidecar.name: (
                json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8"),
        }
        try:
            self._validate()
            _require_retained_names_absent(
                self._parent_descriptor,
                (self._path.name, self._sidecar.name),
            )
            self._files = _commit_restricted_files_at(
                self._parent_descriptor,
                content_by_name,
                publish_last=self._path.name,
            )
            self._validate()
            self._committed = True
            return self._path, self._sidecar
        except BaseException as error:
            try:
                self._rollback_and_close()
            except ConfigurationError as rollback_error:
                raise rollback_error from error
            if isinstance(error, ConfigurationError):
                raise
            if not isinstance(error, Exception):
                raise
            raise ConfigurationError(
                f"retained evidence commit failed: {type(error).__name__}"
            ) from error

    def close(self) -> None:
        """Release the reservation, rolling back only uncommitted owned files."""

        self._rollback_and_close()

    def __enter__(self) -> Self:
        """Return this active reservation."""

        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _validate(self) -> None:
        self._pinned.validate()
        if self._lock_identity is None:
            raise ConfigurationError("retention reservation lock is missing")
        _validate_restricted_file_at(
            self._parent_descriptor,
            _RETENTION_FLOCK_NAME,
            self._lock_identity,
        )
        for name, identity in self._files:
            _validate_restricted_file_at(
                self._parent_descriptor,
                name,
                identity,
            )

    def _rollback_and_close(self) -> None:
        if self._closed:
            return
        rollback_errors: list[str] = []
        if not self._committed:
            for name, identity in reversed(self._files):
                try:
                    _unlink_restricted_file_at(
                        self._parent_descriptor,
                        name,
                        identity,
                    )
                except (OSError, ConfigurationError) as error:
                    rollback_errors.append(type(error).__name__)
            try:
                os.fsync(self._parent_descriptor)
            except OSError as error:
                rollback_errors.append(type(error).__name__)
        self._files.clear()
        if self._lock_descriptor >= 0:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_descriptor)
                self._lock_descriptor = -1
        self._pinned.close()
        self._closed = True
        if rollback_errors:
            raise ConfigurationError(
                "retained evidence reservation rollback was incomplete: "
                + ", ".join(rollback_errors)
            )


def write_retained_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    evidence_type: str,
    config: RetentionConfig,
    include_content: bool,
    now: datetime | None = None,
    parent_directory: PinnedDirectory | None = None,
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
        },
        parent_directory=parent_directory,
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
    parent_directory: PinnedDirectory | None = None,
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
        },
        parent_directory=parent_directory,
    )
    return path, sidecar


def purge_expired_evidence(
    root: Path,
    *,
    now: datetime | None = None,
    dry_run: bool = True,
    max_manifests: int = 10_000,
) -> RetentionPurgeResult:
    """Preview expiration cleanup; destructive traversal is disabled."""

    if not dry_run:
        raise ConfigurationError(
            "destructive evidence pruning is disabled until recursive traversal "
            "and deletion are descriptor-bound"
        )
    return _purge_expired_evidence_locked(
        root,
        now=now,
        dry_run=True,
        max_manifests=max_manifests,
    )


def _purge_expired_evidence_locked(
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
            if sidecar.is_symlink():
                raise OSError("retention sidecar must not be a symbolic link")
            raw = json.loads(sidecar.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise StructuredDataTypeError("retention sidecar must be a JSON object")
            expires_at = datetime.fromisoformat(str(raw["expires_at"]))
            expires_at = _aware_utc(expires_at)
            if expires_at > current:
                continue
            expired += 1
            evidence_name = str(raw.get("evidence_path", ""))
            if not evidence_name or Path(evidence_name).name != evidence_name:
                raise ValueError("retention evidence_path must be a sibling filename")
            evidence_path = sidecar.parent / evidence_name
            if evidence_path.is_symlink() or not evidence_path.is_file():
                raise ValueError("retention evidence file is missing or unsafe")
            evidence = evidence_path.resolve()
            if evidence.parent != sidecar.parent.resolve():
                raise ValueError(
                    "retention evidence path escapes its sidecar directory"
                )
            if resolved_root not in (sidecar.resolve(), *sidecar.resolve().parents):
                raise ValueError("retention sidecar escapes selected root")
            _verify_retained_content(evidence_path, raw)
            for candidate in (evidence, sidecar.resolve()):
                if candidate.exists():
                    removed.append(str(candidate))
                    if not dry_run:
                        candidate.unlink()
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
            # Corrupt sidecars must not stop cleanup of independent records.
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
    """Detect or recoverably quarantine orphaned retained evidence."""

    return _repair_orphaned_evidence_locked(
        root,
        dry_run=dry_run,
        max_files=max_files,
    )


def _repair_orphaned_evidence_locked(
    root: Path,
    *,
    dry_run: bool = True,
    max_files: int = 10_000,
) -> RetentionRepairResult:
    """Scan and quarantine through a pinned root and no-follow relative FDs."""

    if max_files <= 0:
        raise ValueError("max_files must be positive")
    with PinnedDirectory.open(root) as pinned:
        root_descriptor = pinned.fileno()
        existing_lock_missing = False
        if dry_run:
            existing_lock = _open_existing_retention_lock(root_descriptor)
            if existing_lock is None:
                lock_descriptor = -1
                lock_identity = None
                existing_lock_missing = True
            else:
                lock_descriptor, lock_identity = existing_lock
        else:
            lock_descriptor, lock_identity = _open_retention_lock(root_descriptor)
        lock_acquired = False
        try:
            if lock_descriptor >= 0:
                try:
                    fcntl.flock(
                        lock_descriptor,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    lock_acquired = True
                except BlockingIOError as error:
                    if not dry_run:
                        raise ConfigurationError(
                            "retention repair refused while a publication is active"
                        ) from error
                    return RetentionRepairResult(
                        scanned_files=0,
                        orphaned_files=(),
                        quarantined_files=(),
                        errors=("retention publication is active; scan deferred",),
                        dry_run=True,
                    )
                assert lock_identity is not None
                _validate_restricted_file_at(
                    root_descriptor,
                    _RETENTION_FLOCK_NAME,
                    lock_identity,
                )
            pinned.validate()
            records, scan_errors = _scan_retained_files_at(
                root_descriptor,
                max_files=max_files,
            )
            orphans, classification_errors = _classify_orphaned_records_at(
                root_descriptor,
                records,
            )
            errors = [*scan_errors, *classification_errors]
            if existing_lock_missing and _retention_lock_exists_at(root_descriptor):
                errors.append(
                    "retention publication began during the preview; rescan required"
                )
            quarantined: list[str] = []
            if not dry_run and scan_errors:
                errors.append(
                    "quarantine refused because the descriptor scan was incomplete"
                )
            elif not dry_run and orphans:
                quarantined, quarantine_errors = _quarantine_records_at(
                    root_descriptor,
                    pinned.path,
                    orphans,
                )
                errors.extend(quarantine_errors)
            pinned.validate()
            orphan_paths = tuple(
                str(pinned.path.joinpath(*record.relative_parts)) for record in orphans
            )
            return RetentionRepairResult(
                scanned_files=len(records),
                orphaned_files=orphan_paths,
                quarantined_files=tuple(quarantined),
                errors=tuple(errors),
                dry_run=dry_run,
            )
        finally:
            try:
                if lock_acquired:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                if lock_descriptor >= 0:
                    os.close(lock_descriptor)


def _scan_retained_files_at(
    root_descriptor: int,
    *,
    max_files: int,
) -> tuple[list[_RetainedFileRecord], list[str]]:
    """Recursively enumerate files without following a pathname or symlink."""

    records: list[_RetainedFileRecord] = []
    errors: list[str] = []
    truncated = False

    def visit(directory_descriptor: int, prefix: tuple[str, ...]) -> None:
        nonlocal truncated
        if len(prefix) > _MAX_REPAIR_DEPTH or len(records) >= max_files:
            truncated = True
            return
        try:
            names = sorted(os.listdir(directory_descriptor))
        except OSError as error:
            errors.append(
                f"{'/'.join(prefix) or '.'}: scan failed: {type(error).__name__}"
            )
            return
        for name in names:
            if len(records) >= max_files:
                truncated = True
                return
            if not prefix and name in {
                _RETENTION_FLOCK_NAME,
                _RETENTION_QUARANTINE_NAME,
            }:
                continue
            relative = (*prefix, name)
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                errors.append(
                    f"{'/'.join(relative)}: scan failed: {type(error).__name__}"
                )
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if len(relative) > _MAX_REPAIR_DEPTH:
                    errors.append(f"{'/'.join(relative)}: directory is too deep")
                    continue
                child_descriptor = -1
                try:
                    child_descriptor = os.open(
                        name,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=directory_descriptor,
                    )
                    current = os.fstat(child_descriptor)
                    if (
                        not stat.S_ISDIR(current.st_mode)
                        or (current.st_dev, current.st_ino)
                        != (metadata.st_dev, metadata.st_ino)
                        or current.st_uid != os.getuid()
                        or stat.S_IMODE(current.st_mode) & 0o022
                    ):
                        raise ConfigurationError(
                            "evidence directory is not privately controlled"
                        )
                    visit(child_descriptor, relative)
                except (OSError, ConfigurationError) as error:
                    errors.append(
                        f"{'/'.join(relative)}: scan failed: {type(error).__name__}"
                    )
                finally:
                    if child_descriptor >= 0:
                        os.close(child_descriptor)
                continue
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                records.append(
                    _RetainedFileRecord(
                        relative_parts=relative,
                        identity=(metadata.st_dev, metadata.st_ino),
                        mode=metadata.st_mode,
                        size=metadata.st_size,
                    )
                )

    visit(root_descriptor, ())
    if truncated:
        errors.append(f"descriptor scan exceeded the {max_files}-file limit")
    return records, errors


def _classify_orphaned_records_at(
    root_descriptor: int,
    records: list[_RetainedFileRecord],
) -> tuple[list[_RetainedFileRecord], list[str]]:
    """Validate evidence/sidecar pairs from descriptor-discovered identities."""

    by_relative = {record.relative_parts: record for record in records}
    paired_evidence: set[tuple[str, ...]] = set()
    orphaned: dict[tuple[str, ...], _RetainedFileRecord] = {}
    errors: list[str] = []
    sidecars = sorted(
        (record for record in records if record.name.endswith(".retention.json")),
        key=lambda record: record.relative_parts,
    )
    for sidecar in sidecars:
        display = "/".join(sidecar.relative_parts)
        try:
            if sidecar.is_symlink:
                raise OSError("retention sidecar must not be a symbolic link")
            raw_bytes = _read_record_bytes_at(root_descriptor, sidecar)
            raw = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(raw, Mapping):
                raise StructuredDataTypeError("retention sidecar must be a JSON object")
            evidence_name = str(raw.get("evidence_path", ""))
            if (
                not evidence_name
                or evidence_name in {".", ".."}
                or Path(evidence_name).name != evidence_name
            ):
                raise ValueError("retention evidence_path must be a sibling filename")
            evidence_relative = (*sidecar.relative_parts[:-1], evidence_name)
            evidence = by_relative.get(evidence_relative)
            if evidence is None or evidence.is_symlink:
                orphaned[sidecar.relative_parts] = sidecar
                continue
            try:
                _verify_retained_record_at(root_descriptor, evidence, raw)
            except (
                OSError,
                StructuredDataTypeError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ):
                orphaned[sidecar.relative_parts] = sidecar
                orphaned[evidence.relative_parts] = evidence
                errors.append(f"{display}: content digest mismatch")
            else:
                paired_evidence.add(evidence.relative_parts)
        except (
            OSError,
            StructuredDataTypeError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as error:
            orphaned[sidecar.relative_parts] = sidecar
            errors.append(f"{display}: {type(error).__name__}")

    for record in records:
        if record.name.endswith(".retention.json"):
            continue
        if record.is_symlink or record.relative_parts not in paired_evidence:
            orphaned[record.relative_parts] = record
    return (
        [orphaned[key] for key in sorted(orphaned)],
        errors,
    )


def _verify_retained_record_at(
    root_descriptor: int,
    record: _RetainedFileRecord,
    manifest: Mapping[str, Any],
) -> None:
    """Require descriptor-read evidence bytes to match one manifest digest."""

    expected = manifest.get("content_digest")
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ValueError("retention content digest is invalid")
    raw = _read_record_bytes_at(root_descriptor, record)
    text = raw.decode("utf-8")
    value: Any = json.loads(text) if record.name.casefold().endswith(".json") else text
    if content_digest(value) != expected:
        raise ValueError("retention content digest does not match evidence")


def _read_record_bytes_at(
    root_descriptor: int,
    record: _RetainedFileRecord,
) -> bytes:
    """Read one bounded regular file through its validated relative descriptor."""

    if record.is_symlink or record.size > _MAX_REPAIR_FILE_BYTES:
        raise OSError("retained evidence file is unsafe or too large")
    parent_descriptor = _open_relative_directory_at(
        root_descriptor,
        record.relative_parts[:-1],
    )
    descriptor = -1
    try:
        descriptor = os.open(
            record.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino) != record.identity
            or metadata.st_size != record.size
        ):
            raise OSError("retained evidence file identity changed")
        chunks: list[bytes] = []
        remaining = _MAX_REPAIR_FILE_BYTES
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("retained evidence file is too large")
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _open_relative_directory_at(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
) -> int:
    """Open a private descendant directory one no-follow component at a time."""

    descriptor = os.dup(root_descriptor)
    try:
        for component in relative_parts:
            if component in {"", ".", ".."} or Path(component).name != component:
                raise ConfigurationError("unsafe evidence directory component")
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise ConfigurationError(
                    "evidence directory is not privately controlled"
                )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _quarantine_records_at(
    root_descriptor: int,
    root: Path,
    records: list[_RetainedFileRecord],
) -> tuple[list[str], list[str]]:
    """Hard-link then unlink exact orphan identities into private quarantine."""

    quarantine_descriptor = _open_or_create_private_directory_at(
        root_descriptor,
        _RETENTION_QUARANTINE_NAME,
    )
    quarantined: list[str] = []
    errors: list[str] = []
    try:
        for record in records:
            source_parent = -1
            destination_parent = -1
            display = root.joinpath(*record.relative_parts)
            try:
                source_parent = _open_relative_directory_at(
                    root_descriptor,
                    record.relative_parts[:-1],
                )
                destination_parent = _open_or_create_relative_directories_at(
                    quarantine_descriptor,
                    record.relative_parts[:-1],
                )
                _quarantine_owned_name_at(
                    source_parent,
                    destination_parent,
                    record.name,
                    record.identity,
                    record.mode,
                )
                quarantined.append(
                    str(
                        root / _RETENTION_QUARANTINE_NAME / Path(*record.relative_parts)
                    )
                )
            except (OSError, ConfigurationError) as error:
                errors.append(f"{display}: quarantine failed: {type(error).__name__}")
            finally:
                if destination_parent >= 0:
                    os.close(destination_parent)
                if source_parent >= 0:
                    os.close(source_parent)
        os.fsync(quarantine_descriptor)
        os.fsync(root_descriptor)
        return quarantined, errors
    finally:
        os.close(quarantine_descriptor)


def _open_or_create_relative_directories_at(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
) -> int:
    """Open or create private quarantine descendants without following links."""

    descriptor = os.dup(root_descriptor)
    try:
        for component in relative_parts:
            child = _open_or_create_private_directory_at(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_private_directory_at(
    parent_descriptor: int,
    name: str,
) -> int:
    """Open one owner-private directory, creating it without symlink traversal."""

    if name in {"", ".", ".."} or Path(name).name != name:
        raise ConfigurationError("unsafe quarantine directory component")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except FileExistsError:
        pass
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_descriptor,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise ConfigurationError("quarantine directory is not owner-private")
    return descriptor


def _quarantine_owned_name_at(
    source_parent: int,
    destination_parent: int,
    name: str,
    expected_identity: tuple[int, int],
    expected_mode: int,
) -> None:
    """Move one exact file or symlink with create-only hard-link semantics."""

    source = os.stat(name, dir_fd=source_parent, follow_symlinks=False)
    if (
        (source.st_dev, source.st_ino) != expected_identity
        or source.st_uid != os.getuid()
        or source.st_nlink != 1
        or stat.S_IFMT(source.st_mode) != stat.S_IFMT(expected_mode)
        or not (stat.S_ISREG(source.st_mode) or stat.S_ISLNK(source.st_mode))
    ):
        raise ConfigurationError("orphaned evidence identity changed")
    linked = False
    source_unlinked = False
    try:
        os.link(
            name,
            name,
            src_dir_fd=source_parent,
            dst_dir_fd=destination_parent,
            follow_symlinks=False,
        )
        linked = True
        destination = os.stat(
            name,
            dir_fd=destination_parent,
            follow_symlinks=False,
        )
        if (
            destination.st_dev,
            destination.st_ino,
        ) != expected_identity or destination.st_nlink != 2:
            raise ConfigurationError("quarantine destination identity changed")
        current_source = os.stat(
            name,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        if (
            current_source.st_dev,
            current_source.st_ino,
        ) != expected_identity or current_source.st_nlink != 2:
            raise ConfigurationError("orphaned evidence identity changed")
        os.unlink(name, dir_fd=source_parent)
        source_unlinked = True
        final = os.stat(
            name,
            dir_fd=destination_parent,
            follow_symlinks=False,
        )
        if (final.st_dev, final.st_ino) != expected_identity or final.st_nlink != 1:
            raise ConfigurationError("quarantine destination identity changed")
        os.fsync(source_parent)
        os.fsync(destination_parent)
    except BaseException as error:
        if linked and not source_unlinked:
            try:
                destination = os.stat(
                    name,
                    dir_fd=destination_parent,
                    follow_symlinks=False,
                )
                if (destination.st_dev, destination.st_ino) == expected_identity:
                    os.unlink(name, dir_fd=destination_parent)
                    os.fsync(destination_parent)
            except OSError as cleanup_error:
                raise ConfigurationError(
                    "quarantine rollback was incomplete"
                ) from cleanup_error
        if source_unlinked:
            raise ConfigurationError(
                "orphan was quarantined but final durability validation failed"
            ) from error
        raise


def _verify_retained_content(path: Path, manifest: Mapping[str, Any]) -> None:
    """Require retained bytes to match the digest recorded by their sidecar."""

    expected = manifest.get("content_digest")
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ValueError("retention content digest is invalid")
    text = path.read_text(encoding="utf-8")
    value: Any = json.loads(text) if path.suffix.casefold() == ".json" else text
    if content_digest(value) != expected:
        raise ValueError("retention content digest does not match evidence")


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
    for key in ("schema", "system", "deployment"):
        if (digest := _identifier_digest(payload.get(key))) is not None:
            output[f"{key}_digest"] = digest
    for key in ("returned", "total"):
        if (value := _nonnegative_integer(payload.get(key))) is not None:
            output[key] = value

    citations = payload.get("citations")
    if isinstance(citations, (list, tuple)):
        projected_citations = [
            projected
            for item in citations
            if isinstance(item, Mapping)
            if (projected := _project_citation(item))
        ]
        output["citations"] = projected_citations
        output["citation_ids"] = [
            str(item["citation_id"])
            for item in projected_citations
            if "citation_id" in item
        ]

    evidence = payload.get("evidence")
    projected_evidence = _project_evidence(
        evidence if isinstance(evidence, Mapping) else {},
        payload_digest=content_digest(payload),
    )
    output["evidence"] = projected_evidence

    retention = payload.get("retention")
    if isinstance(retention, Mapping):
        projected_retention = _project_retention(retention)
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

    output: dict[str, Any] = {}
    if (citation_id := _derived_citation_id(value)) is not None:
        output["citation_id"] = citation_id
    for key in ("system", "resource_type"):
        if (digest := _identifier_digest(value.get(key))) is not None:
            output[f"{key}_digest"] = digest
    if (resource_digest := _identifier_digest(value.get("resource_id"))) is not None:
        output["resource_id_digest"] = resource_digest
    if (retrieved_at := _timestamp(value.get("retrieved_at"))) is not None:
        output["retrieved_at"] = retrieved_at
    for key in ("version", "etag"):
        if (digest := _identifier_digest(value.get(key))) is not None:
            output[f"{key}_digest"] = digest
    return output


def _project_evidence(
    value: Mapping[str, Any],
    *,
    payload_digest: str,
) -> dict[str, Any]:
    """Return validated evidence facts and derived opaque identifiers."""

    output: dict[str, Any] = {"content_digest": payload_digest}
    if (retrieved_at := _timestamp(value.get("retrieved_at"))) is not None:
        output["retrieved_at"] = retrieved_at
    for key in ("version", "etag"):
        if (digest := _identifier_digest(value.get(key))) is not None:
            output[f"{key}_digest"] = digest
    for key in ("count", "returned", "total"):
        if (count := _nonnegative_integer(value.get(key))) is not None:
            output[key] = count
    return output


def _project_retention(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return semantically valid retention metadata."""

    output: dict[str, Any] = {}
    persistence = value.get("persistence")
    if isinstance(persistence, str):
        try:
            output["persistence"] = str(PersistenceMode(persistence))
        except ValueError:
            pass
    for key in ("created_at", "expires_at"):
        if (timestamp := _timestamp(value.get(key))) is not None:
            output[key] = timestamp
    content_included = value.get("content_included")
    if isinstance(content_included, bool):
        output["content_included"] = content_included
    return output


def _project_security(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return finding classifications without retrieved-content excerpts."""

    output: dict[str, Any] = {}
    content_is_untrusted = value.get("content_is_untrusted")
    if isinstance(content_is_untrusted, bool):
        output["content_is_untrusted"] = content_is_untrusted
    findings = value.get("prompt_injection_findings")
    if isinstance(findings, (list, tuple)):
        projected_findings = [
            projected
            for item in findings
            if isinstance(item, Mapping)
            if (projected := _project_security_finding(item))
        ]
        output["prompt_injection_findings"] = projected_findings
    return output


def _project_security_finding(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return one finding without its source location or excerpt content."""

    output: dict[str, Any] = {}
    if (path_digest := _identifier_digest(value.get("path"))) is not None:
        output["path_digest"] = path_digest
    category = value.get("category")
    if isinstance(category, str) and category in _SECURITY_CATEGORIES:
        output["category"] = category
    severity = value.get("severity")
    if isinstance(severity, str) and severity in _SECURITY_SEVERITIES:
        output["severity"] = severity
    return output


def _derived_citation_id(value: Mapping[str, Any]) -> str | None:
    """Derive a citation ID from its complete provider resource identity."""

    parts = tuple(
        _identifier_text(value.get(key))
        for key in ("system", "resource_type", "resource_id")
    )
    if any(part is None for part in parts):
        return None
    identity = "\0".join(str(part) for part in parts).encode("utf-8")
    return "CIT-" + hashlib.sha256(identity).hexdigest()[:12].upper()


def _identifier_digest(value: Any) -> str | None:
    """Derive a bounded digest for an opaque provider identifier."""

    rendered = _identifier_text(value)
    if rendered is None:
        return None
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _identifier_text(value: Any) -> str | None:
    """Return a bounded identifier only for local hashing or derivation."""

    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    rendered = str(value)
    if not rendered or len(rendered) > 2_048:
        return None
    return rendered


def _nonnegative_integer(value: Any) -> int | None:
    """Return a non-negative count without accepting booleans as integers."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _timestamp(value: Any) -> str | None:
    """Return a timezone-aware ISO timestamp normalized to UTC."""

    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat()


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


def _atomic_write_files(
    files: Mapping[Path, bytes],
    *,
    parent_directory: PinnedDirectory | None = None,
) -> None:
    """Commit same-directory retained files with rollback on partial failure."""

    if not files:
        raise ValueError("at least one retained file is required")
    targets = tuple(files)
    parent = targets[0].parent
    if any(target.parent != parent for target in targets):
        raise ConfigurationError("retained evidence and sidecar must be siblings")
    if parent_directory is not None:
        _atomic_write_files_at(files, parent_directory)
        return
    with PinnedDirectory.open(parent) as pinned:
        canonical_files = {
            pinned.path / target.name: content for target, content in files.items()
        }
        _atomic_write_files_at(canonical_files, pinned)


def _atomic_write_files_at(
    files: Mapping[Path, bytes],
    parent_directory: PinnedDirectory,
) -> None:
    """Stage and create-only publish retained siblings under one lock."""

    targets = tuple(files)
    content_by_name = {target.name: content for target, content in files.items()}
    if any(
        Path(os.path.realpath(target.parent)) != parent_directory.path
        or target.name in {"", ".", ".."}
        or Path(target.name).name != target.name
        for target in targets
    ) or len(content_by_name) != len(targets):
        raise ConfigurationError(
            "retained evidence must be an immediate child of its pinned parent"
        )
    pinned = parent_directory.duplicate()
    parent_descriptor = pinned.fileno()
    lock_descriptor = -1
    lock_identity: tuple[int, int] | None = None
    published: list[tuple[str, tuple[int, int]]] = []
    try:
        lock_descriptor, lock_identity = _open_retention_lock(parent_descriptor)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        _validate_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            lock_identity,
        )
        pinned.validate()
        published = _commit_restricted_files_at(
            parent_descriptor,
            content_by_name,
            # Callers put the evidence file first. Publish its already-durable
            # sidecar(s) first so a crash can never expose evidence without a
            # retention manifest.
            publish_last=targets[0].name,
        )
        pinned.validate()
        _validate_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            lock_identity,
        )
        for target_name, identity in published:
            _validate_restricted_file_at(
                parent_descriptor,
                target_name,
                identity,
            )
    except BaseException as error:
        rollback_errors: list[str] = []
        for target_name, identity in reversed(published):
            try:
                _unlink_restricted_file_at(
                    parent_descriptor,
                    target_name,
                    identity,
                )
            except (OSError, ConfigurationError) as rollback_error:
                rollback_errors.append(type(rollback_error).__name__)
        try:
            os.fsync(parent_descriptor)
        except OSError as rollback_error:
            rollback_errors.append(type(rollback_error).__name__)
        if rollback_errors:
            raise ConfigurationError(
                "retained evidence commit failed and rollback was incomplete: "
                + ", ".join(rollback_errors)
            ) from error
        if isinstance(error, ConfigurationError):
            raise
        if not isinstance(error, Exception):
            raise
        raise ConfigurationError(
            f"retained evidence commit failed: {type(error).__name__}"
        ) from error
    finally:
        if lock_descriptor >= 0:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
        pinned.close()


def _commit_restricted_files_at(
    parent_descriptor: int,
    content_by_name: Mapping[str, bytes],
    *,
    publish_last: str,
) -> list[tuple[str, tuple[int, int]]]:
    """Stage, verify, and create-only publish a retained file set.

    Every byte is written through a mode-0600, no-follow temporary file in the
    destination directory. The manifest is linked into place before evidence,
    and final names are never replaced. Any exception rolls back all names
    owned by this transaction.
    """

    if publish_last not in content_by_name:
        raise ConfigurationError("retained publication target is missing")
    final_names = tuple(content_by_name)
    _require_retained_names_absent(parent_descriptor, final_names)
    staged: list[tuple[str, str, int, tuple[int, int]]] = []
    published: list[tuple[str, tuple[int, int]]] = []
    try:
        for final_name, content in content_by_name.items():
            temporary_name, descriptor, identity = _open_restricted_temp_file_at(
                parent_descriptor
            )
            staged.append((final_name, temporary_name, descriptor, identity))
            _write_restricted_descriptor(descriptor, content)
            _validate_restricted_file_at(
                parent_descriptor,
                temporary_name,
                identity,
            )
            if _read_restricted_descriptor(descriptor) != content:
                raise ConfigurationError("retained evidence content changed")

        _require_retained_names_absent(parent_descriptor, final_names)
        staged_by_final = {item[0]: item for item in staged}
        publication_order = tuple(
            name for name in final_names if name != publish_last
        ) + (publish_last,)
        for final_name in publication_order:
            _, temporary_name, _, identity = staged_by_final[final_name]
            _publish_restricted_temp_file_at(
                parent_descriptor,
                temporary_name,
                final_name,
                identity,
            )
            published.append((final_name, identity))
        os.fsync(parent_descriptor)
        for final_name, identity in published:
            _validate_restricted_file_at(
                parent_descriptor,
                final_name,
                identity,
            )
        return published
    except BaseException as error:
        rollback_errors: list[str] = []
        for final_name, identity in reversed(published):
            try:
                _unlink_restricted_file_at(
                    parent_descriptor,
                    final_name,
                    identity,
                )
            except (OSError, ConfigurationError) as rollback_error:
                rollback_errors.append(type(rollback_error).__name__)
        for _, temporary_name, _, identity in reversed(staged):
            try:
                _unlink_restricted_file_at(
                    parent_descriptor,
                    temporary_name,
                    identity,
                )
            except (OSError, ConfigurationError) as rollback_error:
                rollback_errors.append(type(rollback_error).__name__)
        try:
            os.fsync(parent_descriptor)
        except OSError as rollback_error:
            rollback_errors.append(type(rollback_error).__name__)
        if rollback_errors:
            raise ConfigurationError(
                "retained evidence staging rollback was incomplete: "
                + ", ".join(rollback_errors)
            ) from error
        raise
    finally:
        for _, _, descriptor, _ in reversed(staged):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _require_retained_names_absent(
    parent_descriptor: int,
    names: tuple[str, ...],
) -> None:
    """Reject any preexisting final retained-output name without following it."""

    for name in names:
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ConfigurationError(
            f"retained evidence destination already exists: {name}"
        )


def _open_retention_lock(
    parent_descriptor: int,
) -> tuple[int, tuple[int, int]]:
    """Open or create the content-free persistent retention lock."""

    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    created = False
    try:
        descriptor = os.open(_RETENTION_FLOCK_NAME, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        try:
            descriptor = os.open(
                _RETENTION_FLOCK_NAME,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(
                _RETENTION_FLOCK_NAME,
                flags,
                dir_fd=parent_descriptor,
            )
    except OSError as error:
        raise ConfigurationError("retention transaction lock is unsafe") from error
    try:
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(parent_descriptor)
        identity = _restricted_file_identity(
            os.fstat(descriptor),
            _RETENTION_FLOCK_NAME,
        )
        _validate_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            identity,
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _open_existing_retention_lock(
    parent_descriptor: int,
) -> tuple[int, tuple[int, int]] | None:
    """Open an existing lock without mutating state during a repair preview."""

    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(
            _RETENTION_FLOCK_NAME,
            flags,
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ConfigurationError("retention transaction lock is unsafe") from error
    try:
        identity = _restricted_file_identity(
            os.fstat(descriptor),
            _RETENTION_FLOCK_NAME,
        )
        _validate_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            identity,
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _retention_lock_exists_at(parent_descriptor: int) -> bool:
    """Return whether a no-follow lock name appeared during an unlocked preview."""

    try:
        metadata = os.stat(
            _RETENTION_FLOCK_NAME,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError("retention transaction lock is unsafe")
    return True


def _open_new_restricted_file_at(
    parent_descriptor: int,
    name: str,
) -> tuple[int, tuple[int, int]]:
    """Create one restricted name without replacing an existing entry."""

    try:
        descriptor = os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
    except FileExistsError as error:
        raise ConfigurationError(
            f"retained evidence destination already exists: {name}"
        ) from error
    except OSError as error:
        raise ConfigurationError(
            f"retained evidence destination is unsafe: {name}"
        ) from error
    identity: tuple[int, int] | None = None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ConfigurationError(f"retained evidence file is unsafe: {name}")
        identity = metadata.st_dev, metadata.st_ino
        os.fchmod(descriptor, 0o600)
        if _restricted_file_identity(os.fstat(descriptor), name) != identity:
            raise ConfigurationError(f"retained evidence file is unsafe: {name}")
        return descriptor, identity
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if identity is not None:
            try:
                _unlink_new_private_file_at(
                    parent_descriptor,
                    name,
                    identity,
                )
            except (OSError, ConfigurationError) as caught:
                cleanup_error = caught
        os.close(descriptor)
        if cleanup_error is not None:
            raise ConfigurationError(
                "retained evidence file initialization rollback was incomplete"
            ) from error
        raise


def _open_restricted_temp_file_at(
    parent_descriptor: int,
) -> tuple[str, int, tuple[int, int]]:
    """Create a private unpredictable staging file in the destination directory."""

    for _ in range(32):
        name = f".master-agent-retention-{secrets.token_hex(16)}.tmp"
        try:
            descriptor, identity = _open_new_restricted_file_at(
                parent_descriptor,
                name,
            )
        except ConfigurationError:
            collision_exists = True
            try:
                os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                collision_exists = False
            if not collision_exists:
                raise
            continue
        return name, descriptor, identity
    raise ConfigurationError("could not allocate a retained evidence staging file")


def _publish_restricted_temp_file_at(
    parent_descriptor: int,
    temporary_name: str,
    final_name: str,
    expected_identity: tuple[int, int],
) -> None:
    """Create a final hard link without replacement, then remove its staging name."""

    linked = False
    try:
        os.link(
            temporary_name,
            final_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        linked = True
    except FileExistsError as error:
        raise ConfigurationError(
            f"retained evidence destination already exists: {final_name}"
        ) from error
    except OSError as error:
        raise ConfigurationError(
            f"retained evidence destination is unsafe: {final_name}"
        ) from error

    try:
        temporary = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        final = os.stat(
            final_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        for metadata in (temporary, final):
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 2
                or (metadata.st_dev, metadata.st_ino) != expected_identity
            ):
                raise ConfigurationError("retained staging file identity changed")
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        _validate_restricted_file_at(
            parent_descriptor,
            final_name,
            expected_identity,
        )
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if linked:
            try:
                _unlink_owned_file_at(
                    parent_descriptor,
                    final_name,
                    expected_identity,
                    allowed_link_counts=frozenset({1, 2}),
                )
            except (OSError, ConfigurationError) as caught:
                cleanup_error = caught
        if cleanup_error is not None:
            raise ConfigurationError(
                "retained staging publication rollback was incomplete"
            ) from error
        raise


def _write_restricted_descriptor(
    descriptor: int,
    content: bytes,
) -> None:
    """Write and fsync exact retained bytes through the created descriptor."""

    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short retained evidence write")
        remaining = remaining[written:]
    os.fsync(descriptor)


def _read_restricted_descriptor(descriptor: int) -> bytes:
    """Read back all retained bytes through the created descriptor."""

    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_restricted_file_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    """Require one public name to remain the exact restricted inode."""

    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if _restricted_file_identity(current, name) != expected_identity:
        raise ConfigurationError("retained evidence file identity changed")


def _unlink_restricted_file_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    """Unlink only the exact regular inode owned by this transaction."""

    _unlink_owned_file_at(
        parent_descriptor,
        name,
        expected_identity,
        allowed_link_counts=frozenset({1}),
    )


def _unlink_new_private_file_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    """Remove a just-created owner-only file even when final chmod failed."""

    try:
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) & 0o077
        or (current.st_dev, current.st_ino) != expected_identity
    ):
        raise ConfigurationError("retained evidence file identity changed")
    os.unlink(name, dir_fd=parent_descriptor)


def _unlink_owned_file_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
    *,
    allowed_link_counts: frozenset[int],
) -> None:
    """Unlink an exact private inode with an explicitly allowed link count."""

    try:
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or stat.S_IMODE(current.st_mode) != 0o600
        or current.st_nlink not in allowed_link_counts
        or (current.st_dev, current.st_ino) != expected_identity
    ):
        raise ConfigurationError("retained evidence file identity changed")
    os.unlink(name, dir_fd=parent_descriptor)


def _restricted_file_identity(
    metadata: os.stat_result,
    name: str,
) -> tuple[int, int]:
    """Validate one private retained file and return its stable identity."""

    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ConfigurationError(f"retained evidence file is unsafe: {name}")
    return metadata.st_dev, metadata.st_ino


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
