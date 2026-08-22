"""Retention metadata and restricted evidence-file handling."""

from __future__ import annotations

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
from master_agent.platform_runtime import (
    LockMode,
    PlatformContract,
    get_cross_process_locking_backend,
    get_secure_filesystem_backend,
    require_platform_contract,
)

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
_RETENTION_PRUNE_STAGE_NAME = ".retention-prune"
_RETENTION_PRUNE_MARKER_NAME = "transaction.json"
_RETENTION_PRUNE_EVIDENCE_NAME = "evidence"
_RETENTION_PRUNE_SIDECAR_NAME = "sidecar"
_RETENTION_PRUNE_TRANSACTION_SCHEMA = "master-agent/evidence-prune-transaction@1"
_MAX_REPAIR_FILE_BYTES = 64 * 1024 * 1024
_MAX_REPAIR_DEPTH = 64
_MAX_PRUNE_TRANSACTION_ENTRIES = 4
_RETENTION_MANIFEST_KEYS = frozenset(
    {
        "evidence_path",
        "evidence_type",
        "created_at",
        "expires_at",
        "persistence",
        "content_included",
        "content_digest",
        "citation_ids",
    }
)


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


@dataclass(frozen=True, slots=True)
class _RetainedEvidencePair:
    """One fully validated evidence-and-sidecar identity."""

    evidence: _RetainedFileRecord
    sidecar: _RetainedFileRecord
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _PruneTransaction:
    """Content-free recovery binding for one staged expiration transaction."""

    evidence_parts: tuple[str, ...]
    evidence_identity: tuple[int, int]
    sidecar_parts: tuple[str, ...]
    sidecar_identity: tuple[int, int]
    expires_at: str
    selected_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the recovery binding without retained content."""

        return {
            "schema": _RETENTION_PRUNE_TRANSACTION_SCHEMA,
            "evidence_parts": list(self.evidence_parts),
            "evidence_device": self.evidence_identity[0],
            "evidence_inode": self.evidence_identity[1],
            "sidecar_parts": list(self.sidecar_parts),
            "sidecar_device": self.sidecar_identity[0],
            "sidecar_inode": self.sidecar_identity[1],
            "expires_at": self.expires_at,
            "selected_at": self.selected_at,
        }


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
        _require_retention_platform()
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
        try:
            self._sidecar = _retention_sidecar_path(self._path)
        except ConfigurationError:
            self._pinned.close()
            raise
        self._lock_descriptor = -1
        self._lock_identity: tuple[int, int] | None = None
        self._hierarchy_locks: list[int] = []
        self._files: list[tuple[str, tuple[int, int]]] = []
        self._committed = False
        self._closed = False
        try:
            self._lock_descriptor, self._lock_identity = _open_retention_lock(
                self._parent_descriptor
            )
            _acquire_file_lock(
                self._lock_descriptor,
                mode=LockMode.EXCLUSIVE,
            )
            self._hierarchy_locks = _acquire_retention_directory_hierarchy(
                self._pinned,
            )
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
        evidence_payload, normalized = _serialize_retained_json(output)
        citations = normalized.get("citations", [])
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
            digest=content_digest(normalized),
            citation_ids=citation_ids,
        )
        content_by_name = {
            self._path.name: evidence_payload,
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
                _release_file_lock(self._lock_descriptor)
            finally:
                os.close(self._lock_descriptor)
                self._lock_descriptor = -1
        _release_retention_directory_hierarchy(self._hierarchy_locks)
        self._hierarchy_locks.clear()
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

    _require_retention_platform()
    rule = _permitted_rule(
        config,
        evidence_type=evidence_type,
        include_content=include_content,
    )
    created = _aware_utc(now)
    output = dict(payload) if include_content else _metadata_only(payload)
    evidence_payload, normalized = _serialize_retained_json(output)
    citations = normalized.get("citations", [])
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
        digest=content_digest(normalized),
        citation_ids=citation_ids,
    )
    _atomic_write_files(
        {
            path: evidence_payload,
            sidecar: (
                json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8"),
        },
        parent_directory=parent_directory,
    )
    return path, sidecar


def _serialize_retained_json(
    value: Mapping[str, Any],
) -> tuple[bytes, Mapping[str, Any]]:
    """Serialize once and return the exact semantic value used for its digest."""

    try:
        payload = (
            json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n"
        ).encode("utf-8")
        normalized = _load_json_bytes(payload)
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeError) as error:
        raise ConfigurationError(
            "retained JSON evidence is not serializable"
        ) from error
    if not isinstance(normalized, Mapping):
        raise ConfigurationError("retained JSON evidence must be an object")
    return payload, normalized


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

    _require_retention_platform()
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
    """Preview or apply bounded descriptor-safe expiration cleanup."""

    _require_retention_platform()
    if os.name == "nt":
        raise ConfigurationError(
            "evidence pruning is unavailable on Windows until native filesystem "
            "identity and atomic-state guarantees are enabled"
        )
    return _purge_expired_evidence_locked(
        root,
        now=now,
        dry_run=dry_run,
        max_manifests=max_manifests,
    )


def _purge_expired_evidence_locked(
    root: Path,
    *,
    now: datetime | None = None,
    dry_run: bool = True,
    max_manifests: int = 10_000,
) -> RetentionPurgeResult:
    """Plan and remove expired pairs beneath one pinned, locked root."""

    if max_manifests <= 0:
        raise ValueError("max_manifests must be positive")
    current = _aware_utc(now)
    with PinnedDirectory.open(root) as pinned:
        root_descriptor = pinned.fileno()
        existing_lock_missing = False
        lock_descriptor = -1
        lock_identity: tuple[int, int] | None = None
        lock_acquired = False
        hierarchy_locks: list[int] = []
        descendant_locks: list[tuple[tuple[str, ...], int, tuple[int, int]]] = []
        try:
            if dry_run:
                try:
                    existing_lock = _open_existing_retention_lock(root_descriptor)
                except ConfigurationError:
                    return RetentionPurgeResult(
                        scanned_manifests=0,
                        expired_manifests=0,
                        removed_files=(),
                        errors=("retention transaction lock is unsafe",),
                        dry_run=True,
                    )
                if existing_lock is None:
                    existing_lock_missing = True
                else:
                    lock_descriptor, lock_identity = existing_lock
            else:
                lock_descriptor, lock_identity = _open_retention_lock(root_descriptor)
            if lock_descriptor >= 0:
                try:
                    _acquire_file_lock(
                        lock_descriptor,
                        mode=LockMode.EXCLUSIVE,
                        blocking=False,
                    )
                    lock_acquired = True
                except BlockingIOError as error:
                    if not dry_run:
                        raise ConfigurationError(
                            "evidence prune refused while retention maintenance "
                            "is active"
                        ) from error
                    return RetentionPurgeResult(
                        scanned_manifests=0,
                        expired_manifests=0,
                        removed_files=(),
                        errors=("retention maintenance is active; scan deferred",),
                        dry_run=True,
                    )
                assert lock_identity is not None
                _validate_restricted_file_at(
                    root_descriptor,
                    _RETENTION_FLOCK_NAME,
                    lock_identity,
                )
            try:
                hierarchy_locks = _acquire_retention_directory_hierarchy(pinned)
            except ConfigurationError:
                if not dry_run:
                    raise
                return RetentionPurgeResult(
                    scanned_manifests=0,
                    expired_manifests=0,
                    removed_files=(),
                    errors=("retention directory hierarchy is active; scan deferred",),
                    dry_run=True,
                )
            pinned.validate()
            recovered: list[tuple[str, str]] = []
            if dry_run:
                recovery_errors = _inspect_prune_transactions_at(
                    root_descriptor,
                    max_transactions=max_manifests,
                )
            else:
                recovery_errors = []
            lock_parents: set[tuple[str, ...]] = set()
            records, scan_errors = _scan_retained_files_at(
                root_descriptor,
                max_files=max_manifests * 2,
                lock_parents=lock_parents,
                strict_unsupported=False,
            )
            lock_parents.update(
                record.relative_parts[:-1]
                for record in records
                if record.name.endswith(".retention.json")
                and record.relative_parts[:-1]
            )
            pending_lock_parents, pending_parent_errors = (
                _discover_prune_transaction_parents_at(
                    root_descriptor,
                    max_transactions=max_manifests,
                    normalize_restricted=not dry_run,
                )
            )
            lock_parents.update(pending_lock_parents)
            recovery_errors.extend(pending_parent_errors)
            (
                descendant_locks,
                missing_descendant_locks,
                descendant_lock_errors,
            ) = _acquire_descendant_retention_locks_at(
                root_descriptor,
                lock_parents,
                dry_run=dry_run,
            )
            if (
                not dry_run
                and not recovery_errors
                and not scan_errors
                and not descendant_lock_errors
            ):
                recovered, recovered_errors = _recover_prune_transactions_at(
                    root_descriptor,
                    pinned.path,
                    current=current,
                    max_transactions=max_manifests,
                )
                recovery_errors.extend(recovered_errors)
            baseline_lock_parents: set[tuple[str, ...]] = set()
            baseline_records, baseline_errors = _scan_retained_files_at(
                root_descriptor,
                max_files=max_manifests * 2,
                lock_parents=baseline_lock_parents,
                strict_unsupported=False,
            )
            baseline_lock_parents.update(
                record.relative_parts[:-1]
                for record in baseline_records
                if record.name.endswith(".retention.json")
                and record.relative_parts[:-1]
            )
            recovered_parts = {
                tuple(Path(path).relative_to(pinned.path).parts)
                for pair in recovered
                for path in pair
            }
            expected_records = [
                record
                for record in records
                if record.relative_parts not in recovered_parts
            ]
            stability_errors: list[str] = []
            if lock_parents != baseline_lock_parents:
                stability_errors.append(
                    "retention lock topology changed while locks were acquired"
                )
            if expected_records != baseline_records or scan_errors != baseline_errors:
                stability_errors.append(
                    "retained evidence tree changed while locks were acquired"
                )
            rescanned_lock_parents: set[tuple[str, ...]] = set()
            rescanned_records, rescan_errors = _scan_retained_files_at(
                root_descriptor,
                max_files=max_manifests * 2,
                lock_parents=rescanned_lock_parents,
                strict_unsupported=False,
            )
            rescanned_lock_parents.update(
                record.relative_parts[:-1]
                for record in rescanned_records
                if record.name.endswith(".retention.json")
                and record.relative_parts[:-1]
            )
            if (
                baseline_records != rescanned_records
                or baseline_errors != rescan_errors
                or baseline_lock_parents != rescanned_lock_parents
            ):
                stability_errors.append(
                    "retained evidence tree changed during the validating rescan"
                )
            records = rescanned_records
            for relative_parts in missing_descendant_locks:
                parent_descriptor = _open_relative_directory_at(
                    root_descriptor,
                    relative_parts,
                )
                try:
                    if _retention_lock_exists_at(parent_descriptor):
                        rescan_errors.append(
                            f"{'/'.join(relative_parts)}: retention publication "
                            "began during the preview"
                        )
                finally:
                    os.close(parent_descriptor)
            _validate_descendant_retention_locks_at(
                root_descriptor,
                descendant_locks,
            )
            pairs, validation_errors, scanned_manifests = _plan_retained_pairs_at(
                root_descriptor,
                records,
                max_manifests=max_manifests,
            )
            errors = [
                *recovery_errors,
                *rescan_errors,
                *stability_errors,
                *descendant_lock_errors,
                *validation_errors,
            ]
            if existing_lock_missing and _retention_lock_exists_at(root_descriptor):
                errors.append(
                    "retention publication began during the preview; rescan required"
                )
            expired_pairs = [pair for pair in pairs if pair.expires_at <= current]
            removed = [path for pair in recovered for path in pair]
            if not errors:
                if dry_run:
                    removed.extend(
                        path
                        for pair in expired_pairs
                        for path in _pair_display_paths(pinned.path, pair)
                    )
                else:
                    for pair in expired_pairs:
                        try:
                            _delete_retained_pair_at(
                                root_descriptor,
                                pair,
                                current=current,
                            )
                        except (OSError, ConfigurationError) as error:
                            display = "/".join(pair.sidecar.relative_parts)
                            errors.append(
                                f"{display}: deletion failed: {type(error).__name__}"
                            )
                            break
                        removed.extend(_pair_display_paths(pinned.path, pair))
            pinned.validate()
            return RetentionPurgeResult(
                scanned_manifests=scanned_manifests + len(recovered),
                expired_manifests=len(expired_pairs) + len(recovered),
                removed_files=tuple(removed),
                errors=tuple(errors),
                dry_run=dry_run,
            )
        finally:
            try:
                for _, descriptor, _ in reversed(descendant_locks):
                    try:
                        _release_file_lock(descriptor)
                    finally:
                        os.close(descriptor)
            finally:
                try:
                    if lock_acquired:
                        _release_file_lock(lock_descriptor)
                finally:
                    try:
                        if lock_descriptor >= 0:
                            os.close(lock_descriptor)
                    finally:
                        _release_retention_directory_hierarchy(hierarchy_locks)


def repair_orphaned_evidence(
    root: Path,
    *,
    dry_run: bool = True,
    max_files: int = 10_000,
) -> RetentionRepairResult:
    """Detect or recoverably quarantine orphaned retained evidence."""

    _require_retention_platform()
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
        lock_descriptor = -1
        lock_identity: tuple[int, int] | None = None
        lock_acquired = False
        hierarchy_locks: list[int] = []
        descendant_locks: list[tuple[tuple[str, ...], int, tuple[int, int]]] = []
        try:
            if dry_run:
                try:
                    existing_lock = _open_existing_retention_lock(root_descriptor)
                except ConfigurationError:
                    return RetentionRepairResult(
                        scanned_files=0,
                        orphaned_files=(),
                        quarantined_files=(),
                        errors=("retention transaction lock is unsafe",),
                        dry_run=True,
                    )
                if existing_lock is None:
                    existing_lock_missing = True
                else:
                    lock_descriptor, lock_identity = existing_lock
            else:
                lock_descriptor, lock_identity = _open_retention_lock(root_descriptor)
            if lock_descriptor >= 0:
                try:
                    _acquire_file_lock(
                        lock_descriptor,
                        mode=LockMode.EXCLUSIVE,
                        blocking=False,
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
            try:
                hierarchy_locks = _acquire_retention_directory_hierarchy(pinned)
            except ConfigurationError:
                if not dry_run:
                    raise
                return RetentionRepairResult(
                    scanned_files=0,
                    orphaned_files=(),
                    quarantined_files=(),
                    errors=("retention directory hierarchy is active; scan deferred",),
                    dry_run=True,
                )
            pinned.validate()
            lock_parents: set[tuple[str, ...]] = set()
            records, scan_errors = _scan_retained_files_at(
                root_descriptor,
                max_files=max_files,
                lock_parents=lock_parents,
            )
            lock_parents.update(
                record.relative_parts[:-1]
                for record in records
                if record.relative_parts[:-1]
            )
            (
                descendant_locks,
                missing_descendant_locks,
                descendant_lock_errors,
            ) = _acquire_descendant_retention_locks_at(
                root_descriptor,
                lock_parents,
                dry_run=dry_run,
            )
            rescanned_lock_parents: set[tuple[str, ...]] = set()
            rescanned_records, rescan_errors = _scan_retained_files_at(
                root_descriptor,
                max_files=max_files,
                lock_parents=rescanned_lock_parents,
            )
            rescanned_lock_parents.update(
                record.relative_parts[:-1]
                for record in rescanned_records
                if record.relative_parts[:-1]
            )
            stability_errors: list[str] = []
            if lock_parents != rescanned_lock_parents:
                stability_errors.append(
                    "retention lock topology changed while locks were acquired"
                )
            if records != rescanned_records or scan_errors != rescan_errors:
                stability_errors.append(
                    "retained evidence tree changed while locks were acquired"
                )
            records = rescanned_records
            for relative_parts in missing_descendant_locks:
                parent_descriptor = _open_relative_directory_at(
                    root_descriptor,
                    relative_parts,
                )
                try:
                    if _retention_lock_exists_at(parent_descriptor):
                        rescan_errors.append(
                            f"{'/'.join(relative_parts)}: retention publication "
                            "began during the preview"
                        )
                finally:
                    os.close(parent_descriptor)
            _validate_descendant_retention_locks_at(
                root_descriptor,
                descendant_locks,
            )
            orphans, classification_errors = _classify_orphaned_records_at(
                root_descriptor,
                records,
            )
            blocking_errors = [
                *rescan_errors,
                *stability_errors,
                *descendant_lock_errors,
            ]
            errors = [
                *blocking_errors,
                *classification_errors,
            ]
            if existing_lock_missing and _retention_lock_exists_at(root_descriptor):
                errors.append(
                    "retention publication began during the preview; rescan required"
                )
            quarantined: list[str] = []
            if not dry_run and blocking_errors:
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
                for _, descriptor, _ in reversed(descendant_locks):
                    try:
                        _release_file_lock(descriptor)
                    finally:
                        os.close(descriptor)
            finally:
                try:
                    if lock_acquired:
                        _release_file_lock(lock_descriptor)
                finally:
                    try:
                        if lock_descriptor >= 0:
                            os.close(lock_descriptor)
                    finally:
                        _release_retention_directory_hierarchy(hierarchy_locks)


def _scan_retained_files_at(
    root_descriptor: int,
    *,
    max_files: int,
    lock_parents: set[tuple[str, ...]] | None = None,
    strict_unsupported: bool = True,
) -> tuple[list[_RetainedFileRecord], list[str]]:
    """Recursively enumerate files without following a pathname or symlink."""

    records: list[_RetainedFileRecord] = []
    errors: list[str] = []
    truncated = False
    visited_entries = 0

    def visit(directory_descriptor: int, prefix: tuple[str, ...]) -> None:
        nonlocal truncated, visited_entries
        if len(prefix) > _MAX_REPAIR_DEPTH:
            truncated = True
            return
        try:
            names: list[str] = []
            remaining = max_files - visited_entries
            with os.scandir(directory_descriptor) as entries:
                for entry in entries:
                    if entry.name == _RETENTION_FLOCK_NAME:
                        if prefix and lock_parents is not None:
                            lock_parents.add(prefix)
                        continue
                    if not prefix and entry.name == _RETENTION_PRUNE_STAGE_NAME:
                        continue
                    if entry.name == _RETENTION_QUARANTINE_NAME:
                        continue
                    if len(names) >= remaining:
                        truncated = True
                        return
                    names.append(entry.name)
            names.sort()
        except OSError as error:
            errors.append(
                f"{'/'.join(prefix) or '.'}: scan failed: {type(error).__name__}"
            )
            return
        for name in names:
            if visited_entries >= max_files:
                truncated = True
                return
            visited_entries += 1
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
            if prefix and name == _RETENTION_PRUNE_STAGE_NAME:
                stage_descriptor = -1
                try:
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ConfigurationError(
                            "nested prune state is not a directory"
                        )
                    opened = _open_existing_private_directory_at(
                        directory_descriptor,
                        name,
                    )
                    if opened is None:
                        raise ConfigurationError("nested prune state disappeared")
                    stage_descriptor = opened
                    current = os.fstat(stage_descriptor)
                    if (current.st_dev, current.st_ino) != (
                        metadata.st_dev,
                        metadata.st_ino,
                    ):
                        raise ConfigurationError("nested prune state identity changed")
                    pending = _bounded_sorted_names_at(
                        stage_descriptor,
                        max_entries=max_files,
                        label="nested prune state",
                    )
                    if pending:
                        errors.append(
                            f"{'/'.join(relative)}: nested prune state requires "
                            "recovery at its exact root"
                        )
                except (OSError, ConfigurationError) as error:
                    errors.append(
                        f"{'/'.join(relative)}: scan failed: {type(error).__name__}"
                    )
                finally:
                    if stage_descriptor >= 0:
                        os.close(stage_descriptor)
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
                        or current.st_uid
                        != get_secure_filesystem_backend().real_user_id()
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
                continue
            if strict_unsupported or name.endswith(".retention.json"):
                errors.append(f"{'/'.join(relative)}: unsupported retained file type")

    visit(root_descriptor, ())
    if truncated:
        errors.append(f"descriptor scan exceeded the {max_files}-entry limit")
    return records, errors


def _plan_retained_pairs_at(
    root_descriptor: int,
    records: list[_RetainedFileRecord],
    *,
    max_manifests: int,
) -> tuple[list[_RetainedEvidencePair], list[str], int]:
    """Validate every discovered record and return canonical retained pairs."""

    root_device = os.fstat(root_descriptor).st_dev
    by_relative: dict[tuple[str, ...], _RetainedFileRecord] = {}
    errors: list[str] = []
    for record in records:
        if record.relative_parts in by_relative:
            errors.append(
                f"{'/'.join(record.relative_parts)}: duplicate descriptor record"
            )
            continue
        by_relative[record.relative_parts] = record
    sidecars = sorted(
        (record for record in records if record.name.endswith(".retention.json")),
        key=lambda record: record.relative_parts,
    )
    if len(sidecars) > max_manifests:
        errors.append(f"retention scan exceeded the {max_manifests}-manifest limit")
    paired_evidence: set[tuple[str, ...]] = set()
    pairs: list[_RetainedEvidencePair] = []
    for sidecar in sidecars[:max_manifests]:
        display = "/".join(sidecar.relative_parts)
        try:
            if sidecar.identity[0] != root_device:
                raise OSError("retention sidecar cannot use the root transaction")
            raw_bytes = _read_record_bytes_at(root_descriptor, sidecar)
            raw = _load_json_bytes(raw_bytes)
            if not isinstance(raw, Mapping):
                raise StructuredDataTypeError("retention sidecar must be a JSON object")
            evidence_name, expires_at = _validate_retention_manifest(
                raw,
                sidecar_name=sidecar.name,
            )
            evidence_relative = (*sidecar.relative_parts[:-1], evidence_name)
            evidence = by_relative.get(evidence_relative)
            if evidence is None:
                raise ValueError("retention evidence file is missing")
            if evidence.identity[0] != root_device:
                raise OSError("retention evidence cannot use the root transaction")
            if evidence_relative in paired_evidence:
                raise ValueError("retention evidence has conflicting sidecars")
            _verify_retained_record_at(root_descriptor, evidence, raw)
            paired_evidence.add(evidence_relative)
            pairs.append(
                _RetainedEvidencePair(
                    evidence=evidence,
                    sidecar=sidecar,
                    expires_at=expires_at,
                )
            )
        except (
            OSError,
            StructuredDataTypeError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as error:
            errors.append(f"{display}: invalid retained pair: {type(error).__name__}")

    return pairs, errors, len(sidecars)


def _load_json_bytes(raw: bytes) -> Any:
    """Decode bounded JSON while rejecting duplicate object member names."""

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds the retention limit") from error


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object only when every member name is unique."""

    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON object member")
        output[key] = value
    return output


def _validate_retention_manifest(
    raw: Mapping[str, Any],
    *,
    sidecar_name: str,
) -> tuple[str, datetime]:
    """Validate the exact persisted manifest schema and sibling binding."""

    if set(raw) != _RETENTION_MANIFEST_KEYS:
        raise ValueError("retention sidecar fields are invalid")
    evidence_name = raw["evidence_path"]
    if (
        not isinstance(evidence_name, str)
        or not evidence_name
        or evidence_name in {".", ".."}
        or Path(evidence_name).name != evidence_name
        or _is_reserved_retained_evidence_name(evidence_name)
        or sidecar_name != f"{evidence_name}.retention.json"
    ):
        raise ValueError("retention evidence sibling relationship is invalid")
    evidence_type = raw["evidence_type"]
    if not isinstance(evidence_type, str) or not evidence_type.strip():
        raise ValueError("retention evidence_type is invalid")
    created_at = _validated_manifest_timestamp(raw["created_at"])
    expires_at = _validated_manifest_timestamp(raw["expires_at"])
    if expires_at <= created_at:
        raise ValueError("retention expiration must follow creation")
    persistence_raw = raw["persistence"]
    if not isinstance(persistence_raw, str):
        raise TypeError("retention persistence is invalid")
    persistence = PersistenceMode(persistence_raw)
    if persistence is PersistenceMode.PROHIBITED:
        raise ValueError("prohibited evidence must not be persisted")
    content_included = raw["content_included"]
    if type(content_included) is not bool:
        raise ValueError("retention content_included is invalid")
    if content_included and persistence is not PersistenceMode.EXPLICIT_CONTENT:
        raise ValueError("retained content is inconsistent with persistence")
    digest = raw["content_digest"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("retention content digest is invalid")
    citation_ids = raw["citation_ids"]
    if (
        not isinstance(citation_ids, list)
        or any(not isinstance(value, str) or not value for value in citation_ids)
        or len(set(citation_ids)) != len(citation_ids)
    ):
        raise ValueError("retention citation_ids are invalid")
    return evidence_name, expires_at


def _validated_manifest_timestamp(value: Any) -> datetime:
    """Return one canonical aware manifest timestamp in UTC."""

    if not isinstance(value, str):
        raise TypeError("retention timestamp is invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("retention timestamp must be timezone-aware")
    if parsed.isoformat() != value:
        raise ValueError("retention timestamp is not canonical")
    return parsed.astimezone(UTC)


def _pair_display_paths(
    root: Path,
    pair: _RetainedEvidencePair,
) -> tuple[str, str]:
    """Return deterministic content-free source paths for one pair."""

    return (
        str(root.joinpath(*pair.evidence.relative_parts)),
        str(root.joinpath(*pair.sidecar.relative_parts)),
    )


def _acquire_retention_directory_hierarchy(
    pinned: PinnedDirectory,
) -> list[int]:
    """Share-lock existing ancestor retention boundaries for coordination."""

    directory_descriptors = list(pinned.duplicate_descriptor_chain())
    acquired_locks: list[int] = []
    try:
        for directory_descriptor in directory_descriptors[:-1]:
            directory = os.fstat(directory_descriptor)
            if (
                directory.st_uid != get_secure_filesystem_backend().real_user_id()
                or stat.S_IMODE(directory.st_mode) & 0o022
            ):
                continue
            opened = _open_existing_retention_lock(directory_descriptor)
            if opened is None:
                continue
            lock_descriptor, identity = opened
            try:
                _acquire_file_lock(
                    lock_descriptor,
                    mode=LockMode.SHARED,
                    blocking=False,
                )
            except BlockingIOError as error:
                os.close(lock_descriptor)
                raise ConfigurationError(
                    "retention directory hierarchy is active"
                ) from error
            except BaseException:
                os.close(lock_descriptor)
                raise
            try:
                _validate_restricted_file_at(
                    directory_descriptor,
                    _RETENTION_FLOCK_NAME,
                    identity,
                )
            except BaseException:
                try:
                    _release_file_lock(lock_descriptor)
                finally:
                    os.close(lock_descriptor)
                raise
            acquired_locks.append(lock_descriptor)
        pinned.validate()
        return acquired_locks
    except BaseException:
        for descriptor in reversed(acquired_locks):
            try:
                _release_file_lock(descriptor)
            finally:
                os.close(descriptor)
        raise
    finally:
        for descriptor in directory_descriptors:
            os.close(descriptor)


def _release_retention_directory_hierarchy(descriptors: list[int]) -> None:
    """Release caller-owned hierarchy locks in reverse order."""

    for descriptor in reversed(descriptors):
        try:
            _release_file_lock(descriptor)
        finally:
            os.close(descriptor)


def _acquire_descendant_retention_locks_at(
    root_descriptor: int,
    relative_parents: set[tuple[str, ...]],
    *,
    dry_run: bool,
) -> tuple[
    list[tuple[tuple[str, ...], int, tuple[int, int]]],
    list[tuple[str, ...]],
    list[str],
]:
    """Hold every relevant descendant lock before a validating rescan."""
    acquired: list[tuple[tuple[str, ...], int, tuple[int, int]]] = []
    missing: list[tuple[str, ...]] = []
    errors: list[str] = []
    try:
        for relative_parts in sorted(relative_parents):
            parent_descriptor = _open_relative_directory_at(
                root_descriptor,
                relative_parts,
            )
            try:
                try:
                    if dry_run:
                        opened = _open_existing_retention_lock(parent_descriptor)
                        if opened is None:
                            missing.append(relative_parts)
                            continue
                        descriptor, identity = opened
                    else:
                        descriptor, identity = _open_retention_lock(parent_descriptor)
                except ConfigurationError:
                    if not dry_run:
                        raise
                    errors.append(
                        f"{'/'.join(relative_parts)}: retention lock is unsafe"
                    )
                    continue
                try:
                    _acquire_file_lock(
                        descriptor,
                        mode=LockMode.EXCLUSIVE,
                        blocking=False,
                    )
                except BlockingIOError as error:
                    os.close(descriptor)
                    if not dry_run:
                        raise ConfigurationError(
                            "retention operation refused while descendant "
                            "retention maintenance is active"
                        ) from error
                    errors.append(
                        f"{'/'.join(relative_parts)}: retention maintenance is active"
                    )
                    continue
                except BaseException:
                    os.close(descriptor)
                    raise
                try:
                    _validate_restricted_file_at(
                        parent_descriptor,
                        _RETENTION_FLOCK_NAME,
                        identity,
                    )
                except BaseException:
                    try:
                        _release_file_lock(descriptor)
                    finally:
                        os.close(descriptor)
                    raise
                acquired.append((relative_parts, descriptor, identity))
            finally:
                os.close(parent_descriptor)
        return acquired, missing, errors
    except BaseException:
        for _, descriptor, _ in reversed(acquired):
            try:
                _release_file_lock(descriptor)
            finally:
                os.close(descriptor)
        raise


def _validate_descendant_retention_locks_at(
    root_descriptor: int,
    locks: list[tuple[tuple[str, ...], int, tuple[int, int]]],
) -> None:
    """Revalidate held descendant lock names against their exact identities."""

    for relative_parts, descriptor, identity in locks:
        parent_descriptor = _open_relative_directory_at(
            root_descriptor,
            relative_parts,
        )
        try:
            _restricted_file_identity(
                os.fstat(descriptor),
                _RETENTION_FLOCK_NAME,
            )
            _validate_restricted_file_at(
                parent_descriptor,
                _RETENTION_FLOCK_NAME,
                identity,
            )
        finally:
            os.close(parent_descriptor)


def _delete_retained_pair_at(
    root_descriptor: int,
    pair: _RetainedEvidencePair,
    *,
    current: datetime,
) -> None:
    """Delete one exact pair through a recoverable descriptor-bound stage."""

    if pair.expires_at > current:
        raise ConfigurationError("retained pair is not expired")
    try:
        _revalidate_retained_pair_at(root_descriptor, pair)
    except (
        OSError,
        StructuredDataTypeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as error:
        raise ConfigurationError("retained pair changed after planning") from error
    stage_descriptor = _open_or_create_private_directory_at(
        root_descriptor,
        _RETENTION_PRUNE_STAGE_NAME,
    )
    transaction_name = ""
    transaction_descriptor = -1
    transaction_identity: tuple[int, int] | None = None
    try:
        (
            transaction_name,
            transaction_descriptor,
            transaction_identity,
        ) = _create_private_transaction_directory_at(stage_descriptor)
        transaction = _PruneTransaction(
            evidence_parts=pair.evidence.relative_parts,
            evidence_identity=pair.evidence.identity,
            sidecar_parts=pair.sidecar.relative_parts,
            sidecar_identity=pair.sidecar.identity,
            expires_at=pair.expires_at.isoformat(),
            selected_at=current.isoformat(),
        )
        marker_payload = (
            json.dumps(
                transaction.to_dict(),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        _write_prune_transaction_marker_at(
            transaction_descriptor,
            marker_payload,
        )
        _link_prune_stage_file_at(
            root_descriptor,
            pair.evidence,
            transaction_descriptor,
            _RETENTION_PRUNE_EVIDENCE_NAME,
        )
        _link_prune_stage_file_at(
            root_descriptor,
            pair.sidecar,
            transaction_descriptor,
            _RETENTION_PRUNE_SIDECAR_NAME,
        )
        os.fsync(transaction_descriptor)
        _revalidate_staged_pair_at(
            transaction_descriptor,
            pair,
            allowed_link_counts=frozenset({2}),
        )
        _unlink_relative_record_at(
            root_descriptor,
            pair.sidecar,
            allowed_link_counts=frozenset({2}),
        )
        _unlink_relative_record_at(
            root_descriptor,
            pair.evidence,
            allowed_link_counts=frozenset({2}),
        )
        _fsync_absent_transaction_sources_at(root_descriptor, transaction)
        _unlink_stage_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_EVIDENCE_NAME,
            pair.evidence.identity,
        )
        _unlink_stage_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_SIDECAR_NAME,
            pair.sidecar.identity,
        )
        marker = _stat_immediate_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_MARKER_NAME,
        )
        if marker is None:
            raise ConfigurationError("prune transaction marker disappeared")
        _unlink_stage_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_MARKER_NAME,
            marker.identity,
        )
        os.fsync(transaction_descriptor)
        assert transaction_identity is not None
        _remove_private_transaction_directory_at(
            stage_descriptor,
            transaction_name,
            transaction_identity,
        )
    except BaseException as error:
        if transaction_descriptor >= 0:
            os.close(transaction_descriptor)
            transaction_descriptor = -1
        if transaction_name:
            try:
                recovered = _recover_prune_transaction_at(
                    root_descriptor,
                    stage_descriptor,
                    transaction_name,
                )
            except (
                OSError,
                ConfigurationError,
                StructuredDataTypeError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as recovery_error:
                if not isinstance(error, Exception):
                    raise error
                raise ConfigurationError(
                    "expired evidence transaction recovery failed"
                ) from recovery_error
            if recovered is not None:
                if not isinstance(error, Exception):
                    raise
                return
        if isinstance(error, (OSError, ConfigurationError)):
            raise
        if not isinstance(error, Exception):
            raise
        raise ConfigurationError("expired evidence deletion failed") from error
    finally:
        if transaction_descriptor >= 0:
            os.close(transaction_descriptor)
        os.close(stage_descriptor)


def _revalidate_retained_pair_at(
    root_descriptor: int,
    pair: _RetainedEvidencePair,
) -> None:
    """Re-read one planned pair immediately before destructive staging."""

    raw_bytes = _read_record_bytes_at(root_descriptor, pair.sidecar)
    raw = _load_json_bytes(raw_bytes)
    if not isinstance(raw, Mapping):
        raise StructuredDataTypeError("retention sidecar must be a JSON object")
    evidence_name, expires_at = _validate_retention_manifest(
        raw,
        sidecar_name=pair.sidecar.name,
    )
    if (
        *pair.sidecar.relative_parts[:-1],
        evidence_name,
    ) != pair.evidence.relative_parts or expires_at != pair.expires_at:
        raise ConfigurationError("retained pair changed after planning")
    _verify_retained_record_at(root_descriptor, pair.evidence, raw)


def _link_prune_stage_file_at(
    root_descriptor: int,
    record: _RetainedFileRecord,
    transaction_descriptor: int,
    stage_name: str,
) -> None:
    """Create-only hard-link one exact source inode into a private stage."""

    source_parent = _open_relative_directory_at(
        root_descriptor,
        record.relative_parts[:-1],
    )
    linked = False
    try:
        source = os.stat(
            record.name,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        if _restricted_file_identity(source, record.name) != record.identity:
            raise ConfigurationError("retained evidence file identity changed")
        _require_retained_names_absent(transaction_descriptor, (stage_name,))
        os.link(
            record.name,
            stage_name,
            src_dir_fd=source_parent,
            dst_dir_fd=transaction_descriptor,
            follow_symlinks=False,
        )
        linked = True
        staged = os.stat(
            stage_name,
            dir_fd=transaction_descriptor,
            follow_symlinks=False,
        )
        current = os.stat(
            record.name,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        for metadata in (staged, current):
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 2
                or (metadata.st_dev, metadata.st_ino) != record.identity
            ):
                raise ConfigurationError("prune staging identity changed")
    except BaseException:
        if linked:
            try:
                _unlink_owned_file_at(
                    transaction_descriptor,
                    stage_name,
                    record.identity,
                    allowed_link_counts=frozenset({2}),
                )
                os.fsync(transaction_descriptor)
            except (OSError, ConfigurationError):
                pass
        raise
    finally:
        os.close(source_parent)


def _revalidate_staged_pair_at(
    transaction_descriptor: int,
    pair: _RetainedEvidencePair,
    *,
    allowed_link_counts: frozenset[int],
) -> None:
    """Require staged inodes and bytes to remain the validated planned pair."""

    evidence = _stage_record(
        pair.evidence,
        name=_RETENTION_PRUNE_EVIDENCE_NAME,
    )
    sidecar = _stage_record(
        pair.sidecar,
        name=_RETENTION_PRUNE_SIDECAR_NAME,
    )
    raw_bytes = _read_record_bytes_at(
        transaction_descriptor,
        sidecar,
        allowed_link_counts=allowed_link_counts,
    )
    raw = _load_json_bytes(raw_bytes)
    if not isinstance(raw, Mapping):
        raise StructuredDataTypeError("retention sidecar must be a JSON object")
    evidence_name, expires_at = _validate_retention_manifest(
        raw,
        sidecar_name=pair.sidecar.name,
    )
    if evidence_name != pair.evidence.name or expires_at != pair.expires_at:
        raise ConfigurationError("staged retained pair changed")
    _verify_retained_record_at(
        transaction_descriptor,
        evidence,
        raw,
        allowed_link_counts=allowed_link_counts,
    )


def _stage_record(
    source: _RetainedFileRecord,
    *,
    name: str,
) -> _RetainedFileRecord:
    """Describe a staged hard link using its source identity and bounded size."""

    return _RetainedFileRecord(
        relative_parts=(name,),
        identity=source.identity,
        mode=source.mode,
        size=source.size,
    )


def _unlink_relative_record_at(
    root_descriptor: int,
    record: _RetainedFileRecord,
    *,
    allowed_link_counts: frozenset[int],
) -> None:
    """Unlink one exact root-relative regular file and sync its parent."""

    parent_descriptor = _open_relative_directory_at(
        root_descriptor,
        record.relative_parts[:-1],
    )
    try:
        _unlink_owned_file_at(
            parent_descriptor,
            record.name,
            record.identity,
            allowed_link_counts=allowed_link_counts,
        )
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _fsync_absent_transaction_sources_at(
    root_descriptor: int,
    transaction: _PruneTransaction,
) -> None:
    """Persist both absent public names before discarding recovery links."""

    if transaction.evidence_parts[:-1] != transaction.sidecar_parts[:-1]:
        raise ConfigurationError("prune transaction source parents differ")
    parent_descriptor = _open_relative_directory_at(
        root_descriptor,
        transaction.evidence_parts[:-1],
    )
    try:
        source_names = (
            transaction.evidence_parts[-1],
            transaction.sidecar_parts[-1],
        )
        for name in source_names:
            try:
                os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ConfigurationError(
                "prune transaction source reappeared before durable commit"
            )
        os.fsync(parent_descriptor)
        for name in source_names:
            try:
                os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ConfigurationError(
                "prune transaction source reappeared during durable commit"
            )
    finally:
        os.close(parent_descriptor)


def _unlink_stage_record_at(
    transaction_descriptor: int,
    name: str,
    identity: tuple[int, int],
) -> None:
    """Unlink one final single-link transaction-stage inode."""

    _unlink_owned_file_at(
        transaction_descriptor,
        name,
        identity,
        allowed_link_counts=frozenset({1}),
    )
    os.fsync(transaction_descriptor)


def _create_private_transaction_directory_at(
    stage_descriptor: int,
) -> tuple[str, int, tuple[int, int]]:
    """Create and open one unpredictable owner-private transaction directory."""

    for _ in range(32):
        name = f"txn-{secrets.token_hex(16)}"
        try:
            descriptor, identity = _create_private_directory_at(
                stage_descriptor,
                name,
            )
        except FileExistsError:
            continue
        return name, descriptor, identity
    raise ConfigurationError("could not allocate a prune transaction directory")


def _write_prune_transaction_marker_at(
    transaction_descriptor: int,
    payload: bytes,
) -> None:
    """Publish one complete marker directly inside its private transaction."""

    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        descriptor, identity = _open_new_restricted_file_at(
            transaction_descriptor,
            _RETENTION_PRUNE_MARKER_NAME,
        )
        _write_restricted_descriptor(descriptor, payload)
        _validate_restricted_file_at(
            transaction_descriptor,
            _RETENTION_PRUNE_MARKER_NAME,
            identity,
        )
        if _read_restricted_descriptor(descriptor) != payload:
            raise ConfigurationError("prune transaction marker readback failed")
        os.fsync(transaction_descriptor)
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if identity is not None:
            try:
                _unlink_new_private_file_at(
                    transaction_descriptor,
                    _RETENTION_PRUNE_MARKER_NAME,
                    identity,
                )
                os.fsync(transaction_descriptor)
            except (OSError, ConfigurationError) as caught:
                cleanup_error = caught
        if cleanup_error is not None:
            raise ConfigurationError(
                "prune transaction marker rollback was incomplete"
            ) from error
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _normalize_prune_transaction_marker_at(
    transaction_descriptor: int,
) -> None:
    """Apply-only recovery for a marker left stricter than mode ``0600``."""

    opened = _open_existing_restricted_file_at(
        transaction_descriptor,
        _RETENTION_PRUNE_MARKER_NAME,
        normalize_restricted=True,
    )
    if opened is None:
        raise ConfigurationError("prune transaction marker disappeared")
    descriptor, _ = opened
    os.close(descriptor)


def _open_existing_private_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    normalize_restricted: bool = False,
) -> int | None:
    """Open one existing owner-private no-follow child directory.

    Apply-only recovery may normalize an owner-owned directory whose permission
    bits are a strict subset of ``0700``. This repairs the bounded crash window
    between ``mkdir`` and ``chmod`` without making preview mutate state or
    accepting a directory that was ever accessible to another account.
    """

    if name in {"", ".", ".."} or Path(name).name != name:
        raise ConfigurationError("unsafe private directory component")
    expected_identity: tuple[int, int] | None = None
    if normalize_restricted:
        try:
            initial = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        initial_mode = stat.S_IMODE(initial.st_mode)
        if (
            not stat.S_ISDIR(initial.st_mode)
            or initial.st_uid != get_secure_filesystem_backend().real_user_id()
            or initial_mode & ~0o700
        ):
            raise ConfigurationError("private transaction directory is unsafe")
        expected_identity = initial.st_dev, initial.st_ino
        if initial_mode != 0o700:
            os.chmod(
                name,
                0o700,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            os.fsync(parent_descriptor)
            normalized = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(normalized.st_mode)
                or normalized.st_uid != get_secure_filesystem_backend().real_user_id()
                or stat.S_IMODE(normalized.st_mode) != 0o700
                or (normalized.st_dev, normalized.st_ino) != expected_identity
            ):
                raise ConfigurationError(
                    "private transaction directory identity changed"
                )
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        return None
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (
            expected_identity is not None
            and (metadata.st_dev, metadata.st_ino) != expected_identity
        )
    ):
        os.close(descriptor)
        raise ConfigurationError("private transaction directory is unsafe")
    return descriptor


def _create_private_directory_at(
    parent_descriptor: int,
    name: str,
) -> tuple[int, tuple[int, int]]:
    """Create, normalize, and open one exact owner-private directory."""

    if name in {"", ".", ".."} or Path(name).name != name:
        raise ConfigurationError("unsafe private directory component")
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        created = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(created.st_mode)
            or created.st_uid != get_secure_filesystem_backend().real_user_id()
        ):
            raise ConfigurationError("created private directory is unsafe")
        identity = created.st_dev, created.st_ino
        os.chmod(
            name,
            0o700,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened = _open_existing_private_directory_at(parent_descriptor, name)
        if opened is None:
            raise ConfigurationError("created private directory disappeared")
        descriptor = opened
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != identity:
            raise ConfigurationError("created private directory identity changed")
        os.fsync(descriptor)
        os.fsync(parent_descriptor)
        return descriptor, identity
    except FileExistsError:
        raise
    except BaseException as error:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if identity is not None:
            try:
                _remove_new_private_directory_at(
                    parent_descriptor,
                    name,
                    identity,
                )
            except (OSError, ConfigurationError):
                raise ConfigurationError(
                    "private directory initialization rollback was incomplete"
                ) from error
        raise


def _remove_new_private_directory_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    """Remove only the exact empty directory created by this transaction."""

    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != get_secure_filesystem_backend().real_user_id()
        or (current.st_dev, current.st_ino) != expected_identity
    ):
        raise ConfigurationError("created private directory identity changed")
    os.rmdir(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _bounded_sorted_names_at(
    directory_descriptor: int,
    *,
    max_entries: int,
    label: str,
) -> list[str]:
    """Return deterministic names without materializing an unbounded directory."""

    if max_entries <= 0:
        raise ValueError("directory entry limit must be positive")
    names: list[str] = []
    with os.scandir(directory_descriptor) as entries:
        for entry in entries:
            if len(names) >= max_entries:
                raise ConfigurationError(
                    f"{label} exceeded the {max_entries}-entry limit"
                )
            names.append(entry.name)
    names.sort()
    return names


def _remove_private_transaction_directory_at(
    stage_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    """Remove only the empty transaction directory opened by this operation."""

    current = os.stat(name, dir_fd=stage_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != get_secure_filesystem_backend().real_user_id()
        or stat.S_IMODE(current.st_mode) != 0o700
        or (current.st_dev, current.st_ino) != expected_identity
    ):
        raise ConfigurationError("prune transaction directory identity changed")
    os.rmdir(name, dir_fd=stage_descriptor)
    os.fsync(stage_descriptor)


def _inspect_prune_transactions_at(
    root_descriptor: int,
    *,
    max_transactions: int,
) -> list[str]:
    """Report pending apply recovery without mutating preview state."""

    try:
        stage_descriptor = _open_existing_private_directory_at(
            root_descriptor,
            _RETENTION_PRUNE_STAGE_NAME,
        )
    except (OSError, ConfigurationError) as error:
        return [f"prune transaction inspection failed: {type(error).__name__}"]
    if stage_descriptor is None:
        return []
    try:
        try:
            transaction_names = _bounded_sorted_names_at(
                stage_descriptor,
                max_entries=max_transactions,
                label="prune transaction stage",
            )
        except (OSError, ConfigurationError) as error:
            return [f"prune transaction inspection failed: {type(error).__name__}"]
        if transaction_names:
            return ["pending evidence-prune transaction requires apply recovery"]
        return []
    finally:
        os.close(stage_descriptor)


def _discover_prune_transaction_parents_at(
    root_descriptor: int,
    *,
    max_transactions: int,
    normalize_restricted: bool,
) -> tuple[set[tuple[str, ...]], list[str]]:
    """Discover every source parent that pending recovery could mutate."""

    try:
        stage_descriptor = _open_existing_private_directory_at(
            root_descriptor,
            _RETENTION_PRUNE_STAGE_NAME,
            normalize_restricted=normalize_restricted,
        )
    except (OSError, ConfigurationError) as error:
        return set(), [f"prune transaction discovery failed: {type(error).__name__}"]
    if stage_descriptor is None:
        return set(), []
    parents: set[tuple[str, ...]] = set()
    errors: list[str] = []
    try:
        try:
            transaction_names = _bounded_sorted_names_at(
                stage_descriptor,
                max_entries=max_transactions,
                label="prune transaction stage",
            )
        except (OSError, ConfigurationError) as error:
            return set(), [
                f"prune transaction discovery failed: {type(error).__name__}"
            ]
        for transaction_name in transaction_names:
            transaction_descriptor = -1
            try:
                opened = _open_existing_private_directory_at(
                    stage_descriptor,
                    transaction_name,
                    normalize_restricted=normalize_restricted,
                )
                if opened is None:
                    raise ConfigurationError("prune transaction disappeared")
                transaction_descriptor = opened
                entries = set(
                    _bounded_sorted_names_at(
                        transaction_descriptor,
                        max_entries=_MAX_PRUNE_TRANSACTION_ENTRIES,
                        label="prune transaction",
                    )
                )
                if normalize_restricted and _RETENTION_PRUNE_MARKER_NAME in entries:
                    _normalize_prune_transaction_marker_at(transaction_descriptor)
                if not entries.intersection(
                    {
                        _RETENTION_PRUNE_EVIDENCE_NAME,
                        _RETENTION_PRUNE_SIDECAR_NAME,
                    }
                ):
                    continue
                if not entries <= {
                    _RETENTION_PRUNE_MARKER_NAME,
                    _RETENTION_PRUNE_EVIDENCE_NAME,
                    _RETENTION_PRUNE_SIDECAR_NAME,
                }:
                    raise ConfigurationError(
                        "prune transaction contains unexpected entries"
                    )
                transaction, _ = _load_prune_transaction_at(transaction_descriptor)
                parent = transaction.evidence_parts[:-1]
                if parent:
                    parents.add(parent)
            except (
                OSError,
                ConfigurationError,
                StructuredDataTypeError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as error:
                errors.append(
                    f"{_RETENTION_PRUNE_STAGE_NAME}/{transaction_name}: "
                    f"lock discovery failed: {type(error).__name__}"
                )
            finally:
                if transaction_descriptor >= 0:
                    os.close(transaction_descriptor)
        return parents, errors
    finally:
        os.close(stage_descriptor)


def _recover_prune_transactions_at(
    root_descriptor: int,
    root: Path,
    *,
    current: datetime,
    max_transactions: int,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Complete or roll back bounded transactions left by interrupted apply."""

    # Recovery trusts the marker's original descriptor-bound expiry decision.
    # Keep ``current`` in this private interface for deterministic test hooks and
    # compatibility with the first implementation, but never re-evaluate TTLs.
    del current

    stage_descriptor = _open_existing_private_directory_at(
        root_descriptor,
        _RETENTION_PRUNE_STAGE_NAME,
        normalize_restricted=True,
    )
    if stage_descriptor is None:
        return [], []
    recovered: list[tuple[str, str]] = []
    errors: list[str] = []
    try:
        try:
            transaction_names = _bounded_sorted_names_at(
                stage_descriptor,
                max_entries=max_transactions,
                label="prune transaction stage",
            )
        except (OSError, ConfigurationError) as error:
            return [], [f"prune transaction scan failed: {type(error).__name__}"]
        for transaction_name in transaction_names:
            try:
                _preflight_prune_transaction_at(
                    root_descriptor,
                    stage_descriptor,
                    transaction_name,
                )
            except (
                OSError,
                ConfigurationError,
                StructuredDataTypeError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as error:
                errors.append(
                    f"{_RETENTION_PRUNE_STAGE_NAME}/{transaction_name}: "
                    f"recovery preflight failed: {type(error).__name__}"
                )
        if errors:
            return [], errors
        for transaction_name in transaction_names:
            try:
                paths = _recover_prune_transaction_at(
                    root_descriptor,
                    stage_descriptor,
                    transaction_name,
                )
                if paths is not None:
                    recovered.append(
                        (
                            str(root.joinpath(*paths[0])),
                            str(root.joinpath(*paths[1])),
                        )
                    )
            except (
                OSError,
                ConfigurationError,
                StructuredDataTypeError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as error:
                errors.append(
                    f"{_RETENTION_PRUNE_STAGE_NAME}/{transaction_name}: "
                    f"recovery failed: {type(error).__name__}"
                )
        return recovered, errors
    finally:
        os.close(stage_descriptor)


def _preflight_prune_transaction_at(
    root_descriptor: int,
    stage_descriptor: int,
    transaction_name: str,
) -> None:
    """Validate one pending transaction completely before any recovery mutates."""

    transaction_descriptor = _open_existing_private_directory_at(
        stage_descriptor,
        transaction_name,
        normalize_restricted=True,
    )
    if transaction_descriptor is None:
        raise ConfigurationError("prune transaction disappeared")
    try:
        entries = set(
            _bounded_sorted_names_at(
                transaction_descriptor,
                max_entries=_MAX_PRUNE_TRANSACTION_ENTRIES,
                label="prune transaction",
            )
        )
        if _RETENTION_PRUNE_MARKER_NAME in entries:
            _normalize_prune_transaction_marker_at(transaction_descriptor)
        has_staged_source = bool(
            entries.intersection(
                {
                    _RETENTION_PRUNE_EVIDENCE_NAME,
                    _RETENTION_PRUNE_SIDECAR_NAME,
                }
            )
        )
        if not has_staged_source:
            if not entries <= {_RETENTION_PRUNE_MARKER_NAME}:
                raise ConfigurationError(
                    "prune transaction contains unexpected entries"
                )
            if _RETENTION_PRUNE_MARKER_NAME not in entries:
                return
            try:
                transaction, _ = _load_prune_transaction_at(transaction_descriptor)
            except (
                OSError,
                ConfigurationError,
                StructuredDataTypeError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ):
                return
            source_evidence = _stat_relative_record_at(
                root_descriptor,
                transaction.evidence_parts,
            )
            source_sidecar = _stat_relative_record_at(
                root_descriptor,
                transaction.sidecar_parts,
            )
            if (source_evidence is None) != (source_sidecar is None):
                raise ConfigurationError(
                    "stage-free prune transaction has incomplete sources"
                )
            return

        if not entries <= {
            _RETENTION_PRUNE_MARKER_NAME,
            _RETENTION_PRUNE_EVIDENCE_NAME,
            _RETENTION_PRUNE_SIDECAR_NAME,
        }:
            raise ConfigurationError("prune transaction contains unexpected entries")
        if _RETENTION_PRUNE_MARKER_NAME not in entries:
            raise ConfigurationError("prune transaction marker is missing")
        transaction, _ = _load_prune_transaction_at(transaction_descriptor)
        staged_evidence = _stat_immediate_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_EVIDENCE_NAME,
        )
        staged_sidecar = _stat_immediate_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_SIDECAR_NAME,
        )
        source_evidence = _stat_relative_record_at(
            root_descriptor,
            transaction.evidence_parts,
        )
        source_sidecar = _stat_relative_record_at(
            root_descriptor,
            transaction.sidecar_parts,
        )
        _require_transaction_record_identity(
            staged_evidence,
            transaction.evidence_identity,
        )
        _require_transaction_record_identity(
            staged_sidecar,
            transaction.sidecar_identity,
        )
        _require_transaction_record_identity(
            source_evidence,
            transaction.evidence_identity,
        )
        _require_transaction_record_identity(
            source_sidecar,
            transaction.sidecar_identity,
        )
        if staged_evidence is not None and staged_sidecar is not None:
            pair = _RetainedEvidencePair(
                evidence=_transaction_source_record(
                    transaction.evidence_parts,
                    staged_evidence,
                ),
                sidecar=_transaction_source_record(
                    transaction.sidecar_parts,
                    staged_sidecar,
                ),
                expires_at=_validated_manifest_timestamp(transaction.expires_at),
            )
            _revalidate_staged_pair_at(
                transaction_descriptor,
                pair,
                allowed_link_counts=frozenset({1, 2}),
            )
            _read_record_bytes_at(
                transaction_descriptor,
                staged_evidence,
                allowed_link_counts=frozenset(
                    {2 if source_evidence is not None else 1}
                ),
            )
            _read_record_bytes_at(
                transaction_descriptor,
                staged_sidecar,
                allowed_link_counts=frozenset({2 if source_sidecar is not None else 1}),
            )
            for source in (source_evidence, source_sidecar):
                if source is not None:
                    _read_record_bytes_at(
                        root_descriptor,
                        source,
                        allowed_link_counts=frozenset({2}),
                    )
            return

        if (source_evidence is None) != (source_sidecar is None):
            raise ConfigurationError("incomplete prune transaction is not recoverable")
        if staged_evidence is not None:
            _read_record_bytes_at(
                transaction_descriptor,
                staged_evidence,
                allowed_link_counts=frozenset(
                    {2 if source_evidence is not None else 1}
                ),
            )
        if staged_sidecar is not None:
            _read_record_bytes_at(
                transaction_descriptor,
                staged_sidecar,
                allowed_link_counts=frozenset({2 if source_sidecar is not None else 1}),
            )
        if source_evidence is not None and source_sidecar is not None:
            _read_record_bytes_at(
                root_descriptor,
                source_evidence,
                allowed_link_counts=frozenset(
                    {2 if staged_evidence is not None else 1}
                ),
            )
            _read_record_bytes_at(
                root_descriptor,
                source_sidecar,
                allowed_link_counts=frozenset({2 if staged_sidecar is not None else 1}),
            )
    finally:
        os.close(transaction_descriptor)


def _recover_prune_transaction_at(
    root_descriptor: int,
    stage_descriptor: int,
    transaction_name: str,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Recover one exact transaction, returning paths when deletion completed."""

    transaction_descriptor = _open_existing_private_directory_at(
        stage_descriptor,
        transaction_name,
        normalize_restricted=True,
    )
    if transaction_descriptor is None:
        raise ConfigurationError("prune transaction disappeared")
    transaction_metadata = os.fstat(transaction_descriptor)
    transaction_identity = (
        transaction_metadata.st_dev,
        transaction_metadata.st_ino,
    )
    try:
        entries = set(
            _bounded_sorted_names_at(
                transaction_descriptor,
                max_entries=_MAX_PRUNE_TRANSACTION_ENTRIES,
                label="prune transaction",
            )
        )
        if _RETENTION_PRUNE_MARKER_NAME in entries:
            _normalize_prune_transaction_marker_at(transaction_descriptor)
        has_staged_source = bool(
            entries.intersection(
                {
                    _RETENTION_PRUNE_EVIDENCE_NAME,
                    _RETENTION_PRUNE_SIDECAR_NAME,
                }
            )
        )
        if not has_staged_source:
            if not entries <= {_RETENTION_PRUNE_MARKER_NAME}:
                raise ConfigurationError(
                    "prune transaction contains unexpected entries"
                )
            completed_paths: tuple[tuple[str, ...], tuple[str, ...]] | None = None
            if _RETENTION_PRUNE_MARKER_NAME in entries:
                try:
                    transaction, _ = _load_prune_transaction_at(transaction_descriptor)
                except (
                    OSError,
                    ConfigurationError,
                    StructuredDataTypeError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                ):
                    transaction = None
                if transaction is not None:
                    source_evidence = _stat_relative_record_at(
                        root_descriptor,
                        transaction.evidence_parts,
                    )
                    source_sidecar = _stat_relative_record_at(
                        root_descriptor,
                        transaction.sidecar_parts,
                    )
                    if (source_evidence is None) != (source_sidecar is None):
                        raise ConfigurationError(
                            "stage-free prune transaction has incomplete sources"
                        )
                    if source_evidence is None and source_sidecar is None:
                        completed_paths = (
                            transaction.evidence_parts,
                            transaction.sidecar_parts,
                        )
                        _fsync_absent_transaction_sources_at(
                            root_descriptor,
                            transaction,
                        )
            for name in sorted(entries):
                record = _stat_immediate_record_at(transaction_descriptor, name)
                if record is None:
                    raise ConfigurationError("prune transaction entry disappeared")
                _unlink_owned_file_at(
                    transaction_descriptor,
                    name,
                    record.identity,
                    allowed_link_counts=frozenset({1}),
                )
            if entries:
                os.fsync(transaction_descriptor)
            _remove_private_transaction_directory_at(
                stage_descriptor,
                transaction_name,
                transaction_identity,
            )
            return completed_paths
        allowed_entries = {
            _RETENTION_PRUNE_MARKER_NAME,
            _RETENTION_PRUNE_EVIDENCE_NAME,
            _RETENTION_PRUNE_SIDECAR_NAME,
        }
        if not entries <= allowed_entries:
            raise ConfigurationError("prune transaction contains unexpected entries")
        if _RETENTION_PRUNE_MARKER_NAME not in entries:
            raise ConfigurationError("prune transaction marker is missing")
        transaction, marker = _load_prune_transaction_at(transaction_descriptor)
        staged_evidence = _stat_immediate_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_EVIDENCE_NAME,
        )
        staged_sidecar = _stat_immediate_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_SIDECAR_NAME,
        )
        source_evidence = _stat_relative_record_at(
            root_descriptor,
            transaction.evidence_parts,
        )
        source_sidecar = _stat_relative_record_at(
            root_descriptor,
            transaction.sidecar_parts,
        )
        _require_transaction_record_identity(
            staged_evidence,
            transaction.evidence_identity,
        )
        _require_transaction_record_identity(
            staged_sidecar,
            transaction.sidecar_identity,
        )
        _require_transaction_record_identity(
            source_evidence,
            transaction.evidence_identity,
        )
        _require_transaction_record_identity(
            source_sidecar,
            transaction.sidecar_identity,
        )
        if staged_evidence is not None and staged_sidecar is not None:
            pair = _RetainedEvidencePair(
                evidence=_transaction_source_record(
                    transaction.evidence_parts,
                    staged_evidence,
                ),
                sidecar=_transaction_source_record(
                    transaction.sidecar_parts,
                    staged_sidecar,
                ),
                expires_at=_validated_manifest_timestamp(transaction.expires_at),
            )
            _revalidate_staged_pair_at(
                transaction_descriptor,
                pair,
                allowed_link_counts=frozenset({1, 2}),
            )
            if source_sidecar is not None:
                _unlink_relative_record_at(
                    root_descriptor,
                    source_sidecar,
                    allowed_link_counts=frozenset({2}),
                )
            if source_evidence is not None:
                _unlink_relative_record_at(
                    root_descriptor,
                    source_evidence,
                    allowed_link_counts=frozenset({2}),
                )
            _fsync_absent_transaction_sources_at(root_descriptor, transaction)
            _unlink_stage_record_at(
                transaction_descriptor,
                _RETENTION_PRUNE_EVIDENCE_NAME,
                transaction.evidence_identity,
            )
            _unlink_stage_record_at(
                transaction_descriptor,
                _RETENTION_PRUNE_SIDECAR_NAME,
                transaction.sidecar_identity,
            )
            _unlink_stage_record_at(
                transaction_descriptor,
                _RETENTION_PRUNE_MARKER_NAME,
                marker.identity,
            )
            _remove_private_transaction_directory_at(
                stage_descriptor,
                transaction_name,
                transaction_identity,
            )
            return transaction.evidence_parts, transaction.sidecar_parts

        if source_evidence is None and source_sidecar is None:
            _fsync_absent_transaction_sources_at(root_descriptor, transaction)
            if staged_evidence is not None:
                _unlink_stage_record_at(
                    transaction_descriptor,
                    _RETENTION_PRUNE_EVIDENCE_NAME,
                    transaction.evidence_identity,
                )
            if staged_sidecar is not None:
                _unlink_stage_record_at(
                    transaction_descriptor,
                    _RETENTION_PRUNE_SIDECAR_NAME,
                    transaction.sidecar_identity,
                )
            _unlink_stage_record_at(
                transaction_descriptor,
                _RETENTION_PRUNE_MARKER_NAME,
                marker.identity,
            )
            _remove_private_transaction_directory_at(
                stage_descriptor,
                transaction_name,
                transaction_identity,
            )
            return transaction.evidence_parts, transaction.sidecar_parts

        if source_evidence is None or source_sidecar is None:
            raise ConfigurationError("incomplete prune transaction is not recoverable")
        if staged_evidence is not None:
            _unlink_owned_file_at(
                transaction_descriptor,
                _RETENTION_PRUNE_EVIDENCE_NAME,
                transaction.evidence_identity,
                allowed_link_counts=frozenset({2}),
            )
        if staged_sidecar is not None:
            _unlink_owned_file_at(
                transaction_descriptor,
                _RETENTION_PRUNE_SIDECAR_NAME,
                transaction.sidecar_identity,
                allowed_link_counts=frozenset({2}),
            )
        _unlink_stage_record_at(
            transaction_descriptor,
            _RETENTION_PRUNE_MARKER_NAME,
            marker.identity,
        )
        os.fsync(transaction_descriptor)
        _remove_private_transaction_directory_at(
            stage_descriptor,
            transaction_name,
            transaction_identity,
        )
        return None
    finally:
        os.close(transaction_descriptor)


def _load_prune_transaction_at(
    transaction_descriptor: int,
) -> tuple[_PruneTransaction, _RetainedFileRecord]:
    """Load and validate one content-free transaction marker."""

    marker = _stat_immediate_record_at(
        transaction_descriptor,
        _RETENTION_PRUNE_MARKER_NAME,
    )
    if marker is None:
        raise ConfigurationError("prune transaction marker is missing")
    raw_bytes = _read_record_bytes_at(transaction_descriptor, marker)
    raw = _load_json_bytes(raw_bytes)
    if not isinstance(raw, Mapping):
        raise ConfigurationError("prune transaction marker is malformed")
    expected_keys = {
        "schema",
        "evidence_parts",
        "evidence_device",
        "evidence_inode",
        "sidecar_parts",
        "sidecar_device",
        "sidecar_inode",
        "expires_at",
        "selected_at",
    }
    if (
        set(raw) != expected_keys
        or raw["schema"] != _RETENTION_PRUNE_TRANSACTION_SCHEMA
    ):
        raise ConfigurationError("prune transaction marker schema is invalid")
    evidence_parts = _validated_relative_parts(raw["evidence_parts"])
    sidecar_parts = _validated_relative_parts(raw["sidecar_parts"])
    if (
        sidecar_parts[:-1] != evidence_parts[:-1]
        or sidecar_parts[-1] != f"{evidence_parts[-1]}.retention.json"
    ):
        raise ConfigurationError("prune transaction pair relationship is invalid")
    expires_at = raw["expires_at"]
    selected_at = raw["selected_at"]
    if not isinstance(expires_at, str) or not isinstance(selected_at, str):
        raise ConfigurationError("prune transaction expiration is invalid")
    expires = _validated_manifest_timestamp(expires_at)
    selected = _validated_manifest_timestamp(selected_at)
    if selected < expires:
        raise ConfigurationError("prune transaction was not selected after expiry")
    return (
        _PruneTransaction(
            evidence_parts=evidence_parts,
            evidence_identity=(
                _validated_identity_integer(raw["evidence_device"]),
                _validated_identity_integer(raw["evidence_inode"]),
            ),
            sidecar_parts=sidecar_parts,
            sidecar_identity=(
                _validated_identity_integer(raw["sidecar_device"]),
                _validated_identity_integer(raw["sidecar_inode"]),
            ),
            expires_at=expires_at,
            selected_at=selected_at,
        ),
        marker,
    )


def _validated_relative_parts(value: Any) -> tuple[str, ...]:
    """Validate a bounded normalized descriptor-relative path component list."""

    if not isinstance(value, list) or not value or len(value) > _MAX_REPAIR_DEPTH + 1:
        raise ConfigurationError("prune transaction path is invalid")
    parts = tuple(value)
    if any(
        not isinstance(part, str)
        or not part
        or part in {".", ".."}
        or Path(part).name != part
        for part in parts
    ):
        raise ConfigurationError("prune transaction path is invalid")
    return parts


def _validated_identity_integer(value: Any) -> int:
    """Validate a filesystem identity integer without accepting booleans."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigurationError("prune transaction identity is invalid")
    return value


def _stat_immediate_record_at(
    parent_descriptor: int,
    name: str,
) -> _RetainedFileRecord | None:
    """Return one no-follow immediate record, or None when it is absent."""

    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _RetainedFileRecord(
        relative_parts=(name,),
        identity=(metadata.st_dev, metadata.st_ino),
        mode=metadata.st_mode,
        size=metadata.st_size,
    )


def _stat_relative_record_at(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
) -> _RetainedFileRecord | None:
    """Return one no-follow root-relative record, or None when absent."""

    parent_descriptor = _open_relative_directory_at(
        root_descriptor,
        relative_parts[:-1],
    )
    try:
        try:
            metadata = os.stat(
                relative_parts[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        return _RetainedFileRecord(
            relative_parts=relative_parts,
            identity=(metadata.st_dev, metadata.st_ino),
            mode=metadata.st_mode,
            size=metadata.st_size,
        )
    finally:
        os.close(parent_descriptor)


def _require_transaction_record_identity(
    record: _RetainedFileRecord | None,
    expected_identity: tuple[int, int],
) -> None:
    """Reject a present transaction or source name bound to another inode."""

    if record is not None and record.identity != expected_identity:
        raise ConfigurationError("prune transaction identity changed")


def _transaction_source_record(
    relative_parts: tuple[str, ...],
    staged: _RetainedFileRecord,
) -> _RetainedFileRecord:
    """Reconstruct source display metadata from one exact staged inode."""

    return _RetainedFileRecord(
        relative_parts=relative_parts,
        identity=staged.identity,
        mode=staged.mode,
        size=staged.size,
    )


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
            raw = _load_json_bytes(raw_bytes)
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
    *,
    allowed_link_counts: frozenset[int] = frozenset({1}),
) -> None:
    """Require descriptor-read evidence bytes to match one manifest digest."""

    expected = manifest.get("content_digest")
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ValueError("retention content digest is invalid")
    raw = _read_record_bytes_at(
        root_descriptor,
        record,
        allowed_link_counts=allowed_link_counts,
    )
    text = raw.decode("utf-8")
    if content_digest(text) == expected:
        return
    try:
        value = _load_json_bytes(raw)
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("retention content digest does not match evidence") from error
    if content_digest(value) == expected:
        return
    raise ValueError("retention content digest does not match evidence")


def _read_record_bytes_at(
    root_descriptor: int,
    record: _RetainedFileRecord,
    *,
    allowed_link_counts: frozenset[int] = frozenset({1}),
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
            or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
            or metadata.st_nlink not in allowed_link_counts
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
                or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
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
        descriptor, _ = _create_private_directory_at(parent_descriptor, name)
        return descriptor
    except FileExistsError:
        pass
    existing_descriptor = _open_existing_private_directory_at(
        parent_descriptor,
        name,
        normalize_restricted=True,
    )
    if existing_descriptor is None:
        raise ConfigurationError("private maintenance directory disappeared")
    return existing_descriptor


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
        or source.st_uid != get_secure_filesystem_backend().real_user_id()
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
    value: Any = (
        _load_json_bytes(text.encode("utf-8"))
        if path.suffix.casefold() == ".json"
        else text
    )
    if content_digest(value) != expected:
        raise ValueError("retention content digest does not match evidence")


def _permitted_rule(
    config: RetentionConfig,
    *,
    evidence_type: str,
    include_content: bool,
) -> RetentionRule:
    if not isinstance(evidence_type, str) or not evidence_type.strip():
        raise ConfigurationError("retention evidence_type must not be empty")
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
    sidecar = _retention_sidecar_path(path)
    if any(not isinstance(value, str) or not value for value in citation_ids):
        raise ConfigurationError("retention citation_ids are invalid")
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
    try:
        _validate_retention_manifest(
            manifest.to_dict(),
            sidecar_name=sidecar.name,
        )
    except (TypeError, ValueError) as error:
        raise ConfigurationError("generated retention manifest is invalid") from error
    return sidecar, manifest


def _retention_sidecar_path(path: Path) -> Path:
    """Return an unambiguous sidecar name outside internal maintenance names."""

    if _is_reserved_retained_evidence_name(path.name):
        raise ConfigurationError("retained evidence filename is reserved")
    sidecar = path.with_suffix(path.suffix + ".retention.json")
    if sidecar.name == path.name:
        raise ConfigurationError("retained evidence names must be distinct")
    return sidecar


def _is_reserved_retained_evidence_name(name: str) -> bool:
    """Return whether one name collides with maintenance or sidecar roles."""

    reserved_names = {
        _RETENTION_FLOCK_NAME.casefold(),
        _RETENTION_PRUNE_STAGE_NAME.casefold(),
        _RETENTION_QUARANTINE_NAME.casefold(),
    }
    folded_name = name.casefold()
    return folded_name in reserved_names or folded_name.endswith(".retention.json")


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


def _require_retention_platform() -> None:
    """Require the complete native state-publication contract set."""

    get_secure_filesystem_backend()
    get_cross_process_locking_backend()
    require_platform_contract(PlatformContract.ATOMIC_PUBLICATION_RECOVERY)


def _acquire_file_lock(
    descriptor: int,
    *,
    mode: LockMode,
    blocking: bool = True,
) -> None:
    """Acquire one lock through the selected native locking contract."""

    get_cross_process_locking_backend().acquire(
        descriptor,
        mode=mode,
        blocking=blocking,
    )


def _release_file_lock(descriptor: int) -> None:
    """Release one lock through the selected native locking contract."""

    get_cross_process_locking_backend().release(descriptor)


def _atomic_write_files(
    files: Mapping[Path, bytes],
    *,
    parent_directory: PinnedDirectory | None = None,
) -> None:
    """Commit same-directory retained files with rollback on partial failure."""

    _require_retention_platform()
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
    hierarchy_locks: list[int] = []
    published: list[tuple[str, tuple[int, int]]] = []
    try:
        lock_descriptor, lock_identity = _open_retention_lock(parent_descriptor)
        _acquire_file_lock(lock_descriptor, mode=LockMode.EXCLUSIVE)
        hierarchy_locks = _acquire_retention_directory_hierarchy(pinned)
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
                _release_file_lock(lock_descriptor)
            finally:
                os.close(lock_descriptor)
        try:
            _release_retention_directory_hierarchy(hierarchy_locks)
        finally:
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
    if any(
        len(content) > _MAX_REPAIR_FILE_BYTES for content in content_by_name.values()
    ):
        raise ConfigurationError(
            "retained evidence exceeds the descriptor validation size limit"
        )
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

    try:
        existing = _open_existing_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            normalize_restricted=True,
        )
    except (OSError, ConfigurationError) as error:
        raise ConfigurationError("retention transaction lock is unsafe") from error
    if existing is not None:
        return existing

    try:
        descriptor, identity = _open_new_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
        )
    except ConfigurationError as error:
        # A competing create can win after the absent stat. Reopen and validate
        # only the exact persistent lock contract; initialization failures from
        # our own create have already rolled their inode back.
        try:
            existing = _open_existing_restricted_file_at(
                parent_descriptor,
                _RETENTION_FLOCK_NAME,
                normalize_restricted=True,
            )
        except (OSError, ConfigurationError) as reopen_error:
            raise ConfigurationError(
                "retention transaction lock is unsafe"
            ) from reopen_error
        if existing is not None:
            return existing
        raise ConfigurationError("retention transaction lock is unsafe") from error

    try:
        os.fsync(descriptor)
        os.fsync(parent_descriptor)
        _validate_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            identity,
        )
        return descriptor, identity
    except BaseException as error:
        cleanup_error: BaseException | None = None
        try:
            _unlink_new_private_file_at(
                parent_descriptor,
                _RETENTION_FLOCK_NAME,
                identity,
            )
            os.fsync(parent_descriptor)
        except (OSError, ConfigurationError) as caught:
            cleanup_error = caught
        os.close(descriptor)
        if cleanup_error is not None:
            raise ConfigurationError(
                "retention lock initialization rollback was incomplete"
            ) from error
        raise


def _open_existing_retention_lock(
    parent_descriptor: int,
) -> tuple[int, tuple[int, int]] | None:
    """Open an existing lock without mutating state during a repair preview."""

    try:
        return _open_existing_restricted_file_at(
            parent_descriptor,
            _RETENTION_FLOCK_NAME,
            normalize_restricted=False,
        )
    except (OSError, ConfigurationError) as error:
        raise ConfigurationError("retention transaction lock is unsafe") from error


def _open_existing_restricted_file_at(
    parent_descriptor: int,
    name: str,
    *,
    normalize_restricted: bool,
) -> tuple[int, tuple[int, int]] | None:
    """Open a known internal file, optionally repairing stricter owner bits."""

    if name in {"", ".", ".."} or Path(name).name != name:
        raise ConfigurationError("unsafe restricted file component")
    try:
        initial = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    initial_mode = stat.S_IMODE(initial.st_mode)
    if (
        not stat.S_ISREG(initial.st_mode)
        or initial.st_uid != get_secure_filesystem_backend().real_user_id()
        or initial.st_nlink != 1
        or (normalize_restricted and initial_mode & ~0o600 != 0)
        or (not normalize_restricted and initial_mode != 0o600)
    ):
        raise ConfigurationError(f"retained evidence file is unsafe: {name}")
    expected_identity = initial.st_dev, initial.st_ino
    if normalize_restricted and initial_mode != 0o600:
        os.chmod(
            name,
            0o600,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.fsync(parent_descriptor)
        normalized = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _restricted_file_identity(normalized, name) != expected_identity:
            raise ConfigurationError("retained evidence file identity changed")

    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise ConfigurationError(f"retained evidence file is unsafe: {name}") from error
    try:
        if _restricted_file_identity(os.fstat(descriptor), name) != expected_identity:
            raise ConfigurationError("retained evidence file identity changed")
        _validate_restricted_file_at(
            parent_descriptor,
            name,
            expected_identity,
        )
        return descriptor, expected_identity
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
    _restricted_file_identity(metadata, _RETENTION_FLOCK_NAME)
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
            or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
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
                or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
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
        or current.st_uid != get_secure_filesystem_backend().real_user_id()
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
        or current.st_uid != get_secure_filesystem_backend().real_user_id()
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
        or metadata.st_uid != get_secure_filesystem_backend().real_user_id()
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
