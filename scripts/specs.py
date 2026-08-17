#!/usr/bin/env python3
"""Validate and archive MasterAgent development specifications."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

_SCHEMA = "master-agent/change@1"
_ACTIVE_STATES = frozenset(
    {"draft", "proposed", "accepted", "implementing", "verifying"}
)
_TERMINAL_STATES = frozenset({"archived", "rejected", "superseded"})
_CURRENT_STATES = frozenset({"Active", "Deprecated", "Retired"})
_OPERATIONS = frozenset({"add", "modify", "remove"})
_REQUIREMENT_ID = re.compile(r"MA-(?:[A-Z][A-Z0-9]*-)+[0-9]{3,}\Z")
_REQUIREMENT_HEADING = re.compile(
    r"# (MA-(?:[A-Z][A-Z0-9]*-)+[0-9]{3,}) — (\S.*)\Z"
)
_DELTA_HEADING = re.compile(
    r"### (MA-(?:[A-Z][A-Z0-9]*-)+[0-9]{3,}) — (\S.*)\Z"
)
_CHANGE_ID = re.compile(r"[0-9]{4,}-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_TASK = re.compile(r"^- \[([ xX])\] \S.*$")
_PATH_REFERENCE = re.compile(
    r"`((?:(?:src|tests|scripts|docs|config|specs|\.ai|\.github)/[^`]+)"
    r"|(?:AGENTS|README|CHANGELOG|MANIFEST)\.md|pyproject\.toml)`"
)
_REQUIRED_CURRENT_SECTIONS = (
    "## Status",
    "## Requirement",
    "## Rationale",
    "## Scenarios",
    "## Implementation",
    "## Verification",
    "## History",
)
_REQUIRED_CHANGE_FILES = ("change.toml", "proposal.md", "requirements.md", "tasks.md")
_REQUIRED_PROPOSAL_SECTIONS = (
    "## Problem",
    "## Desired outcome",
    "## Scope",
    "## Rationale",
    "## Alternatives considered",
    "## Non-goals",
    "## Risks",
)
_REQUIRED_DESIGN_SECTIONS = (
    "## Approach",
    "## Affected components",
    "## Data flow",
    "## Compatibility",
    "## Security",
    "## Rejected alternatives",
)
_DELTA_SECTIONS = ("## ADDED", "## MODIFIED", "## REMOVED")
_MAX_TEXT_BYTES = 512 * 1024
_MAX_CHANGE_FILES = 128
_MAX_CHANGES = 512
_MAX_REQUIREMENTS = 2048
_MAX_DELTAS = 128


class SpecificationError(ValueError):
    """Raised when a specification operation cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Result of validating the repository specification tree."""

    checks: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """Return whether validation completed without errors."""

        return not self.errors


@dataclass(frozen=True, slots=True)
class Delta:
    """One machine-readable current-requirement delta."""

    operation: str
    requirement_id: str
    destination: str
    source: str | None = None


@dataclass(frozen=True, slots=True)
class ChangeMetadata:
    """Validated metadata for one active or archived change."""

    change_id: str
    title: str
    status: str
    github_issue: int
    created: str
    updated: str
    design_required: bool
    deltas: tuple[Delta, ...]
    schema: str = _SCHEMA


@dataclass(frozen=True, slots=True)
class ChangeStatus:
    """Compact status information for one change."""

    change_id: str
    status: str
    github_issue: int
    complete_tasks: int
    total_tasks: int
    location: str


def validate_repository(root: Path) -> ValidationReport:
    """Validate MasterAgent's development specification tree.

    Parameters
    ----------
    root
        Repository root containing ``specs/``.

    Returns
    -------
    ValidationReport
        Deterministically ordered checks and validation errors.
    """

    root = root.resolve()
    checks: list[str] = []
    errors: list[str] = []
    specs_root = root / "specs"
    expected = (
        specs_root / "README.md",
        specs_root / "current",
        specs_root / "changes",
        specs_root / "archive",
        specs_root / "templates",
    )
    for path in expected:
        if not path.exists():
            errors.append(f"specification path is missing: {_display(root, path)}")
    if errors:
        return ValidationReport((), tuple(sorted(errors)))

    _validate_tree_safety(specs_root, root, errors)
    current = _validate_current_requirements(root, specs_root / "current", errors)
    changes = _validate_changes(
        root,
        specs_root,
        current,
        errors,
    )

    if not errors:
        active_count = sum(item.location == "changes" for item in changes)
        archived_count = sum(item.location == "archive" for item in changes)
        checks.extend(
            (
                f"validated {len(current)} current behavioral requirements",
                (
                    f"validated {active_count} active and "
                    f"{archived_count} archived changes"
                ),
                (
                    "specification paths, references, deltas, and lifecycle "
                    "states are safe"
                ),
            )
        )
    return ValidationReport(tuple(checks), tuple(sorted(set(errors))))


def list_status(root: Path) -> tuple[ChangeStatus, ...]:
    """Return deterministic status rows for active and archived changes."""

    root = root.resolve()
    specs_root = root / "specs"
    rows: list[ChangeStatus] = []
    for location in ("changes", "archive"):
        directory = specs_root / location
        if not directory.is_dir():
            continue
        for path in _bounded_directories(directory, _MAX_CHANGES):
            metadata = _load_change_metadata(path, root)
            complete, total = _task_counts(path / "tasks.md", root)
            rows.append(
                ChangeStatus(
                    change_id=metadata.change_id,
                    status=metadata.status,
                    github_issue=metadata.github_issue,
                    complete_tasks=complete,
                    total_tasks=total,
                    location=location,
                )
            )
    return tuple(sorted(rows, key=lambda item: (item.location, item.change_id)))


def archive_change(root: Path, change_id: str) -> Path:
    """Apply one verified change's deltas and move it into the archive.

    Parameters
    ----------
    root
        Repository root containing ``specs/``.
    change_id
        Active change directory name.

    Returns
    -------
    pathlib.Path
        Final archived change path.

    Raises
    ------
    SpecificationError
        If the change is unsafe, incomplete, invalid, or cannot be archived.
    """

    root = root.resolve()
    if not _CHANGE_ID.fullmatch(change_id):
        raise SpecificationError(f"invalid change ID: {change_id!r}")
    preflight = validate_repository(root)
    if not preflight.ok:
        raise SpecificationError(
            "repository specifications are invalid: " + preflight.errors[0]
        )

    specs_root = root / "specs"
    active_path = specs_root / "changes" / change_id
    archive_path = specs_root / "archive" / change_id
    _require_directory(active_path, root, "active change")
    if archive_path.exists() or archive_path.is_symlink():
        raise SpecificationError(f"archive destination already exists: {archive_path}")

    metadata = _load_change_metadata(active_path, root)
    if metadata.status != "verifying":
        raise SpecificationError(
            f"change {change_id} must be in verifying state before archival"
        )
    complete, total = _task_counts(active_path / "tasks.md", root)
    if total == 0 or complete != total:
        raise SpecificationError(
            f"change {change_id} has incomplete tasks: {complete}/{total}"
        )

    staged: list[tuple[Delta, bytes | None]] = []
    for delta in metadata.deltas:
        destination = _resolve_relative(
            specs_root / "current",
            delta.destination,
            root,
            must_exist=delta.operation in {"modify", "remove"},
        )
        if delta.operation == "add" and (
            destination.exists() or destination.is_symlink()
        ):
            raise SpecificationError(
                f"add delta destination already exists: {delta.destination}"
            )
        if delta.operation in {"modify", "remove"}:
            observed_id = _read_requirement_id(destination, root)
            if observed_id != delta.requirement_id:
                raise SpecificationError(
                    f"delta {delta.requirement_id} targets {observed_id} at "
                    f"{delta.destination}"
                )
        content: bytes | None = None
        if delta.operation in {"add", "modify"}:
            if delta.source is None:
                raise SpecificationError(
                    f"delta {delta.requirement_id} is missing a source snapshot"
                )
            source = _resolve_relative(
                active_path,
                delta.source,
                root,
                must_exist=True,
            )
            content = _read_bytes(source, root)
            source_id = _requirement_id_from_bytes(content, source)
            if source_id != delta.requirement_id:
                raise SpecificationError(
                    f"delta source {delta.source} declares {source_id}, expected "
                    f"{delta.requirement_id}"
                )
        staged.append((delta, content))

    archived_metadata = replace(
        metadata,
        status="archived",
        updated=date.today().isoformat(),
    )
    transaction_parent = specs_root.parent
    transaction_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".spec-archive-{change_id}-",
        dir=transaction_parent,
    ) as temporary:
        transaction = Path(temporary)
        backups = transaction / "backups"
        staged_archive = transaction / "archived-change"
        backups.mkdir(mode=0o700)
        _copy_tree_no_links(active_path, staged_archive, root)
        _atomic_write_text(
            staged_archive / "change.toml",
            _render_change_toml(archived_metadata),
        )

        backed_up: dict[Path, Path | None] = {}
        active_backup = transaction / "active-change"
        archive_installed = False
        try:
            for delta, content in staged:
                destination = _resolve_relative(
                    specs_root / "current",
                    delta.destination,
                    root,
                    must_exist=False,
                )
                backup_path: Path | None = None
                if destination.exists():
                    backup_path = backups / delta.destination
                    backup_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(destination, backup_path, follow_symlinks=False)
                backed_up[destination] = backup_path
                if delta.operation == "remove":
                    destination.unlink()
                else:
                    assert content is not None
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    _atomic_write_bytes(destination, content)

            os.replace(active_path, active_backup)
            os.replace(staged_archive, archive_path)
            archive_installed = True
            postflight = validate_repository(root)
            if not postflight.ok:
                raise SpecificationError(
                    "archived specification tree is invalid: " + postflight.errors[0]
                )
        except Exception:
            if archive_installed and archive_path.exists():
                shutil.rmtree(archive_path)
            if active_backup.exists() and not active_path.exists():
                os.replace(active_backup, active_path)
            for destination, backup_path in reversed(tuple(backed_up.items())):
                if backup_path is None:
                    if destination.exists():
                        destination.unlink()
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    _atomic_write_bytes(destination, backup_path.read_bytes())
            raise
    return archive_path


def _validate_current_requirements(
    root: Path,
    current_root: Path,
    errors: list[str],
) -> dict[str, tuple[Path, bytes]]:
    requirements: dict[str, tuple[Path, bytes]] = {}
    try:
        files = _bounded_files(current_root, suffix=".md", limit=_MAX_REQUIREMENTS)
    except SpecificationError as error:
        errors.append(str(error))
        return requirements
    for path in files:
        try:
            content = _read_bytes(path, root)
            requirement_id = _validate_requirement_document(
                path,
                content,
                root,
                errors,
                validate_references=True,
            )
            expected_name = f"{requirement_id}.md"
            if path.name != expected_name:
                errors.append(
                    f"current requirement {requirement_id} must use filename "
                    f"{expected_name}, found {_display(root, path)}"
                )
        except SpecificationError as error:
            errors.append(str(error))
            continue
        if requirement_id in requirements:
            errors.append(
                f"duplicate current requirement ID {requirement_id}: "
                f"{_display(root, requirements[requirement_id][0])} and "
                f"{_display(root, path)}"
            )
        else:
            requirements[requirement_id] = (path, content)
    return requirements


def _validate_changes(
    root: Path,
    specs_root: Path,
    current: Mapping[str, tuple[Path, bytes]],
    errors: list[str],
) -> list[ChangeStatus]:
    statuses: list[ChangeStatus] = []
    observed_ids: dict[str, Path] = {}
    observed_issues: dict[int, str] = {}
    active_requirements: dict[str, str] = {}
    active_destinations: dict[str, str] = {}
    archived_changes: list[tuple[Path, ChangeMetadata]] = []
    for location in ("changes", "archive"):
        directory = specs_root / location
        try:
            paths = _bounded_directories(directory, _MAX_CHANGES)
        except SpecificationError as error:
            errors.append(str(error))
            continue
        for change_path in paths:
            try:
                metadata = _load_change_metadata(change_path, root)
                _validate_change_directory(
                    root,
                    specs_root,
                    change_path,
                    location,
                    metadata,
                    current,
                    errors,
                )
                complete, total = _task_counts(change_path / "tasks.md", root)
            except SpecificationError as error:
                errors.append(str(error))
                continue
            previous = observed_ids.get(metadata.change_id)
            if previous is not None:
                errors.append(
                    f"duplicate change ID {metadata.change_id}: "
                    f"{_display(root, previous)} and {_display(root, change_path)}"
                )
            else:
                observed_ids[metadata.change_id] = change_path
            previous_issue_change = observed_issues.get(metadata.github_issue)
            if (
                previous_issue_change is not None
                and previous_issue_change != metadata.change_id
            ):
                errors.append(
                    f"GitHub issue #{metadata.github_issue} is linked by changes "
                    f"{previous_issue_change} and {metadata.change_id}"
                )
            else:
                observed_issues[metadata.github_issue] = metadata.change_id
            if location == "changes":
                for delta in metadata.deltas:
                    previous_change = active_requirements.get(delta.requirement_id)
                    if previous_change is not None:
                        errors.append(
                            f"active changes {previous_change} and "
                            f"{metadata.change_id} both modify "
                            f"{delta.requirement_id}"
                        )
                    else:
                        active_requirements[delta.requirement_id] = metadata.change_id
                    previous_destination = active_destinations.get(delta.destination)
                    if previous_destination is not None:
                        errors.append(
                            f"active changes {previous_destination} and "
                            f"{metadata.change_id} both target "
                            f"{delta.destination}"
                        )
                    else:
                        active_destinations[delta.destination] = metadata.change_id
            elif metadata.status == "archived":
                archived_changes.append((change_path, metadata))
            statuses.append(
                ChangeStatus(
                    change_id=metadata.change_id,
                    status=metadata.status,
                    github_issue=metadata.github_issue,
                    complete_tasks=complete,
                    total_tasks=total,
                    location=location,
                )
            )

    _validate_latest_archived_state(
        root,
        specs_root,
        current,
        archived_changes,
        errors,
    )
    return statuses


def _validate_change_directory(
    root: Path,
    specs_root: Path,
    change_path: Path,
    location: str,
    metadata: ChangeMetadata,
    current: Mapping[str, tuple[Path, bytes]],
    errors: list[str],
) -> None:
    if metadata.change_id != change_path.name:
        errors.append(
            f"change ID {metadata.change_id} does not match directory "
            f"{change_path.name}"
        )
    expected_states = _ACTIVE_STATES if location == "changes" else _TERMINAL_STATES
    if metadata.status not in expected_states:
        errors.append(
            f"change {metadata.change_id} has status {metadata.status!r} in {location}/"
        )

    observed_files = [
        path
        for path in change_path.rglob("*")
        if path.is_file() and not path.is_symlink()
    ]
    if len(observed_files) > _MAX_CHANGE_FILES:
        errors.append(
            f"change {metadata.change_id} exceeds the {_MAX_CHANGE_FILES}-file limit"
        )

    for filename in _REQUIRED_CHANGE_FILES:
        if not (change_path / filename).is_file():
            errors.append(f"change {metadata.change_id} is missing {filename}")
    if metadata.design_required and not (change_path / "design.md").is_file():
        errors.append(f"change {metadata.change_id} requires design.md")

    _validate_required_sections(
        change_path / "proposal.md",
        _REQUIRED_PROPOSAL_SECTIONS,
        root,
        errors,
    )
    if metadata.design_required:
        _validate_required_sections(
            change_path / "design.md",
            _REQUIRED_DESIGN_SECTIONS,
            root,
            errors,
        )
    _validate_required_sections(
        change_path / "requirements.md",
        _DELTA_SECTIONS,
        root,
        errors,
    )
    for filename in (*_REQUIRED_CHANGE_FILES[1:], "design.md"):
        path = change_path / filename
        if path.is_file():
            _validate_markdown_references(path, root, errors)
    delta_headings = _parse_delta_headings(change_path / "requirements.md", root)
    expected_headings = {
        "add": "ADDED",
        "modify": "MODIFIED",
        "remove": "REMOVED",
    }
    declared_ids = {delta.requirement_id for delta in metadata.deltas}
    unexpected_headings = sorted(set(delta_headings) - declared_ids)
    if unexpected_headings:
        errors.append(
            f"change {metadata.change_id} requirements.md has undeclared deltas: "
            + ", ".join(unexpected_headings)
        )
    for delta in metadata.deltas:
        observed_section = delta_headings.get(delta.requirement_id)
        expected_section = expected_headings[delta.operation]
        if observed_section != expected_section:
            errors.append(
                f"change {metadata.change_id} delta {delta.requirement_id} must appear "
                f"under ## {expected_section}"
            )

    complete, total = _task_counts(change_path / "tasks.md", root)
    if total == 0:
        errors.append(f"change {metadata.change_id} has no implementation tasks")
    if metadata.status in {"verifying", "archived"} and complete != total:
        errors.append(
            f"change {metadata.change_id} has incomplete tasks for "
            f"{metadata.status}: {complete}/{total}"
        )

    validate_snapshot_references = location == "changes"
    for delta in metadata.deltas:
        destination = _resolve_relative(
            specs_root / "current",
            delta.destination,
            root,
            must_exist=False,
        )
        if location == "changes":
            current_entry = current.get(delta.requirement_id)
            if delta.operation == "add":
                if current_entry is not None or destination.exists():
                    errors.append(
                        f"change {metadata.change_id} add delta already exists: "
                        f"{delta.requirement_id}"
                    )
            elif current_entry is None:
                errors.append(
                    f"change {metadata.change_id} {delta.operation} delta targets "
                    f"missing requirement {delta.requirement_id}"
                )
            elif current_entry[0] != destination:
                errors.append(
                    f"change {metadata.change_id} {delta.operation} delta maps "
                    f"{delta.requirement_id} to {_display(root, destination)}, "
                    f"but current uses {_display(root, current_entry[0])}"
                )

        if delta.operation in {"add", "modify"}:
            assert delta.source is not None
            source = _resolve_relative(
                change_path,
                delta.source,
                root,
                must_exist=True,
            )
            try:
                source_content = _read_bytes(source, root)
                source_id = _validate_requirement_document(
                    source,
                    source_content,
                    root,
                    errors,
                    validate_references=validate_snapshot_references,
                )
            except SpecificationError as error:
                errors.append(str(error))
                continue
            if source_id != delta.requirement_id:
                errors.append(
                    f"change {metadata.change_id} source {delta.source} declares "
                    f"{source_id}, expected {delta.requirement_id}"
                )


def _validate_latest_archived_state(
    root: Path,
    specs_root: Path,
    current: Mapping[str, tuple[Path, bytes]],
    archived_changes: Sequence[tuple[Path, ChangeMetadata]],
    errors: list[str],
) -> None:
    latest: dict[str, tuple[int, str, Path, Delta, bytes | None]] = {}
    for change_path, metadata in sorted(
        archived_changes,
        key=lambda item: (item[1].github_issue, item[1].change_id),
    ):
        for delta in metadata.deltas:
            content: bytes | None = None
            if delta.operation in {"add", "modify"}:
                assert delta.source is not None
                source = _resolve_relative(
                    change_path,
                    delta.source,
                    root,
                    must_exist=True,
                )
                content = _read_bytes(source, root)
            latest[delta.requirement_id] = (
                metadata.github_issue,
                metadata.change_id,
                change_path,
                delta,
                content,
            )

    for requirement_id, record in sorted(latest.items()):
        _, change_id, _, delta, content = record
        destination = _resolve_relative(
            specs_root / "current",
            delta.destination,
            root,
            must_exist=False,
        )
        current_entry = current.get(requirement_id)
        if delta.operation == "remove":
            if current_entry is not None or destination.exists():
                errors.append(
                    f"latest archived change {change_id} did not remove "
                    f"{requirement_id} from current requirements"
                )
            continue
        if current_entry is None:
            errors.append(
                f"latest archived change {change_id} did not merge "
                f"{requirement_id} into current requirements"
            )
        elif current_entry[0] != destination:
            errors.append(
                f"latest archived change {change_id} maps {requirement_id} to "
                f"{_display(root, current_entry[0])}, expected "
                f"{_display(root, destination)}"
            )
        elif current_entry[1] != content:
            errors.append(
                f"current requirement {requirement_id} differs from the latest "
                f"archived snapshot in {change_id}"
            )


def _validate_requirement_document(
    path: Path,
    content: bytes,
    root: Path,
    errors: list[str],
    *,
    validate_references: bool,
) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeError as error:
        raise SpecificationError(
            f"specification file is not UTF-8: {_display(root, path)}: {error}"
        ) from error
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), "")
    match = _REQUIREMENT_HEADING.fullmatch(first)
    if match is None:
        raise SpecificationError(
            f"current requirement has an invalid heading: {_display(root, path)}"
        )
    requirement_id = match.group(1)
    duplicates = [
        section for section in _REQUIRED_CURRENT_SECTIONS if lines.count(section) > 1
    ]
    if duplicates:
        errors.append(
            f"current requirement {requirement_id} repeats sections: "
            + ", ".join(duplicates)
        )
    positions = _section_positions(lines, _REQUIRED_CURRENT_SECTIONS)
    missing = [
        section for section in _REQUIRED_CURRENT_SECTIONS if section not in positions
    ]
    if missing:
        errors.append(
            f"current requirement {requirement_id} is missing sections: "
            + ", ".join(missing)
        )
        return requirement_id
    observed_order = [positions[section] for section in _REQUIRED_CURRENT_SECTIONS]
    if observed_order != sorted(observed_order):
        errors.append(f"current requirement {requirement_id} sections are out of order")

    status = _first_section_value(lines, positions, "## Status")
    if status not in _CURRENT_STATES:
        errors.append(
            f"current requirement {requirement_id} has unsupported status {status!r}"
        )
    requirement_text = _section_text(lines, positions, "## Requirement")
    if not any(term in requirement_text for term in ("MUST", "SHOULD", "MAY")):
        errors.append(
            f"current requirement {requirement_id} lacks normative "
            "MUST/SHOULD/MAY language"
        )
    scenario_text = _section_text(lines, positions, "## Scenarios")
    if not any(line.startswith("### ") for line in scenario_text.splitlines()):
        errors.append(f"current requirement {requirement_id} has no scenarios")

    if validate_references:
        for section in ("## Implementation", "## Verification"):
            section_text = _section_text(lines, positions, section)
            references = tuple(_PATH_REFERENCE.findall(section_text))
            if status == "Active" and not references:
                errors.append(
                    f"current requirement {requirement_id} has no "
                    f"{section[3:].lower()} references"
                )
            for reference in references:
                try:
                    _resolve_relative(root, reference, root, must_exist=True)
                except SpecificationError as error:
                    errors.append(
                        f"current requirement {requirement_id} has invalid reference "
                        f"{reference!r}: {error}"
                    )
    return requirement_id


def _load_change_metadata(change_path: Path, root: Path) -> ChangeMetadata:
    document = _load_toml(change_path / "change.toml", root)
    allowed = {
        "schema",
        "id",
        "title",
        "status",
        "github_issue",
        "created",
        "updated",
        "design_required",
        "deltas",
    }
    unexpected = sorted(set(document) - allowed)
    if unexpected:
        raise SpecificationError(
            f"change {change_path.name} has unsupported metadata fields: "
            + ", ".join(unexpected)
        )
    schema = _required_string(document, "schema")
    if schema != _SCHEMA:
        raise SpecificationError(
            f"change {change_path.name} has unsupported schema {schema!r}"
        )
    change_id = _required_string(document, "id")
    if not _CHANGE_ID.fullmatch(change_id):
        raise SpecificationError(f"change has invalid ID: {change_id!r}")
    title = _required_string(document, "title")
    if len(title) > 200:
        raise SpecificationError(f"change {change_id} title exceeds 200 characters")
    status = _required_string(document, "status")
    if status not in _ACTIVE_STATES | _TERMINAL_STATES:
        raise SpecificationError(
            f"change {change_id} has unsupported lifecycle state {status!r}"
        )
    github_issue = document.get("github_issue")
    if (
        not isinstance(github_issue, int)
        or isinstance(github_issue, bool)
        or github_issue < 1
    ):
        raise SpecificationError(f"change {change_id} has invalid github_issue")
    issue_prefix = int(change_id.split("-", 1)[0])
    if issue_prefix != github_issue:
        raise SpecificationError(
            f"change {change_id} prefix does not match GitHub issue "
            f"#{github_issue}"
        )
    created = _required_date(document, "created", change_id)
    updated = _required_date(document, "updated", change_id)
    if updated < created:
        raise SpecificationError(f"change {change_id} updated date precedes creation")
    design_required = document.get("design_required")
    if not isinstance(design_required, bool):
        raise SpecificationError(f"change {change_id} design_required must be boolean")
    raw_deltas = document.get("deltas")
    if not isinstance(raw_deltas, list) or not 1 <= len(raw_deltas) <= _MAX_DELTAS:
        raise SpecificationError(
            f"change {change_id} must contain 1-{_MAX_DELTAS} deltas"
        )
    deltas = tuple(_parse_delta(change_id, item) for item in raw_deltas)
    if len({item.requirement_id for item in deltas}) != len(deltas):
        raise SpecificationError(f"change {change_id} has duplicate requirement deltas")
    if len({item.destination for item in deltas}) != len(deltas):
        raise SpecificationError(f"change {change_id} has duplicate delta destinations")
    return ChangeMetadata(
        schema=schema,
        change_id=change_id,
        title=title,
        status=status,
        github_issue=github_issue,
        created=created,
        updated=updated,
        design_required=design_required,
        deltas=deltas,
    )


def _parse_delta(change_id: str, raw: object) -> Delta:
    if not isinstance(raw, Mapping):
        raise SpecificationError(f"change {change_id} delta must be a table")
    allowed = {"operation", "requirement_id", "source", "destination"}
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        raise SpecificationError(
            f"change {change_id} delta has unsupported fields: "
            + ", ".join(unexpected)
        )
    operation = _required_string(raw, "operation")
    if operation not in _OPERATIONS:
        raise SpecificationError(
            f"change {change_id} delta has unsupported operation {operation!r}"
        )
    requirement_id = _required_string(raw, "requirement_id")
    if not _REQUIREMENT_ID.fullmatch(requirement_id):
        raise SpecificationError(
            f"change {change_id} delta has invalid requirement ID {requirement_id!r}"
        )
    destination = _required_string(raw, "destination")
    _validate_relative_text(destination, context="delta destination")
    if not destination.endswith(".md"):
        raise SpecificationError(
            f"change {change_id} delta destination must be Markdown: {destination}"
        )
    expected_name = f"{requirement_id}.md"
    if PurePosixPath(destination).name != expected_name:
        raise SpecificationError(
            f"change {change_id} delta destination must end with {expected_name}"
        )
    source_value = raw.get("source")
    source: str | None
    if operation in {"add", "modify"}:
        if not isinstance(source_value, str) or not source_value.strip():
            raise SpecificationError(
                f"change {change_id} {operation} delta requires a source"
            )
        source = source_value
        _validate_relative_text(source, context="delta source")
        if not source.endswith(".md"):
            raise SpecificationError(
                f"change {change_id} delta source must be Markdown: {source}"
            )
        if not source.startswith("current/"):
            raise SpecificationError(
                f"change {change_id} delta source must be below current/: {source}"
            )
        if PurePosixPath(source).name != expected_name:
            raise SpecificationError(
                f"change {change_id} delta source must end with {expected_name}"
            )
    else:
        if source_value is not None:
            raise SpecificationError(
                f"change {change_id} remove delta must not declare a source"
            )
        source = None
    return Delta(operation, requirement_id, destination, source)


def _validate_tree_safety(specs_root: Path, root: Path, errors: list[str]) -> None:
    seen = 0
    for directory, directory_names, filenames in os.walk(specs_root, followlinks=False):
        base = Path(directory)
        for name in tuple(directory_names) + tuple(filenames):
            seen += 1
            if seen > 10_000:
                errors.append("specification tree exceeds the 10000-entry limit")
                return
            path = base / name
            try:
                metadata = path.lstat()
            except OSError as error:
                errors.append(
                    f"specification path is unreadable: {_display(root, path)}: {error}"
                )
                continue
            if stat.S_ISLNK(metadata.st_mode):
                errors.append(
                    "specification tree contains a symlink: "
                    f"{_display(root, path)}"
                )
            elif not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                errors.append(
                    "specification tree contains a non-regular entry: "
                    f"{_display(root, path)}"
                )


def _validate_required_sections(
    path: Path,
    sections: Sequence[str],
    root: Path,
    errors: list[str],
) -> None:
    try:
        text = _read_text(path, root)
    except SpecificationError as error:
        errors.append(str(error))
        return
    lines = text.splitlines()
    section_list = tuple(sections)
    duplicates = [section for section in section_list if lines.count(section) > 1]
    if duplicates:
        errors.append(
            f"{_display(root, path)} repeats sections: " + ", ".join(duplicates)
        )
    positions = _section_positions(lines, section_list)
    missing = [section for section in section_list if section not in positions]
    if missing:
        errors.append(
            f"{_display(root, path)} is missing sections: " + ", ".join(missing)
        )
        return
    order = [positions[section] for section in sections]
    if order != sorted(order):
        errors.append(f"{_display(root, path)} sections are out of order")


def _validate_markdown_references(
    path: Path,
    root: Path,
    errors: list[str],
) -> None:
    try:
        text = _read_text(path, root)
    except SpecificationError as error:
        errors.append(str(error))
        return
    for reference in _PATH_REFERENCE.findall(text):
        try:
            if reference.endswith("/"):
                directory = _resolve_relative(
                    root,
                    reference.removesuffix("/"),
                    root,
                    must_exist=False,
                )
                _require_directory(directory, root, "referenced directory")
            else:
                _resolve_relative(root, reference, root, must_exist=True)
        except SpecificationError as error:
            errors.append(
                f"{_display(root, path)} has invalid reference "
                f"{reference!r}: {error}"
            )


def _parse_delta_headings(path: Path, root: Path) -> dict[str, str]:
    text = _read_text(path, root)
    active: str | None = None
    headings: dict[str, str] = {}
    for line in text.splitlines():
        if line in _DELTA_SECTIONS:
            active = line[3:]
            continue
        match = _DELTA_HEADING.fullmatch(line)
        if match is not None:
            requirement_id = match.group(1)
            if active is None:
                raise SpecificationError(
                    f"{_display(root, path)} has delta heading "
                    f"{requirement_id} outside a delta section"
                )
            if requirement_id in headings:
                raise SpecificationError(
                    f"{_display(root, path)} repeats delta heading {requirement_id}"
                )
            headings[requirement_id] = active
    return headings


def _task_counts(path: Path, root: Path) -> tuple[int, int]:
    text = _read_text(path, root)
    complete = 0
    total = 0
    for line in text.splitlines():
        match = _TASK.fullmatch(line)
        if match is None:
            continue
        total += 1
        complete += match.group(1).casefold() == "x"
    return complete, total


def _section_positions(lines: Sequence[str], sections: Iterable[str]) -> dict[str, int]:
    wanted = set(sections)
    return {line: index for index, line in enumerate(lines) if line in wanted}


def _first_section_value(
    lines: Sequence[str], positions: Mapping[str, int], section: str
) -> str:
    return next(
        (
            line.strip()
            for line in _section_text(lines, positions, section).splitlines()
            if line.strip()
        ),
        "",
    )


def _section_text(
    lines: Sequence[str], positions: Mapping[str, int], section: str
) -> str:
    start = positions[section] + 1
    later = [index for index in positions.values() if index > positions[section]]
    end = min(later) if later else len(lines)
    return "\n".join(lines[start:end]).strip()


def _load_toml(path: Path, root: Path) -> dict[str, Any]:
    try:
        content = _read_bytes(path, root)
        parsed = tomllib.loads(content.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise SpecificationError(
            f"change metadata is malformed: {_display(root, path)}: {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise SpecificationError(
            f"change metadata is malformed: {_display(root, path)}"
        )
    return parsed


def _required_string(document: Mapping[str, object], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value.strip():
        raise SpecificationError(f"change metadata field {name} must be non-empty")
    if len(value) > 512 or any(ord(character) < 32 for character in value):
        raise SpecificationError(f"change metadata field {name} is unsafe")
    return value


def _required_date(document: Mapping[str, object], name: str, change_id: str) -> str:
    value = _required_string(document, name)
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise SpecificationError(
            f"change {change_id} field {name} must be an ISO date"
        ) from error
    return value


def _bounded_files(directory: Path, *, suffix: str, limit: int) -> tuple[Path, ...]:
    files = tuple(
        sorted(
            (path for path in directory.rglob(f"*{suffix}") if path.is_file()),
            key=lambda path: path.as_posix(),
        )
    )
    if len(files) > limit:
        raise SpecificationError(f"{directory} exceeds the {limit}-file limit")
    return files


def _bounded_directories(directory: Path, limit: int) -> tuple[Path, ...]:
    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise SpecificationError(
            f"change directory is unreadable: {directory}: {error}"
        ) from error
    paths: list[Path] = []
    for path in entries:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise SpecificationError(
                f"change entry is unreadable: {path}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise SpecificationError(f"change directory contains a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            if path.name.startswith("."):
                raise SpecificationError(
                    f"hidden change directory is not allowed: {path}"
                )
            paths.append(path)
    ordered = tuple(sorted(paths, key=lambda path: path.name))
    if len(ordered) > limit:
        raise SpecificationError(f"{directory} exceeds the {limit}-change limit")
    return ordered


def _read_text(path: Path, root: Path) -> str:
    try:
        return _read_bytes(path, root).decode("utf-8")
    except UnicodeError as error:
        raise SpecificationError(
            f"specification file is not UTF-8: {_display(root, path)}: {error}"
        ) from error


def _read_bytes(path: Path, root: Path) -> bytes:
    _require_regular(path, root)
    size = path.stat().st_size
    if size > _MAX_TEXT_BYTES:
        raise SpecificationError(
            f"specification file exceeds {_MAX_TEXT_BYTES} bytes: "
            f"{_display(root, path)}"
        )
    try:
        content = path.read_bytes()
    except OSError as error:
        raise SpecificationError(
            f"specification file is unreadable: {_display(root, path)}: {error}"
        ) from error
    if len(content) != size:
        raise SpecificationError(
            f"specification file changed while reading: {_display(root, path)}"
        )
    return content


def _require_regular(path: Path, root: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SpecificationError(
            f"required specification file is missing: {_display(root, path)}: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SpecificationError(
            f"specification file must be a regular non-symlink: {_display(root, path)}"
        )


def _require_directory(path: Path, root: Path, context: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SpecificationError(
            f"{context} is missing: {_display(root, path)}: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SpecificationError(
            f"{context} must be a real directory: {_display(root, path)}"
        )


def _resolve_relative(
    base: Path,
    relative: str,
    root: Path,
    *,
    must_exist: bool,
) -> Path:
    _validate_relative_text(relative, context="relative path")
    pure = PurePosixPath(relative)
    candidate = base.joinpath(*pure.parts)
    root_resolved = root.resolve()
    base_resolved = base.resolve()
    if not base_resolved.is_relative_to(root_resolved):
        raise SpecificationError(f"base path escapes repository root: {base}")
    current = base_resolved
    for part in pure.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise SpecificationError(
                    f"path contains a symlink: {_display(root, current)}"
                )
    parent = candidate.parent.resolve(strict=False)
    if not parent.is_relative_to(base_resolved):
        raise SpecificationError(f"path escapes its allowed root: {relative}")
    if must_exist:
        _require_regular(candidate, root)
    return candidate


def _validate_relative_text(value: str, *, context: str) -> None:
    if "\\" in value:
        raise SpecificationError(f"{context} contains a backslash: {value!r}")
    pure = PurePosixPath(value)
    if (
        not value
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or value != pure.as_posix()
    ):
        raise SpecificationError(
            f"{context} is not a normalized relative path: {value!r}"
        )


def _read_requirement_id(path: Path, root: Path) -> str:
    return _requirement_id_from_bytes(_read_bytes(path, root), path)


def _requirement_id_from_bytes(content: bytes, path: Path) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeError as error:
        raise SpecificationError(
            f"requirement is not UTF-8: {path}: {error}"
        ) from error
    first = next((line for line in text.splitlines() if line.strip()), "")
    match = _REQUIREMENT_HEADING.fullmatch(first)
    if match is None:
        raise SpecificationError(f"requirement has an invalid heading: {path}")
    return match.group(1)


def _copy_tree_no_links(source: Path, destination: Path, root: Path) -> None:
    for path in source.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SpecificationError(
                f"change tree contains a symlink: {_display(root, path)}"
            )
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise SpecificationError(
                f"change tree contains an unsafe entry: {_display(root, path)}"
            )
    shutil.copytree(source, destination, symlinks=False)


def _atomic_write_text(path: Path, content: str) -> None:
    _atomic_write_bytes(path, content.encode("utf-8"))


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _render_change_toml(metadata: ChangeMetadata) -> str:
    lines = [
        f'schema = "{metadata.schema}"',
        f'id = "{metadata.change_id}"',
        f'title = "{_toml_escape(metadata.title)}"',
        f'status = "{metadata.status}"',
        f"github_issue = {metadata.github_issue}",
        f'created = "{metadata.created}"',
        f'updated = "{metadata.updated}"',
        f"design_required = {str(metadata.design_required).lower()}",
    ]
    for delta in metadata.deltas:
        lines.extend(
            (
                "",
                "[[deltas]]",
                f'operation = "{delta.operation}"',
                f'requirement_id = "{delta.requirement_id}"',
                f'destination = "{_toml_escape(delta.destination)}"',
            )
        )
        if delta.source is not None:
            lines.append(f'source = "{_toml_escape(delta.source)}"')
    return "\n".join(lines) + "\n"


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _display(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _format_status(root: Path) -> str:
    report = validate_repository(root)
    if not report.ok:
        return "INVALID\n" + "\n".join(f"- {error}" for error in report.errors)
    current_count = int(report.checks[0].split()[1]) if report.checks else 0
    rows = list_status(root)
    lines = [f"CURRENT {current_count}"]
    for row in rows:
        lines.append(
            f"{row.location.upper()} {row.change_id} {row.status} "
            f"issue=#{row.github_issue} tasks={row.complete_tasks}/{row.total_tasks}"
        )
    if not rows:
        lines.append("NO CHANGES")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and archive MasterAgent development specifications."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the script's parent repository)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate current and change specifications")
    subparsers.add_parser("status", help="show deterministic specification status")
    archive = subparsers.add_parser("archive", help="archive one verified change")
    archive.add_argument("change_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the specification CLI."""

    args = _build_parser().parse_args(argv)
    root = args.root.resolve()
    if args.command == "validate":
        report = validate_repository(root)
        if report.ok:
            for check in report.checks:
                print(f"PASS: {check}")
            return 0
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.command == "status":
        report = validate_repository(root)
        print(_format_status(root))
        return 0 if report.ok else 1
    if args.command == "archive":
        try:
            archived = archive_change(root, str(args.change_id))
        except (OSError, SpecificationError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print(f"ARCHIVED: {_display(root, archived)}")
        return 0
    raise AssertionError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
