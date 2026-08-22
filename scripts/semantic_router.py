#!/usr/bin/env python3
"""Validate and generate MasterAgent's bounded semantic router."""

from __future__ import annotations

import argparse
import ast
import errno
import hashlib
import json
import os
import re
import secrets
import selectors
import stat
import statistics
import subprocess
import sys
import time
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

MANIFEST_PATH: Final = ".ai/semantic-router.toml"
GENERATED_DOCUMENT_PATH: Final = "docs/semantic-index.md"
MAX_MANIFEST_BYTES: Final = 2 * 1024 * 1024
MAX_ITEMS: Final = 4_096
MAX_WALK_ENTRIES: Final = 50_000
MAX_STRING_LENGTH: Final = 4_096
MAX_QUERY_LENGTH: Final = 2_048
MAX_REVISION_LENGTH: Final = 256
MAX_GIT_OUTPUT_BYTES: Final = 4 * 1024 * 1024
MAX_GIT_COMMIT_BYTES: Final = 2 * 1024 * 1024
MAX_GIT_TREE_BYTES: Final = 4 * 1024 * 1024
MAX_GIT_TREE_ENTRIES: Final = 50_000
MAX_CHANGED_PATHS: Final = MAX_WALK_ENTRIES
GIT_TIMEOUT_SECONDS: Final = 15.0
LIFECYCLES: Final = ("released", "implementing", "planned", "archived")
AGENT_KINDS: Final = ("profile", "contract", "runtime")
OWNERSHIP_CATEGORIES: Final = (
    "production_modules",
    "tests",
    "current_requirements",
    "configurations",
    "cli_commands",
    "capabilities",
    "connectors",
    "agent_profiles",
    "platform_capabilities",
)
PATH_OWNERSHIP_CATEGORIES: Final = (
    "production_modules",
    "tests",
    "current_requirements",
    "configurations",
    "connectors",
    "agent_profiles",
)
ROUTE_PATH_FIELDS: Final = (
    "authority",
    "implementation",
    "configuration",
    "tests",
    "release_gates",
)
REQUIRED_PLATFORM_CAPABILITIES: Final = (
    "direct_read",
    "governed_applied_run",
    "advisory_sdk",
    "specification_lifecycle",
    "windows.filesystem",
    "windows.atomic_state_retention",
    "windows.credentials",
    "windows.process_supervision",
    "windows.git_isolation",
    "windows.capsule_isolation",
    "windows.certification",
)
REQUIRED_WINDOWS_PLATFORM_CAPABILITIES: Final = (
    "windows.filesystem",
    "windows.atomic_state_retention",
    "windows.credentials",
    "windows.process_supervision",
    "windows.git_isolation",
    "windows.capsule_isolation",
    "windows.certification",
)
REQUIRED_PLANNED_PLATFORM_CAPABILITIES: Final = tuple(
    capability
    for capability in REQUIRED_WINDOWS_PLATFORM_CAPABILITIES
    if capability
    not in {
        "windows.filesystem",
        "windows.atomic_state_retention",
        "windows.credentials",
        "windows.process_supervision",
        "windows.git_isolation",
        "windows.capsule_isolation",
    }
)
REQUIRED_AGENT_PROFILES: Final = {
    "master-agent": ("profile", ".github/agents/MasterAgent.agent.md"),
    "read-researcher": (
        "profile",
        ".github/agents/MasterAgent-Read-Researcher.agent.md",
    ),
    "plan-reviewer": (
        "profile",
        ".github/agents/MasterAgent-Plan-Reviewer.agent.md",
    ),
    "docs-contract": ("contract", ".ai/DOCS_AGENT.md"),
    "deterministic-runtime": ("runtime", "src/master_agent/orchestrator.py"),
}
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_PATH_PART = re.compile(r"^[A-Za-z0-9._-]+$")
_TOKEN = re.compile(r"[a-z0-9]+")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}^~:+-]{0,255}$")
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IGNORED_DIRECTORY_NAMES: Final = {
    ".git",
    ".master-agent",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}


class ManifestError(ValueError):
    """Raised when the semantic-router manifest cannot be trusted."""


@dataclass(frozen=True, slots=True)
class AgentRecord:
    """One node in the bounded hub-and-spoke agent topology."""

    id: str
    kind: str
    profile: str
    parent: str
    tools: tuple[str, ...]
    max_delegation_depth: int
    fallback: str
    sibling_awareness: bool
    input_contract: str
    output_contract: str
    return_path: str


@dataclass(frozen=True, slots=True)
class RouteRecord:
    """One semantic repository route."""

    id: str
    title: str
    lifecycle: str
    summary: str
    authority: tuple[str, ...]
    implementation: tuple[str, ...]
    configuration: tuple[str, ...]
    tests: tuple[str, ...]
    release_gates: tuple[str, ...]
    dependencies: tuple[str, ...]
    aliases: tuple[str, ...]
    agent: str


@dataclass(frozen=True, slots=True)
class RoutingCase:
    """A deterministic routing fixture stored in the manifest."""

    query: str
    route: str


@dataclass(frozen=True, slots=True)
class SemanticManifest:
    """Parsed semantic-router manifest."""

    version: int
    generated_document: str
    allowed_lifecycles: tuple[str, ...]
    agents: tuple[AgentRecord, ...]
    routes: tuple[RouteRecord, ...]
    ownership: Mapping[str, Mapping[str, str]]
    routing_cases: tuple[RoutingCase, ...]

    @property
    def agents_by_id(self) -> dict[str, AgentRecord]:
        """Return agent records keyed by their stable identifiers."""

        return {agent.id: agent for agent in self.agents}

    @property
    def routes_by_id(self) -> dict[str, RouteRecord]:
        """Return route records keyed by their stable identifiers."""

        return {route.id: route for route in self.routes}


@dataclass(frozen=True, slots=True)
class RouteMatch:
    """A deterministic route-selection result."""

    route: RouteRecord
    score: int
    matched_alias: str


def _expect_table(value: object, location: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ManifestError(f"{location} must be a table")
    if len(value) > MAX_ITEMS:
        raise ManifestError(f"{location} exceeds {MAX_ITEMS} entries")
    return value


def _expect_exact_keys(
    table: Mapping[str, object], location: str, expected: set[str]
) -> None:
    actual = set(table)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unknown {', '.join(extra)}")
        raise ManifestError(f"{location} schema mismatch: {'; '.join(details)}")


def _expect_string(value: object, location: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{location} must be a string")
    if not allow_empty and not value:
        raise ManifestError(f"{location} must not be empty")
    if len(value) > MAX_STRING_LENGTH:
        raise ManifestError(f"{location} exceeds {MAX_STRING_LENGTH} characters")
    if any(ord(character) < 32 for character in value):
        raise ManifestError(f"{location} contains a control character")
    return value


def _expect_identifier(value: object, location: str) -> str:
    identifier = _expect_string(value, location)
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise ManifestError(f"{location} is not a bounded lowercase identifier")
    return identifier


def _expect_string_list(
    value: object,
    location: str,
    *,
    allow_empty: bool = True,
    identifiers: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ManifestError(f"{location} must be an array")
    if not allow_empty and not value:
        raise ManifestError(f"{location} must not be empty")
    if len(value) > MAX_ITEMS:
        raise ManifestError(f"{location} exceeds {MAX_ITEMS} entries")
    result: list[str] = []
    for index, item in enumerate(value):
        item_location = f"{location}[{index}]"
        parsed = (
            _expect_identifier(item, item_location)
            if identifiers
            else _expect_string(item, item_location)
        )
        result.append(parsed)
    if len(set(result)) != len(result):
        raise ManifestError(f"{location} contains duplicate values")
    return tuple(result)


def _parse_agent(raw: object, index: int) -> AgentRecord:
    table = _expect_table(raw, f"agents[{index}]")
    fields = {
        "id",
        "kind",
        "profile",
        "parent",
        "tools",
        "max_delegation_depth",
        "fallback",
        "sibling_awareness",
        "input_contract",
        "output_contract",
        "return_path",
    }
    _expect_exact_keys(table, f"agents[{index}]", fields)
    kind = _expect_string(table["kind"], f"agents[{index}].kind")
    if kind not in AGENT_KINDS:
        raise ManifestError(
            f"agents[{index}].kind must be one of {', '.join(AGENT_KINDS)}"
        )
    depth = table["max_delegation_depth"]
    if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= 1:
        raise ManifestError(f"agents[{index}].max_delegation_depth must be 0 or 1")
    sibling_awareness = table["sibling_awareness"]
    if not isinstance(sibling_awareness, bool):
        raise ManifestError(f"agents[{index}].sibling_awareness must be a boolean")
    return AgentRecord(
        id=_expect_identifier(table["id"], f"agents[{index}].id"),
        kind=kind,
        profile=_expect_string(table["profile"], f"agents[{index}].profile"),
        parent=_expect_string(
            table["parent"], f"agents[{index}].parent", allow_empty=True
        ),
        tools=_expect_string_list(
            table["tools"], f"agents[{index}].tools", identifiers=True
        ),
        max_delegation_depth=depth,
        fallback=_expect_string(
            table["fallback"], f"agents[{index}].fallback", allow_empty=True
        ),
        sibling_awareness=sibling_awareness,
        input_contract=_expect_string(
            table["input_contract"], f"agents[{index}].input_contract"
        ),
        output_contract=_expect_string(
            table["output_contract"], f"agents[{index}].output_contract"
        ),
        return_path=_expect_string(
            table["return_path"], f"agents[{index}].return_path", allow_empty=True
        ),
    )


def _parse_route(raw: object, index: int, allowed_lifecycles: set[str]) -> RouteRecord:
    table = _expect_table(raw, f"routes[{index}]")
    fields = {
        "id",
        "title",
        "lifecycle",
        "summary",
        "authority",
        "implementation",
        "configuration",
        "tests",
        "release_gates",
        "dependencies",
        "aliases",
        "agent",
    }
    _expect_exact_keys(table, f"routes[{index}]", fields)
    lifecycle = _expect_string(table["lifecycle"], f"routes[{index}].lifecycle")
    if lifecycle not in allowed_lifecycles:
        raise ManifestError(f"routes[{index}].lifecycle {lifecycle!r} is not allowed")
    return RouteRecord(
        id=_expect_identifier(table["id"], f"routes[{index}].id"),
        title=_expect_string(table["title"], f"routes[{index}].title"),
        lifecycle=lifecycle,
        summary=_expect_string(table["summary"], f"routes[{index}].summary"),
        authority=_expect_string_list(
            table["authority"], f"routes[{index}].authority", allow_empty=False
        ),
        implementation=_expect_string_list(
            table["implementation"], f"routes[{index}].implementation"
        ),
        configuration=_expect_string_list(
            table["configuration"], f"routes[{index}].configuration"
        ),
        tests=_expect_string_list(table["tests"], f"routes[{index}].tests"),
        release_gates=_expect_string_list(
            table["release_gates"], f"routes[{index}].release_gates"
        ),
        dependencies=_expect_string_list(
            table["dependencies"],
            f"routes[{index}].dependencies",
            identifiers=True,
        ),
        aliases=_expect_string_list(
            table["aliases"], f"routes[{index}].aliases", allow_empty=False
        ),
        agent=_expect_identifier(table["agent"], f"routes[{index}].agent"),
    )


def _parse_ownership(raw: object) -> dict[str, dict[str, str]]:
    table = _expect_table(raw, "ownership")
    _expect_exact_keys(table, "ownership", set(OWNERSHIP_CATEGORIES))
    parsed: dict[str, dict[str, str]] = {}
    for category in OWNERSHIP_CATEGORIES:
        entries = _expect_table(table[category], f"ownership.{category}")
        category_map: dict[str, str] = {}
        for raw_key, raw_route in entries.items():
            key = _expect_string(raw_key, f"ownership.{category} key")
            route = _expect_identifier(raw_route, f"ownership.{category}.{raw_key}")
            category_map[key] = route
        parsed[category] = category_map
    return parsed


def _parse_routing_case(raw: object, index: int) -> RoutingCase:
    table = _expect_table(raw, f"routing_cases[{index}]")
    _expect_exact_keys(table, f"routing_cases[{index}]", {"query", "route"})
    query = _expect_string(table["query"], f"routing_cases[{index}].query")
    if len(query) > MAX_QUERY_LENGTH:
        raise ManifestError(
            f"routing_cases[{index}].query exceeds {MAX_QUERY_LENGTH} characters"
        )
    return RoutingCase(
        query=query,
        route=_expect_identifier(table["route"], f"routing_cases[{index}].route"),
    )


def _read_bounded_regular_file(path: Path, *, limit: int) -> bytes:
    _mode, data = _read_bounded_regular_file_state(path, limit=limit)
    return data


def _read_bounded_regular_file_state(
    path: Path,
    *,
    limit: int,
) -> tuple[int, bytes]:
    """Read one stable regular file and return its observed POSIX mode."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ManifestError(f"refusing symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ManifestError(f"not a regular file: {path}")
    if metadata.st_size > limit:
        raise ManifestError(f"file exceeds {limit} bytes: {path}")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if not stat.S_ISREG(opened.st_mode) or not _same_file_state(metadata, opened):
            raise ManifestError(f"not a regular file: {path}")
        if not _same_file_state(opened, current):
            raise ManifestError(f"file identity changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            data = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
        public = path.lstat()
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > limit:
        raise ManifestError(f"file exceeds {limit} bytes: {path}")
    if not _same_file_state(opened, after) or not _same_file_state(opened, public):
        raise ManifestError(f"file changed while reading: {path}")
    return stat.S_IMODE(opened.st_mode), data


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    """Return whether two observations describe one unchanged regular file."""

    return (
        stat.S_ISREG(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _safe_repository_file(root: Path, raw_path: str) -> Path:
    """Resolve one manifest path without escaping or following symlinks.

    Parameters
    ----------
    root:
        Trusted repository root.
    raw_path:
        Canonical POSIX repository-relative path.

    Returns
    -------
    pathlib.Path
        The checked regular file.
    """

    _expect_string(raw_path, "repository path")
    if "\\" in raw_path:
        raise ManifestError(f"repository path must use POSIX separators: {raw_path}")
    pure = PurePosixPath(raw_path)
    if pure.is_absolute() or raw_path != pure.as_posix():
        raise ManifestError(f"repository path is not canonical: {raw_path}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ManifestError(f"repository path is unsafe: {raw_path}")
    if any(_PATH_PART.fullmatch(part) is None for part in pure.parts):
        raise ManifestError(f"repository path contains unsafe characters: {raw_path}")
    candidate = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ManifestError(f"stale repository path {raw_path}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ManifestError(f"repository path crosses a symbolic link: {raw_path}")
    if not stat.S_ISREG(candidate.stat().st_mode):
        raise ManifestError(f"repository path is not a regular file: {raw_path}")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ManifestError(
            f"repository path escapes the repository: {raw_path}"
        ) from exc
    return candidate


def load_manifest(
    root: Path,
    manifest_path: Path | None = None,
    *,
    manifest_bytes: bytes | None = None,
) -> SemanticManifest:
    """Load and strictly parse the semantic-router manifest.

    Parameters
    ----------
    root:
        Repository root containing the manifest and referenced files.
    manifest_path:
        Optional manifest path. Relative paths are resolved below ``root``.
    manifest_bytes:
        Optional already-captured manifest bytes. This is reserved for callers
        that bind parsing to an immutable repository object.

    Returns
    -------
    SemanticManifest
        Strictly typed manifest content.

    Raises
    ------
    ManifestError
        If the manifest path, TOML, or schema is invalid.
    """

    trusted_root = root.resolve(strict=True)
    if manifest_bytes is None:
        selected = manifest_path or Path(MANIFEST_PATH)
        if selected.is_absolute():
            try:
                relative = selected.relative_to(trusted_root)
            except ValueError as exc:
                raise ManifestError("manifest path escapes the repository") from exc
            selected_raw = relative.as_posix()
        else:
            selected_raw = selected.as_posix()
        manifest_file = _safe_repository_file(trusted_root, selected_raw)
        raw_bytes = _read_bounded_regular_file(
            manifest_file,
            limit=MAX_MANIFEST_BYTES,
        )
    else:
        if manifest_path is not None:
            raise ManifestError(
                "manifest path and captured manifest bytes are mutually exclusive"
            )
        if not isinstance(manifest_bytes, bytes):
            raise ManifestError("captured semantic-router manifest must be bytes")
        if not manifest_bytes or len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ManifestError(
                "captured semantic-router manifest must contain "
                f"1-{MAX_MANIFEST_BYTES} bytes"
            )
        raw_bytes = manifest_bytes
    try:
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"invalid semantic-router TOML: {exc}") from exc
    root_table = _expect_table(raw, "manifest root")
    _expect_exact_keys(
        root_table,
        "manifest root",
        {"manifest", "agents", "routes", "ownership", "routing_cases"},
    )
    metadata = _expect_table(root_table["manifest"], "manifest")
    _expect_exact_keys(
        metadata,
        "manifest",
        {"version", "generated_document", "allowed_lifecycles"},
    )
    version = metadata["version"]
    if isinstance(version, bool) or version != 1:
        raise ManifestError("manifest.version must be integer 1")
    generated_document = _expect_string(
        metadata["generated_document"], "manifest.generated_document"
    )
    if generated_document != GENERATED_DOCUMENT_PATH:
        raise ManifestError(
            f"manifest.generated_document must be exactly {GENERATED_DOCUMENT_PATH}"
        )
    allowed_lifecycles = _expect_string_list(
        metadata["allowed_lifecycles"],
        "manifest.allowed_lifecycles",
        allow_empty=False,
        identifiers=True,
    )
    if allowed_lifecycles != LIFECYCLES:
        raise ManifestError(
            "manifest.allowed_lifecycles must be released, implementing, planned, archived"
        )
    raw_agents = root_table["agents"]
    raw_routes = root_table["routes"]
    raw_cases = root_table["routing_cases"]
    if not isinstance(raw_agents, list) or not raw_agents:
        raise ManifestError("agents must be a non-empty array of tables")
    if not isinstance(raw_routes, list) or not raw_routes:
        raise ManifestError("routes must be a non-empty array of tables")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ManifestError("routing_cases must be a non-empty array of tables")
    if any(len(items) > MAX_ITEMS for items in (raw_agents, raw_routes, raw_cases)):
        raise ManifestError(f"manifest arrays must not exceed {MAX_ITEMS} entries")
    agents = tuple(_parse_agent(item, index) for index, item in enumerate(raw_agents))
    allowed_set = set(allowed_lifecycles)
    routes = tuple(
        _parse_route(item, index, allowed_set) for index, item in enumerate(raw_routes)
    )
    cases = tuple(
        _parse_routing_case(item, index) for index, item in enumerate(raw_cases)
    )
    if len({agent.id for agent in agents}) != len(agents):
        raise ManifestError("agent identifiers must be unique")
    if len({agent.profile for agent in agents}) != len(agents):
        raise ManifestError("agent profile paths must be unique")
    if len({route.id for route in routes}) != len(routes):
        raise ManifestError("route identifiers must be unique")
    return SemanticManifest(
        version=1,
        generated_document=generated_document,
        allowed_lifecycles=allowed_lifecycles,
        agents=agents,
        routes=routes,
        ownership=_parse_ownership(root_table["ownership"]),
        routing_cases=cases,
    )


def load_manifest_at_revision(root: Path, revision: str) -> SemanticManifest:
    """Load the manifest from one immutable commit and reject worktree drift."""

    trusted_root = root.resolve(strict=True)
    if not isinstance(revision, str) or _OBJECT_ID.fullmatch(revision) is None:
        raise ManifestError("bound manifest revision must be one exact object ID")
    committed_mode, committed_id, committed = _verified_blob_at_revision(
        trusted_root,
        revision,
        MANIFEST_PATH,
        limit=MAX_MANIFEST_BYTES,
    )
    staged_mode, staged_id = _index_entry(trusted_root, MANIFEST_PATH)
    manifest_file = _safe_repository_file(trusted_root, MANIFEST_PATH)
    current_mode, current = _read_bounded_regular_file_state(
        manifest_file,
        limit=MAX_MANIFEST_BYTES,
    )
    current_git_mode = b"100755" if current_mode & 0o111 else b"100644"
    if (
        staged_mode != committed_mode
        or staged_id != committed_id
        or current_git_mode != committed_mode
        or current != committed
    ):
        raise ManifestError(
            "live advisory routing requires the semantic manifest to match bound HEAD"
        )
    return load_manifest(trusted_root, manifest_bytes=committed)


def _verified_blob_at_revision(
    root: Path,
    revision: str,
    path: str,
    *,
    limit: int,
) -> tuple[bytes, str, bytes]:
    """Resolve and verify every object from one commit to one regular blob."""

    commit = _verified_git_object(
        root,
        "commit",
        revision,
        limit=MAX_GIT_COMMIT_BYTES,
    )
    first_line, separator, _rest = commit.partition(b"\n")
    if not separator or not first_line.startswith(b"tree "):
        raise ManifestError("bound commit has no canonical root tree")
    tree_id = _validated_git_object_id(first_line.removeprefix(b"tree "), len(revision))
    parts = tuple(part.encode("utf-8") for part in PurePosixPath(path).parts)
    for index, component in enumerate(parts):
        entries = _verified_git_tree_entries(root, tree_id)
        selected = entries.get(component)
        if selected is None:
            raise ManifestError("bound manifest path is absent from immutable commit")
        mode, selected_id = selected
        if index == len(parts) - 1:
            if mode not in {b"100644", b"100755"}:
                raise ManifestError("bound manifest is not a regular Git blob")
            return (
                mode,
                selected_id,
                _verified_git_object(root, "blob", selected_id, limit=limit),
            )
        if mode != b"40000":
            raise ManifestError("bound manifest path traverses a non-tree object")
        tree_id = selected_id
    raise ManifestError("bound manifest path is invalid")


def _verified_git_tree_entries(
    root: Path,
    object_id: str,
) -> dict[bytes, tuple[bytes, str]]:
    """Parse one verified raw Git tree into unique byte-name entries."""

    payload = _verified_git_object(
        root,
        "tree",
        object_id,
        limit=MAX_GIT_TREE_BYTES,
    )
    object_bytes = len(object_id) // 2
    entries: dict[bytes, tuple[bytes, str]] = {}
    cursor = 0
    while cursor < len(payload):
        space = payload.find(b" ", cursor)
        nul = payload.find(b"\0", space + 1) if space >= 0 else -1
        object_end = nul + 1 + object_bytes
        if (
            space <= cursor
            or nul <= space + 1
            or object_end > len(payload)
            or len(entries) >= MAX_GIT_TREE_ENTRIES
        ):
            raise ManifestError("bound Git tree is malformed")
        mode = payload[cursor:space]
        name = payload[space + 1 : nul]
        raw_object_id = payload[nul + 1 : object_end]
        if (
            mode not in {b"40000", b"100644", b"100755", b"120000", b"160000"}
            or not name
            or b"/" in name
            or name in {b".", b".."}
            or name in entries
        ):
            raise ManifestError("bound Git tree is unsafe")
        entries[name] = (mode, raw_object_id.hex())
        cursor = object_end
    return entries


def _verified_git_object(
    root: Path,
    object_type: str,
    object_id: str,
    *,
    limit: int,
) -> bytes:
    """Read one Git object and recompute its requested content address."""

    if not isinstance(object_id, str) or _OBJECT_ID.fullmatch(object_id) is None:
        raise ManifestError("bound Git object ID is malformed")
    if object_type not in {"blob", "commit", "tree"}:
        raise ManifestError("bound Git object type is unsafe")
    payload = _bounded_git_output(
        root,
        ("cat-file", object_type, object_id),
        limit=limit,
    )
    framed = f"{object_type} {len(payload)}\0".encode("ascii") + payload
    if len(object_id) == 40:
        observed = hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    else:
        observed = hashlib.sha256(framed).hexdigest()
    if observed != object_id:
        raise ManifestError("bound Git object failed content-address verification")
    return payload


def _validated_git_object_id(raw: bytes, expected_length: int) -> str:
    """Validate one raw object ID extracted from a verified object."""

    if (
        len(raw) != expected_length
        or len(raw) not in (40, 64)
        or any(byte not in b"0123456789abcdef" for byte in raw)
    ):
        raise ManifestError("bound Git object ID is malformed")
    return raw.decode("ascii")


def _index_entry(root: Path, path: str) -> tuple[bytes, str]:
    """Return one exact stage-zero index entry without reading its blob."""

    raw = _bounded_git_output(
        root,
        ("ls-files", "--stage", "-z", "--", f":(literal){path}"),
        limit=MAX_MANIFEST_BYTES,
    )
    record = raw[:-1] if raw.endswith(b"\0") else b""
    metadata, separator, name = record.partition(b"\t")
    fields = metadata.split(b" ")
    if (
        not raw.endswith(b"\0")
        or raw.count(b"\0") != 1
        or not separator
        or name != path.encode("utf-8")
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or _OBJECT_ID.fullmatch(os.fsdecode(fields[1])) is None
        or fields[2] != b"0"
    ):
        raise ManifestError("bound manifest index entry is missing or malformed")
    return fields[0], fields[1].decode("ascii")


def _bounded_file_inventory(
    root: Path,
    start: str,
    suffix: str,
    *,
    excluded_first_parts: frozenset[str] = frozenset(),
) -> set[str]:
    base = root / start if start else root
    if not base.exists():
        return set()
    try:
        metadata = base.lstat()
    except OSError as exc:
        raise ManifestError(f"cannot inspect inventory root {base}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ManifestError(f"inventory root is not a safe directory: {base}")
    found: set[str] = set()
    pending = [base]
    visited = 0
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ManifestError(
                f"cannot scan inventory directory {directory}: {exc}"
            ) from exc
        for entry in entries:
            visited += 1
            if visited > MAX_WALK_ENTRIES:
                raise ManifestError(
                    f"repository inventory exceeds {MAX_WALK_ENTRIES} entries"
                )
            path = Path(entry.path)
            relative = path.relative_to(root)
            if relative.parts and relative.parts[0] in excluded_first_parts:
                continue
            if entry.name in _IGNORED_DIRECTORY_NAMES:
                continue
            if entry.is_symlink():
                if entry.name.endswith(suffix):
                    found.add(relative.as_posix())
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False) and entry.name.endswith(
                    suffix
                ):
                    found.add(relative.as_posix())
            except OSError as exc:
                raise ManifestError(
                    f"cannot inspect inventory entry {path}: {exc}"
                ) from exc
    return found


def _cli_commands(root: Path) -> set[str]:
    cli_path = _safe_repository_file(root, "src/master_agent/cli.py")
    source = _read_bounded_regular_file(cli_path, limit=2 * MAX_MANIFEST_BYTES)
    try:
        tree = ast.parse(source, filename=cli_path.as_posix())
    except SyntaxError as exc:
        raise ManifestError(f"cannot parse CLI command inventory: {exc}") from exc
    commands: set[str] = set()
    dynamic_calls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "add_parser":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            dynamic_calls += 1
            continue
        command = node.args[0].value
        if isinstance(command, str):
            commands.add(command)
        else:
            dynamic_calls += 1
            continue
        aliases = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "aliases"),
            None,
        )
        if aliases is None:
            continue
        if not isinstance(aliases, (ast.List, ast.Tuple)):
            dynamic_calls += 1
            continue
        for alias_node in aliases.elts:
            if not isinstance(alias_node, ast.Constant) or not isinstance(
                alias_node.value, str
            ):
                dynamic_calls += 1
                break
            commands.add(alias_node.value)
    if dynamic_calls:
        raise ManifestError("CLI contains non-literal add_parser command declarations")
    if not commands:
        raise ManifestError("CLI command inventory is empty")
    return commands


def _capabilities(root: Path) -> set[str]:
    path = _safe_repository_file(root, "config/capabilities.toml")
    data = _read_bounded_regular_file(path, limit=MAX_MANIFEST_BYTES)
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"cannot parse capability inventory: {exc}") from exc
    capabilities = parsed.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ManifestError("config/capabilities.toml has no capabilities table")
    result: set[str] = set()
    for identifier in capabilities:
        result.add(_expect_identifier(identifier, "capability identifier"))
    return result


def collect_inventory(root: Path) -> dict[str, set[str]]:
    """Collect all manifest-owned repository surfaces without using Git.

    Parameters
    ----------
    root:
        Repository root to inspect.

    Returns
    -------
    dict[str, set[str]]
        Exact inventory keyed by ownership category.
    """

    trusted_root = root.resolve(strict=True)
    production = _bounded_file_inventory(
        trusted_root,
        "",
        ".py",
        excluded_first_parts=frozenset({"tests"}),
    )
    tests = _bounded_file_inventory(trusted_root, "tests", ".py")
    requirements = _bounded_file_inventory(trusted_root, "specs/current", ".md")
    configurations = _bounded_file_inventory(
        trusted_root,
        "",
        ".toml",
        excluded_first_parts=frozenset({"specs"}),
    )
    connectors = _bounded_file_inventory(
        trusted_root, "src/master_agent/connectors", ".py"
    )
    profiles = _bounded_file_inventory(trusted_root, ".github/agents", ".agent.md")
    return {
        "production_modules": production,
        "tests": tests,
        "current_requirements": requirements,
        "configurations": configurations,
        "cli_commands": _cli_commands(trusted_root),
        "capabilities": _capabilities(trusted_root),
        "connectors": connectors,
        "agent_profiles": profiles,
        "platform_capabilities": set(REQUIRED_PLATFORM_CAPABILITIES),
    }


def _parse_profile_boolean(path: Path, field: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized not in {"true", "false"}:
        raise ManifestError(f"agent profile {path} has invalid {field}")
    return normalized == "true"


def _parse_profile_front_matter(path: Path) -> tuple[set[str], bool, bool]:
    data = _read_bounded_regular_file(path, limit=MAX_MANIFEST_BYTES)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"agent profile is not UTF-8: {path}") from exc
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ManifestError(f"agent profile has no front matter: {path}")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise ManifestError(
            f"agent profile front matter is unterminated: {path}"
        ) from exc
    tools: list[str] = []
    user_invocable: bool | None = None
    model_disabled: bool | None = None
    in_tools = False
    for line in lines[1:end]:
        if line == "tools:":
            in_tools = True
            continue
        if in_tools and line.startswith("  - "):
            tool = line[4:].strip()
            if _IDENTIFIER.fullmatch(tool) is None:
                raise ManifestError(f"agent profile {path} has invalid tool {tool!r}")
            tools.append(tool)
            continue
        in_tools = False
        if line.startswith("user-invocable:"):
            user_invocable = _parse_profile_boolean(
                path, "user-invocable", line.partition(":")[2]
            )
        elif line.startswith("disable-model-invocation:"):
            model_disabled = _parse_profile_boolean(
                path, "disable-model-invocation", line.partition(":")[2]
            )
    if user_invocable is None or model_disabled is None:
        raise ManifestError(f"agent profile invocation gates are incomplete: {path}")
    if len(set(tools)) != len(tools):
        raise ManifestError(f"agent profile has duplicate tools: {path}")
    return set(tools), user_invocable, model_disabled


def _validate_topology(
    root: Path, manifest: SemanticManifest, inventory: Mapping[str, set[str]]
) -> list[str]:
    errors: list[str] = []
    agents = manifest.agents_by_id
    actual_agent_ids = set(agents)
    expected_agent_ids = set(REQUIRED_AGENT_PROFILES)
    if actual_agent_ids != expected_agent_ids:
        missing = sorted(expected_agent_ids - actual_agent_ids)
        extra = sorted(actual_agent_ids - expected_agent_ids)
        if missing:
            errors.append(f"topology is missing agents: {', '.join(missing)}")
        if extra:
            errors.append(f"topology has unexpected agents: {', '.join(extra)}")
    for agent_id, (expected_kind, expected_profile) in REQUIRED_AGENT_PROFILES.items():
        agent = agents.get(agent_id)
        if agent is None:
            continue
        if (agent.kind, agent.profile) != (expected_kind, expected_profile):
            errors.append(
                f"agent {agent_id} must use kind {expected_kind} at {expected_profile}"
            )
    roots = [agent for agent in manifest.agents if not agent.parent]
    if len(roots) != 1:
        errors.append("topology must contain exactly one parent agent")
        return errors
    parent = roots[0]
    if parent.kind != "profile":
        errors.append("topology parent must be a checked-in profile")
    if parent.max_delegation_depth != 1:
        errors.append("topology parent max_delegation_depth must be 1")
    if parent.return_path:
        errors.append("topology parent return_path must be empty")
    if len(manifest.agents) != 5:
        errors.append("topology must contain exactly five nodes")
    profile_paths = {
        agent.profile for agent in manifest.agents if agent.kind == "profile"
    }
    expected_profiles = inventory["agent_profiles"]
    if profile_paths != expected_profiles:
        missing = sorted(expected_profiles - profile_paths)
        stale = sorted(profile_paths - expected_profiles)
        if missing:
            errors.append(f"unmapped agent profiles: {', '.join(missing)}")
        if stale:
            errors.append(f"stale agent profiles: {', '.join(stale)}")
    for agent in manifest.agents:
        try:
            profile_path = _safe_repository_file(root, agent.profile)
        except ManifestError as exc:
            errors.append(f"agent {agent.id}: {exc}")
            continue
        if agent.id == parent.id:
            pass
        else:
            if agent.parent != parent.id:
                errors.append(f"agent {agent.id} must have parent {parent.id}")
            if agent.max_delegation_depth != 0:
                errors.append(f"agent {agent.id} must not delegate")
            if agent.sibling_awareness:
                errors.append(f"agent {agent.id} must not have sibling awareness")
            if agent.fallback != parent.id:
                errors.append(f"agent {agent.id} fallback must be {parent.id}")
            if agent.return_path != parent.id:
                errors.append(f"agent {agent.id} return_path must be {parent.id}")
        if agent.parent and agent.parent not in agents:
            errors.append(f"agent {agent.id} references unknown parent {agent.parent}")
        if agent.kind == "profile":
            try:
                tools, user_invocable, model_disabled = _parse_profile_front_matter(
                    profile_path
                )
            except ManifestError as exc:
                errors.append(str(exc))
                continue
            if tools != set(agent.tools):
                errors.append(
                    f"agent {agent.id} tool inventory differs from its profile"
                )
            if not model_disabled:
                errors.append(f"agent {agent.id} must disable model invocation")
            if agent.id == parent.id and not user_invocable:
                errors.append("topology parent profile must be user invocable")
            if agent.id != parent.id and user_invocable:
                errors.append(
                    f"specialist profile {agent.id} must not be user invocable"
                )
    child_kinds = [agent.kind for agent in manifest.agents if agent.id != parent.id]
    if child_kinds.count("profile") != 2:
        errors.append("topology must contain exactly two specialist profiles")
    if child_kinds.count("contract") != 1:
        errors.append("topology must contain exactly one direct contract node")
    if child_kinds.count("runtime") != 1:
        errors.append("topology must contain exactly one deterministic runtime node")
    return errors


def _validate_inventory(
    root: Path, manifest: SemanticManifest, inventory: Mapping[str, set[str]]
) -> list[str]:
    errors: list[str] = []
    routes = manifest.routes_by_id
    for category in OWNERSHIP_CATEGORIES:
        actual = set(manifest.ownership[category])
        expected = inventory[category]
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            errors.append(f"unmapped {category}: {', '.join(missing)}")
        if extra:
            errors.append(f"stale {category}: {', '.join(extra)}")
        for item, route_id in sorted(manifest.ownership[category].items()):
            if route_id not in routes:
                errors.append(
                    f"ownership.{category}.{item} references unknown route {route_id}"
                )
            if category in PATH_OWNERSHIP_CATEGORIES:
                try:
                    _safe_repository_file(root, item)
                except ManifestError as exc:
                    errors.append(f"ownership.{category}.{item}: {exc}")
            elif _IDENTIFIER.fullmatch(item) is None:
                errors.append(f"ownership.{category} has invalid identifier {item!r}")
    production = manifest.ownership["production_modules"]
    for connector, route_id in manifest.ownership["connectors"].items():
        if production.get(connector) != route_id:
            errors.append(
                f"connector {connector} must have the same production-module owner"
            )
    return errors


def _validate_route_contracts(root: Path, manifest: SemanticManifest) -> list[str]:
    errors: list[str] = []
    agents = manifest.agents_by_id
    ownership = manifest.ownership
    alias_owners: dict[str, str] = {}
    for route in manifest.routes:
        if route.agent not in agents:
            errors.append(f"route {route.id} references unknown agent {route.agent}")
        dependency_ids = set(route.dependencies)
        unknown_dependencies = sorted(dependency_ids - set(manifest.routes_by_id))
        if unknown_dependencies:
            errors.append(
                f"route {route.id} references unknown dependencies: "
                f"{', '.join(unknown_dependencies)}"
            )
        if route.id in dependency_ids:
            errors.append(f"route {route.id} cannot depend on itself")
        if route.lifecycle == "released":
            if not route.implementation:
                errors.append(f"released route {route.id} has no implementation")
            if not route.tests:
                errors.append(f"released route {route.id} has no tests")
            if not route.release_gates:
                errors.append(f"released route {route.id} has no release gates")
        for field in ROUTE_PATH_FIELDS:
            for path in getattr(route, field):
                try:
                    _safe_repository_file(root, path)
                except ManifestError as exc:
                    errors.append(f"route {route.id}.{field}: {exc}")
        cross_owned_dependencies: set[str] = set()
        for path in route.authority:
            for category in PATH_OWNERSHIP_CATEGORIES:
                owner = ownership[category].get(path)
                if owner is not None and owner != route.id:
                    cross_owned_dependencies.add(owner)
        for path in route.implementation:
            owner = ownership["production_modules"].get(path)
            if owner is None:
                errors.append(
                    f"route {route.id}.implementation path {path} is not an owned "
                    "production module"
                )
            elif owner != route.id:
                errors.append(
                    f"route {route.id}.implementation path {path} is owned by "
                    f"route {owner}"
                )
        for path in route.configuration:
            owner = ownership["configurations"].get(path)
            if owner is None:
                errors.append(
                    f"route {route.id}.configuration path {path} is not an owned "
                    "configuration"
                )
            elif owner != route.id:
                cross_owned_dependencies.add(owner)
        for path in route.tests:
            owner = ownership["tests"].get(path)
            if owner is None:
                errors.append(
                    f"route {route.id}.tests path {path} is not an owned test module"
                )
            elif owner != route.id:
                errors.append(
                    f"route {route.id}.tests path {path} is owned by route {owner}"
                )
        for path in route.release_gates:
            referenced_owners = {
                ownership[category][path]
                for category in PATH_OWNERSHIP_CATEGORIES
                if path in ownership[category]
            }
            cross_owned_dependencies.update(referenced_owners - {route.id})
        missing_dependencies = sorted(cross_owned_dependencies - dependency_ids)
        stale_dependencies = sorted(dependency_ids - cross_owned_dependencies)
        if missing_dependencies:
            errors.append(
                f"route {route.id} is missing cross-owned dependencies: "
                f"{', '.join(missing_dependencies)}"
            )
        if stale_dependencies:
            errors.append(
                f"route {route.id} has unused dependencies: "
                f"{', '.join(stale_dependencies)}"
            )
        for alias in route.aliases:
            normalized = " ".join(_TOKEN.findall(alias.lower()))
            if not normalized:
                errors.append(f"route {route.id} contains an empty normalized alias")
                continue
            other = alias_owners.setdefault(normalized, route.id)
            if other != route.id:
                errors.append(
                    f"ambiguous alias {alias!r} belongs to routes {other} and {route.id}"
                )
    released_surfaces = (
        "production_modules",
        "current_requirements",
        "configurations",
        "cli_commands",
        "capabilities",
        "connectors",
        "agent_profiles",
    )
    for category in released_surfaces:
        for item, owner_id in ownership[category].items():
            owner_route = manifest.routes_by_id.get(owner_id)
            if owner_route is not None and owner_route.lifecycle in {
                "planned",
                "archived",
            }:
                errors.append(
                    f"{category} entry {item} cannot be owned by "
                    f"{owner_route.lifecycle} route {owner_id}"
                )
    for path, owner_id in ownership["configurations"].items():
        owner_route = manifest.routes_by_id.get(owner_id)
        if owner_route is not None and path not in owner_route.configuration:
            errors.append(
                f"configuration {path} is not linked by its owner route {owner_id}"
            )
    route_tests = set(ownership["tests"].values())
    active_owners: set[str] = set()
    for category in (
        "production_modules",
        "current_requirements",
        "configurations",
        "cli_commands",
        "capabilities",
        "connectors",
        "agent_profiles",
    ):
        active_owners.update(ownership[category].values())
    for route_id in sorted(active_owners - route_tests):
        errors.append(f"active route {route_id} has no owned test route")
    for route in manifest.routes:
        if route.id not in active_owners:
            continue
        if not any(ownership["tests"].get(path) == route.id for path in route.tests):
            errors.append(f"active route {route.id} does not reference an owned test")
    platform_owners = ownership["platform_capabilities"]
    shipped_platform_contracts = {
        "direct_read": "src/master_agent/direct_read.py",
        "governed_applied_run": "src/master_agent/orchestrator.py",
        "advisory_sdk": "scripts/advisory_subagent.py",
        "specification_lifecycle": "scripts/specs.py",
        "windows.filesystem": ("src/master_agent/platform_runtime/windows/runtime.py"),
        "windows.atomic_state_retention": (
            "src/master_agent/platform_runtime/windows/atomic.py"
        ),
        "windows.credentials": (
            "src/master_agent/platform_runtime/windows/credentials.py"
        ),
        "windows.process_supervision": (
            "src/master_agent/platform_runtime/windows/process.py"
        ),
        "windows.git_isolation": "src/master_agent/platform_runtime/windows/git.py",
        "windows.capsule_isolation": (
            "src/master_agent/platform_runtime/windows/capsules.py"
        ),
    }
    shipped_owner_ids: list[str] = []
    for capability, implementation_path in shipped_platform_contracts.items():
        platform_owner_id = platform_owners.get(capability)
        if platform_owner_id is None:
            continue
        shipped_owner_ids.append(platform_owner_id)
        platform_route = manifest.routes_by_id.get(platform_owner_id)
        if platform_route is None:
            continue
        if platform_route.lifecycle != "released":
            errors.append(
                f"platform capability {capability} must be released, "
                f"not {platform_route.lifecycle}"
            )
        if implementation_path not in platform_route.implementation:
            errors.append(
                f"platform capability {capability} route {platform_owner_id} must link "
                f"{implementation_path}"
            )
    if len(set(shipped_owner_ids)) != len(shipped_platform_contracts):
        errors.append("released platform capabilities must have distinct route owners")
    windows_owners: list[str] = []
    for capability in REQUIRED_WINDOWS_PLATFORM_CAPABILITIES:
        platform_owner_id = ownership["platform_capabilities"].get(capability)
        if platform_owner_id is None:
            continue
        windows_owners.append(platform_owner_id)
    for capability in REQUIRED_PLANNED_PLATFORM_CAPABILITIES:
        platform_owner_id = ownership["platform_capabilities"].get(capability)
        if platform_owner_id is None:
            continue
        platform_route = manifest.routes_by_id.get(platform_owner_id)
        if platform_route is not None and platform_route.lifecycle != "planned":
            errors.append(
                f"platform capability {capability} must remain planned, "
                f"not {platform_route.lifecycle}"
            )
    if len(set(windows_owners)) != len(REQUIRED_WINDOWS_PLATFORM_CAPABILITIES):
        errors.append("Windows platform capabilities must have distinct route owners")
    return errors


def _normalized_words(value: str) -> tuple[str, ...]:
    return tuple(_TOKEN.findall(value.lower()))


def _score_route(route: RouteRecord, query: str) -> tuple[int, str]:
    query_words = _normalized_words(query)
    if not query_words:
        return 0, ""
    query_set = set(query_words)
    normalized_query = " ".join(query_words)
    best_score = 0
    best_alias = ""
    candidates = (*route.aliases, route.title, route.id)
    for alias in candidates:
        alias_words = _normalized_words(alias)
        if not alias_words:
            continue
        alias_set = set(alias_words)
        overlap = len(alias_set & query_set)
        if not overlap:
            continue
        phrase = " ".join(alias_words)
        exact_phrase = phrase in normalized_query
        coverage = overlap * 100 // len(alias_set)
        score = overlap * 20 + coverage + (200 if exact_phrase else 0)
        if score > best_score or (score == best_score and alias < best_alias):
            best_score = score
            best_alias = alias
    return best_score, best_alias


def select_route(manifest: SemanticManifest, query: str) -> RouteMatch:
    """Select exactly one route for a bounded natural-language query.

    Parameters
    ----------
    manifest:
        Parsed semantic-router manifest.
    query:
        Operator or maintainer routing query.

    Returns
    -------
    RouteMatch
        Highest-scoring unambiguous route.

    Raises
    ------
    ManifestError
        If the query is empty, oversized, unmatched, or ambiguous.
    """

    _expect_string(query, "query")
    if len(query) > MAX_QUERY_LENGTH:
        raise ManifestError(f"query exceeds {MAX_QUERY_LENGTH} characters")
    scores = [(*_score_route(route, query), route) for route in manifest.routes]
    best_score = max((score for score, _alias, _route in scores), default=0)
    if best_score <= 0:
        raise ManifestError("query does not match a semantic route")
    winners = [item for item in scores if item[0] == best_score]
    if len(winners) != 1:
        identifiers = ", ".join(sorted(item[2].id for item in winners))
        raise ManifestError(f"query ambiguously matches routes: {identifiers}")
    score, alias, route = winners[0]
    return RouteMatch(route=route, score=score, matched_alias=alias)


def _bounded_git_output(root: Path, arguments: Sequence[str], *, limit: int) -> bytes:
    """Run one fixed read-only Git query with bounded output and duration."""

    try:
        trusted_root = root.resolve(strict=True)
    except OSError as exc:
        raise ManifestError(f"cannot resolve bounded Git root: {exc}") from exc
    if not trusted_root.is_dir():
        raise ManifestError("bounded Git root is not a directory")
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": str(trusted_root.parent),
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    command = [
        "git",
        "--no-pager",
        f"--work-tree={trusted_root}",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.ext.allow=never",
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=trusted_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        raise ManifestError(f"cannot start bounded Git discovery: {exc}") from exc
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        if process.stdout is None:
            raise ManifestError("bounded Git discovery has no output stream")
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ManifestError(
                    f"bounded Git discovery exceeded {GIT_TIMEOUT_SECONDS:g} seconds"
                )
            chunk = os.read(
                process.stdout.fileno(),
                min(64 * 1024, limit + 1 - len(output)),
            )
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                raise ManifestError(f"bounded Git discovery exceeds {limit} bytes")
        try:
            return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise ManifestError(
                f"bounded Git discovery exceeded {GIT_TIMEOUT_SECONDS:g} seconds"
            ) from exc
    except BaseException:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
            process.wait()
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
    if return_code != 0:
        detail = (
            bytes(output).decode("utf-8", errors="replace").replace("\x00", " ").strip()
        )
        if len(detail) > 512:
            detail = detail[:509] + "..."
        raise ManifestError(
            f"bounded Git discovery failed with exit {return_code}"
            + (f": {detail}" if detail else "")
        )
    return bytes(output)


def _resolve_commit(root: Path, revision: str) -> str:
    """Resolve one bounded revision token to an immutable commit identifier."""

    _expect_string(revision, "Git revision")
    if len(revision) > MAX_REVISION_LENGTH or _REVISION.fullmatch(revision) is None:
        raise ManifestError("Git revision is not a bounded safe token")
    output = _bounded_git_output(
        root,
        ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        limit=512,
    )
    resolved = output.decode("ascii", errors="strict").strip()
    if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", resolved) is None:
        raise ManifestError("Git revision did not resolve to one commit identifier")
    return resolved


def changed_paths_for_revision(
    root: Path, revision_spec: str
) -> tuple[str | None, str, tuple[str, ...]]:
    """Return bounded changed paths for one commit or an explicit two-dot range."""

    _expect_string(revision_spec, "Git revision or range")
    if len(revision_spec) > MAX_REVISION_LENGTH:
        raise ManifestError(
            f"Git revision or range exceeds {MAX_REVISION_LENGTH} characters"
        )
    if "..." in revision_spec or revision_spec.count("..") > 1:
        raise ManifestError("Git review range must use exactly BASE..HEAD")
    trusted_root = root.resolve(strict=True)
    if ".." in revision_spec:
        base_revision, head_revision = revision_spec.split("..", 1)
        if not base_revision or not head_revision:
            raise ManifestError("Git review range must include BASE and HEAD")
        base = _resolve_commit(trusted_root, base_revision)
        head = _resolve_commit(trusted_root, head_revision)
        arguments = [
            "diff",
            "--name-only",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "-z",
            base,
            head,
            "--",
        ]
    else:
        base = None
        head = _resolve_commit(trusted_root, revision_spec)
        arguments = [
            "diff-tree",
            "--root",
            "-m",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            "-z",
            head,
            "--",
        ]
    output = _bounded_git_output(trusted_root, arguments, limit=MAX_GIT_OUTPUT_BYTES)
    if output and not output.endswith(b"\x00"):
        raise ManifestError("bounded Git changed-path output is not NUL terminated")
    raw_paths = output[:-1].split(b"\x00") if output else []
    if len(raw_paths) > MAX_CHANGED_PATHS:
        raise ManifestError(
            f"Git review contains more than {MAX_CHANGED_PATHS} changed paths"
        )
    paths: set[str] = set()
    for raw_path in raw_paths:
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestError("Git changed path is not valid UTF-8") from exc
        _expect_string(path, "Git changed path")
        pure = PurePosixPath(path)
        if pure.is_absolute() or pure.as_posix() != path:
            raise ManifestError(f"Git changed path is not canonical: {path!r}")
        if any(part in {"", ".", ".."} for part in pure.parts):
            raise ManifestError(f"Git changed path is unsafe: {path!r}")
        paths.add(path)
    return base, head, tuple(sorted(paths))


def _route_contract_payload(
    manifest: SemanticManifest, route: RouteRecord
) -> dict[str, object]:
    """Build one route's selected-only navigation contract."""

    agent = manifest.agents_by_id.get(route.agent)
    if agent is None:
        raise ManifestError(f"route {route.id} references unknown agent {route.agent}")
    return {
        "route": route.id,
        "title": route.title,
        "lifecycle": route.lifecycle,
        "summary": route.summary,
        "authority": list(route.authority),
        "implementation": list(route.implementation),
        "configuration": list(route.configuration),
        "tests": list(route.tests),
        "release_gates": list(route.release_gates),
        "dependencies": list(route.dependencies),
        "agent": {
            "id": agent.id,
            "kind": agent.kind,
            "profile": agent.profile,
            "parent": agent.parent,
            "tools": list(agent.tools),
            "max_delegation_depth": agent.max_delegation_depth,
            "fallback": agent.fallback,
            "sibling_awareness": agent.sibling_awareness,
            "input_contract": agent.input_contract,
            "output_contract": agent.output_contract,
            "return_path": agent.return_path,
        },
    }


def route_payload(manifest: SemanticManifest, match: RouteMatch) -> dict[str, object]:
    """Build the selected route and local role contract without sibling context.

    Parameters
    ----------
    manifest:
        Parsed semantic-router manifest.
    match:
        Unambiguous selected route.

    Returns
    -------
    dict[str, object]
        JSON-compatible selected-only discovery payload.
    """

    payload = _route_contract_payload(manifest, match.route)
    payload.update({"score": match.score, "matched_alias": match.matched_alias})
    return payload


def changed_routes_payload(
    manifest: SemanticManifest,
    *,
    revision_spec: str,
    base: str | None,
    head: str,
    changed_paths: Sequence[str],
) -> dict[str, object]:
    """Map a bounded Git path inventory to every exact affected route."""

    route_paths: dict[str, set[str]] = {}
    unmapped_paths: list[str] = []
    routes = manifest.routes_by_id
    for path in changed_paths:
        route_ids = {
            category[path]
            for name, category in manifest.ownership.items()
            if name in PATH_OWNERSHIP_CATEGORIES and path in category
        }
        for route in manifest.routes:
            if any(path in getattr(route, field) for field in ROUTE_PATH_FIELDS):
                route_ids.add(route.id)
        if path == manifest.generated_document:
            route_ids.add("semantic-router")
        if path.startswith(("specs/changes/", "specs/archive/", "specs/templates/")):
            route_ids.add("specification-lifecycle")
        known_route_ids = route_ids & set(routes)
        if not known_route_ids:
            unmapped_paths.append(path)
            continue
        for route_id in known_route_ids:
            route_paths.setdefault(route_id, set()).add(path)
    affected: list[dict[str, object]] = []
    for route_id in sorted(route_paths):
        payload = _route_contract_payload(manifest, routes[route_id])
        payload["matched_paths"] = sorted(route_paths[route_id])
        affected.append(payload)
    return {
        "revision": revision_spec,
        "base": base,
        "head": head,
        "changed_paths": list(changed_paths),
        "routes": affected,
        "unmapped_paths": unmapped_paths,
    }


def _validate_routing(manifest: SemanticManifest) -> list[str]:
    errors: list[str] = []
    route_ids = set(manifest.routes_by_id)
    seen_queries: set[str] = set()
    covered_routes: set[str] = set()
    for case in manifest.routing_cases:
        normalized = " ".join(_normalized_words(case.query))
        if normalized in seen_queries:
            errors.append(f"duplicate routing fixture query: {case.query!r}")
            continue
        seen_queries.add(normalized)
        if case.route not in route_ids:
            errors.append(
                f"routing fixture {case.query!r} references unknown route {case.route}"
            )
            continue
        try:
            match = select_route(manifest, case.query)
        except ManifestError as exc:
            errors.append(f"routing fixture {case.query!r}: {exc}")
            continue
        if match.route.id != case.route:
            errors.append(
                f"routing fixture {case.query!r} expected {case.route} but selected {match.route.id}"
            )
        else:
            covered_routes.add(case.route)
    missing = sorted(route_ids - covered_routes)
    if missing:
        errors.append(f"routes without passing routing fixtures: {', '.join(missing)}")
    return errors


def _markdown_link(path: str) -> str:
    return f"[`{path}`](../{path})"


def _path_list(paths: Sequence[str]) -> str:
    return ", ".join(_markdown_link(path) for path in paths) if paths else "—"


def render_semantic_index(manifest: SemanticManifest) -> str:
    """Render the deterministic compact semantic index.

    Parameters
    ----------
    manifest:
        Valid semantic-router manifest.

    Returns
    -------
    str
        Generated Markdown with stable ordering.
    """

    lines = [
        "<!-- Generated by scripts/semantic_router.py; edit .ai/semantic-router.toml. -->",
        "# Semantic Router",
        "",
        "Use this generated index as the first discovery hop after loading minimum authority policy. It links to canonical sources and grants no runtime authority.",
        "",
        "## Routes",
        "",
        "| Route | State | Owner | Authority | Implementation | Tests | Dependencies | Aliases |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for route in sorted(manifest.routes, key=lambda item: item.id):
        aliases = ", ".join(f"`{alias}`" for alias in route.aliases)
        lines.append(
            f"| `{route.id}` — {route.title} | {route.lifecycle} | `{route.agent}` | "
            f"{_path_list(route.authority)} | {_path_list(route.implementation)} | "
            f"{_path_list(route.tests)} | "
            f"{', '.join(f'`{item}`' for item in route.dependencies) or '—'} | "
            f"{aliases} |"
        )
    lines.extend(
        [
            "",
            "## Hub-and-spoke topology",
            "",
            "The parent owns the complete registry. Each child receives only its parent, scoped contract, allowed tools, and return path; children do not receive sibling prompts.",
            "",
            "| Agent | Kind | Parent | Tools | Depth | Fallback | Profile |",
            "| --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for agent in sorted(manifest.agents, key=lambda item: item.id):
        tools = ", ".join(f"`{tool}`" for tool in agent.tools) or "—"
        parent = f"`{agent.parent}`" if agent.parent else "—"
        fallback = f"`{agent.fallback}`" if agent.fallback else "—"
        lines.append(
            f"| `{agent.id}` | {agent.kind} | {parent} | {tools} | "
            f"{agent.max_delegation_depth} | {fallback} | {_markdown_link(agent.profile)} |"
        )
    lines.extend(["", "## Exact ownership coverage", ""])
    for category in OWNERSHIP_CATEGORIES:
        lines.append(
            f"- `{category}`: {len(manifest.ownership[category])} exact entries"
        )
    lines.append("")
    return "\n".join(lines)


def validate_repository(
    root: Path,
    manifest: SemanticManifest,
    *,
    check_generated: bool = True,
) -> list[str]:
    """Validate manifest coverage, topology, lifecycle, and generated output.

    Parameters
    ----------
    root:
        Repository root to inspect.
    manifest:
        Parsed semantic-router manifest.
    check_generated:
        Whether the checked-in generated document must match exactly.

    Returns
    -------
    list[str]
        Deterministically ordered validation errors.
    """

    trusted_root = root.resolve(strict=True)
    try:
        inventory = collect_inventory(trusted_root)
    except ManifestError as exc:
        return [str(exc)]
    errors = [
        *_validate_inventory(trusted_root, manifest, inventory),
        *_validate_topology(trusted_root, manifest, inventory),
        *_validate_route_contracts(trusted_root, manifest),
        *_validate_routing(manifest),
    ]
    try:
        generated_path = _safe_repository_file(
            trusted_root, manifest.generated_document
        )
    except ManifestError as exc:
        if check_generated:
            errors.append(f"generated document: {exc}")
        generated_path = None
    if check_generated and generated_path is not None:
        expected = render_semantic_index(manifest).encode("utf-8")
        try:
            actual = _read_bounded_regular_file(
                generated_path, limit=MAX_MANIFEST_BYTES
            )
        except ManifestError as exc:
            errors.append(f"generated document: {exc}")
        else:
            if actual != expected:
                errors.append(
                    f"generated document drift: {manifest.generated_document}"
                )
    return sorted(set(errors))


def _open_generated_parent(root: Path, parts: Sequence[str]) -> int:
    """Open a generated document's parent through no-follow descriptors.

    Parameters
    ----------
    root:
        Trusted canonical repository root.
    parts:
        Canonical parent path components below ``root``.

    Returns
    -------
    int
        Caller-owned descriptor for the pinned parent directory.
    """

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None:
        raise ManifestError(
            "descriptor-safe semantic-index generation is unavailable on this platform"
        )
    flags = os.O_RDONLY | no_follow | directory_only | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(root, flags)
        for part in parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ManifestError("generated document parent is not a directory")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _fsync_if_supported(descriptor: int) -> None:
    """Synchronize one descriptor, accepting only documented unsupported cases."""

    unsupported = {
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    try:
        os.fsync(descriptor)
    except OSError as exc:
        if exc.errno not in unsupported:
            raise


def _write_all(descriptor: int, content: bytes) -> None:
    """Write every byte to a descriptor or fail closed."""

    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("generated document write made no progress")
        remaining = remaining[written:]


def _atomic_write_generated_file(
    root: Path, path: PurePosixPath, content: bytes
) -> None:
    """Atomically replace a generated file within a pinned repository directory.

    Parameters
    ----------
    root:
        Trusted canonical repository root.
    path:
        Validated repository-relative output path.
    content:
        Complete deterministic generated bytes.
    """

    parent_descriptor = -1
    temporary_descriptor = -1
    temporary_name: str | None = None
    failure: BaseException | None = None
    try:
        parent_descriptor = _open_generated_parent(root, path.parts[:-1])
        destination_name = path.name
        try:
            destination_metadata = os.stat(
                destination_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            final_mode = 0o644
        else:
            if stat.S_ISLNK(destination_metadata.st_mode):
                raise ManifestError("refusing symbolic-link generated document")
            if not stat.S_ISREG(destination_metadata.st_mode):
                raise ManifestError("refusing non-regular generated document")
            final_mode = stat.S_IMODE(destination_metadata.st_mode) & 0o666

        create_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _attempt in range(32):
            candidate = f".semantic-router.tmp-{secrets.token_hex(16)}"
            try:
                temporary_descriptor = os.open(
                    candidate,
                    create_flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        else:
            raise ManifestError("cannot allocate a private semantic-index temp file")

        os.fchmod(temporary_descriptor, 0o600)
        _write_all(temporary_descriptor, content)
        _fsync_if_supported(temporary_descriptor)
        temporary_metadata = os.fstat(temporary_descriptor)
        if not stat.S_ISREG(temporary_metadata.st_mode):
            raise ManifestError("semantic-index temp output is not a regular file")

        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fchmod(temporary_descriptor, final_mode)
        _fsync_if_supported(temporary_descriptor)

        verify_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        verification_descriptor = os.open(
            destination_name,
            verify_flags,
            dir_fd=parent_descriptor,
        )
        try:
            installed_metadata = os.fstat(verification_descriptor)
            if not stat.S_ISREG(installed_metadata.st_mode):
                raise ManifestError("generated document is not a regular file")
            if (installed_metadata.st_dev, installed_metadata.st_ino) != (
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
            ):
                raise ManifestError(
                    "generated document identity changed after replacement"
                )
        finally:
            os.close(verification_descriptor)
        _fsync_if_supported(parent_descriptor)
    except OSError as exc:
        failure = ManifestError(f"cannot atomically generate semantic index: {exc}")
    finally:
        if temporary_descriptor >= 0:
            try:
                os.close(temporary_descriptor)
            except OSError as exc:
                if failure is None:
                    failure = ManifestError(
                        f"cannot close semantic-index temp file: {exc}"
                    )
                else:
                    failure.add_note(f"temp descriptor close also failed: {exc}")
        if temporary_name is not None and parent_descriptor >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except OSError as exc:
                if failure is None:
                    failure = ManifestError(
                        f"cannot clean up semantic-index temp file: {exc}"
                    )
                else:
                    failure.add_note(f"temp cleanup also failed: {exc}")
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError as exc:
                if failure is None:
                    failure = ManifestError(
                        f"cannot close semantic-index parent descriptor: {exc}"
                    )
                else:
                    failure.add_note(f"parent descriptor close also failed: {exc}")
    if failure is not None:
        raise failure


def generate_index(root: Path, manifest: SemanticManifest, *, check: bool) -> bool:
    """Generate or check the compact semantic index.

    Parameters
    ----------
    root:
        Repository root.
    manifest:
        Parsed and semantically valid manifest.
    check:
        If true, compare without writing.

    Returns
    -------
    bool
        True when the output already matched or was written successfully.
    """

    if manifest.generated_document != GENERATED_DOCUMENT_PATH:
        raise ManifestError(
            f"manifest.generated_document must be exactly {GENERATED_DOCUMENT_PATH}"
        )
    errors = validate_repository(root, manifest, check_generated=False)
    if errors:
        raise ManifestError("\n".join(errors))
    output = render_semantic_index(manifest).encode("utf-8")
    trusted_root = root.resolve(strict=True)
    pure = PurePosixPath(manifest.generated_document)
    if (
        pure.is_absolute()
        or pure.as_posix() != manifest.generated_document
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(_PATH_PART.fullmatch(part) is None for part in pure.parts)
    ):
        raise ManifestError("generated document path is unsafe")
    destination = trusted_root.joinpath(*pure.parts)
    try:
        destination.parent.resolve(strict=True).relative_to(trusted_root)
    except (OSError, ValueError) as exc:
        raise ManifestError("generated document parent is unsafe") from exc
    for ancestor in (destination.parent, *destination.parent.parents):
        if ancestor == trusted_root.parent:
            break
        if ancestor.is_symlink():
            raise ManifestError("generated document parent crosses a symbolic link")
        if ancestor == trusted_root:
            break
    if check:
        try:
            actual = _read_bounded_regular_file(destination, limit=MAX_MANIFEST_BYTES)
        except ManifestError:
            return False
        return actual == output
    _atomic_write_generated_file(trusted_root, pure, output)
    return True


def routing_metrics(manifest: SemanticManifest) -> dict[str, int | float]:
    """Measure compact-router size, accuracy, and lookup latency.

    Timing is informational and intentionally excluded from validation gates.

    Parameters
    ----------
    manifest:
        Parsed semantic-router manifest.

    Returns
    -------
    dict[str, int | float]
        Stable metric names with a non-gating observed lookup latency.
    """

    rendered_bytes = len(render_semantic_index(manifest).encode("utf-8"))
    correct = sum(
        1
        for case in manifest.routing_cases
        if select_route(manifest, case.query).route.id == case.route
    )
    accuracy = correct / len(manifest.routing_cases) if manifest.routing_cases else 0.0
    batch_iterations = 20
    samples: list[float] = []
    lookups_per_sample = batch_iterations * len(manifest.routing_cases)
    for _ in range(11):
        started = time.perf_counter_ns()
        for _iteration in range(batch_iterations):
            for case in manifest.routing_cases:
                select_route(manifest, case.query)
        elapsed = time.perf_counter_ns() - started
        samples.append(elapsed / lookups_per_sample / 1_000)
    return {
        "generated_router_bytes": rendered_bytes,
        "approx_context_tokens": (rendered_bytes + 3) // 4,
        "route_count": len(manifest.routes),
        "routing_fixture_count": len(manifest.routing_cases),
        "routing_fixture_accuracy": accuracy,
        "median_lookup_microseconds": statistics.median(samples),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--manifest", type=Path, default=Path(MANIFEST_PATH))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="validate manifest and generated index")
    generate = commands.add_parser("generate", help="generate the semantic index")
    generate.add_argument(
        "--check", action="store_true", help="fail if generated output would change"
    )
    route = commands.add_parser("route", help="select a semantic route")
    route.add_argument("query")
    changes = commands.add_parser(
        "changes", help="map one commit or BASE..HEAD range to affected routes"
    )
    changes.add_argument("revision")
    commands.add_parser("metrics", help="report non-gating router measurements")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the semantic-router command-line interface."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        manifest = load_manifest(root, args.manifest)
        if args.command == "validate":
            errors = validate_repository(root, manifest)
            if errors:
                for error in errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print(
                f"semantic router valid: {len(manifest.routes)} routes, "
                f"{len(manifest.routing_cases)} routing fixtures"
            )
            return 0
        if args.command == "generate":
            matched = generate_index(root, manifest, check=args.check)
            if args.check and not matched:
                print(
                    f"ERROR: generated document drift: {manifest.generated_document}",
                    file=sys.stderr,
                )
                return 1
            print(
                f"semantic index {'matches' if args.check else 'generated'}: "
                f"{manifest.generated_document}"
            )
            return 0
        if args.command == "route":
            errors = validate_repository(root, manifest)
            if errors:
                raise ManifestError("\n".join(errors))
            match = select_route(manifest, args.query)
            print(json.dumps(route_payload(manifest, match), sort_keys=True))
            return 0
        if args.command == "changes":
            errors = validate_repository(root, manifest)
            if errors:
                raise ManifestError("\n".join(errors))
            base, head, paths = changed_paths_for_revision(root, args.revision)
            print(
                json.dumps(
                    changed_routes_payload(
                        manifest,
                        revision_spec=args.revision,
                        base=base,
                        head=head,
                        changed_paths=paths,
                    ),
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "metrics":
            errors = validate_repository(root, manifest)
            if errors:
                raise ManifestError("\n".join(errors))
            print(json.dumps(routing_metrics(manifest), sort_keys=True))
            return 0
    except (ManifestError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
