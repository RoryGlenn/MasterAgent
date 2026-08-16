#!/usr/bin/env python3
"""Bounded live Confluence Cloud sandbox lifecycle and recovery harness.

The preflight command intentionally imports only the Python standard library so
it can reject an unsafe destination before package installation or provider
network access. Provider-returned page bodies stay in memory and are never
written to logs, reports, or workflow artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_EMAIL_ENV = "CONFLUENCE_SANDBOX_EMAIL"
_TOKEN_ENV = "CONFLUENCE_SANDBOX_API_TOKEN"
_APPROVAL_ENV = "CONFLUENCE_SANDBOX_APPROVAL_SECRET"
_OWNERSHIP_ENV = "CONFLUENCE_SANDBOX_OWNERSHIP_KEY"
_MARKER_PREFIX = "MA-SANDBOX-"
_BODY_PREFIX = "master-agent-sandbox:v1"
_MARKER_PATTERN = re.compile(r"[0-9a-f]{32}")
_RUN_LABEL_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,96}")
_SPACE_KEY_PATTERN = re.compile(r"[A-Za-z0-9]{1,255}")
_IDENTITY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}")
_BODY_PATTERN = re.compile(
    rf"{re.escape(_BODY_PREFIX)};marker=([0-9a-f]{{32}});"
    r"created=([^;\s]+);owner=([0-9a-f]{64});phase=(create|update)"
)
_MAX_REAPER_RESOURCES = 5
_SEARCH_ATTEMPTS = 3
_SEARCH_DELAY_SECONDS = 2.0


class SandboxError(RuntimeError):
    """A secret-safe sandbox validation or lifecycle failure."""


@dataclass(frozen=True, slots=True)
class SandboxTarget:
    """An exact allowlisted Cloud destination."""

    origin: str
    space_id: str | None = None
    space_key: str | None = None
    parent_id: str | None = None


@dataclass(frozen=True, slots=True)
class PageOwnership:
    """Secret-free metadata proving which disposable page this run owns."""

    marker: str
    created_at: str
    owner_tag: str
    run_label: str
    origin: str
    space_id: str
    space_key: str
    parent_id: str | None

    @property
    def title(self) -> str:
        return f"{_MARKER_PREFIX}{self.marker}"

    def to_dict(self) -> dict[str, str | None]:
        return {
            "schema": "master-agent/confluence-sandbox-page@1",
            "marker": self.marker,
            "created_at": self.created_at,
            "owner_tag": self.owner_tag,
            "run_label": self.run_label,
            "origin": self.origin,
            "space_id": self.space_id,
            "space_key": self.space_key,
            "parent_id": self.parent_id,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PageOwnership:
        if value.get("schema") != "master-agent/confluence-sandbox-page@1":
            raise SandboxError("sandbox page metadata schema is unsupported")
        ownership = cls(
            marker=str(value.get("marker", "")),
            created_at=str(value.get("created_at", "")),
            owner_tag=str(value.get("owner_tag", "")),
            run_label=str(value.get("run_label", "")),
            origin=str(value.get("origin", "")),
            space_id=str(value.get("space_id", "")),
            space_key=str(value.get("space_key", "")),
            parent_id=(
                str(value["parent_id"]) if value.get("parent_id") is not None else None
            ),
        )
        _validate_page_ownership_shape(ownership)
        return ownership


@dataclass(frozen=True, slots=True)
class SpaceOwnership:
    """Secret-free metadata proving which disposable space this run owns."""

    marker: str
    created_at: str
    owner_tag: str
    run_label: str
    origin: str
    key: str
    name: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": "master-agent/confluence-sandbox-space@1",
            "marker": self.marker,
            "created_at": self.created_at,
            "owner_tag": self.owner_tag,
            "run_label": self.run_label,
            "origin": self.origin,
            "key": self.key,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SpaceOwnership:
        if value.get("schema") != "master-agent/confluence-sandbox-space@1":
            raise SandboxError("sandbox space metadata schema is unsupported")
        ownership = cls(
            marker=str(value.get("marker", "")),
            created_at=str(value.get("created_at", "")),
            owner_tag=str(value.get("owner_tag", "")),
            run_label=str(value.get("run_label", "")),
            origin=str(value.get("origin", "")),
            key=str(value.get("key", "")),
            name=str(value.get("name", "")),
        )
        _validate_space_ownership_shape(ownership)
        return ownership


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """Private paths used by one ephemeral workflow job."""

    root: Path

    @property
    def integrations(self) -> Path:
        return self.root / "integrations.toml"

    @property
    def credentials(self) -> Path:
        return self.root / "credentials.json"

    @property
    def authorities(self) -> Path:
        return self.root / "approval-authorities.toml"

    @property
    def connection(self) -> Path:
        return self.root / "connection.json"

    @property
    def target(self) -> Path:
        return self.root / "sandbox-target.json"

    @property
    def page_metadata(self) -> Path:
        return self.root / "page-ownership.json"

    @property
    def space_metadata(self) -> Path:
        return self.root / "space-ownership.json"

    def page_state(self, phase: str) -> Path:
        return self.root / f"page-{phase}-state.json"

    def attempted(self, resource: str) -> Path:
        return self.root / f"{resource}-create-attempted"


def validate_sandbox_origin(
    configured_origin: str,
    allowlisted_origin: str,
    non_production_attestation: str,
) -> str:
    """Return the canonical origin or fail before any provider request."""

    configured = _canonical_atlassian_origin(configured_origin, "configured")
    allowlisted = _canonical_atlassian_origin(allowlisted_origin, "allowlisted")
    if configured != allowlisted:
        raise SandboxError("configured origin is not the exact approved sandbox origin")
    if non_production_attestation.strip().casefold() != "true":
        raise SandboxError("the approved origin lacks a non-production attestation")
    if configured == "https://example.atlassian.net":
        raise SandboxError("the placeholder Atlassian origin is not a sandbox tenant")
    return configured


def validate_target(
    *,
    configured_origin: str,
    allowlisted_origin: str,
    non_production_attestation: str,
    space_id: str | None = None,
    space_key: str | None = None,
    parent_id: str | None = None,
    require_space: bool,
) -> SandboxTarget:
    """Validate public workflow configuration without inspecting credentials."""

    origin = validate_sandbox_origin(
        configured_origin,
        allowlisted_origin,
        non_production_attestation,
    )
    normalized_space_id = _optional_identity(space_id, "space ID")
    normalized_space_key = _optional_space_key(space_key)
    normalized_parent = _optional_identity(parent_id, "parent page ID")
    if require_space and (normalized_space_id is None or normalized_space_key is None):
        raise SandboxError("sandbox space ID and key are both required")
    if (
        not require_space
        and (normalized_space_id or normalized_space_key)
        and (normalized_space_id is None or normalized_space_key is None)
    ):
        raise SandboxError("sandbox space ID and key must be supplied together")
    return SandboxTarget(
        origin=origin,
        space_id=normalized_space_id,
        space_key=normalized_space_key,
        parent_id=normalized_parent,
    )


def build_page_ownership(
    target: SandboxTarget,
    *,
    run_label: str,
    ownership_key: str,
    marker: str | None = None,
    created_at: str | None = None,
) -> PageOwnership:
    """Create a collision-resistant, authenticated page ownership marker."""

    if target.space_id is None or target.space_key is None:
        raise SandboxError("page ownership requires an exact space")
    label = _normalized_run_label(run_label)
    selected_marker = marker or secrets.token_hex(16)
    if _MARKER_PATTERN.fullmatch(selected_marker) is None:
        raise SandboxError("sandbox marker must be 128-bit lowercase hexadecimal")
    selected_created = created_at or _utc_now()
    _parse_timestamp(selected_created, "sandbox creation time")
    tag = _page_owner_tag(
        ownership_key,
        origin=target.origin,
        space_id=target.space_id,
        marker=selected_marker,
        created_at=selected_created,
    )
    return PageOwnership(
        marker=selected_marker,
        created_at=selected_created,
        owner_tag=tag,
        run_label=label,
        origin=target.origin,
        space_id=target.space_id,
        space_key=target.space_key,
        parent_id=target.parent_id,
    )


def build_space_ownership(
    target: SandboxTarget,
    *,
    run_label: str,
    ownership_key: str,
    marker: str | None = None,
    created_at: str | None = None,
) -> SpaceOwnership:
    """Create a collision-resistant, authenticated disposable-space marker."""

    label = _normalized_run_label(run_label)
    selected_marker = marker or secrets.token_hex(16)
    if _MARKER_PATTERN.fullmatch(selected_marker) is None:
        raise SandboxError("sandbox marker must be 128-bit lowercase hexadecimal")
    selected_created = created_at or _utc_now()
    _parse_timestamp(selected_created, "sandbox creation time")
    key = f"MAS{selected_marker[:20]}".upper()
    tag = _space_owner_tag(
        ownership_key,
        origin=target.origin,
        space_key=key,
        marker=selected_marker,
        created_at=selected_created,
    )
    name = f"MasterAgent Sandbox {selected_marker} {tag[:16]}"
    return SpaceOwnership(
        marker=selected_marker,
        created_at=selected_created,
        owner_tag=tag,
        run_label=label,
        origin=target.origin,
        key=key,
        name=name,
    )


def page_body(ownership: PageOwnership, phase: str) -> str:
    """Return the only page body accepted by lifecycle cleanup or reaping."""

    if phase not in {"create", "update"}:
        raise SandboxError("sandbox page phase must be create or update")
    marker_line = (
        f"{_BODY_PREFIX};marker={ownership.marker};created={ownership.created_at};"
        f"owner={ownership.owner_tag};phase={phase}"
    )
    return (
        "<p>MasterAgent automated Confluence sandbox test. No user content.</p>"
        f"<p>{marker_line}</p>"
    )


def page_body_text(ownership: PageOwnership, phase: str) -> str:
    """Return the normalized text expected from the exact sandbox HTML."""

    marker_line = (
        f"{_BODY_PREFIX};marker={ownership.marker};created={ownership.created_at};"
        f"owner={ownership.owner_tag};phase={phase}"
    )
    return (
        "MasterAgent automated Confluence sandbox test. No user content.\n"
        + marker_line
    )


def is_stale_candidate(
    page: dict[str, Any],
    *,
    target: SandboxTarget,
    ownership_key: str,
    cutoff: datetime,
) -> tuple[PageOwnership, str] | None:
    """Return authenticated ownership and phase only for an exact stale page."""

    title = str(page.get("title", ""))
    if not title.startswith(_MARKER_PREFIX):
        return None
    marker = title.removeprefix(_MARKER_PREFIX)
    if _MARKER_PATTERN.fullmatch(marker) is None:
        return None
    match = _BODY_PATTERN.search(str(page.get("body_text", "")))
    if match is None or match.group(1) != marker:
        return None
    created_at, supplied_tag, phase = match.group(2), match.group(3), match.group(4)
    if target.space_id is None or target.space_key is None:
        return None
    expected_tag = _page_owner_tag(
        ownership_key,
        origin=target.origin,
        space_id=target.space_id,
        marker=marker,
        created_at=created_at,
    )
    if not hmac.compare_digest(supplied_tag, expected_tag):
        return None
    ownership = PageOwnership(
        marker=marker,
        created_at=created_at,
        owner_tag=supplied_tag,
        run_label="stale-reaper",
        origin=target.origin,
        space_id=target.space_id,
        space_key=target.space_key,
        parent_id=target.parent_id,
    )
    try:
        created = _parse_timestamp(created_at, "sandbox creation time")
        updated = _parse_timestamp(
            str(page.get("updated_at", "")), "provider update time"
        )
    except SandboxError:
        return None
    if created > cutoff or updated > cutoff:
        return None
    if (
        not _identity_is_valid(page.get("id"), "provider page ID")
        or str(page.get("space_id", "")) != target.space_id
    ):
        return None
    if page.get("status") != "current" or page.get("version") not in {1, 2}:
        return None
    if page.get("title") != ownership.title:
        return None
    if page.get("body_text") != page_body_text(ownership, phase):
        return None
    if page.get("version") != (1 if phase == "create" else 2):
        return None
    return ownership, phase


def _canonical_atlassian_origin(value: str, label: str) -> str:
    raw = value.strip()
    if not raw or raw != value or any(ord(character) < 32 for character in raw):
        raise SandboxError(f"{label} sandbox origin is absent or malformed")
    parsed = urlsplit(raw)
    try:
        explicit_port = parsed.port
    except ValueError as error:
        raise SandboxError(f"{label} sandbox origin has an invalid port") from error
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or explicit_port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise SandboxError(
            f"{label} sandbox origin must be a credential-free HTTPS origin"
        )
    hostname = parsed.hostname.casefold().rstrip(".")
    if hostname == "atlassian.net" or not hostname.endswith(".atlassian.net"):
        raise SandboxError(f"{label} sandbox origin is outside atlassian.net")
    if not all(
        label_part
        and len(label_part) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label_part)
        for label_part in hostname.split(".")
    ):
        raise SandboxError(f"{label} sandbox origin has an invalid hostname")
    return urlunsplit(("https", hostname, "", "", ""))


def _optional_identity(value: str | None, label: str) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip()
    if normalized != value or _IDENTITY_PATTERN.fullmatch(normalized) is None:
        raise SandboxError(f"sandbox {label} is malformed")
    return normalized


def _required_identity(value: object, label: str) -> str:
    if value is None or isinstance(value, bool):
        raise SandboxError(f"sandbox {label} is absent")
    normalized = _optional_identity(str(value), label)
    if normalized is None:
        raise SandboxError(f"sandbox {label} is absent")
    return normalized


def _identity_is_valid(value: object, label: str) -> bool:
    try:
        _required_identity(value, label)
    except SandboxError:
        return False
    return True


def _optional_space_key(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().upper()
    if value.strip() != value or _SPACE_KEY_PATTERN.fullmatch(normalized) is None:
        raise SandboxError("sandbox space key is malformed")
    return normalized


def _normalized_run_label(value: str) -> str:
    if value != value.strip() or _RUN_LABEL_PATTERN.fullmatch(value) is None:
        raise SandboxError("sandbox run label is malformed")
    return value


def _sandbox_cql(*, space_key: str, title: str | None) -> str:
    """Build the only two bounded CQL searches used by this harness."""

    if _SPACE_KEY_PATTERN.fullmatch(space_key) is None:
        raise SandboxError("sandbox search space key is malformed")
    base = f'type = page AND space = "{space_key}"'
    if title is None:
        return f'{base} AND title ~ "{_MARKER_PREFIX}*" ORDER BY lastmodified ASC'
    if (
        not title.startswith(_MARKER_PREFIX)
        or _MARKER_PATTERN.fullmatch(title.removeprefix(_MARKER_PREFIX)) is None
    ):
        raise SandboxError("sandbox search title is malformed")
    # Confluence Cloud requires escaped inner quotes for an exact title match.
    return f'{base} AND title = "\\"{title}\\""'


def _require_secret(name: str, *, minimum_bytes: int = 1) -> str:
    value = os.environ.get(name, "")
    if len(value.encode("utf-8")) < minimum_bytes or "\x00" in value:
        raise SandboxError(f"required protected secret {name} is unavailable")
    return value


def _page_owner_tag(
    key: str,
    *,
    origin: str,
    space_id: str,
    marker: str,
    created_at: str,
) -> str:
    if len(key.encode("utf-8")) < 32:
        raise SandboxError("sandbox ownership key must contain at least 32 bytes")
    material = f"page\nv1\n{origin}\n{space_id}\n{marker}\n{created_at}".encode()
    return hmac.new(key.encode(), material, hashlib.sha256).hexdigest()


def _space_owner_tag(
    ownership_key: str,
    *,
    origin: str,
    space_key: str,
    marker: str,
    created_at: str,
) -> str:
    if len(ownership_key.encode("utf-8")) < 32:
        raise SandboxError("sandbox ownership key must contain at least 32 bytes")
    material = f"space\nv1\n{origin}\n{space_key}\n{marker}\n{created_at}".encode()
    return hmac.new(ownership_key.encode(), material, hashlib.sha256).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise SandboxError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise SandboxError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_page_ownership_shape(ownership: PageOwnership) -> None:
    target = validate_target(
        configured_origin=ownership.origin,
        allowlisted_origin=ownership.origin,
        non_production_attestation="true",
        space_id=ownership.space_id,
        space_key=ownership.space_key,
        parent_id=ownership.parent_id,
        require_space=True,
    )
    del target
    _normalized_run_label(ownership.run_label)
    if _MARKER_PATTERN.fullmatch(ownership.marker) is None:
        raise SandboxError("sandbox page marker is malformed")
    if re.fullmatch(r"[0-9a-f]{64}", ownership.owner_tag) is None:
        raise SandboxError("sandbox page owner tag is malformed")
    _parse_timestamp(ownership.created_at, "sandbox creation time")


def _validate_space_ownership_shape(ownership: SpaceOwnership) -> None:
    validate_sandbox_origin(ownership.origin, ownership.origin, "true")
    _normalized_run_label(ownership.run_label)
    if _MARKER_PATTERN.fullmatch(ownership.marker) is None:
        raise SandboxError("sandbox space marker is malformed")
    if _SPACE_KEY_PATTERN.fullmatch(ownership.key) is None:
        raise SandboxError("sandbox space key is malformed")
    if re.fullmatch(r"[0-9a-f]{64}", ownership.owner_tag) is None:
        raise SandboxError("sandbox space owner tag is malformed")
    if ownership.name != (
        f"MasterAgent Sandbox {ownership.marker} {ownership.owner_tag[:16]}"
    ):
        raise SandboxError("sandbox space name does not match its ownership marker")
    _parse_timestamp(ownership.created_at, "sandbox creation time")


def _private_root(path: Path, *, create: bool) -> RuntimePaths:
    selected = path.expanduser()
    if not selected.is_absolute():
        raise SandboxError("sandbox runtime root must be absolute")
    if create:
        selected.mkdir(mode=0o700, parents=False, exist_ok=True)
    try:
        observed = selected.lstat()
    except FileNotFoundError as error:
        raise SandboxError("sandbox runtime root does not exist") from error
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise SandboxError("sandbox runtime root must be a non-symlink directory")
    if os.name == "posix" and (
        observed.st_uid != os.geteuid() or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise SandboxError("sandbox runtime root must be current-user mode 0700")
    return RuntimePaths(selected.resolve(strict=True))


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private_text(path: Path, value: str) -> None:
    _write_private(path, value.encode("utf-8"))


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    payload = (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    _write_private(path, payload)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SandboxError(
            f"private sandbox state is unavailable: {path.name}"
        ) from error
    if not isinstance(value, dict):
        raise SandboxError(f"private sandbox state is malformed: {path.name}")
    return value


def _initialize_runtime(paths: RuntimePaths, origin: str) -> None:
    email = _require_secret(_EMAIL_ENV)
    token = _require_secret(_TOKEN_ENV)
    _require_secret(_APPROVAL_ENV, minimum_bytes=32)
    _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    existing = [
        path.name
        for path in (
            paths.integrations,
            paths.credentials,
            paths.authorities,
            paths.target,
        )
        if path.exists()
    ]
    if existing:
        raise SandboxError("sandbox runtime was already initialized")
    integrations = f'''[connectors.confluence]
enabled = true
deployment = "cloud"
base_url = "{origin}"
auth_mode = "basic"
username_env = "MASTER_AGENT_CONFLUENCE_USERNAME"
secret_env = "MASTER_AGENT_CONFLUENCE_TOKEN"
timeout_seconds = 15
max_pages = 8
max_items = 5
max_response_bytes = 1048576
writes_enabled = true
write_enabled = true
'''
    authorities = f'''[authorities.sandbox_ci]
subject = "confluence-sandbox-ci"
issuer = "master-agent.github-actions"
tenant = "confluence-sandbox"
roles = ["change-approver"]
secret_env = "{_APPROVAL_ENV}"
'''
    credential_document = {
        "schema": "master-agent/credential-store@1",
        "credentials": {
            "MASTER_AGENT_CONFLUENCE_USERNAME": email,
            "MASTER_AGENT_CONFLUENCE_TOKEN": token,
        },
    }
    _write_private_text(paths.integrations, integrations)
    _write_private_json(paths.credentials, credential_document)
    _write_private_text(paths.authorities, authorities)
    _write_private_json(
        paths.target,
        {
            "schema": "master-agent/confluence-sandbox-target@1",
            "origin": origin,
        },
    )


def _run_cli(
    paths: RuntimePaths,
    label: str,
    arguments: list[str],
    *,
    expected_status: int,
    discard_stdout: bool = False,
) -> None:
    log = paths.root / f"{label}.log"
    descriptor = os.open(
        log,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        stdout: int = subprocess.DEVNULL if discard_stdout else descriptor
        completed = subprocess.run(
            [sys.executable, "-m", "master_agent", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=descriptor,
            check=False,
            close_fds=True,
            timeout=180,
            env=dict(os.environ),
        )
    except subprocess.TimeoutExpired as error:
        raise SandboxError(
            f"{label} exceeded the three-minute command bound"
        ) from error
    finally:
        os.close(descriptor)
    if completed.returncode != expected_status:
        raise SandboxError(
            f"{label} failed with status {completed.returncode}; "
            f"inspect the private runner log {log.name}"
        )


def _connect(paths: RuntimePaths) -> None:
    _run_cli(
        paths,
        "connect",
        [
            "connect",
            "--integrations",
            str(paths.integrations),
            "--credentials-file",
            str(paths.credentials),
            "--systems",
            "confluence",
            "--output",
            str(paths.connection),
        ],
        expected_status=0,
    )
    payload = _read_json(paths.connection)
    records = payload.get("records")
    if (
        not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
        or records[0].get("system") != "confluence"
        or records[0].get("status") != "reachable"
    ):
        raise SandboxError("normal Confluence connection probe was not reachable")


def _runtime_arguments(paths: RuntimePaths, phase: str) -> tuple[list[str], Path]:
    phase_root = paths.root / phase
    phase_root.mkdir(mode=0o700)
    drafts = phase_root / "drafts"
    approvals = phase_root / "approvals"
    drafts.mkdir(mode=0o700)
    approvals.mkdir(mode=0o700)
    arguments = [
        "--connector-mode",
        "live",
        "--integrations",
        str(paths.integrations),
        "--approval-authorities",
        str(paths.authorities),
        "--database",
        str(phase_root / "audit.sqlite3"),
        "--draft-output-dir",
        str(drafts),
        "--credentials-file",
        str(paths.credentials),
        "--enable-writes",
    ]
    return arguments, approvals


def _run_governed_plan(
    paths: RuntimePaths,
    *,
    phase: str,
    plan: Any,
    attempt_flag: Path | None = None,
) -> None:
    """Bind, request, inspect, authenticate, and resume one exact write plan."""

    from master_agent.approval_handoff import load_approval_request

    phase_root = paths.root / phase
    plan_path = paths.root / f"{phase}-plan.json"
    bound_path = paths.root / f"{phase}-bound-plan.json"
    _write_private_json(plan_path, plan.to_dict())
    runtime_arguments, approvals = _runtime_arguments(paths, phase)
    _run_cli(
        paths,
        f"{phase}-bind",
        [
            "bind-context",
            str(plan_path),
            *runtime_arguments,
            "--output",
            str(bound_path),
        ],
        expected_status=0,
    )
    _run_cli(
        paths,
        f"{phase}-request",
        ["run", str(bound_path), "--apply", *runtime_arguments],
        expected_status=2,
    )
    requests = tuple((phase_root / "drafts").glob("approval-request-*.json"))
    if len(requests) != 1:
        raise SandboxError("write did not produce exactly one private approval request")
    request_path = requests[0]
    request = load_approval_request(request_path)
    if (
        len(request.required_approvals) != 1
        or request.required_approvals[0].action.action_id != plan.actions[0].action_id
    ):
        raise SandboxError("approval request did not bind the exact sandbox action")
    _run_cli(
        paths,
        f"{phase}-inspect",
        ["inspect-approval-request", str(request_path)],
        expected_status=0,
        discard_stdout=True,
    )
    approval_path = approvals / "sandbox-ci-approval.json"
    _run_cli(
        paths,
        f"{phase}-approve",
        [
            "approve-request",
            str(request_path),
            "--key-id",
            "sandbox_ci",
            "--expected-fingerprint",
            request.fingerprint,
            "--output",
            str(approval_path),
            "--ttl-minutes",
            "10",
        ],
        expected_status=0,
    )
    if attempt_flag is not None:
        _write_private_text(attempt_flag, "attempted\n")
    _run_cli(
        paths,
        f"{phase}-resume",
        [
            "resume-approval",
            str(request_path),
            "--expected-fingerprint",
            request.fingerprint,
            "--approval",
            str(approval_path),
        ],
        expected_status=0,
    )


def _page_create_action(ownership: PageOwnership) -> Any:
    from master_agent.models import (
        AgentAction,
        AuthoritySource,
        ChangePlan,
        DataClassification,
        ResourceRef,
        RiskLevel,
    )

    parameters: dict[str, Any] = {
        "space_id": ownership.space_id,
        "title": ownership.title,
        "body": page_body(ownership, "create"),
        "representation": "storage",
        "status": "current",
    }
    if ownership.parent_id is not None:
        parameters["parent_id"] = ownership.parent_id
    action = AgentAction(
        capability="confluence.page.create",
        target=ResourceRef(
            system="confluence",
            resource_type="page",
            resource_id=f"new:{ownership.marker}",
        ),
        parameters=parameters,
        risk=RiskLevel.REVERSIBLE_WRITE,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=True,
        idempotency_key=f"confluence-sandbox:create:{ownership.marker}",
        justification="Create one owned disposable page in the approved sandbox.",
    )
    return ChangePlan(
        goal=f"Create disposable Confluence sandbox page {ownership.marker}",
        actions=(action,),
        created_by="confluence-sandbox-ci",
    )


def _page_update_action(ownership: PageOwnership, page_id: str) -> Any:
    from master_agent.models import (
        AgentAction,
        AuthoritySource,
        ChangePlan,
        DataClassification,
        ResourceRef,
        RiskLevel,
    )

    action = AgentAction(
        capability="confluence.page.update",
        target=ResourceRef(
            system="confluence",
            resource_type="page",
            resource_id=page_id,
            expected_version="1",
        ),
        parameters={
            "title": ownership.title,
            "body": page_body(ownership, "update"),
            "representation": "storage",
            "status": "current",
            "version_message": "MasterAgent sandbox lifecycle verification",
        },
        risk=RiskLevel.REVERSIBLE_WRITE,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=True,
        idempotency_key=f"confluence-sandbox:update:{ownership.marker}",
        justification="Version-check and update the exact disposable sandbox page.",
    )
    return ChangePlan(
        goal=f"Update disposable Confluence sandbox page {ownership.marker}",
        actions=(action,),
        created_by="confluence-sandbox-ci",
    )


def _space_create_plan(ownership: SpaceOwnership) -> Any:
    from master_agent.models import (
        AgentAction,
        AuthoritySource,
        ChangePlan,
        DataClassification,
        ResourceRef,
        RiskLevel,
    )

    action = AgentAction(
        capability="confluence.space.create",
        target=ResourceRef(
            system="confluence",
            resource_type="space",
            resource_id=ownership.key,
        ),
        parameters={
            "key": ownership.key,
            "name": ownership.name,
            "description": (
                "Disposable MasterAgent sandbox space. "
                f"marker={ownership.marker}; owner={ownership.owner_tag}"
            ),
        },
        risk=RiskLevel.REVERSIBLE_WRITE,
        data_classification=DataClassification.INTERNAL,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=True,
        idempotency_key=f"confluence-sandbox:space:{ownership.marker}",
        justification="Create one owned disposable space in the approved sandbox.",
    )
    return ChangePlan(
        goal=f"Create disposable Confluence sandbox space {ownership.marker}",
        actions=(action,),
        created_by="confluence-sandbox-ci",
    )


def _load_registry(paths: RuntimePaths) -> Any:
    from master_agent.config import IntegrationConfig
    from master_agent.connectors.factory import build_live_registry
    from master_agent.credentials import CredentialStoreSnapshot

    target = _read_json(paths.target)
    if target.get("schema") != "master-agent/confluence-sandbox-target@1":
        raise SandboxError("sandbox runtime target schema is unsupported")
    origin = validate_sandbox_origin(
        str(target.get("origin", "")),
        str(target.get("origin", "")),
        "true",
    )
    integrations = IntegrationConfig.from_toml(paths.integrations)
    connector = integrations.connector("confluence")
    if connector.base_url != origin or connector.system != "confluence":
        raise SandboxError("sandbox integration destination drifted after preflight")
    store = CredentialStoreSnapshot.load(
        paths.credentials,
        allowed_names=integrations.credential_environment_variables(),
    )
    ambient = {
        name: value for name, value in os.environ.items() if name not in store.names
    }
    return build_live_registry(
        integrations,
        environ=store.overlay(ambient),
        systems={"confluence"},
        include_writes=True,
    )


def _search_pages(
    paths: RuntimePaths,
    *,
    space_key: str,
    title: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    from master_agent.models import (
        AgentAction,
        AuthoritySource,
        ResourceRef,
        RiskLevel,
    )

    if limit < 1 or limit > _MAX_REAPER_RESOURCES:
        raise SandboxError("sandbox search limit is outside the reviewed bound")
    cql = _sandbox_cql(space_key=space_key, title=title)
    action = AgentAction(
        capability="confluence.page.search",
        target=ResourceRef(
            system="confluence",
            resource_type="search",
            resource_id=f"sandbox:{space_key}",
        ),
        parameters={"cql": cql, "limit": limit, "include_body": True},
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.REGISTERED_WORKFLOW,
        requires_approval=False,
        idempotency_key=f"sandbox-search:{space_key}:{title or 'stale'}:{time.time_ns()}",
        justification="Find only bounded MasterAgent sandbox pages.",
    )
    connector = _load_registry(paths).resolve("confluence", "confluence.page.search")
    result = connector.execute(action)
    after = result.after
    if not isinstance(after, dict) or not isinstance(after.get("pages"), list):
        raise SandboxError("Confluence sandbox search returned malformed evidence")
    return [dict(page) for page in after["pages"] if isinstance(page, dict)]


def _find_exact_page(
    paths: RuntimePaths,
    ownership: PageOwnership,
    *,
    attempts: int,
) -> tuple[dict[str, Any], str] | None:
    ownership_key = _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    target = SandboxTarget(
        origin=ownership.origin,
        space_id=ownership.space_id,
        space_key=ownership.space_key,
        parent_id=ownership.parent_id,
    )
    for attempt in range(attempts):
        pages = _search_pages(
            paths,
            space_key=ownership.space_key,
            title=ownership.title,
            limit=2,
        )
        exact: list[tuple[dict[str, Any], str]] = []
        for page in pages:
            match = _owned_page_without_age(
                page,
                target=target,
                ownership_key=ownership_key,
            )
            if match is not None and match[0].marker == ownership.marker:
                exact.append((page, match[1]))
        if len(exact) > 1:
            raise SandboxError(
                "multiple pages carry the exact sandbox ownership marker"
            )
        if exact:
            return exact[0]
        if attempt + 1 < attempts:
            time.sleep(_SEARCH_DELAY_SECONDS)
    return None


def _owned_page_without_age(
    page: dict[str, Any],
    *,
    target: SandboxTarget,
    ownership_key: str,
) -> tuple[PageOwnership, str] | None:
    title = str(page.get("title", ""))
    marker = (
        title.removeprefix(_MARKER_PREFIX) if title.startswith(_MARKER_PREFIX) else ""
    )
    match = _BODY_PATTERN.search(str(page.get("body_text", "")))
    if (
        _MARKER_PATTERN.fullmatch(marker) is None
        or match is None
        or match.group(1) != marker
    ):
        return None
    if target.space_id is None or target.space_key is None:
        return None
    created_at, supplied_tag, phase = match.group(2), match.group(3), match.group(4)
    expected_tag = _page_owner_tag(
        ownership_key,
        origin=target.origin,
        space_id=target.space_id,
        marker=marker,
        created_at=created_at,
    )
    if not hmac.compare_digest(supplied_tag, expected_tag):
        return None
    ownership = PageOwnership(
        marker=marker,
        created_at=created_at,
        owner_tag=supplied_tag,
        run_label="observed",
        origin=target.origin,
        space_id=target.space_id,
        space_key=target.space_key,
        parent_id=target.parent_id,
    )
    expected_version = 1 if phase == "create" else 2
    if (
        page.get("title") != ownership.title
        or page.get("body_text") != page_body_text(ownership, phase)
        or page.get("status") != "current"
        or not _identity_is_valid(page.get("id"), "provider page ID")
        or str(page.get("space_id", "")) != target.space_id
        or page.get("version") != expected_version
    ):
        return None
    return ownership, phase


def _expected_page_state(
    ownership: PageOwnership,
    page_id: str,
    phase: str,
) -> dict[str, Any]:
    return {
        "id": page_id,
        "title": ownership.title,
        "status": "current",
        "version": 1 if phase == "create" else 2,
        "space_id": ownership.space_id,
        "space_key": None,
        "parent_id": ownership.parent_id,
        "body": page_body(ownership, phase),
        "body_text": page_body_text(ownership, phase),
        "representation": "storage",
    }


def _verify_page(
    paths: RuntimePaths,
    ownership: PageOwnership,
    *,
    page_id: str,
    phase: str,
) -> dict[str, Any]:
    from master_agent.models import ActionState, ExecutionResult

    registry = _load_registry(paths)
    connector = registry.resolve("confluence", "confluence.page.create")
    if phase == "create":
        action = _page_create_action(ownership).actions[0]
        before = None
    else:
        action = _page_update_action(ownership, page_id).actions[0]
        before = _expected_page_state(ownership, page_id, "create")
    expected = _expected_page_state(ownership, page_id, phase)
    synthetic = ExecutionResult(
        action_id=action.action_id,
        state=ActionState.SUCCEEDED,
        before=before,
        after=expected,
        message="sandbox in-memory verification snapshot",
    )
    verification = connector.verify(action, synthetic)
    if not verification.verified or not isinstance(verification.observed, dict):
        raise SandboxError(
            "fresh Confluence read did not match the exact approved page"
        )
    observed = dict(verification.observed)
    for key, value in expected.items():
        if observed.get(key) != value:
            raise SandboxError(f"fresh Confluence page verification mismatched {key}")
    return observed


def _persist_page_state(
    paths: RuntimePaths,
    *,
    page_id: str,
    phase: str,
    reference: str | None,
) -> None:
    page_id = _required_identity(page_id, "provider page ID")
    _write_private_json(
        paths.page_state(phase),
        {
            "schema": "master-agent/confluence-sandbox-safe-state@1",
            "page_id": page_id,
            "phase": phase,
            "version": 1 if phase == "create" else 2,
            "reference": _safe_reference(reference),
        },
    )


def _safe_reference(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return None
    return urlunsplit(("https", parsed.netloc, parsed.path, "", ""))


def _delete_verified_page(
    paths: RuntimePaths,
    ownership: PageOwnership,
    *,
    page_id: str,
    phase: str,
) -> str | None:
    from master_agent.models import ActionState, ExecutionResult

    observed = _verify_page(
        paths,
        ownership,
        page_id=page_id,
        phase=phase,
    )
    create_action = _page_create_action(ownership).actions[0]
    original = ExecutionResult(
        action_id=create_action.action_id,
        state=ActionState.SUCCEEDED,
        before=None,
        after=observed,
        message="sandbox exact created-resource recovery",
    )
    connector = _load_registry(paths).resolve("confluence", "confluence.page.create")
    compensation = connector.compensate(create_action, original)
    verification = connector.verify_compensation(
        create_action,
        original,
        compensation,
    )
    if not verification.verified:
        raise SandboxError("fresh provider observation did not confirm page cleanup")
    return _safe_reference(compensation.connector_reference)


def _page_is_terminal(paths: RuntimePaths, page_id: str) -> bool:
    """Confirm through a fresh lifecycle read that a prior cleanup is complete."""

    from master_agent.errors import ResourceNotFoundError

    connector = _load_registry(paths).resolve("confluence", "confluence.page.create")
    try:
        observed = connector._read_page_lifecycle_state(page_id)
    except ResourceNotFoundError:
        return True
    return observed.get("id") == page_id and observed.get("status") == "trashed"


def _page_lifecycle(args: argparse.Namespace) -> int:
    target = _target_from_args(args, require_space=True)
    paths = _private_root(args.root, create=True)
    _initialize_runtime(paths, target.origin)
    ownership_key = _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    ownership = build_page_ownership(
        target,
        run_label=args.run_label,
        ownership_key=ownership_key,
    )
    _write_private_json(paths.page_metadata, ownership.to_dict())
    _connect(paths)
    create_plan = _page_create_action(ownership)
    _run_governed_plan(
        paths,
        phase="page-create",
        plan=create_plan,
        attempt_flag=paths.attempted("page"),
    )
    found = _find_exact_page(paths, ownership, attempts=_SEARCH_ATTEMPTS)
    if found is None:
        raise SandboxError("created sandbox page was not independently discoverable")
    page, phase = found
    if phase != "create":
        raise SandboxError("new sandbox page did not have its create-phase content")
    page_id = _required_identity(page["id"], "provider page ID")
    observed = _verify_page(
        paths,
        ownership,
        page_id=page_id,
        phase="create",
    )
    _persist_page_state(
        paths,
        page_id=page_id,
        phase="create",
        reference=str(observed.get("reference", "")),
    )
    update_plan = _page_update_action(ownership, page_id)
    _run_governed_plan(paths, phase="page-update", plan=update_plan)
    observed = _verify_page(
        paths,
        ownership,
        page_id=page_id,
        phase="update",
    )
    _persist_page_state(
        paths,
        page_id=page_id,
        phase="update",
        reference=str(observed.get("reference", "")),
    )
    print(f"verified sandbox page lifecycle for provider page {page_id}")
    return 0


def _cleanup_page(args: argparse.Namespace) -> int:
    paths = _private_root(args.root, create=False)
    if not paths.page_metadata.exists():
        print("no sandbox page ownership metadata exists; cleanup safely skipped")
        return 0
    ownership = PageOwnership.from_dict(_read_json(paths.page_metadata))
    runtime_origin = str(_read_json(paths.target).get("origin", ""))
    if ownership.origin != runtime_origin:
        raise SandboxError("sandbox page ownership destination drifted")
    ownership_key = _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    expected_tag = _page_owner_tag(
        ownership_key,
        origin=ownership.origin,
        space_id=ownership.space_id,
        marker=ownership.marker,
        created_at=ownership.created_at,
    )
    if not hmac.compare_digest(expected_tag, ownership.owner_tag):
        raise SandboxError("sandbox page ownership metadata failed authentication")
    state_path = (
        paths.page_state("update")
        if paths.page_state("update").exists()
        else paths.page_state("create")
    )
    if state_path.exists():
        state = _read_json(state_path)
        phase = str(state.get("phase", ""))
        page_id = _required_identity(state.get("page_id", ""), "provider page ID")
        if phase not in {"create", "update"} or not page_id:
            raise SandboxError("safe page cleanup state is malformed")
        # The update command may have reached Confluence before its CLI process
        # failed. Prefer a bounded exact-marker read over stale local phase state.
        found = _find_exact_page(paths, ownership, attempts=_SEARCH_ATTEMPTS)
        if found is not None:
            page, observed_phase = found
            observed_id = _required_identity(page.get("id"), "provider page ID")
            if observed_id != page_id:
                raise SandboxError(
                    "sandbox ownership marker resolved to another provider page"
                )
            phase = observed_phase
    elif paths.attempted("page").exists():
        found = _find_exact_page(paths, ownership, attempts=_SEARCH_ATTEMPTS)
        if found is None:
            print("fresh bounded search confirms no active owned sandbox page")
            return 0
        page, phase = found
        page_id = _required_identity(page["id"], "provider page ID")
    else:
        print("sandbox page mutation was never attempted; cleanup safely skipped")
        return 0
    if _page_is_terminal(paths, page_id):
        print(f"fresh provider read confirms page {page_id} is already cleaned up")
        return 0
    reference = _delete_verified_page(
        paths,
        ownership,
        page_id=page_id,
        phase=phase,
    )
    suffix = f" ({reference})" if reference else ""
    print(f"verified cleanup of provider page {page_id}{suffix}")
    return 0


def _verify_space(
    paths: RuntimePaths,
    ownership: SpaceOwnership,
    *,
    space_id: str,
) -> dict[str, Any]:
    from master_agent.models import ActionState, ExecutionResult

    action = _space_create_plan(ownership).actions[0]
    expected = {
        "id": space_id,
        "key": ownership.key,
        "name": ownership.name,
        "type": "global",
        "status": "current",
    }
    synthetic = ExecutionResult(
        action_id=action.action_id,
        state=ActionState.SUCCEEDED,
        before=None,
        after=expected,
        message="sandbox in-memory space verification snapshot",
    )
    connector = _load_registry(paths).resolve("confluence", "confluence.space.create")
    verification = connector.verify(action, synthetic)
    if not verification.verified or not isinstance(verification.observed, dict):
        raise SandboxError("fresh Confluence read did not match the approved space")
    return dict(verification.observed)


def _find_exact_space(
    paths: RuntimePaths,
    ownership: SpaceOwnership,
) -> dict[str, Any] | None:
    connector = _load_registry(paths).resolve("confluence", "confluence.space.create")
    data, _ = connector._client.request_json(
        "GET",
        "wiki/api/v2/spaces",
        query={"keys": ownership.key, "limit": 2},
    )
    if not isinstance(data, Mapping) or not isinstance(data.get("results"), list):
        raise SandboxError("Confluence space lookup returned malformed evidence")
    matches = [
        item
        for item in data["results"]
        if isinstance(item, Mapping)
        and str(item.get("key", "")).upper() == ownership.key
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise SandboxError("sandbox space key resolved to multiple provider spaces")
    space_id = _required_identity(matches[0].get("id", ""), "provider space ID")
    observed = connector._read_space(space_id)
    if (
        observed.get("key") != ownership.key
        or observed.get("name") != ownership.name
        or observed.get("type") != "global"
        or observed.get("status") != "current"
    ):
        raise SandboxError("space key resolved to content outside this sandbox run")
    return dict(observed)


def _persist_space_state(
    paths: RuntimePaths,
    *,
    space_id: str,
    reference: str | None,
) -> None:
    space_id = _required_identity(space_id, "provider space ID")
    _write_private_json(
        paths.root / "space-create-state.json",
        {
            "schema": "master-agent/confluence-sandbox-safe-space-state@1",
            "space_id": space_id,
            "reference": _safe_reference(reference),
        },
    )


def _delete_verified_space(
    paths: RuntimePaths,
    ownership: SpaceOwnership,
    *,
    space_id: str,
) -> str | None:
    from master_agent.models import ActionState, ExecutionResult

    observed = _verify_space(paths, ownership, space_id=space_id)
    action = _space_create_plan(ownership).actions[0]
    original = ExecutionResult(
        action_id=action.action_id,
        state=ActionState.SUCCEEDED,
        before=None,
        after=observed,
        message="sandbox exact created-space recovery",
    )
    connector = _load_registry(paths).resolve("confluence", "confluence.space.create")
    compensation = connector.compensate(action, original)
    verification = connector.verify_compensation(action, original, compensation)
    if not verification.verified:
        raise SandboxError("fresh provider observation did not confirm space cleanup")
    return _safe_reference(compensation.connector_reference)


def _space_lifecycle(args: argparse.Namespace) -> int:
    target = _target_from_args(args, require_space=False)
    paths = _private_root(args.root, create=True)
    _initialize_runtime(paths, target.origin)
    ownership_key = _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    space = build_space_ownership(
        target,
        run_label=args.run_label,
        ownership_key=ownership_key,
    )
    _write_private_json(paths.space_metadata, space.to_dict())
    _connect(paths)
    plan = _space_create_plan(space)
    _run_governed_plan(
        paths,
        phase="space-create",
        plan=plan,
        attempt_flag=paths.attempted("space"),
    )
    observed_space = _find_exact_space(paths, space)
    if observed_space is None:
        raise SandboxError("created sandbox space was not independently discoverable")
    space_id = _required_identity(observed_space.get("id", ""), "provider space ID")
    observed_space = _verify_space(paths, space, space_id=space_id)
    _persist_space_state(
        paths,
        space_id=space_id,
        reference=str(observed_space.get("reference", "")),
    )
    page_target = SandboxTarget(
        origin=target.origin,
        space_id=space_id,
        space_key=space.key,
        parent_id=None,
    )
    page = build_page_ownership(
        page_target,
        run_label=args.run_label,
        ownership_key=ownership_key,
    )
    _write_private_json(paths.page_metadata, page.to_dict())
    page_plan = _page_create_action(page)
    _run_governed_plan(
        paths,
        phase="space-page-create",
        plan=page_plan,
        attempt_flag=paths.attempted("page"),
    )
    found = _find_exact_page(paths, page, attempts=_SEARCH_ATTEMPTS)
    if found is None:
        raise SandboxError("disposable page in created space was not discoverable")
    observed_page, phase = found
    page_id = _required_identity(observed_page["id"], "provider page ID")
    verified_page = _verify_page(
        paths,
        page,
        page_id=page_id,
        phase=phase,
    )
    _persist_page_state(
        paths,
        page_id=page_id,
        phase=phase,
        reference=str(verified_page.get("reference", "")),
    )
    print(f"verified sandbox space {space_id} and disposable provider page {page_id}")
    return 0


def _cleanup_space(args: argparse.Namespace) -> int:
    paths = _private_root(args.root, create=False)
    if not paths.space_metadata.exists():
        print("no sandbox space ownership metadata exists; cleanup safely skipped")
        return 0
    if paths.page_metadata.exists():
        _cleanup_page(args)
    space = SpaceOwnership.from_dict(_read_json(paths.space_metadata))
    runtime_origin = str(_read_json(paths.target).get("origin", ""))
    if space.origin != runtime_origin:
        raise SandboxError("sandbox space ownership destination drifted")
    ownership_key = _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    expected = _space_owner_tag(
        ownership_key,
        origin=space.origin,
        space_key=space.key,
        marker=space.marker,
        created_at=space.created_at,
    )
    if not hmac.compare_digest(expected, space.owner_tag):
        raise SandboxError("sandbox space ownership metadata failed authentication")
    state_path = paths.root / "space-create-state.json"
    if state_path.exists():
        state = _read_json(state_path)
        space_id = _required_identity(state.get("space_id", ""), "provider space ID")
    elif paths.attempted("space").exists():
        found = _find_exact_space(paths, space)
        if found is None:
            print("fresh exact-key read confirms no owned sandbox space")
            return 0
        space_id = _required_identity(found.get("id", ""), "provider space ID")
    else:
        print("sandbox space mutation was never attempted; cleanup safely skipped")
        return 0
    current = _find_exact_space(paths, space)
    if current is None:
        print(f"fresh exact-key read confirms space {space_id} is already gone")
        return 0
    if str(current.get("id", "")) != space_id:
        raise SandboxError("sandbox space key now resolves to another provider ID")
    reference = _delete_verified_space(
        paths,
        space,
        space_id=space_id,
    )
    suffix = f" ({reference})" if reference else ""
    print(f"verified cleanup of provider space {space_id}{suffix}")
    return 0


def _reap(args: argparse.Namespace) -> int:
    target = _target_from_args(args, require_space=True)
    _normalized_run_label(args.run_label)
    if args.max_resources < 1 or args.max_resources > _MAX_REAPER_RESOURCES:
        raise SandboxError(f"reaper max-resources must be 1..{_MAX_REAPER_RESOURCES}")
    if args.min_age_hours < 1 or args.min_age_hours > 24 * 30:
        raise SandboxError("reaper min-age-hours must be 1..720")
    paths = _private_root(args.root, create=True)
    _initialize_runtime(paths, target.origin)
    _connect(paths)
    ownership_key = _require_secret(_OWNERSHIP_ENV, minimum_bytes=32)
    cutoff = datetime.now(UTC) - timedelta(hours=args.min_age_hours)
    pages = _search_pages(
        paths,
        space_key=target.space_key or "",
        title=None,
        limit=args.max_resources,
    )
    candidates: list[tuple[dict[str, Any], PageOwnership, str]] = []
    for page in pages:
        matched = is_stale_candidate(
            page,
            target=target,
            ownership_key=ownership_key,
            cutoff=cutoff,
        )
        if matched is not None:
            candidates.append((page, matched[0], matched[1]))
    print(f"stale sandbox reaper preview: {len(candidates)} exact owned candidate(s)")
    for page, _, _ in candidates:
        page_id = _required_identity(page.get("id"), "provider page ID")
        print(f"candidate provider page {page_id} ({page['title']})")
    if args.mode == "preview":
        return 0
    for page, ownership, phase in candidates:
        page_id = _required_identity(page["id"], "provider page ID")
        reference = _delete_verified_page(
            paths,
            ownership,
            page_id=page_id,
            phase=phase,
        )
        suffix = f" ({reference})" if reference else ""
        print(f"verified reaping of provider page {page_id}{suffix}")
    return 0


def _target_from_args(
    args: argparse.Namespace,
    *,
    require_space: bool,
) -> SandboxTarget:
    return validate_target(
        configured_origin=args.origin,
        allowlisted_origin=args.allowlisted_origin,
        non_production_attestation=args.non_production,
        space_id=getattr(args, "space_id", None),
        space_key=getattr(args, "space_key", None),
        parent_id=getattr(args, "parent_id", None),
        require_space=require_space,
    )


def _add_origin_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--origin", required=True)
    parser.add_argument("--allowlisted-origin", required=True)
    parser.add_argument("--non-production", required=True)


def _add_space_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--space-id", required=True)
    parser.add_argument("--space-key", required=True)
    parser.add_argument("--parent-id")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded MasterAgent tests in an approved Confluence sandbox."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser(
        "preflight",
        help="validate the public sandbox destination without network or secrets",
    )
    _add_origin_arguments(preflight)
    preflight.add_argument("--space-id")
    preflight.add_argument("--space-key")
    preflight.add_argument("--parent-id")
    preflight.add_argument("--require-space", action="store_true")

    page = commands.add_parser("page-lifecycle")
    _add_origin_arguments(page)
    _add_space_arguments(page)
    page.add_argument("--root", type=Path, required=True)
    page.add_argument("--run-label", required=True)

    cleanup_page = commands.add_parser("cleanup-page")
    cleanup_page.add_argument("--root", type=Path, required=True)

    space = commands.add_parser("space-lifecycle")
    _add_origin_arguments(space)
    space.add_argument("--root", type=Path, required=True)
    space.add_argument("--run-label", required=True)

    cleanup_space = commands.add_parser("cleanup-space")
    cleanup_space.add_argument("--root", type=Path, required=True)

    reap = commands.add_parser("reap")
    _add_origin_arguments(reap)
    _add_space_arguments(reap)
    reap.add_argument("--root", type=Path, required=True)
    reap.add_argument("--run-label", required=True)
    reap.add_argument("--mode", choices=("preview", "delete"), default="preview")
    reap.add_argument("--min-age-hours", type=int, default=24)
    reap.add_argument("--max-resources", type=int, default=_MAX_REAPER_RESOURCES)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one secret-safe sandbox command."""

    args = _build_parser().parse_args(argv)
    try:
        if args.command == "preflight":
            target = _target_from_args(args, require_space=args.require_space)
            print(f"approved non-production Confluence origin: {target.origin}")
            return 0
        if args.command == "page-lifecycle":
            return _page_lifecycle(args)
        if args.command == "cleanup-page":
            return _cleanup_page(args)
        if args.command == "space-lifecycle":
            return _space_lifecycle(args)
        if args.command == "cleanup-space":
            return _cleanup_space(args)
        if args.command == "reap":
            return _reap(args)
        raise SandboxError("unsupported sandbox command")
    except SandboxError as error:
        print(f"Confluence sandbox test failed safely: {error}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001 - never expose provider content.
        print(
            "Confluence sandbox test failed safely: " + type(error).__name__,
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
