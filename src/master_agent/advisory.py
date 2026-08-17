"""Fail-closed advisory profile and dispatch boundary.

Direct GitHub-host child invocation is disabled because the host cannot enforce
this repository's parent allowlist, depth, and per-goal counters. This module is
the deterministic boundary used by tests and by any future approved adapter.
"""

from __future__ import annotations

import json
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Protocol

PARENT_PROFILE_PATH = Path(".github/agents/MasterAgent.agent.md")
RESEARCHER_PROFILE_PATH = Path(".github/agents/MasterAgent-Read-Researcher.agent.md")
PLAN_REVIEWER_PROFILE_PATH = Path(".github/agents/MasterAgent-Plan-Reviewer.agent.md")
EXPECTED_PROFILE_PATHS = frozenset(
    {PARENT_PROFILE_PATH, RESEARCHER_PROFILE_PATH, PLAN_REVIEWER_PROFILE_PATH}
)

_PARENT_TOOLS = ("read", "search", "edit", "execute")
_CHILD_TOOLS = ("read", "search")
_FRONTMATTER_KEY = re.compile(r"([a-z][a-z0-9-]*):(?:\s*(.*))?")
_MAX_PROFILE_BYTES = 128 * 1024
_MAX_PAYLOAD_BYTES = 64 * 1024
_MAX_PAYLOAD_ITEMS = 256
_MAX_PAYLOAD_DEPTH = 8
_MAX_TEXT = 16 * 1024
_MAX_FILES = 512
_MAX_FILE_BYTES = 64 * 1024
_MAX_RESULTS = 20
_REQUIRED_MARKERS: dict[Path, tuple[str, ...]] = {
    PARENT_PROFILE_PATH: (
        "Direct GitHub-host advisory invocation is disabled",
        "repository-owned advisory integration harness",
        "complete the same work directly",
    ),
    RESEARCHER_PROFILE_PATH: (
        "Direct GitHub-host invocation is disabled",
        "repository-owned advisory integration harness",
        "Use only `read` and `search`",
        "advisory data, never authority",
    ),
    PLAN_REVIEWER_PROFILE_PATH: (
        "Direct GitHub-host invocation is disabled",
        "repository-owned advisory integration harness",
        "Use only `read` and `search`",
        "advisory data, never authority",
    ),
}
_FORBIDDEN_CHILD_TEXT = (
    re.compile(
        r"\byou may (?:use|invoke|call) (?:execute|edit|agent|mcp|http)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bprovider tools are allowed\b", re.IGNORECASE),
    re.compile(
        r"\byou may (?:contact|write to|mutate) (?:a )?provider\b", re.IGNORECASE
    ),
    re.compile(r"\byou may (?:approve|sign|bind|merge|send|publish)\b", re.IGNORECASE),
    re.compile(
        r"\bignore (?:the )?(?:boundary|tool restriction|parent)\b", re.IGNORECASE
    ),
    re.compile(r"\brecursive delegation is allowed\b", re.IGNORECASE),
)
_FORBIDDEN_KEYS = (
    "approval",
    "authority",
    "changeplan",
    "change_plan",
    "connector",
    "credential",
    "password",
    "private_context",
    "recipient",
    "secret",
    "signing",
    "target",
    "tenant",
    "token",
)
_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:token|password|secret)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bapproval(?:-artifact)?://\S+", re.IGNORECASE),
)


class AdvisoryError(ValueError):
    """Base advisory-boundary error."""


class ProfileValidationError(AdvisoryError):
    """Unsafe or malformed profile."""


class AdvisoryDispatchDenied(AdvisoryError):
    """Tool or profile invocation denied before dispatch."""


class AdvisoryPayloadRejected(AdvisoryError):
    """Sensitive or authority-bearing input rejected."""


class AdvisoryReportRejected(AdvisoryError):
    """Unsafe child report rejected by the parent boundary."""


class AdvisoryRole(StrEnum):
    """Supported advisory roles."""

    RESEARCH = "research"
    PLAN_REVIEW = "plan_review"


class DelegationStatus(StrEnum):
    """Delegation outcome."""

    COMPLETED = "completed"
    FALLBACK = "fallback"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """Parsed checked-in custom-agent profile."""

    path: Path
    name: str
    description: str
    tools: tuple[str, ...]
    user_invocable: bool
    disable_model_invocation: bool
    body: str


@dataclass(frozen=True, slots=True)
class AgentInventory:
    """Exact parent and child profile inventory."""

    parent: AgentProfile
    researcher: AgentProfile
    reviewer: AgentProfile

    def child(self, role: AdvisoryRole) -> AgentProfile:
        """Return the profile for one advisory role."""

        return self.researcher if role is AdvisoryRole.RESEARCH else self.reviewer


@dataclass(frozen=True, slots=True)
class BoundarySnapshot:
    """Content-free protected-state snapshot."""

    filesystem: tuple[str, ...]
    environment: tuple[str, ...]
    network: tuple[str, ...]
    provider: tuple[str, ...]
    credential: tuple[str, ...]
    approval: tuple[str, ...]
    audit: tuple[str, ...]


@dataclass(slots=True)
class BoundaryRecorders:
    """Record any protected effect attempted by a test adapter."""

    filesystem: list[str] = field(default_factory=list)
    environment: list[str] = field(default_factory=list)
    network: list[str] = field(default_factory=list)
    provider: list[str] = field(default_factory=list)
    credential: list[str] = field(default_factory=list)
    approval: list[str] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)

    def snapshot(self) -> BoundarySnapshot:
        """Return an immutable snapshot."""

        return BoundarySnapshot(
            tuple(self.filesystem),
            tuple(self.environment),
            tuple(self.network),
            tuple(self.provider),
            tuple(self.credential),
            tuple(self.approval),
            tuple(self.audit),
        )


@dataclass(frozen=True, slots=True)
class Citation:
    """Bounded repository evidence."""

    path: str
    excerpt: str


class RepositoryFixture:
    """Hermetic repository view for deterministic integration tests."""

    def __init__(self, files: Mapping[str, str]) -> None:
        if len(files) > _MAX_FILES:
            raise AdvisoryDispatchDenied("repository fixture exceeds the file limit")
        normalized: dict[str, str] = {}
        for path, content in files.items():
            if len(content.encode("utf-8")) > _MAX_FILE_BYTES:
                raise AdvisoryDispatchDenied(f"repository fixture is too large: {path}")
            normalized[_normalize_path(path)] = content
        self._files = MappingProxyType(normalized)

    def read(self, path: str) -> Citation:
        """Read one exact fixture path."""

        normalized = _normalize_path(path)
        try:
            content = self._files[normalized]
        except KeyError as error:
            raise AdvisoryDispatchDenied(
                f"repository path is unavailable: {path}"
            ) from error
        return Citation(normalized, content[:8192])

    def search(self, query: str) -> tuple[Citation, ...]:
        """Search bounded fixture text for a literal query."""

        if not query or len(query) > 512:
            raise AdvisoryDispatchDenied("search query must contain 1-512 characters")
        results: list[Citation] = []
        folded = query.casefold()
        for path, content in sorted(self._files.items()):
            index = content.casefold().find(folded)
            if index < 0:
                continue
            start = max(0, index - 80)
            end = min(len(content), index + len(query) + 160)
            results.append(Citation(path, content[start:end]))
            if len(results) >= _MAX_RESULTS:
                break
        return tuple(results)

    def contains(self, path: str) -> bool:
        """Return whether a normalized path exists."""

        try:
            return _normalize_path(path) in self._files
        except AdvisoryDispatchDenied:
            return False


@dataclass(frozen=True, slots=True)
class AdvisoryToolResult:
    """Allowed tool result."""

    tool: str
    citations: tuple[Citation, ...]


class AdvisoryDispatcher:
    """Profile-derived dispatcher with no generic execution surface."""

    def __init__(self, profile: AgentProfile, repository: RepositoryFixture) -> None:
        self._profile = profile
        self._repository = repository

    @property
    def allowed_tools(self) -> frozenset[str]:
        """Return the exact checked-in profile tools."""

        return frozenset(self._profile.tools)

    def dispatch(
        self, tool: str, arguments: Mapping[str, object]
    ) -> AdvisoryToolResult:
        """Dispatch one bounded read/search call or deny it pre-effect."""

        if tool not in self.allowed_tools:
            raise AdvisoryDispatchDenied(
                f"tool {tool!r} is absent from profile {self._profile.name!r}"
            )
        if tool == "read" and set(arguments) == {"path"}:
            path = arguments.get("path")
            if isinstance(path, str):
                return AdvisoryToolResult(tool, (self._repository.read(path),))
        if tool == "search" and set(arguments) == {"query"}:
            query = arguments.get("query")
            if isinstance(query, str):
                return AdvisoryToolResult(tool, self._repository.search(query))
        raise AdvisoryDispatchDenied(f"invalid arguments for safe tool {tool!r}")


@dataclass(frozen=True, slots=True)
class AdvisoryEnvelope:
    """Sanitized child task."""

    task_id: str
    role: AdvisoryRole
    profile_name: str
    depth: int
    payload: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class AdvisoryReport:
    """Untrusted child output awaiting parent re-validation."""

    summary: str
    findings: tuple[str, ...]
    citations: tuple[str, ...]
    proposed_target: str | None = None
    claimed_approval: str | None = None
    proposed_plan: Mapping[str, object] | None = None
    extra: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VerifiedAdvisoryEvidence:
    """Report evidence accepted after parent re-read."""

    summary: str
    findings: tuple[str, ...]
    citations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DelegationOutcome:
    """One bounded delegation outcome."""

    status: DelegationStatus
    role: AdvisoryRole
    fallback_to_parent: bool
    reason: str
    report: AdvisoryReport | None = None


class AdvisoryWorker(Protocol):
    """Future approved worker adapter."""

    def __call__(
        self, envelope: AdvisoryEnvelope, dispatcher: AdvisoryDispatcher
    ) -> AdvisoryReport:
        """Run one sanitized task and return untrusted output."""
        ...


class AdvisoryBroker:
    """Parent-bound repository-owned advisory boundary."""

    MAX_RESEARCH_TASKS = 3
    MAX_PLAN_REVIEWS = 1

    def __init__(
        self,
        inventory: AgentInventory,
        repository: RepositoryFixture,
        recorders: BoundaryRecorders | None = None,
    ) -> None:
        self._inventory = inventory
        self._repository = repository
        self._recorders = recorders or BoundaryRecorders()

    @property
    def protected_state(self) -> BoundarySnapshot:
        """Return the protected state snapshot."""

        return self._recorders.snapshot()

    def select_profile(self, name: str, *, by_user: bool) -> AgentProfile:
        """Enforce direct invocation flags."""

        profiles = {
            self._inventory.parent.name: self._inventory.parent,
            self._inventory.researcher.name: self._inventory.researcher,
            self._inventory.reviewer.name: self._inventory.reviewer,
        }
        try:
            profile = profiles[name]
        except KeyError as error:
            raise ProfileValidationError(f"unknown profile: {name}") from error
        if by_user and not profile.user_invocable:
            raise AdvisoryDispatchDenied(f"profile {name!r} is not user-invocable")
        if not by_user and profile.disable_model_invocation:
            raise AdvisoryDispatchDenied(f"direct host invocation is disabled: {name}")
        return profile

    def start_session(self, parent_name: str, task_id: str) -> AdvisorySession:
        """Create one selected-parent delegation budget."""

        if parent_name != self._inventory.parent.name:
            raise AdvisoryDispatchDenied(
                "session must be owned by selected MasterAgent"
            )
        if not task_id.strip() or len(task_id) > 256:
            raise AdvisoryPayloadRejected("task_id must contain 1-256 characters")
        return AdvisorySession(self, task_id)

    def recheck_report(self, report: AdvisoryReport) -> VerifiedAdvisoryEvidence:
        """Reject authority-bearing output and independently re-read citations."""

        _validate_report(report)
        missing = sorted(
            path
            for path in set(report.citations)
            if not self._repository.contains(path)
        )
        if missing:
            raise AdvisoryReportRejected(
                "report cites unavailable evidence: " + ", ".join(missing)
            )
        return VerifiedAdvisoryEvidence(
            report.summary,
            report.findings,
            tuple(sorted(set(report.citations))),
        )


class AdvisorySession:
    """One operator-goal depth and call budget."""

    def __init__(self, broker: AdvisoryBroker, task_id: str) -> None:
        self._broker = broker
        self._task_id = task_id
        self._research_attempts = 0
        self._review_attempts = 0

    @property
    def research_attempts(self) -> int:
        """Return reserved research attempts."""

        return self._research_attempts

    @property
    def review_attempts(self) -> int:
        """Return reserved review attempts."""

        return self._review_attempts

    def delegate(
        self,
        role: AdvisoryRole,
        payload: Mapping[str, object],
        *,
        worker: AdvisoryWorker | None,
        depth: int = 0,
    ) -> DelegationOutcome:
        """Attempt one child task or return explicit parent fallback."""

        if depth != 0:
            return DelegationOutcome(
                DelegationStatus.DENIED,
                role,
                True,
                "nested delegation is denied; keep the task on the parent",
            )
        try:
            sanitized = sanitize_payload(payload)
        except AdvisoryPayloadRejected as error:
            return DelegationOutcome(DelegationStatus.DENIED, role, True, str(error))
        if not self._reserve(role):
            return DelegationOutcome(
                DelegationStatus.FALLBACK,
                role,
                True,
                "delegation budget exhausted; keep work on the parent path",
            )
        if worker is None:
            return DelegationOutcome(
                DelegationStatus.FALLBACK,
                role,
                True,
                "no approved host adapter is available; complete the task directly",
            )
        profile = self._broker._inventory.child(role)
        envelope = AdvisoryEnvelope(self._task_id, role, profile.name, depth, sanitized)
        dispatcher = AdvisoryDispatcher(profile, self._broker._repository)
        try:
            report = worker(envelope, dispatcher)
            _validate_report(report)
        except (RuntimeError, TypeError, ValueError) as error:
            return DelegationOutcome(
                DelegationStatus.FALLBACK,
                role,
                True,
                f"advisory worker failed closed: {error}",
            )
        return DelegationOutcome(
            DelegationStatus.COMPLETED,
            role,
            False,
            "untrusted report returned for parent re-validation",
            report,
        )

    def _reserve(self, role: AdvisoryRole) -> bool:
        if role is AdvisoryRole.RESEARCH:
            if self._research_attempts >= AdvisoryBroker.MAX_RESEARCH_TASKS:
                return False
            self._research_attempts += 1
            return True
        if self._review_attempts >= AdvisoryBroker.MAX_PLAN_REVIEWS:
            return False
        self._review_attempts += 1
        return True


def validate_profile_inventory(root: Path) -> tuple[str, ...]:
    """Validate exact profiles, tools, flags, markers, and contradictory text."""

    root = root.resolve()
    errors: list[str] = []
    agents = root / ".github/agents"
    observed = {
        path.relative_to(root)
        for path in agents.glob("*.md")
        if path.is_file() and not path.is_symlink()
    }
    if missing := sorted(EXPECTED_PROFILE_PATHS - observed):
        errors.append("missing agent profiles: " + ", ".join(map(str, missing)))
    if unexpected := sorted(observed - EXPECTED_PROFILE_PATHS):
        errors.append("unreviewed agent profiles: " + ", ".join(map(str, unexpected)))

    expected: dict[Path, tuple[str, tuple[str, ...], bool, bool]] = {
        PARENT_PROFILE_PATH: ("MasterAgent", _PARENT_TOOLS, True, True),
        RESEARCHER_PROFILE_PATH: (
            "MasterAgent Read Researcher",
            _CHILD_TOOLS,
            False,
            True,
        ),
        PLAN_REVIEWER_PROFILE_PATH: (
            "MasterAgent Plan Reviewer",
            _CHILD_TOOLS,
            False,
            True,
        ),
    }
    for relative in sorted(EXPECTED_PROFILE_PATHS):
        try:
            profile = _load_profile(root / relative, relative)
        except ProfileValidationError as error:
            errors.append(str(error))
            continue
        name, tools, user_invocable, model_disabled = expected[relative]
        if profile.name != name:
            errors.append(f"{relative} must be named {name!r}")
        if profile.tools != tools:
            errors.append(f"{relative} tools must be exactly: {', '.join(tools)}")
        if profile.user_invocable is not user_invocable:
            errors.append(f"{relative} has an unsafe user invocation flag")
        if profile.disable_model_invocation is not model_disabled:
            errors.append(f"{relative} has an unsafe model invocation flag")
        if "agent" in profile.tools:
            errors.append(f"{relative} must not expose direct host delegation")
        for marker in _REQUIRED_MARKERS[relative]:
            if marker.casefold() not in profile.body.casefold():
                errors.append(f"{relative} is missing required boundary {marker!r}")
        if relative != PARENT_PROFILE_PATH:
            for pattern in _FORBIDDEN_CHILD_TEXT:
                if pattern.search(profile.body):
                    errors.append(
                        f"{relative} contains contradictory permission text: "
                        f"{pattern.pattern}"
                    )
    return tuple(sorted(set(errors)))


def load_agent_inventory(root: Path) -> AgentInventory:
    """Load profiles only after complete inventory validation."""

    errors = validate_profile_inventory(root)
    if errors:
        raise ProfileValidationError("; ".join(errors))
    root = root.resolve()
    return AgentInventory(
        _load_profile(root / PARENT_PROFILE_PATH, PARENT_PROFILE_PATH),
        _load_profile(root / RESEARCHER_PROFILE_PATH, RESEARCHER_PROFILE_PATH),
        _load_profile(root / PLAN_REVIEWER_PROFILE_PATH, PLAN_REVIEWER_PROFILE_PATH),
    )


def sanitize_payload(payload: Mapping[str, object]) -> Mapping[str, object]:
    """Return an immutable bounded copy or reject sensitive context."""

    count = [0]
    result = _sanitize(payload, depth=0, count=count, context="payload")
    if not isinstance(result, Mapping):
        raise AdvisoryPayloadRejected("delegated payload must be a mapping")
    material = json.dumps(
        _thaw(result), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(material) > _MAX_PAYLOAD_BYTES:
        raise AdvisoryPayloadRejected("delegated payload exceeds the byte limit")
    return result


def _sanitize(value: object, *, depth: int, count: list[int], context: str) -> object:
    if depth > _MAX_PAYLOAD_DEPTH:
        raise AdvisoryPayloadRejected("delegated payload exceeds the depth limit")
    count[0] += 1
    if count[0] > _MAX_PAYLOAD_ITEMS:
        raise AdvisoryPayloadRejected("delegated payload exceeds the item limit")
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str):
        if len(value) > _MAX_TEXT:
            raise AdvisoryPayloadRejected(f"{context} string is too large")
        _reject_secret_text(value, context)
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise AdvisoryPayloadRejected(f"{context} keys must be strings")
            normalized = key.casefold().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_KEYS):
                raise AdvisoryPayloadRejected(f"forbidden delegated field: {key}")
            result[key] = _sanitize(
                item, depth=depth + 1, count=count, context=f"{context}.{key}"
            )
        return MappingProxyType(result)
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return tuple(
            _sanitize(item, depth=depth + 1, count=count, context=f"{context}[]")
            for item in value
        )
    raise AdvisoryPayloadRejected(
        f"unsupported delegated value: {type(value).__name__}"
    )


def _validate_report(report: AdvisoryReport) -> None:
    if not report.summary.strip() or len(report.summary) > _MAX_TEXT:
        raise AdvisoryReportRejected("report summary must contain bounded text")
    if len(report.findings) > 64 or len(report.citations) > 64:
        raise AdvisoryReportRejected("report exceeds the item limit")
    if report.proposed_target is not None:
        raise AdvisoryReportRejected("report cannot select a target")
    if report.claimed_approval is not None:
        raise AdvisoryReportRejected("report cannot claim approval")
    if report.proposed_plan is not None:
        raise AdvisoryReportRejected("report cannot create or alter a plan")
    try:
        _reject_secret_text(report.summary, "report summary")
        for finding in report.findings:
            if not finding.strip() or len(finding) > _MAX_TEXT:
                raise AdvisoryReportRejected("report finding must contain bounded text")
            _reject_secret_text(finding, "report finding")
        if report.extra:
            sanitize_payload(report.extra)
        for citation in report.citations:
            _normalize_path(citation)
    except (AdvisoryPayloadRejected, AdvisoryDispatchDenied) as error:
        raise AdvisoryReportRejected(str(error)) from error


def _load_profile(path: Path, relative: Path) -> AgentProfile:
    text = _read_profile(path, relative)
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ProfileValidationError(f"{relative} must start with frontmatter")
    try:
        closing = lines.index("---", 1)
    except ValueError as error:
        raise ProfileValidationError(f"{relative} lacks closing frontmatter") from error
    metadata: dict[str, object] = {}
    active: str | None = None
    for number, line in enumerate(lines[1:closing], start=2):
        if line.startswith("  - "):
            current = metadata.get(active or "")
            if not isinstance(current, list) or not line[4:].strip():
                raise ProfileValidationError(
                    f"{relative}:{number} has invalid list data"
                )
            current.append(line[4:].strip())
            continue
        active = None
        match = _FRONTMATTER_KEY.fullmatch(line)
        if match is None:
            raise ProfileValidationError(f"{relative}:{number} has invalid syntax")
        key, raw = match.groups()
        if key in metadata:
            raise ProfileValidationError(f"{relative}:{number} repeats {key}")
        if not raw:
            metadata[key] = []
            active = key
        elif raw == "true":
            metadata[key] = True
        elif raw == "false":
            metadata[key] = False
        else:
            metadata[key] = raw.strip("'\"")
    keys = {
        "name",
        "description",
        "tools",
        "user-invocable",
        "disable-model-invocation",
    }
    if set(metadata) != keys:
        raise ProfileValidationError(f"{relative} has unsupported frontmatter keys")
    name = metadata["name"]
    description = metadata["description"]
    tools = metadata["tools"]
    user_invocable = metadata["user-invocable"]
    model_disabled = metadata["disable-model-invocation"]
    if not isinstance(name, str) or not name.strip():
        raise ProfileValidationError(f"{relative} name is invalid")
    if not isinstance(description, str) or not description.strip():
        raise ProfileValidationError(f"{relative} description is invalid")
    if not isinstance(tools, list) or not all(isinstance(item, str) for item in tools):
        raise ProfileValidationError(f"{relative} tools are invalid")
    if not isinstance(user_invocable, bool) or not isinstance(model_disabled, bool):
        raise ProfileValidationError(f"{relative} invocation flags are invalid")
    body = "\n".join(lines[closing + 1 :]).strip()
    if not body:
        raise ProfileValidationError(f"{relative} body is empty")
    return AgentProfile(
        relative,
        name,
        description,
        tuple(str(item) for item in tools),
        user_invocable,
        model_disabled,
        body,
    )


def _read_profile(path: Path, relative: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProfileValidationError(f"{relative} is unreadable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProfileValidationError(f"{relative} must be a regular non-symlink")
    if metadata.st_size > _MAX_PROFILE_BYTES:
        raise ProfileValidationError(f"{relative} exceeds the byte limit")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ProfileValidationError(f"{relative} is unreadable: {error}") from error


def _normalize_path(value: str) -> str:
    if not value or "\\" in value:
        raise AdvisoryDispatchDenied(f"unsafe repository path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise AdvisoryDispatchDenied(f"unsafe repository path: {value!r}")
    if pure.as_posix() != value:
        raise AdvisoryDispatchDenied(f"repository path is not normalized: {value!r}")
    return value


def _reject_secret_text(value: str, context: str) -> None:
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise AdvisoryPayloadRejected(f"{context} contains secret-like content")


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value
