"""Deterministic local draft and preview generators for Phase 3."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from master_agent.errors import ConnectorError
from master_agent.models import (
    ActionState,
    AgentAction,
    ExecutionResult,
    ResourceRef,
    VerificationResult,
)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True, slots=True)
class GeneratedArtifact:
    """Metadata for a locally generated draft."""

    path: Path
    sha256: str
    media_type: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible artifact metadata."""

        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "media_type": self.media_type,
            "size": self.size,
        }


class _LocalDraftConnector:
    """Base connector for generation under one controlled output root."""

    def __init__(
        self,
        *,
        system: str,
        capabilities: frozenset[str],
        output_root: Path,
    ) -> None:
        self._system = system
        self._capabilities = capabilities
        self._output_root = output_root.expanduser().resolve()
        self._output_root.mkdir(parents=True, exist_ok=True)

    @property
    def system(self) -> str:
        """Return connector system."""

        return self._system

    @property
    def capabilities(self) -> frozenset[str]:
        """Return supported local-generation capabilities."""

        return self._capabilities

    def read(self, resource: ResourceRef) -> dict[str, object] | None:
        """Read generated artifact metadata by resource identifier."""

        matches = sorted(
            self._output_root.glob(f"{_safe_name(resource.resource_id)}.*")
        )
        if not matches:
            return None
        path = matches[0]
        return {
            "path": str(path),
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }

    def verify(
        self,
        action: AgentAction,
        result: ExecutionResult,
    ) -> VerificationResult:
        """Verify the artifact exists and matches its recorded digest."""

        after = result.after or {}
        path_value = after.get("path")
        digest = after.get("sha256")
        if not isinstance(path_value, str) or not isinstance(digest, str):
            return VerificationResult(
                action_id=action.action_id,
                verified=False,
                observed=None,
                message="generated artifact metadata was incomplete",
            )
        path = Path(path_value)
        verified = (
            path.is_file()
            and _contained(path, self._output_root)
            and _sha256(path) == digest
        )
        observed = {
            "path": str(path),
            "sha256": _sha256(path) if path.is_file() else None,
            "size": path.stat().st_size if path.is_file() else None,
        }
        return VerificationResult(
            action_id=action.action_id,
            verified=verified,
            observed=observed,
            message=(
                "verified local artifact digest"
                if verified
                else "local artifact digest mismatch"
            ),
        )

    def _artifact_path(
        self,
        action: AgentAction,
        *,
        default_suffix: str,
    ) -> Path:
        raw = str(action.parameters.get("output_name", "")).strip()
        if raw:
            name = Path(raw).name
            if name != raw or raw in {".", ".."}:
                raise ConnectorError("output_name must be a single filename")
            name = _safe_name(name)
        else:
            name = f"{_safe_name(action.target.resource_id)}{default_suffix}"
        if not name:
            raise ConnectorError("generated artifact filename is empty")
        path = (self._output_root / name).resolve()
        if not _contained(path, self._output_root):
            raise ConnectorError("generated artifact escaped the output root")
        return path

    def _result(
        self,
        action: AgentAction,
        artifact: GeneratedArtifact,
        *,
        message: str,
        extra: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        after = artifact.to_dict()
        if extra:
            after.update(dict(extra))
        return ExecutionResult(
            action_id=action.action_id,
            state=ActionState.SUCCEEDED,
            before=None,
            after=after,
            connector_reference=str(artifact.path),
            message=message,
        )


class JiraDraftConnector(_LocalDraftConnector):
    """Generate Jira update/comment/transition proposals without publishing."""

    _CAPABILITIES = frozenset(
        {
            "jira.issue.update.draft",
            "jira.issue.comment.draft",
            "jira.issue.transition.draft",
        }
    )

    def __init__(self, output_root: Path) -> None:
        super().__init__(
            system="jira",
            capabilities=self._CAPABILITIES,
            output_root=output_root,
        )

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Write a JSON proposal with a Markdown preview."""

        _require_capability(action, self)
        before = _mapping(action.parameters.get("before"), "before", default={})
        if action.capability == "jira.issue.update.draft":
            change = _mapping(action.parameters.get("fields"), "fields")
            after = {**before, **change}
            operation = "update"
        elif action.capability == "jira.issue.comment.draft":
            body = _required_text(action.parameters, "body")
            after = {"comment": body}
            operation = "comment"
        else:
            transition_id = _required_text(action.parameters, "transition_id")
            after = {
                **before,
                "transition_id": transition_id,
                "target_status": str(action.parameters.get("target_status", "")).strip()
                or None,
            }
            operation = "transition"

        payload = {
            "schema": "master-agent/jira-draft@1",
            "system": "jira",
            "issue": action.target.resource_id,
            "operation": operation,
            "expected_version": action.target.expected_version,
            "before": before,
            "after": after,
            "publish": False,
        }
        path = self._artifact_path(action, default_suffix=".jira-draft.json")
        artifact = _write_json(path, payload)
        preview_path = path.with_suffix(".md")
        preview = _render_preview(
            title=f"Jira {operation} draft — {action.target.resource_id}",
            before=before,
            after=after,
        )
        preview_artifact = _write_text(preview_path, preview, "text/markdown")
        return self._result(
            action,
            artifact,
            message="generated Jira draft without publishing",
            extra={"preview": preview_artifact.to_dict(), "operation": operation},
        )


class ConfluenceDraftConnector(_LocalDraftConnector):
    """Generate Confluence create/update proposals without publishing."""

    _CAPABILITIES = frozenset(
        {"confluence.page.create.draft", "confluence.page.update.draft"}
    )

    def __init__(self, output_root: Path) -> None:
        super().__init__(
            system="confluence",
            capabilities=self._CAPABILITIES,
            output_root=output_root,
        )

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Write Confluence page proposal and before/after preview."""

        _require_capability(action, self)
        before = _mapping(action.parameters.get("before"), "before", default={})
        title = _required_text(action.parameters, "title")
        body = _required_text(action.parameters, "body")
        representation = str(action.parameters.get("representation", "storage")).strip()
        if representation not in {"storage", "atlas_doc_format"}:
            raise ConnectorError(
                "Confluence representation must be storage or atlas_doc_format"
            )
        after = {
            "title": title,
            "body": body,
            "representation": representation,
            "space_id": action.parameters.get("space_id"),
            "parent_id": action.parameters.get("parent_id"),
        }
        operation = "create" if action.capability.endswith("create.draft") else "update"
        payload = {
            "schema": "master-agent/confluence-draft@1",
            "system": "confluence",
            "page_id": action.target.resource_id,
            "operation": operation,
            "expected_version": action.target.expected_version,
            "before": before,
            "after": after,
            "publish": False,
        }
        path = self._artifact_path(action, default_suffix=".confluence-draft.json")
        artifact = _write_json(path, payload)
        preview_artifact = _write_text(
            path.with_suffix(".md"),
            _render_preview(
                title=f"Confluence {operation} draft — {title}",
                before=before,
                after=after,
            ),
            "text/markdown",
        )
        return self._result(
            action,
            artifact,
            message="generated Confluence draft without publishing",
            extra={"preview": preview_artifact.to_dict(), "operation": operation},
        )


class OutlookDraftConnector(_LocalDraftConnector):
    """Generate RFC 5322 email drafts without sending."""

    _CAPABILITIES = frozenset({"outlook.email.draft"})

    def __init__(self, output_root: Path) -> None:
        super().__init__(
            system="outlook",
            capabilities=self._CAPABILITIES,
            output_root=output_root,
        )

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Create a local ``.eml`` file and metadata manifest."""

        _require_capability(action, self)
        to = _string_list(action.parameters.get("to"), "to", required=True)
        cc = _string_list(action.parameters.get("cc"), "cc")
        bcc = _string_list(action.parameters.get("bcc"), "bcc")
        subject = _required_text(action.parameters, "subject")
        body = _required_text(action.parameters, "body")
        message = EmailMessage()
        message["To"] = ", ".join(to)
        if cc:
            message["Cc"] = ", ".join(cc)
        if bcc:
            message["Bcc"] = ", ".join(bcc)
        message["Subject"] = subject
        message.set_content(body)
        path = self._artifact_path(action, default_suffix=".eml")
        artifact = _write_bytes(path, message.as_bytes(), "message/rfc822")
        metadata = {
            "schema": "master-agent/outlook-draft@1",
            "to": list(to),
            "cc": list(cc),
            "bcc": list(bcc),
            "subject": subject,
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "send": False,
        }
        manifest = _write_json(path.with_suffix(".json"), metadata)
        return self._result(
            action,
            artifact,
            message="generated local Outlook email draft without sending",
            extra={
                "manifest": manifest.to_dict(),
                "recipients": len(to) + len(cc) + len(bcc),
            },
        )


class TeamsDraftConnector(_LocalDraftConnector):
    """Generate Teams message drafts without posting."""

    _CAPABILITIES = frozenset({"teams.message.draft"})

    def __init__(self, output_root: Path) -> None:
        super().__init__(
            system="teams",
            capabilities=self._CAPABILITIES,
            output_root=output_root,
        )

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Write a Teams draft as Markdown plus structured metadata."""

        _require_capability(action, self)
        body = _required_text(action.parameters, "body")
        recipient_type = str(action.parameters.get("recipient_type", "chat")).strip()
        if recipient_type not in {"chat", "channel", "user", "team"}:
            raise ConnectorError("recipient_type must be chat, channel, user, or team")
        recipient_id = _required_text(action.parameters, "recipient_id")
        path = self._artifact_path(action, default_suffix=".teams-draft.md")
        header = (
            f"# Teams message draft\n\n"
            f"- Recipient type: `{recipient_type}`\n"
            f"- Recipient ID: `{recipient_id}`\n"
            f"- Posted: **no**\n\n"
            f"## Message\n\n{body}\n"
        )
        artifact = _write_text(path, header, "text/markdown")
        manifest = _write_json(
            path.with_suffix(".json"),
            {
                "schema": "master-agent/teams-draft@1",
                "recipient_type": recipient_type,
                "recipient_id": recipient_id,
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "post": False,
            },
        )
        return self._result(
            action,
            artifact,
            message="generated local Teams message draft without posting",
            extra={"manifest": manifest.to_dict()},
        )


class PowerPointDraftConnector(_LocalDraftConnector):
    """Generate local PowerPoint presentations from typed slide data."""

    _CAPABILITIES = frozenset({"powerpoint.presentation.generate"})

    def __init__(self, output_root: Path) -> None:
        super().__init__(
            system="powerpoint",
            capabilities=self._CAPABILITIES,
            output_root=output_root,
        )

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Render a bounded presentation with no external publishing."""

        _require_capability(action, self)
        try:
            from pptx import Presentation
            from pptx.util import Inches, Pt
        except ImportError as error:  # pragma: no cover - declared dependency.
            raise ConnectorError(
                "python-pptx is required for PowerPoint generation"
            ) from error

        title = _required_text(action.parameters, "title")
        slides_value = action.parameters.get("slides")
        if slides_value is None:
            sections = action.parameters.get("sections", [])
            if not isinstance(sections, Sequence) or isinstance(sections, (str, bytes)):
                raise ConnectorError("slides or sections must be a list")
            slides_value = [
                {"title": str(section), "bullets": []} for section in sections
            ]
        if not isinstance(slides_value, Sequence) or isinstance(
            slides_value, (str, bytes)
        ):
            raise ConnectorError("slides must be a list")
        if len(slides_value) > 40:
            raise ConnectorError("PowerPoint generation is limited to 40 slides")

        presentation = Presentation()
        presentation.slide_width = Inches(13.333)
        presentation.slide_height = Inches(7.5)
        title_slide = presentation.slides.add_slide(presentation.slide_layouts[0])
        title_slide.shapes.title.text = title
        if len(title_slide.placeholders) > 1:
            title_slide.placeholders[1].text = str(
                action.parameters.get("subtitle", "Generated by Master Agent")
            )

        for raw_slide in slides_value:
            if not isinstance(raw_slide, Mapping):
                raise ConnectorError("each slide must be an object")
            slide_title = str(raw_slide.get("title", "Untitled")).strip() or "Untitled"
            bullets = raw_slide.get("bullets", [])
            if not isinstance(bullets, Sequence) or isinstance(bullets, (str, bytes)):
                raise ConnectorError("slide bullets must be a list")
            slide = presentation.slides.add_slide(presentation.slide_layouts[1])
            slide.shapes.title.text = slide_title[:160]
            text_frame = slide.placeholders[1].text_frame
            text_frame.clear()
            for index, bullet in enumerate(bullets[:12]):
                paragraph = (
                    text_frame.paragraphs[0]
                    if index == 0
                    else text_frame.add_paragraph()
                )
                paragraph.text = str(bullet)[:800]
                paragraph.level = 0
                paragraph.font.size = Pt(20)

        path = self._artifact_path(action, default_suffix=".pptx")
        if path.suffix.lower() != ".pptx":
            path = path.with_suffix(".pptx")
        presentation.save(str(path))
        _restrict(path)
        artifact = GeneratedArtifact(
            path=path,
            sha256=_sha256(path),
            media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
            size=path.stat().st_size,
        )
        return self._result(
            action,
            artifact,
            message="generated local PowerPoint presentation",
            extra={"slide_count": len(presentation.slides)},
        )


class RepositoryDraftConnector(_LocalDraftConnector):
    """Generate source-code patches and branch plans without touching a repo."""

    _CAPABILITIES = frozenset({"repository.patch.generate", "repository.branch.plan"})

    def __init__(self, output_root: Path) -> None:
        super().__init__(
            system="repository",
            capabilities=self._CAPABILITIES,
            output_root=output_root,
        )

    def execute(self, action: AgentAction) -> ExecutionResult:
        """Generate a unified diff or branch-operation plan."""

        _require_capability(action, self)
        if action.capability == "repository.patch.generate":
            relative_path = _safe_relative_path(
                _required_text(action.parameters, "relative_path")
            )
            before = str(action.parameters.get("before_text", ""))
            after = str(action.parameters.get("after_text", ""))
            diff = "".join(
                difflib.unified_diff(
                    before.splitlines(keepends=True),
                    after.splitlines(keepends=True),
                    fromfile=f"a/{relative_path}",
                    tofile=f"b/{relative_path}",
                )
            )
            if not diff:
                raise ConnectorError("patch generation produced no changes")
            path = self._artifact_path(action, default_suffix=".patch")
            artifact = _write_text(path, diff, "text/x-diff")
            return self._result(
                action,
                artifact,
                message="generated local source-code patch",
                extra={"relative_path": relative_path},
            )

        branch = _required_text(action.parameters, "branch")
        base = _required_text(action.parameters, "base")
        _validate_branch(branch)
        _validate_branch(base)
        payload = {
            "schema": "master-agent/repository-branch-plan@1",
            "branch": branch,
            "base": base,
            "remote": str(action.parameters.get("remote", "origin")).strip()
            or "origin",
            "push": False,
        }
        path = self._artifact_path(action, default_suffix=".branch-plan.json")
        artifact = _write_json(path, payload)
        return self._result(
            action,
            artifact,
            message="generated local repository branch plan",
        )


def _require_capability(action: AgentAction, connector: _LocalDraftConnector) -> None:
    if action.target.system != connector.system:
        raise ConnectorError(
            f"connector {connector.system} cannot execute target {action.target.system}"
        )
    if action.capability not in connector.capabilities:
        raise ConnectorError(f"unsupported draft capability: {action.capability}")


def _render_preview(
    *,
    title: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> str:
    before_text = json.dumps(before, indent=2, sort_keys=True, ensure_ascii=False)
    after_text = json.dumps(after, indent=2, sort_keys=True, ensure_ascii=False)
    diff = "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile="before.json",
            tofile="after.json",
        )
    )
    return (
        f"# {title}\n\n"
        "This is a local proposal. It has not been published.\n\n"
        "## Diff\n\n```diff\n"
        f"{diff}```\n"
    )


def _write_json(path: Path, payload: Mapping[str, Any]) -> GeneratedArtifact:
    return _write_text(
        path,
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        "application/json",
    )


def _write_text(path: Path, text: str, media_type: str) -> GeneratedArtifact:
    return _write_bytes(path, text.encode("utf-8"), media_type)


def _write_bytes(path: Path, payload: bytes, media_type: str) -> GeneratedArtifact:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    _restrict(path)
    return GeneratedArtifact(
        path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
        media_type=media_type,
        size=len(payload),
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _restrict(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _safe_name(value: str) -> str:
    rendered = _SAFE_NAME.sub("-", value.strip()).strip(".-")
    return rendered[:180] or "artifact"


def _mapping(
    value: Any, name: str, *, default: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    if value is None and default is not None:
        return dict(default)
    if not isinstance(value, Mapping):
        raise ConnectorError(f"parameter must be an object: {name}")
    return dict(value)


def _required_text(parameters: Mapping[str, Any], key: str) -> str:
    value = str(parameters.get(key, "")).strip()
    if not value:
        raise ConnectorError(f"missing required parameter: {key}")
    return value


def _string_list(value: Any, name: str, *, required: bool = False) -> tuple[str, ...]:
    if value is None:
        result: tuple[str, ...] = ()
    elif isinstance(value, str):
        result = tuple(item.strip() for item in value.split(",") if item.strip())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        result = tuple(str(item).strip() for item in value if str(item).strip())
    else:
        raise ConnectorError(f"parameter must be a string list: {name}")
    if required and not result:
        raise ConnectorError(f"parameter must not be empty: {name}")
    return result


def _safe_relative_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ConnectorError("relative_path must remain inside the repository")
    return path.as_posix()


def _validate_branch(value: str) -> None:
    if (
        not value
        or value.startswith("-")
        or ".." in value
        or value.endswith("/")
        or any(character.isspace() for character in value)
        or any(token in value for token in ("~", "^", ":", "?", "*", "[", "\\"))
    ):
        raise ConnectorError("unsafe Git branch name")
