#!/usr/bin/env python3
"""Validate the Master Agent source tree before packaging."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Iterable


_MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
_FORBIDDEN_NAMES = {
    ".env",
    "audit.sqlite3",
    "recurring.sqlite3",
}
_FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".pyc"}
_IGNORED_DIRS = {
    ".git",
    ".master-agent",
    ".venv",
    "build",
    "dist",
    "__pycache__",
}


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Result of a release-tree validation.

    Parameters
    ----------
    checks
        Human-readable successful checks.
    errors
        Human-readable validation failures.
    """

    checks: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Return whether the source tree passed every check."""

        return not self.errors

    def to_dict(self) -> dict[str, object]:
        """Serialize the report to JSON-compatible data."""

        return {
            "schema": "master-agent/release-validation@1",
            "valid": self.valid,
            "checks": list(self.checks),
            "errors": list(self.errors),
        }


def validate_project(root: Path) -> ValidationReport:
    """Validate release metadata, safe defaults, links, and file hygiene.

    Parameters
    ----------
    root
        Project root containing ``pyproject.toml``.

    Returns
    -------
    ValidationReport
        Completed validation report.
    """

    root = root.resolve()
    checks: list[str] = []
    errors: list[str] = []

    _validate_versions(root, checks, errors)
    _validate_packaged_defaults(root, checks, errors)
    _validate_capabilities(root, checks, errors)
    _validate_markdown_links(root, checks, errors)
    _validate_demo(root, checks, errors)
    _validate_file_hygiene(root, checks, errors)

    return ValidationReport(tuple(checks), tuple(errors))


def sha256_file(path: Path) -> str:
    """Return a file's SHA-256 digest.

    Parameters
    ----------
    path
        File to hash.

    Returns
    -------
    str
        Lowercase hexadecimal digest.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_versions(root: Path, checks: list[str], errors: list[str]) -> None:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project_version = str(pyproject["project"]["version"])
    init_text = (root / "src/master_agent/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    module_version = match.group(1) if match else ""
    http_text = (root / "src/master_agent/http.py").read_text(encoding="utf-8")
    if project_version != module_version:
        errors.append(
            f"version mismatch: pyproject={project_version}, module={module_version}"
        )
    elif f"master-agent/{project_version}" not in http_text:
        errors.append("HTTP user agent does not match the project version")
    else:
        checks.append(f"version metadata is consistent at {project_version}")


def _validate_packaged_defaults(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    config_dir = root / "config"
    defaults_dir = root / "src/master_agent/defaults"
    expected = sorted(path.name for path in config_dir.glob("*.toml"))
    for name in expected:
        source = config_dir / name
        packaged = defaults_dir / name
        if not packaged.exists():
            errors.append(f"packaged default is missing: {name}")
            continue
        if source.read_bytes() != packaged.read_bytes():
            errors.append(f"packaged default differs from repository config: {name}")
    if not errors:
        checks.append(f"{len(expected)} packaged TOML defaults match repository config")

    integrations = tomllib.loads((defaults_dir / "integrations.toml").read_text())
    connectors = integrations.get("connectors", {})
    for name, connector in connectors.items():
        if bool(connector.get("enabled", False)):
            errors.append(f"packaged connector is enabled: {name}")
        for key, value in connector.items():
            if key.endswith("_enabled") and bool(value):
                errors.append(f"packaged provider gate is enabled: {name}.{key}")
    if connectors and not any(
        bool(value.get("enabled", False)) for value in connectors.values()
    ):
        checks.append("all packaged live connectors and provider gates are disabled")

    recurring = tomllib.loads((defaults_dir / "recurring.toml").read_text())
    workflows = recurring.get("workflows", {})
    enabled = [name for name, item in workflows.items() if item.get("enabled")]
    if enabled:
        errors.append(f"packaged recurring workflows are enabled: {enabled}")
    else:
        checks.append("all packaged recurring workflows are disabled")


def _validate_capabilities(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    raw = tomllib.loads((root / "config/capabilities.toml").read_text())
    capabilities = raw.get("capabilities", {})
    if len(capabilities) != 71:
        errors.append(f"expected 71 v1 capabilities, found {len(capabilities)}")
    else:
        checks.append("capability catalog contains 71 typed capabilities")
    merge = capabilities.get("bitbucket.pull_request.merge", {})
    if merge.get("enabled") is not False:
        errors.append("Bitbucket pull-request merge must remain disabled")
    else:
        checks.append("high-impact pull-request merge remains disabled")


def _validate_markdown_links(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    count = 0
    for path in _iter_files(root, suffixes={".md"}):
        text = path.read_text(encoding="utf-8")
        for target in _MARKDOWN_LINK.findall(text):
            clean = target.strip().split(maxsplit=1)[0].strip("<>")
            if not clean or clean.startswith(("#", "http://", "https://", "mailto:")):
                continue
            file_part = clean.split("#", 1)[0]
            resolved = (path.parent / file_part).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                errors.append(f"Markdown link escapes project root: {path}: {target}")
                continue
            if not resolved.exists():
                errors.append(f"broken Markdown link: {path}: {target}")
            else:
                count += 1
    if not any(item.startswith("broken Markdown") for item in errors):
        checks.append(f"validated {count} local Markdown links")



def _validate_demo(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    demo_root = root / "examples/v1-demo"
    manifest_path = demo_root / "manifest.json"
    if not manifest_path.exists():
        errors.append("v1 demonstration manifest is missing")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("published") is not False:
        errors.append("v1 demonstration must be marked unpublished")
    if manifest.get("uses_live_credentials") is not False:
        errors.append("v1 demonstration must be marked credential-free")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        errors.append("v1 demonstration manifest has no files")
        return
    verified = 0
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("v1 demonstration manifest entry must be an object")
            continue
        relative = Path(str(entry.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"unsafe v1 demonstration path: {relative}")
            continue
        path = (demo_root / relative).resolve()
        try:
            path.relative_to(demo_root.resolve())
        except ValueError:
            errors.append(f"v1 demonstration path escapes root: {relative}")
            continue
        if not path.is_file():
            errors.append(f"v1 demonstration file is missing: {relative}")
            continue
        if path.stat().st_size != int(entry.get("size", -1)):
            errors.append(f"v1 demonstration size mismatch: {relative}")
            continue
        if sha256_file(path) != str(entry.get("sha256", "")):
            errors.append(f"v1 demonstration digest mismatch: {relative}")
            continue
        verified += 1
    if verified == len(entries):
        checks.append(f"validated {verified} v1 demonstration artifacts")

    draft_manifest_path = demo_root / "draft-package/manifest.json"
    draft_manifest = json.loads(draft_manifest_path.read_text(encoding="utf-8"))
    if draft_manifest.get("published") is not False:
        errors.append("draft package must be marked unpublished")
    for entry in draft_manifest.get("artifacts", []):
        relative = Path(str(entry["path"]))
        path = draft_manifest_path.parent / relative
        if not path.is_file() or sha256_file(path) != str(entry["sha256"]):
            errors.append(f"draft package artifact mismatch: {relative}")
    try:
        from pptx import Presentation

        deck = Presentation(demo_root / "draft-package/change-package.pptx")
        if len(deck.slides) != 3:
            errors.append(
                f"v1 demonstration PowerPoint expected 3 slides, found {len(deck.slides)}"
            )
        else:
            checks.append("v1 demonstration PowerPoint opens with 3 slides")
    except Exception as error:
        errors.append(f"v1 demonstration PowerPoint failed to open: {error}")

def _validate_file_hygiene(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    file_count = 0
    for path in root.rglob("*"):
        if any(part in _IGNORED_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.is_symlink():
            errors.append(f"source release must not contain symlink: {path}")
            continue
        if not path.is_file():
            continue
        file_count += 1
        if path.name in _FORBIDDEN_NAMES or path.suffix.lower() in _FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden runtime/secret file in source tree: {path}")
    if not any("forbidden runtime/secret" in item or "symlink" in item for item in errors):
        checks.append(f"source-tree hygiene passed for {file_count} files")


def _iter_files(root: Path, *, suffixes: set[str]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in _IGNORED_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in suffixes:
            yield path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    """Run release validation and return a shell-compatible status."""

    args = _build_parser().parse_args()
    report = validate_project(args.root)
    for check in report.checks:
        print(f"PASS {check}")
    for error in report.errors:
        print(f"FAIL {error}", file=sys.stderr)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report.to_dict(), indent=2) + "\n",
            encoding="utf-8",
        )
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
