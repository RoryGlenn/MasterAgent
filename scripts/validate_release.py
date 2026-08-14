#!/usr/bin/env python3
"""Validate the Master Agent source tree before packaging."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
_FORBIDDEN_NAMES = {
    ".env",
    "audit.sqlite3",
    "recurring.sqlite3",
}
_FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".pyc", ".sqlite3"}
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


def validate_archive(path: Path) -> ValidationReport:
    """Validate one built wheel or source archive without extracting it."""

    checks: list[str] = []
    errors: list[str] = []
    if not path.is_file():
        return ValidationReport((), (f"release archive not found: {path}",))
    names: list[str] = []
    try:
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                bad_member = archive.testzip()
                if bad_member is not None:
                    errors.append(f"wheel integrity check failed: {bad_member}")
                for item in archive.infolist():
                    if item.is_dir():
                        continue
                    names.append(item.filename)
                    with archive.open(item) as handle:
                        _consume_stream(handle)
        elif path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")):
            with tarfile.open(path, mode="r:*") as archive:
                for item in archive.getmembers():
                    if item.issym() or item.islnk():
                        errors.append(
                            f"release archive contains link entry: {item.name}"
                        )
                        continue
                    if not item.isfile():
                        continue
                    names.append(item.name)
                    handle = archive.extractfile(item)
                    if handle is not None:
                        with handle:
                            _consume_stream(handle)
        else:
            errors.append(f"unsupported release archive type: {path.name}")
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        errors.append(f"release archive could not be read: {path}: {error}")

    for name in names:
        _validate_archive_member(name, errors)
    if path.suffix == ".whl":
        required_suffixes = (
            "master_agent/__init__.py",
            "master_agent/defaults/capabilities.toml",
            ".dist-info/METADATA",
        )
    else:
        required_suffixes = (
            "/.ai/MASTER_AGENT.md",
            "/.env.example",
            "/config/capabilities.toml",
            "/scripts/validate_release.py",
            "/tests/test_release_metadata.py",
            "/src/master_agent/__init__.py",
        )
    for required in required_suffixes:
        if not any(name.endswith(required) for name in names):
            errors.append(f"release archive is missing required file: {required}")
    if not errors:
        checks.append(
            f"validated release archive {path.name} ({len(names)} files, no links)"
        )
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
    if len(capabilities) != 70:
        errors.append(f"expected 70 v1 capabilities, found {len(capabilities)}")
    else:
        checks.append("capability catalog contains 70 typed capabilities")
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

    _validate_demo_readiness(root, demo_root, checks, errors)

    draft_manifest_path = demo_root / "draft-package/manifest.json"
    draft_manifest = json.loads(draft_manifest_path.read_text(encoding="utf-8"))
    if draft_manifest.get("published") is not False:
        errors.append("draft package must be marked unpublished")
    for entry in draft_manifest.get("artifacts", []):
        relative = Path(str(entry["path"]))
        path = draft_manifest_path.parent / relative
        if not path.is_file() or sha256_file(path) != str(entry["sha256"]):
            errors.append(f"draft package artifact mismatch: {relative}")
    _validate_demo_powerpoint(demo_root, checks, errors)


def _validate_demo_powerpoint(
    demo_root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    """Validate the packaged demonstration deck with an installed reader."""

    try:
        from pptx import Presentation
        from pptx.exc import PackageNotFoundError
    except ImportError:
        errors.append(
            "v1 demonstration PowerPoint validation requires the python-pptx dependency"
        )
        return

    try:
        deck = Presentation(demo_root / "draft-package/change-package.pptx")
        if len(deck.slides) != 3:
            errors.append(
                f"v1 demonstration PowerPoint expected 3 slides, found {len(deck.slides)}"
            )
        else:
            checks.append("v1 demonstration PowerPoint opens with 3 slides")
    except (KeyError, OSError, PackageNotFoundError, TypeError, ValueError) as error:
        errors.append(f"v1 demonstration PowerPoint failed to open: {error}")


def _validate_demo_readiness(
    root: Path,
    demo_root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    """Cross-check demo readiness claims against the shipped capability catalog."""

    readiness_path = demo_root / "readiness.json"
    catalog_path = root / "config/capabilities.toml"
    try:
        readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
        with catalog_path.open("rb") as handle:
            catalog = tomllib.load(handle)
    except (
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        tomllib.TOMLDecodeError,
    ) as error:
        errors.append(f"v1 demonstration readiness could not be validated: {error}")
        return

    if not isinstance(readiness, dict):
        errors.append("v1 demonstration readiness must be an object")
        return
    raw_checks = readiness.get("checks")
    if not isinstance(raw_checks, list):
        errors.append("v1 demonstration readiness checks must be a list")
        return
    coverage = next(
        (
            item
            for item in raw_checks
            if isinstance(item, dict) and item.get("name") == "governance_coverage"
        ),
        None,
    )
    capabilities = catalog.get("capabilities")
    if coverage is None or not isinstance(capabilities, dict):
        errors.append("v1 demonstration readiness lacks governance coverage metadata")
        return
    observed = coverage.get("covered_capabilities")
    expected = len(capabilities)
    if not isinstance(observed, int) or isinstance(observed, bool):
        errors.append("v1 demonstration covered_capabilities must be an integer")
    elif observed != expected:
        errors.append(
            "v1 demonstration readiness capability count does not match the "
            f"catalog ({observed} != {expected})"
        )
    else:
        checks.append(f"v1 demonstration readiness covers all {expected} capabilities")


def _validate_file_hygiene(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    file_count = 0
    runtime_directory = root / ".master-agent"
    if runtime_directory.exists():
        errors.append(
            f"forbidden runtime directory in source tree: {runtime_directory}"
        )
    for path in root.rglob("*"):
        if any(
            part in _IGNORED_DIRS or part.endswith(".egg-info") for part in path.parts
        ):
            continue
        if path.is_symlink():
            errors.append(f"source release must not contain symlink: {path}")
            continue
        if not path.is_file():
            continue
        file_count += 1
        forbidden_environment = (
            path.name.startswith(".env") and path.name != ".env.example"
        )
        if (
            path.name in _FORBIDDEN_NAMES
            or path.suffix.lower() in _FORBIDDEN_SUFFIXES
            or forbidden_environment
        ):
            errors.append(f"forbidden runtime/secret file in source tree: {path}")
    if not any(
        "forbidden runtime" in item
        or "forbidden runtime/secret" in item
        or "symlink" in item
        for item in errors
    ):
        checks.append(f"source-tree hygiene passed for {file_count} files")


def _validate_archive_member(name: str, errors: list[str]) -> None:
    """Reject unsafe paths and runtime/secret files in a built archive."""

    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        errors.append(f"unsafe path in release archive: {name}")
        return
    if ".master-agent" in relative.parts:
        errors.append(f"forbidden runtime directory in release archive: {name}")
    filename = relative.name
    suffix = Path(filename).suffix.lower()
    forbidden_environment = filename.startswith(".env") and filename != ".env.example"
    if (
        filename in _FORBIDDEN_NAMES
        or filename == ".DS_Store"
        or suffix in _FORBIDDEN_SUFFIXES
        or forbidden_environment
    ):
        errors.append(f"forbidden runtime/secret file in release archive: {name}")


def _consume_stream(handle: BinaryIO) -> None:
    """Read an archive member fully so integrity errors are observed."""

    while handle.read(1024 * 1024):
        pass


def _iter_files(root: Path, *, suffixes: set[str]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(
            part in _IGNORED_DIRS or part.endswith(".egg-info") for part in path.parts
        ):
            continue
        if path.is_file() and path.suffix.lower() in suffixes:
            yield path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--archive",
        action="append",
        type=Path,
        default=[],
        help="also validate a built wheel or source archive",
    )
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    """Run release validation and return a shell-compatible status."""

    args = _build_parser().parse_args()
    report = validate_project(args.root)
    checks = list(report.checks)
    errors = list(report.errors)
    for archive in args.archive:
        archive_report = validate_archive(archive)
        checks.extend(archive_report.checks)
        errors.extend(archive_report.errors)
    for check in checks:
        print(f"PASS {check}")
    for error in errors:
        print(f"FAIL {error}", file=sys.stderr)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                ValidationReport(tuple(checks), tuple(errors)).to_dict(),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
