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
_AGENT_FRONTMATTER_KEY = re.compile(r"([a-z][a-z0-9-]*):(?:\s*(.*))?")
_COPILOT_AGENT_PATH = Path(".github/agents/MasterAgent.agent.md")
_FIRST_RUN_CONTRACT_PATH = Path(".ai/FIRST_RUN.md")
_AUTONOMY_CONTRACT_PATH = Path(".ai/AUTONOMY.md")
_COPILOT_AGENT_TOOLS = ("read", "search", "edit", "execute")
_COPILOT_AGENT_KEYS = {
    "name",
    "description",
    "tools",
    "user-invocable",
    "disable-model-invocation",
}
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
_FIRST_RUN_DOCUMENT_REQUIREMENTS = {
    Path(".ai/MASTER_AGENT.md"): (
        "[`FIRST_RUN.md`](FIRST_RUN.md)",
        "[`AUTONOMY.md`](AUTONOMY.md)",
        "A direct provider-read goal explicitly authorizes",
    ),
    _FIRST_RUN_CONTRACT_PATH: (
        "first operator",
        "python3 scripts/bootstrap_agent.py",
        "MasterAgent is ready locally",
        "I couldn't finish local setup",
        "no live connectors are enabled",
        "[`AUTONOMY.md`](AUTONOMY.md)",
        "A requested provider read",
    ),
    _AUTONOMY_CONTRACT_PATH: (
        "One request, one bounded run",
        "do not ask again whether network access",
        "Do not narrate each inspected JSON key",
        "github-repositories",
        "persistent connector settings unchanged",
    ),
    Path("AGENTS.md"): (
        "[`.ai/FIRST_RUN.md`](.ai/FIRST_RUN.md)",
        "[`.ai/AUTONOMY.md`](.ai/AUTONOMY.md)",
        "Apply the first-run contract",
        "Apply the goal-completion contract",
    ),
    Path("CHANGELOG.md"): ("first ordinary prompt", "one-request goal-completion"),
    Path("README.md"): (
        "[first-run contract](.ai/FIRST_RUN.md)",
        "[goal-completion contract](.ai/AUTONOMY.md)",
        "MasterAgent is ready locally",
        "explicit no-local-change prompt",
        "github-repositories",
    ),
    Path("docs/copilot-custom-agent.md"): (
        "[first-run contract](../.ai/FIRST_RUN.md)",
        "[goal-completion contract](../.ai/AUTONOMY.md)",
        "python3 scripts/bootstrap_agent.py",
        "MasterAgent is ready locally",
        "If automatic setup is blocked",
        "without a second confirmation",
    ),
    Path("docs/release-validation.md"): (
        "first-prompt contract",
        "goal-completion contracts",
        "stable nontechnical responses",
    ),
    Path("docs/semantic-index.md"): (
        "[`.ai/FIRST_RUN.md`](../.ai/FIRST_RUN.md)",
        "[`.ai/AUTONOMY.md`](../.ai/AUTONOMY.md)",
        "[`bootstrap_agent.py`](../scripts/bootstrap_agent.py)",
    ),
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
    _validate_copilot_agent(root, checks, errors)
    _validate_first_run_contract(root, checks, errors)
    _validate_markdown_links(root, checks, errors)
    _validate_documentation(root, checks, errors)
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
            "/.ai/FIRST_RUN.md",
            "/.ai/AUTONOMY.md",
            "/.github/agents/MasterAgent.agent.md",
            "/.env.example",
            "/config/capabilities.toml",
            "/scripts/bootstrap_agent.py",
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
    if len(capabilities) != 75:
        errors.append(f"expected 75 v1 capabilities, found {len(capabilities)}")
    else:
        checks.append("capability catalog contains 75 typed capabilities")
    merge = capabilities.get("bitbucket.pull_request.merge", {})
    if merge.get("enabled") is not False:
        errors.append("Bitbucket pull-request merge must remain disabled")
    else:
        checks.append("high-impact pull-request merge remains disabled")


def _validate_copilot_agent(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    """Require the repository-scoped Copilot entry point to remain fail-closed."""

    path = root / _COPILOT_AGENT_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        errors.append(f"Copilot custom agent is missing or unreadable: {path}: {error}")
        return

    metadata, body, frontmatter_errors = _parse_agent_frontmatter(text)
    errors.extend(
        f"Copilot custom agent frontmatter: {error}" for error in frontmatter_errors
    )
    if frontmatter_errors:
        return

    unexpected = sorted(set(metadata) - _COPILOT_AGENT_KEYS)
    missing = sorted(_COPILOT_AGENT_KEYS - set(metadata))
    if unexpected:
        errors.append(
            "Copilot custom agent has unreviewed frontmatter keys: "
            + ", ".join(unexpected)
        )
    if missing:
        errors.append(
            "Copilot custom agent is missing frontmatter keys: " + ", ".join(missing)
        )
    if metadata.get("name") != "MasterAgent":
        errors.append("Copilot custom agent name must be MasterAgent")
    description = metadata.get("description")
    if not isinstance(description, str) or not description.strip():
        errors.append("Copilot custom agent description must be a non-empty string")
    if metadata.get("user-invocable") is not True:
        errors.append("Copilot custom agent must remain user-invocable")
    if metadata.get("disable-model-invocation") is not True:
        errors.append("Copilot custom agent must not be invoked automatically")
    tools = metadata.get("tools")
    if tools != _COPILOT_AGENT_TOOLS:
        errors.append(
            "Copilot custom agent tools must be exactly: "
            + ", ".join(_COPILOT_AGENT_TOOLS)
        )

    required_references = (
        "[AGENTS.md](../../AGENTS.md)",
        "[Master Agent repository policy](../../.ai/MASTER_AGENT.md)",
        "[first-run contract](../../.ai/FIRST_RUN.md)",
        "[goal-completion contract](../../.ai/AUTONOMY.md)",
    )
    for reference in required_references:
        if reference not in body:
            errors.append(
                f"Copilot custom agent is missing required policy reference: {reference}"
            )
    required_boundaries = (
        "config/capabilities.toml",
        "Never call a provider directly",
        "Repository-inspection, diagnosis-only, or explicit no-local-change",
        "Apply the first-run contract before the substantive response",
        "python3 scripts/bootstrap_agent.py",
        ".venv/bin/python -m pip install -e .",
        "MasterAgent is ready locally",
        "I couldn't finish local setup",
        "Never use `sudo`",
        "Treat one operator goal as one bounded run",
        "github-repositories",
        "python scripts/validate_release.py",
    )
    for boundary in required_boundaries:
        if boundary not in body:
            errors.append(
                f"Copilot custom agent is missing required boundary: {boundary}"
            )

    if not any(error.startswith("Copilot custom agent") for error in errors):
        checks.append(
            "Copilot custom agent is user-invocable, policy-bound, and tool-constrained"
        )


def _validate_first_run_contract(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    """Keep every first-run instruction and onboarding guide synchronized."""

    starting_errors = len(errors)
    for relative, requirements in _FIRST_RUN_DOCUMENT_REQUIREMENTS.items():
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(
                f"first-run contract document is unreadable: {relative}: {error}"
            )
            continue
        for requirement in requirements:
            if requirement not in text:
                errors.append(
                    "first-run contract document is inconsistent: "
                    f"{relative} is missing {requirement!r}"
                )

    script = root / "scripts/bootstrap_agent.py"
    if not script.is_file():
        errors.append(
            "first-run bootstrap script is missing: scripts/bootstrap_agent.py"
        )

    if len(errors) == starting_errors:
        checks.append(
            "first-run and goal-completion contracts are consistent across 9 instruction and onboarding files"
        )


def _parse_agent_frontmatter(
    text: str,
) -> tuple[dict[str, object], str, tuple[str, ...]]:
    """Parse the deliberately small YAML subset used by the agent profile."""

    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return {}, "", ("file must start with a YAML delimiter",)
    try:
        closing = lines.index("---", 1)
    except ValueError:
        return {}, "", ("closing YAML delimiter is missing",)

    metadata: dict[str, object] = {}
    parse_errors: list[str] = []
    active_list: str | None = None
    for number, line in enumerate(lines[1:closing], start=2):
        if line.startswith("  - "):
            if active_list is None:
                parse_errors.append(f"line {number} has a list item without a key")
                continue
            value = line[4:].strip()
            if not value:
                parse_errors.append(f"line {number} has an empty list item")
                continue
            existing = metadata.get(active_list)
            if not isinstance(existing, list):
                parse_errors.append(f"line {number} cannot extend {active_list}")
                continue
            existing.append(value)
            continue
        active_list = None
        match = _AGENT_FRONTMATTER_KEY.fullmatch(line)
        if match is None:
            parse_errors.append(f"line {number} is not a supported key or list item")
            continue
        key, raw_value = match.groups()
        if key in metadata:
            parse_errors.append(f"line {number} repeats key {key}")
            continue
        if not raw_value:
            metadata[key] = []
            active_list = key
        elif raw_value == "true":
            metadata[key] = True
        elif raw_value == "false":
            metadata[key] = False
        else:
            metadata[key] = raw_value.strip("'\"")

    for key, value in tuple(metadata.items()):
        if isinstance(value, list):
            metadata[key] = tuple(value)
    body = "\n".join(lines[closing + 1 :]).strip()
    if not body:
        parse_errors.append("instruction body is empty")
    return metadata, body, tuple(parse_errors)


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


def _validate_documentation(
    root: Path,
    checks: list[str],
    errors: list[str],
) -> None:
    """Cross-check release documentation and checked-in plan examples."""

    readme = (root / "README.md").read_text(encoding="utf-8")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    release_guide = (root / "docs/release-validation.md").read_text(encoding="utf-8")
    cli_reference = (root / "docs/cli-reference.md").read_text(encoding="utf-8")
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(pyproject["project"]["version"])

    version_claims = {
        "README version banner": f"**Version {version} —",
        "release-validation title": f"# Release Validation — v{version}",
        "source-distribution filename": f"master_agent-{version}.tar.gz",
        "wheel filename": f"master_agent-{version}-py3-none-any.whl",
    }
    version_text = {
        "README version banner": readme,
        "release-validation title": release_guide,
        "source-distribution filename": readme,
        "wheel filename": readme,
    }
    for label, claim in version_claims.items():
        if claim not in version_text[label]:
            errors.append(f"documentation has stale {label}: expected {claim}")

    docs = {path.relative_to(root).as_posix() for path in (root / "docs").glob("*.md")}
    indexed = {
        target.split("#", 1)[0]
        for target in _MARKDOWN_LINK.findall(readme)
        if target.startswith("docs/")
    }
    missing_docs = sorted(docs - indexed)
    if missing_docs:
        errors.append(
            "README documentation index is missing: " + ", ".join(missing_docs)
        )

    catalog = tomllib.loads(
        (root / "config/capabilities.toml").read_text(encoding="utf-8")
    )["capabilities"]
    risk_counts: dict[str, int] = {}
    for definition in catalog.values():
        risk = str(definition["risk"])
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    readme_claims = (
        f"**{len(catalog)} typed capabilities**",
        f"{risk_counts.get('read_only', 0)} read-only capabilities",
        f"{risk_counts.get('local_generation', 0)} local-generation capabilities",
        f"{risk_counts.get('reversible_write', 0)} reversible-write definitions",
        f"{risk_counts.get('external_communication', 0)} external-communication capabilities",
        f"{risk_counts.get('high_impact', 0)} high-impact capability",
    )
    for claim in readme_claims:
        if claim not in readme:
            errors.append(f"README capability summary is stale: expected {claim}")

    current_changelog = changelog.split("\n## ", 2)[1]
    changelog_claim = f"a {len(catalog)}-capability catalog"
    if not current_changelog.startswith(f"{version} "):
        errors.append(f"CHANGELOG first release section is not version {version}")
    elif changelog_claim not in current_changelog:
        errors.append(
            f"CHANGELOG capability summary is stale: expected {changelog_claim}"
        )

    models = (root / "src/master_agent/models.py").read_text(encoding="utf-8")
    schema_match = re.search(r'schema_version: str = "([^"]+)"', models)
    if schema_match is None:
        errors.append("could not determine the current ChangePlan schema version")
    else:
        current_schema = schema_match.group(1)
        for path in sorted((root / "examples").glob("*plan.json")):
            try:
                plan = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                errors.append(f"example plan could not be read: {path}: {error}")
                continue
            if plan.get("schema_version") != current_schema:
                errors.append(
                    f"example plan uses stale schema {path}: expected {current_schema}"
                )

    cli = (root / "src/master_agent/cli.py").read_text(encoding="utf-8")
    commands = set(re.findall(r'subparsers\.add_parser\(\s*"([^"]+)"', cli))
    missing_commands = sorted(
        command for command in commands if f"`{command}`" not in cli_reference
    )
    if missing_commands:
        errors.append(
            "CLI reference is missing commands: " + ", ".join(missing_commands)
        )

    if not any(
        item.startswith(
            (
                "documentation has stale",
                "README documentation index",
                "README capability summary",
                "CHANGELOG",
                "could not determine the current ChangePlan",
                "example plan",
                "CLI reference",
            )
        )
        for item in errors
    ):
        checks.append(
            f"documentation matches version {version}, {len(docs)} guides, "
            f"{len(catalog)} capabilities, {len(commands)} CLI commands, and "
            "current plan schema"
        )


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
