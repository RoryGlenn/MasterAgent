#!/usr/bin/env python3
"""Generate and verify the locked runtime SBOM and third-party notices."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "supply-chain/runtime-dependencies.toml"
POLICY = ROOT / "config/dependency-licenses.toml"
LOCK = ROOT / "requirements-runtime.lock"
SBOM = ROOT / "sbom.cdx.json"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"


@dataclass(frozen=True, slots=True)
class Component:
    name: str
    version: str
    license: str
    purl: str
    homepage: str
    notice: str
    dependencies: tuple[str, ...]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic runtime dependency evidence."
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-installed", action="store_true")
    args = parser.parse_args(argv)

    project, components = _load_inventory()
    _validate_inventory(project, components)
    _validate_licenses(project, components)
    if args.verify_installed:
        _validate_installed(components)
    outputs = {
        LOCK: _render_lock(project, components),
        SBOM: _render_sbom(project, components),
        NOTICES: _render_notices(project, components),
    }
    if args.check:
        drifted = [
            path.name
            for path, expected in outputs.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != expected
        ]
        if drifted:
            parser.error("generated supply-chain files drifted: " + ", ".join(drifted))
        print(f"verified {len(components)} locked draft components, SBOM, and notices")
        return 0
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
    print(f"generated {len(components)} locked draft components")
    return 0


def _load_inventory() -> tuple[dict[str, Any], tuple[Component, ...]]:
    raw = tomllib.loads(INVENTORY.read_text(encoding="utf-8"))
    project = raw.get("project")
    values = raw.get("components")
    if not isinstance(project, dict) or not isinstance(values, list):
        raise TypeError("runtime dependency inventory is malformed")
    components: list[Component] = []
    for item in values:
        if not isinstance(item, dict):
            raise TypeError("runtime dependency component must be a table")
        dependencies = item.get("dependencies")
        if not isinstance(dependencies, list) or not all(
            isinstance(value, str) for value in dependencies
        ):
            raise ValueError("runtime dependency edges must be string lists")
        components.append(
            Component(
                name=_required(item, "name"),
                version=_required(item, "version"),
                license=_required(item, "license"),
                purl=_required(item, "purl"),
                homepage=_required(item, "homepage"),
                notice=_required(item, "notice"),
                dependencies=tuple(dependencies),
            )
        )
    return project, tuple(components)


def _validate_inventory(
    project: dict[str, Any],
    components: tuple[Component, ...],
) -> None:
    for name in ("name", "version", "license", "purl", "optional_extra"):
        _required(project, name)
    direct = _dependency_list(project, "dependencies", allow_empty=True)
    optional = _dependency_list(project, "optional_dependencies", allow_empty=False)
    optional_extra = _required(project, "optional_extra")
    by_name = {_key(item.name): item for item in components}
    if len(by_name) != len(components):
        raise ValueError("runtime dependency names must be unique")
    for component in components:
        if not re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z]+)+", component.version):
            raise ValueError(
                f"runtime dependency version is not exact: {component.name}"
            )
        expected_purl = (
            f"pkg:pypi/{component.name.replace('_', '-').casefold()}@"
            f"{component.version}"
        )
        if component.purl.casefold() != expected_purl:
            raise ValueError(f"runtime dependency purl drifted: {component.name}")
        unknown = [name for name in component.dependencies if _key(name) not in by_name]
        if unknown:
            raise ValueError(
                f"runtime dependency closure is incomplete for {component.name}: "
                + ", ".join(unknown)
            )
    pending = [_key(name) for name in (*direct, *optional)]
    reached: set[str] = set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        try:
            component = by_name[name]
        except KeyError as error:
            raise ValueError(
                f"project dependency is absent from lock: {name}"
            ) from error
        reached.add(name)
        pending.extend(_key(item) for item in component.dependencies)
    if reached != set(by_name):
        unreachable = sorted(set(by_name) - reached)
        raise ValueError(
            "runtime lock contains unreachable components: " + ", ".join(unreachable)
        )
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    if str(pyproject["version"]) != _required(project, "version"):
        raise ValueError("SBOM project version differs from pyproject.toml")
    declared = _exact_requirements(
        pyproject.get("dependencies", []),
        scope="core",
    )
    if declared != _versions_for(direct, by_name):
        raise ValueError("pyproject core dependency closure differs from inventory")
    declared_extras = pyproject.get("optional-dependencies")
    if not isinstance(declared_extras, dict):
        raise TypeError("pyproject optional dependencies are missing or malformed")
    declared_drafts = _exact_requirements(
        declared_extras.get(optional_extra),
        scope=f"optional {optional_extra}",
    )
    if declared_drafts != _versions_for(optional, by_name):
        raise ValueError("pyproject optional dependency closure differs from inventory")


def _validate_licenses(
    project: dict[str, Any],
    components: tuple[Component, ...],
) -> None:
    raw = tomllib.loads(POLICY.read_text(encoding="utf-8"))["policy"]
    allowed = set(raw["allowed_spdx"])
    denied = set(raw["denied_spdx"])
    observed = {_required(project, "license"), *(item.license for item in components)}
    blocked = sorted(observed & denied)
    unknown = sorted(observed - allowed)
    if blocked:
        raise ValueError("runtime dependency license is denied: " + ", ".join(blocked))
    if bool(raw["deny_unknown"]) and unknown:
        raise ValueError("runtime dependency license is unknown: " + ", ".join(unknown))
    if bool(raw["require_notices"]) and any(not item.notice for item in components):
        raise ValueError("runtime dependency notice is missing")


def _validate_installed(components: tuple[Component, ...]) -> None:
    for component in components:
        distribution = metadata.distribution(component.name)
        observed_license = distribution.metadata.get(
            "License-Expression"
        ) or distribution.metadata.get("License")
        if distribution.version != component.version:
            raise ValueError(
                f"installed version drifted for {component.name}: "
                f"{distribution.version} != {component.version}"
            )
        if observed_license != component.license:
            raise ValueError(
                f"installed license drifted for {component.name}: "
                f"{observed_license} != {component.license}"
            )


def _render_lock(project: dict[str, Any], components: tuple[Component, ...]) -> str:
    optional_extra = _required(project, "optional_extra")
    lines = [
        "# Generated by scripts/generate_sbom.py; do not edit by hand.",
        f"# Complete dependency closure for MasterAgent's optional {optional_extra!r} extra.",
        *(f"{item.name}=={item.version}" for item in components),
        "",
    ]
    return "\n".join(lines)


def _render_sbom(project: dict[str, Any], components: tuple[Component, ...]) -> str:
    project_ref = _required(project, "purl")
    optional_extra = _required(project, "optional_extra")
    by_name = {_key(item.name): item for item in components}
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": project_ref,
                "name": _required(project, "name"),
                "version": _required(project, "version"),
                "purl": project_ref,
                "licenses": [{"license": {"id": _required(project, "license")}}],
                "properties": [
                    {
                        "name": "master-agent:optional-extra",
                        "value": optional_extra,
                    }
                ],
            }
        },
        "components": [
            {
                "type": "library",
                "bom-ref": item.purl,
                "name": item.name,
                "version": item.version,
                "purl": item.purl,
                "licenses": [{"license": {"id": item.license}}],
                "externalReferences": [{"type": "website", "url": item.homepage}],
                "properties": [
                    {
                        "name": "master-agent:optional-extra",
                        "value": optional_extra,
                    }
                ],
            }
            for item in components
        ],
        "dependencies": [
            {
                "ref": project_ref,
                "dependsOn": [
                    by_name[_key(name)].purl for name in project["dependencies"]
                ],
            },
            *(
                {
                    "ref": item.purl,
                    "dependsOn": [
                        by_name[_key(name)].purl for name in item.dependencies
                    ],
                }
                for item in components
            ),
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _render_notices(project: dict[str, Any], components: tuple[Component, ...]) -> str:
    optional_extra = _required(project, "optional_extra")
    lines = [
        "# Third-Party Notices",
        "",
        f"MasterAgent's optional {optional_extra!r} extra declares the following",
        "complete Python dependency closure. These packages are installed separately",
        "and remain governed by",
        "their own license files. Distributors who bundle dependencies must retain",
        "those full license texts alongside this notice.",
        "",
    ]
    for item in components:
        lines.extend(
            [
                f"## {item.name} {item.version}",
                "",
                f"- License: `{item.license}`",
                f"- Project: {item.homepage}",
                f"- Notice: {item.notice}",
                "",
            ]
        )
    lines.extend(
        [
            "The machine-readable dependency graph is in `sbom.cdx.json`; exact",
            "versions are in `requirements-runtime.lock`; admission policy is in",
            "`config/dependency-licenses.toml`.",
            "",
        ]
    )
    return "\n".join(lines)


def _required(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"runtime dependency {key} is missing or malformed")
    return value


def _dependency_list(
    data: dict[str, Any], key: str, *, allow_empty: bool
) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"project {key} must be a string list")
    if not allow_empty and not value:
        raise ValueError(f"project {key} must not be empty")
    return tuple(value)


def _exact_requirements(values: Any, *, scope: str) -> dict[str, str]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ValueError(f"{scope} pyproject dependencies must be a string list")
    declared: dict[str, str] = {}
    for requirement in values:
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", requirement)
        if match is None:
            raise ValueError(
                f"{scope} pyproject dependency must use one exact version: "
                + requirement
            )
        name = _key(match.group(1))
        if name in declared:
            raise ValueError(f"{scope} pyproject dependency is repeated: {name}")
        declared[name] = match.group(2)
    return declared


def _versions_for(
    names: tuple[str, ...], by_name: dict[str, Component]
) -> dict[str, str]:
    return {_key(name): by_name[_key(name)].version for name in names}


def _key(value: str) -> str:
    return value.replace("_", "-").casefold()


if __name__ == "__main__":
    raise SystemExit(main())
