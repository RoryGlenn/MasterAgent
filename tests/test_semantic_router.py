from __future__ import annotations

import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zlib
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.semantic_router import (
    MANIFEST_PATH,
    REQUIRED_PLATFORM_CAPABILITIES,
    ManifestError,
    SemanticManifest,
    _same_file_state,
    _validate_topology,
    collect_inventory,
    generate_index,
    load_manifest,
    load_manifest_at_revision,
    main,
    render_semantic_index,
    routing_metrics,
    select_route,
    validate_repository,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _link_or_copy(source: str, destination: str) -> str:
    """Create a fast isolated fixture file, falling back across filesystems."""

    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)
    return destination


class SemanticRouterTests(unittest.TestCase):
    def test_windows_file_state_uses_stable_identity_not_posix_projection(
        self,
    ) -> None:
        common = {
            "st_dev": 3,
            "st_ino": 42,
            "st_size": 128,
            "st_mtime_ns": 1_700_000_000_000_000_000,
        }
        path_state = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444,
            st_nlink=2,
            st_ctime_ns=1_600_000_000_000_000_000,
            **common,
        )
        descriptor_state = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o666,
            st_nlink=1,
            st_ctime_ns=1_500_000_000_000_000_000,
            **common,
        )

        with patch("scripts.semantic_router.os.name", "nt"):
            self.assertTrue(_same_file_state(path_state, descriptor_state))
        with patch("scripts.semantic_router.os.name", "posix"):
            self.assertFalse(_same_file_state(path_state, descriptor_state))

        descriptor_state.st_ino = 43
        with patch("scripts.semantic_router.os.name", "nt"):
            self.assertFalse(_same_file_state(path_state, descriptor_state))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        shutil.copytree(
            REPOSITORY_ROOT,
            self.root,
            symlinks=True,
            copy_function=_link_or_copy,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                ".master-agent",
                "__pycache__",
                ".mypy_cache",
                ".ruff_cache",
                "build",
                "dist",
            ),
        )

    def _rewrite(self, relative: str, transform: Callable[[str], str]) -> None:
        path = self.root / relative
        content = path.read_text(encoding="utf-8")
        path.unlink()
        path.write_text(transform(content), encoding="utf-8")

    def _manifest_and_errors(self) -> tuple[SemanticManifest, list[str]]:
        manifest = load_manifest(self.root)
        return manifest, validate_repository(self.root, manifest)

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def test_checked_in_manifest_is_complete_and_generated(self) -> None:
        manifest, errors = self._manifest_and_errors()

        self.assertEqual(errors, [])
        self.assertEqual(
            (self.root / manifest.generated_document).read_text(encoding="utf-8"),
            render_semantic_index(manifest),
        )

    def test_bound_manifest_loads_from_exact_committed_revision(self) -> None:
        """Live routing parses the immutable manifest from its bound commit."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "manifest fixture")
        revision = self._git("rev-parse", "HEAD")

        manifest = load_manifest_at_revision(self.root, revision)

        self.assertEqual(manifest, load_manifest(self.root))

    def test_bound_manifest_supports_sha256_repositories(self) -> None:
        """Content-address verification follows the repository object format."""

        self._git("init", "--object-format=sha256", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "sha256 manifest fixture")
        revision = self._git("rev-parse", "HEAD")

        manifest = load_manifest_at_revision(self.root, revision)

        self.assertEqual(len(revision), 64)
        self.assertEqual(manifest, load_manifest(self.root))

    def test_bound_manifest_rejects_valid_worktree_drift(self) -> None:
        """A transient valid manifest cannot replace the committed authority."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "manifest fixture")
        revision = self._git("rev-parse", "HEAD")
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value + "\n# transient valid manifest\n",
        )

        with self.assertRaisesRegex(ManifestError, "manifest to match bound HEAD"):
            load_manifest_at_revision(self.root, revision)

    def test_bound_manifest_rejects_staged_drift_hidden_from_worktree(self) -> None:
        """A staged manifest cannot differ while the worktree looks committed."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "manifest fixture")
        revision = self._git("rev-parse", "HEAD")
        manifest_path = self.root / ".ai/semantic-router.toml"
        committed = manifest_path.read_bytes()
        manifest_path.write_bytes(committed + b"\n# staged manifest drift\n")
        self._git("add", ".ai/semantic-router.toml")
        manifest_path.write_bytes(committed)

        with self.assertRaisesRegex(ManifestError, "manifest to match bound HEAD"):
            load_manifest_at_revision(self.root, revision)

    def test_bound_manifest_rejects_unstaged_executable_mode_drift(self) -> None:
        """Matching bytes cannot conceal a changed worktree executable bit."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "manifest fixture")
        revision = self._git("rev-parse", "HEAD")
        manifest_path = self.root / ".ai/semantic-router.toml"
        content = manifest_path.read_bytes()
        manifest_path.unlink()
        manifest_path.write_bytes(content)
        manifest_path.chmod(0o755)

        with self.assertRaisesRegex(ManifestError, "manifest to match bound HEAD"):
            load_manifest_at_revision(self.root, revision)

    def test_bound_manifest_rejects_physical_object_substitution(self) -> None:
        """Commit paths are trusted only after object-address verification."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "manifest fixture")
        revision = self._git("rev-parse", "HEAD")
        blob = self._git("rev-parse", f"HEAD:{MANIFEST_PATH}")
        object_path = self.root / ".git" / "objects" / blob[:2] / blob[2:]
        self.assertTrue(object_path.is_file())
        malicious = b"version = 1\n"
        object_path.chmod(0o600)
        object_path.write_bytes(
            zlib.compress(f"blob {len(malicious)}\0".encode("ascii") + malicious)
        )

        with self.assertRaisesRegex(ManifestError, "content-address verification"):
            load_manifest_at_revision(self.root, revision)

    def test_bound_manifest_rejects_physical_commit_substitution(self) -> None:
        """A valid-looking commit under the wrong object ID is never authority."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", ".ai/semantic-router.toml")
        self._git("commit", "-qm", "manifest fixture")
        revision = self._git("rev-parse", "HEAD")
        original = subprocess.run(
            ("git", "cat-file", "commit", revision),
            cwd=self.root,
            check=True,
            capture_output=True,
        ).stdout
        object_path = self.root / ".git" / "objects" / revision[:2] / revision[2:]
        self.assertTrue(object_path.is_file())
        malicious = original + b"\nOBJECT_SUBSTITUTION_SENTINEL\n"
        object_path.chmod(0o600)
        object_path.write_bytes(
            zlib.compress(f"commit {len(malicious)}\0".encode("ascii") + malicious)
        )

        with self.assertRaisesRegex(ManifestError, "content-address verification"):
            load_manifest_at_revision(self.root, revision)

    def test_generated_document_is_pinned_to_semantic_index(self) -> None:
        manifest = load_manifest(self.root)

        self.assertEqual(manifest.generated_document, "docs/semantic-index.md")
        self.assertTrue(generate_index(self.root, manifest, check=True))

    def test_generated_document_rejects_repository_overwrite_targets(self) -> None:
        manifest_path = self.root / ".ai" / "semantic-router.toml"
        original = manifest_path.read_text(encoding="utf-8")
        expected = 'generated_document = "docs/semantic-index.md"'
        self.assertIn(expected, original)

        for destination in (
            "README.md",
            ".git/config",
            ".ai/semantic-router.toml",
        ):
            with self.subTest(destination=destination):
                manifest_path.unlink()
                manifest_path.write_text(
                    original.replace(
                        expected,
                        f'generated_document = "{destination}"',
                        1,
                    ),
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    ManifestError,
                    r"^manifest\.generated_document must be exactly "
                    r"docs/semantic-index\.md$",
                ):
                    load_manifest(self.root)

    def test_generator_rejects_fabricated_overwrite_target(self) -> None:
        """Direct callers cannot bypass the parser's fixed destination."""

        manifest = replace(load_manifest(self.root), generated_document="README.md")

        with self.assertRaisesRegex(
            ManifestError,
            r"^manifest\.generated_document must be exactly "
            r"docs/semantic-index\.md$",
        ):
            generate_index(self.root, manifest, check=False)

    def test_inventory_is_derived_without_git(self) -> None:
        managed_environment = self.root / ".venv-master-agent-0123456789ab"
        site_packages = managed_environment / "lib/python3.13/site-packages/example"
        site_packages.mkdir(parents=True)
        (site_packages / "installed.py").write_text("VALUE = 1\n", encoding="utf-8")
        (managed_environment / "pyvenv.cfg").write_text(
            "home = /trusted/python\n", encoding="utf-8"
        )
        similarly_prefixed_source = (
            self.root / ".venv-master-agent-components" / "tracked.py"
        )
        similarly_prefixed_source.parent.mkdir()
        similarly_prefixed_source.write_text("VALUE = 1\n", encoding="utf-8")

        inventory = collect_inventory(self.root)

        self.assertIn("setup.py", inventory["production_modules"])
        self.assertIn(
            ".venv-master-agent-components/tracked.py",
            inventory["production_modules"],
        )
        self.assertIn(
            "examples/generate_demo_package.py", inventory["production_modules"]
        )
        self.assertIn("tests/fixtures/advisory/source.py", inventory["tests"])
        self.assertEqual(
            inventory["platform_capabilities"], set(REQUIRED_PLATFORM_CAPABILITIES)
        )
        self.assertTrue(
            {
                ".ai/semantic-router.toml",
                "pyproject.toml",
                "src/master_agent/defaults/capabilities.toml",
                "src/master_agent/defaults/retention.toml",
                "supply-chain/runtime-dependencies.toml",
            }.issubset(inventory["configurations"])
        )
        self.assertFalse(
            any(path.startswith("specs/") for path in inventory["configurations"])
        )
        self.assertFalse(
            any(
                path.startswith(".venv-master-agent-0123456789ab/")
                for paths in inventory.values()
                if isinstance(paths, set)
                for path in paths
            )
        )

    def test_simple_inventory_keeps_test_fixtures_out_of_production(self) -> None:
        fixture = self.root / "simple/tests/fixtures/example.py"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text("VALUE = 1\n", encoding="utf-8")

        inventory = collect_inventory(self.root)

        self.assertIn("simple/masteragent/state.py", inventory["production_modules"])
        self.assertIn("simple/run.py", inventory["production_modules"])
        self.assertIn("simple/tests/test_state.py", inventory["tests"])
        self.assertIn("simple/tests/fixtures/example.py", inventory["tests"])
        self.assertFalse(
            any(
                path.startswith("simple/tests/")
                for path in inventory["production_modules"]
            )
        )
        self.assertFalse(inventory["production_modules"] & inventory["tests"])

    def test_unmapped_production_module_fails(self) -> None:
        fixture_directory = self.root / "maintenance_fixture"
        fixture_directory.mkdir()
        added = fixture_directory / "unmapped_fixture.py"
        added.write_text("VALUE = 1\n", encoding="utf-8")

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "unmapped production_modules: maintenance_fixture/unmapped_fixture.py",
            errors,
        )

    def test_unmapped_test_module_fails(self) -> None:
        added = self.root / "tests" / "fixture_unmapped.py"
        added.write_text("VALUE = 1\n", encoding="utf-8")

        _manifest, errors = self._manifest_and_errors()

        self.assertIn("unmapped tests: tests/fixture_unmapped.py", errors)

    def test_unmapped_profile_fails(self) -> None:
        added = self.root / ".github" / "agents" / "Extra.agent.md"
        added.write_text(
            "---\nname: Extra\ntools:\n  - read\n"
            "user-invocable: false\ndisable-model-invocation: true\n---\n",
            encoding="utf-8",
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn("unmapped agent profiles: .github/agents/Extra.agent.md", errors)

    def test_unmapped_current_requirement_fails(self) -> None:
        added = self.root / "specs" / "current" / "runtime" / "MA-UNMAPPED-999.md"
        added.write_text("# Fixture\n", encoding="utf-8")

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "unmapped current_requirements: specs/current/runtime/MA-UNMAPPED-999.md",
            errors,
        )

    def test_unmapped_configuration_fails(self) -> None:
        added = self.root / "config" / "unmapped-fixture.toml"
        added.write_text("enabled = false\n", encoding="utf-8")

        _manifest, errors = self._manifest_and_errors()

        self.assertIn("unmapped configurations: config/unmapped-fixture.toml", errors)

    def test_unmapped_configuration_outside_config_directory_fails(self) -> None:
        fixture_directory = self.root / "maintenance_fixture"
        fixture_directory.mkdir()
        added = fixture_directory / "unmapped-fixture.toml"
        added.write_text("enabled = false\n", encoding="utf-8")

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "unmapped configurations: maintenance_fixture/unmapped-fixture.toml",
            errors,
        )

    def test_specification_metadata_is_not_governed_configuration(self) -> None:
        fixture_directory = self.root / "specs" / "changes" / "0999-fixture"
        fixture_directory.mkdir(parents=True)
        (fixture_directory / "change.toml").write_text(
            'schema = "master-agent/change@1"\n', encoding="utf-8"
        )

        inventory = collect_inventory(self.root)

        self.assertNotIn(
            "specs/changes/0999-fixture/change.toml", inventory["configurations"]
        )

    def test_configuration_must_be_linked_by_its_owner_route(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                'configuration = [".ai/semantic-router.toml"]',
                "configuration = []",
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "configuration .ai/semantic-router.toml is not linked by its owner "
            "route semantic-router",
            errors,
        )

    def test_unmapped_capability_fails(self) -> None:
        self._rewrite(
            "config/capabilities.toml",
            lambda value: (
                value
                + '\n[capabilities."fixture.unmapped.read"]\n'
                + 'enabled = true\nauthentication = "local"\nrisk = "read_only"\n'
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn("unmapped capabilities: fixture.unmapped.read", errors)

    def test_unmapped_cli_command_fails(self) -> None:
        marker = 'subparsers = parser.add_subparsers(dest="command", required=True)'
        self._rewrite(
            "src/master_agent/cli.py",
            lambda value: value.replace(
                marker,
                marker + '\n    subparsers.add_parser("fixture-unmapped")',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn("unmapped cli_commands: fixture-unmapped", errors)

    def test_unmapped_connector_fails(self) -> None:
        added = (
            self.root / "src" / "master_agent" / "connectors" / "unmapped_fixture.py"
        )
        added.write_text("VALUE = 1\n", encoding="utf-8")

        _manifest, errors = self._manifest_and_errors()

        self.assertTrue(
            any(
                error.startswith("unmapped connectors:")
                and "unmapped_fixture.py" in error
                for error in errors
            )
        )

    def test_stale_route_path_fails(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace('"AGENTS.md"', '"docs/not-present.md"', 1),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertTrue(
            any(
                "route semantic-router.authority: stale repository path" in error
                for error in errors
            )
        )

    def test_cross_owned_authority_requirement_fails(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                '"specs/current/development/MA-ROUTER-001.md"',
                '"specs/current/development/MA-SPEC-001.md"',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "route semantic-router is missing cross-owned dependencies: "
            "specification-lifecycle",
            errors,
        )

    def test_cross_owned_implementation_fails(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                'implementation = ["scripts/semantic_router.py"]',
                'implementation = ["scripts/specs.py"]',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "route semantic-router.implementation path scripts/specs.py is owned "
            "by route specification-lifecycle",
            errors,
        )

    def test_cross_owned_test_fails(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                'tests = ["tests/test_semantic_router.py"]',
                'tests = ["tests/test_specifications.py"]',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "route semantic-router.tests path tests/test_specifications.py is owned "
            "by route specification-lifecycle",
            errors,
        )

    def test_cross_owned_configuration_requires_exact_dependency(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                'configuration = ["config/integrations.toml", "config/oauth.toml", '
                '"src/master_agent/defaults/integrations.toml", '
                '"src/master_agent/defaults/oauth.toml"]',
                'configuration = ["config/retention.toml"]',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "route direct-read is missing cross-owned dependencies: retention-audit",
            errors,
        )

    def test_unused_route_dependency_fails(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                'dependencies = ["packaging-release"]',
                'dependencies = ["packaging-release", "retention-audit"]',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "route semantic-router has unused dependencies: retention-audit",
            errors,
        )

    def test_unsafe_ownership_path_fails(self) -> None:
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                '"setup.py" = "packaging-release"',
                '"../setup.py" = "packaging-release"',
                1,
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertTrue(any("repository path is unsafe" in error for error in errors))

    def test_released_windows_filesystem_lifecycle_cannot_regress(self) -> None:
        marker = 'id = "windows-filesystem"\ntitle = "Windows filesystem identity and ACL backend"\nlifecycle = "released"'
        replacement = marker.replace('lifecycle = "released"', 'lifecycle = "planned"')
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(marker, replacement, 1),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "platform capability windows.filesystem must be released, not planned",
            errors,
        )

    def test_topology_parent_drift_fails(self) -> None:
        marker = (
            'id = "read-researcher"\nkind = "profile"\n'
            'profile = ".github/agents/MasterAgent-Read-Researcher.agent.md"\n'
            'parent = "master-agent"'
        )
        replacement = marker.replace(
            'parent = "master-agent"', 'parent = "plan-reviewer"'
        )
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(marker, replacement, 1),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn("agent read-researcher must have parent master-agent", errors)

    def test_simple_profile_is_an_independent_root_with_its_own_route(self) -> None:
        manifest = load_manifest(self.root)
        inventory = collect_inventory(self.root)

        self.assertEqual(_validate_topology(self.root, manifest, inventory), [])
        self.assertEqual(
            {agent.id for agent in manifest.agents if not agent.parent},
            {"master-agent", "masteragent-simple"},
        )
        match = select_route(manifest, "masteragent-simple")
        self.assertEqual(match.route.id, "masteragent-simple")
        self.assertEqual(match.route.agent, "masteragent-simple")
        self.assertEqual(manifest.agents_by_id["master-agent"].max_delegation_depth, 1)

    def test_simple_profile_cannot_gain_delegation_or_join_legacy_tree(self) -> None:
        manifest = load_manifest(self.root)
        inventory = collect_inventory(self.root)
        simple = manifest.agents_by_id["masteragent-simple"]
        cases = (
            ({"parent": "master-agent"}, "must be an independent root"),
            ({"return_path": "master-agent"}, "must be an independent root"),
            ({"max_delegation_depth": 1}, "must not delegate"),
            ({"sibling_awareness": True}, "must not have sibling awareness"),
            ({"fallback": "master-agent"}, "fallback must remain independent"),
            (
                {"tools": (*simple.tools, "agent")},
                "tools must be read, search, edit, execute",
            ),
        )
        for mutation, message in cases:
            with self.subTest(mutation=mutation):
                changed = replace(simple, **mutation)
                candidate = replace(
                    manifest,
                    agents=tuple(
                        changed if agent.id == simple.id else agent
                        for agent in manifest.agents
                    ),
                )
                errors = _validate_topology(self.root, candidate, inventory)
                self.assertIn(f"agent masteragent-simple {message}", errors)

    def test_simple_profile_does_not_allow_arbitrary_additional_roots(self) -> None:
        manifest = load_manifest(self.root)
        simple = manifest.agents_by_id["masteragent-simple"]
        candidate = replace(
            manifest, agents=(*manifest.agents, replace(simple, id="extra-root"))
        )

        errors = _validate_topology(self.root, candidate, collect_inventory(self.root))

        self.assertIn("topology has unexpected agents: extra-root", errors)
        self.assertIn(
            "topology roots must be exactly master-agent and masteragent-simple", errors
        )
        self.assertIn("topology must contain exactly six nodes", errors)

    def test_simple_root_does_not_relax_legacy_specialist_constraints(self) -> None:
        manifest = load_manifest(self.root)
        inventory = collect_inventory(self.root)
        for agent_id in (
            "read-researcher", "plan-reviewer", "docs-contract", "deterministic-runtime"
        ):
            original = manifest.agents_by_id[agent_id]
            cases = (
                ({"parent": "masteragent-simple"}, "must have parent master-agent"),
                ({"max_delegation_depth": 1}, "must not delegate"),
                ({"sibling_awareness": True}, "must not have sibling awareness"),
                ({"fallback": "masteragent-simple"}, "fallback must be master-agent"),
                (
                    {"return_path": "masteragent-simple"},
                    "return_path must be master-agent",
                ),
            )
            for mutation, message in cases:
                with self.subTest(agent=agent_id, mutation=mutation):
                    changed = replace(original, **mutation)
                    candidate = replace(
                        manifest,
                        agents=tuple(
                            changed if agent.id == agent_id else agent
                            for agent in manifest.agents
                        ),
                    )
                    errors = _validate_topology(self.root, candidate, inventory)
                    self.assertIn(f"agent {agent_id} {message}", errors)

    def test_legacy_specialists_still_cannot_be_invoked_directly(self) -> None:
        for profile in (
            ".github/agents/MasterAgent-Read-Researcher.agent.md",
            ".github/agents/MasterAgent-Plan-Reviewer.agent.md",
        ):
            self._rewrite(
                profile,
                lambda content: content.replace(
                    "user-invocable: false", "user-invocable: true"
                ),
            )
        manifest = load_manifest(self.root)
        errors = _validate_topology(self.root, manifest, collect_inventory(self.root))

        self.assertIn(
            "specialist profile read-researcher must not be user invocable", errors
        )
        self.assertIn(
            "specialist profile plan-reviewer must not be user invocable", errors
        )

    def test_profile_tool_inventory_drift_fails(self) -> None:
        marker = 'tools = ["read", "search"]'
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(marker, 'tools = ["read"]', 1),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "agent read-researcher tool inventory differs from its profile", errors
        )

    def test_profile_role_mapping_drift_fails(self) -> None:
        researcher = ".github/agents/MasterAgent-Read-Researcher.agent.md"
        reviewer = ".github/agents/MasterAgent-Plan-Reviewer.agent.md"
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: (
                value.replace(researcher, "PROFILE_SWAP", 1)
                .replace(reviewer, researcher, 1)
                .replace("PROFILE_SWAP", reviewer, 1)
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertIn(
            "agent read-researcher must use kind profile at "
            ".github/agents/MasterAgent-Read-Researcher.agent.md",
            errors,
        )

    def test_generated_document_drift_fails(self) -> None:
        manifest, initial_errors = self._manifest_and_errors()
        self.assertEqual(initial_errors, [])
        self._rewrite(
            manifest.generated_document,
            lambda value: value + "\nhand-edited drift\n",
        )

        errors = validate_repository(self.root, manifest)

        self.assertIn(
            f"generated document drift: {manifest.generated_document}", errors
        )

    def test_generate_check_is_deterministic(self) -> None:
        manifest, initial_errors = self._manifest_and_errors()
        self.assertEqual(initial_errors, [])
        self.assertTrue(generate_index(self.root, manifest, check=True))
        self._rewrite(manifest.generated_document, lambda value: value + "drift")
        self.assertFalse(generate_index(self.root, manifest, check=True))

        self.assertTrue(generate_index(self.root, manifest, check=False))
        self.assertTrue(generate_index(self.root, manifest, check=True))

    def test_generate_refuses_symlink_destination_without_touching_target(
        self,
    ) -> None:
        manifest = load_manifest(self.root)
        destination = self.root / manifest.generated_document
        outside = Path(self.temporary.name) / "outside.md"
        outside.write_text("outside sentinel\n", encoding="utf-8")
        destination.unlink()
        destination.symlink_to(outside)

        with self.assertRaisesRegex(
            ManifestError, "refusing symbolic-link generated document"
        ):
            generate_index(self.root, manifest, check=False)

        self.assertTrue(destination.is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside sentinel\n")
        self.assertEqual(list(destination.parent.glob(".semantic-router.tmp-*")), [])

    def test_atomic_generate_uses_private_temp_and_preserves_destination_mode(
        self,
    ) -> None:
        manifest = load_manifest(self.root)
        destination = self.root / manifest.generated_document
        destination_mode = stat.S_IMODE(destination.stat().st_mode)
        observed_temp_modes: list[int] = []
        original_replace = os.replace

        def inspect_replace(
            source: str,
            target: str,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
        ) -> None:
            self.assertIsNotNone(src_dir_fd)
            self.assertIsNotNone(dst_dir_fd)
            assert src_dir_fd is not None
            metadata = os.stat(source, dir_fd=src_dir_fd, follow_symlinks=False)
            observed_temp_modes.append(stat.S_IMODE(metadata.st_mode))
            original_replace(
                source,
                target,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        with patch("scripts.semantic_router.os.replace", side_effect=inspect_replace):
            self.assertTrue(generate_index(self.root, manifest, check=False))

        self.assertEqual(observed_temp_modes, [0o600])
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), destination_mode)
        self.assertEqual(
            destination.read_text(encoding="utf-8"), render_semantic_index(manifest)
        )
        self.assertEqual(list(destination.parent.glob(".semantic-router.tmp-*")), [])

    def test_atomic_generate_cleans_temp_when_replace_fails(self) -> None:
        manifest = load_manifest(self.root)
        destination = self.root / manifest.generated_document
        original = destination.read_bytes()

        with (
            patch(
                "scripts.semantic_router.os.replace",
                side_effect=OSError("injected replacement failure"),
            ),
            self.assertRaisesRegex(
                ManifestError, "cannot atomically generate semantic index"
            ),
        ):
            generate_index(self.root, manifest, check=False)

        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(list(destination.parent.glob(".semantic-router.tmp-*")), [])

    def test_atomic_generate_does_not_follow_raced_destination_symlink(self) -> None:
        manifest = load_manifest(self.root)
        destination = self.root / manifest.generated_document
        outside = Path(self.temporary.name) / "race-target.md"
        outside.write_text("outside sentinel\n", encoding="utf-8")
        original_replace = os.replace

        def race_destination(
            source: str,
            target: str,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
        ) -> None:
            self.assertIsNotNone(src_dir_fd)
            self.assertIsNotNone(dst_dir_fd)
            assert src_dir_fd is not None
            assert dst_dir_fd is not None
            os.unlink(target, dir_fd=dst_dir_fd)
            os.symlink(outside, target, dir_fd=dst_dir_fd)
            original_replace(
                source,
                target,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        with patch("scripts.semantic_router.os.replace", side_effect=race_destination):
            self.assertTrue(generate_index(self.root, manifest, check=False))

        self.assertFalse(destination.is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside sentinel\n")
        self.assertEqual(
            destination.read_text(encoding="utf-8"), render_semantic_index(manifest)
        )
        self.assertEqual(list(destination.parent.glob(".semantic-router.tmp-*")), [])

    def test_query_routing_selects_expected_owner(self) -> None:
        manifest = load_manifest(self.root)

        match = select_route(manifest, "please make a stateless direct read")

        self.assertEqual(match.route.id, "direct-read")
        self.assertGreater(match.score, 0)
        self.assertEqual(match.matched_alias, "direct read")

    def test_commit_only_query_routes_to_bounded_discovery(self) -> None:
        manifest = load_manifest(self.root)

        match = select_route(manifest, "review commit b5f3997")

        self.assertEqual(match.route.id, "semantic-router")
        self.assertEqual(match.matched_alias, "review commit")

    def test_ambiguous_routing_fixture_fails(self) -> None:
        marker = 'aliases = ["advisory sdk",'
        self._rewrite(
            ".ai/semantic-router.toml",
            lambda value: value.replace(
                marker, 'aliases = ["semantic router", "advisory sdk",', 1
            ),
        )

        _manifest, errors = self._manifest_and_errors()

        self.assertTrue(any("ambiguous alias" in error for error in errors))

    def test_metrics_report_shape_and_perfect_fixture_accuracy(self) -> None:
        manifest, errors = self._manifest_and_errors()
        self.assertEqual(errors, [])

        metrics = routing_metrics(manifest)

        self.assertEqual(metrics["routing_fixture_accuracy"], 1.0)
        self.assertEqual(metrics["route_count"], len(manifest.routes))
        self.assertEqual(metrics["routing_fixture_count"], len(manifest.routing_cases))
        self.assertGreater(metrics["generated_router_bytes"], 0)
        self.assertGreaterEqual(metrics["median_lookup_microseconds"], 0.0)

    def test_route_and_metrics_cli_emit_json(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            route_status = main(
                ["--root", str(self.root), "route", "repair retained evidence"]
            )
        route_result = json.loads(output.getvalue())
        self.assertEqual(route_status, 0)
        self.assertEqual(route_result["route"], "retention-audit")
        self.assertEqual(route_result["agent"]["id"], "master-agent")
        self.assertEqual(route_result["agent"]["max_delegation_depth"], 1)
        self.assertIn("src/master_agent/retention.py", route_result["implementation"])
        self.assertIn("tests/test_retention.py", route_result["tests"])
        serialized = json.dumps(route_result, sort_keys=True)
        self.assertNotIn("read-researcher", serialized)
        self.assertNotIn("plan-reviewer", serialized)
        self.assertNotIn("one sanitized scoped research task", serialized)

        output = io.StringIO()
        with redirect_stdout(output):
            metrics_status = main(["--root", str(self.root), "metrics"])
        metrics_result = json.loads(output.getvalue())
        self.assertEqual(metrics_status, 0)
        self.assertEqual(metrics_result["routing_fixture_accuracy"], 1.0)

    def test_changes_cli_rejects_unsafe_or_ambiguous_revisions(self) -> None:
        for revision, expected in (
            ("--output=outside", "bounded safe token"),
            ("HEAD...HEAD", "must use exactly BASE..HEAD"),
            ("..HEAD", "must include BASE and HEAD"),
            ("HEAD..", "must include BASE and HEAD"),
        ):
            with self.subTest(revision=revision):
                error = io.StringIO()
                arguments = ["--root", str(self.root), "changes"]
                if revision.startswith("-"):
                    arguments.append("--")
                arguments.append(revision)
                with redirect_stderr(error):
                    status = main(arguments)
                self.assertEqual(status, 1)
                self.assertIn(expected, error.getvalue())

    def test_changes_cli_never_lazy_fetches_missing_promisor_objects(self) -> None:
        """Untrusted partial-clone config cannot execute a remote helper."""

        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", "scripts/semantic_router.py")
        self._git("commit", "-qm", "promisor fixture")
        head = self._git("rev-parse", "HEAD")
        marker = Path(self.temporary.name) / "remote-helper-executed"
        self._git("config", "extensions.partialClone", "origin")
        self._git("config", "remote.origin.promisor", "true")
        self._git("config", "remote.origin.url", f"ext::touch {marker}")
        self._git("config", "protocol.ext.allow", "always")
        commit_object = self.root / ".git" / "objects" / head[:2] / head[2:]
        self.assertTrue(commit_object.is_file())
        commit_object.unlink()

        error = io.StringIO()
        with redirect_stderr(error):
            status = main(["--root", str(self.root), "changes", "HEAD"])

        self.assertEqual(status, 1)
        self.assertIn("bounded Git discovery failed", error.getvalue())
        self.assertFalse(marker.exists())

    def test_changes_cli_maps_one_commit_and_an_explicit_range(self) -> None:
        self._git("init", "-q")
        self._git("config", "user.name", "Semantic Router Test")
        self._git("config", "user.email", "router@example.invalid")
        self._git("add", "scripts/semantic_router.py", "config/policy.toml")
        self._git("commit", "-qm", "baseline")
        base = self._git("rev-parse", "HEAD")

        self._rewrite(
            "scripts/semantic_router.py", lambda value: value + "\n# review fixture\n"
        )
        self._git("add", "scripts/semantic_router.py")
        self._git("commit", "-qm", "change router")
        router_head = self._git("rev-parse", "HEAD")

        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["--root", str(self.root), "changes", router_head])
        result = json.loads(output.getvalue())

        self.assertEqual(status, 0)
        self.assertIsNone(result["base"])
        self.assertEqual(result["head"], router_head)
        self.assertEqual(result["changed_paths"], ["scripts/semantic_router.py"])
        self.assertEqual(
            [route["route"] for route in result["routes"]], ["semantic-router"]
        )
        self.assertEqual(result["unmapped_paths"], [])

        self._rewrite("config/policy.toml", lambda value: value + "\n# range fixture\n")
        self._git("add", "config/policy.toml")
        self._git("commit", "-qm", "change policy")
        final_head = self._git("rev-parse", "HEAD")

        output = io.StringIO()
        revision_range = f"{base}..{final_head}"
        with redirect_stdout(output):
            status = main(["--root", str(self.root), "changes", revision_range])
        result = json.loads(output.getvalue())

        self.assertEqual(status, 0)
        self.assertEqual(result["base"], base)
        self.assertEqual(result["head"], final_head)
        self.assertEqual(
            result["changed_paths"],
            ["config/policy.toml", "scripts/semantic_router.py"],
        )
        self.assertEqual(
            [route["route"] for route in result["routes"]],
            ["governed-applied-run", "semantic-router"],
        )
        self.assertEqual(result["unmapped_paths"], [])

        unmapped = self.root / "review-notes.txt"
        unmapped.write_text("unmapped review fixture\n", encoding="utf-8")
        self._git("add", "review-notes.txt")
        self._git("commit", "-qm", "add unmapped review path")
        unmapped_head = self._git("rev-parse", "HEAD")

        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["--root", str(self.root), "changes", unmapped_head])
        result = json.loads(output.getvalue())

        self.assertEqual(status, 0)
        self.assertEqual(result["routes"], [])
        self.assertEqual(result["unmapped_paths"], ["review-notes.txt"])

    def test_manifest_path_must_remain_inside_repository(self) -> None:
        outside = Path(self.temporary.name) / "outside.toml"
        outside.write_text("[manifest]\nversion = 1\n", encoding="utf-8")

        with self.assertRaisesRegex(ManifestError, "escapes the repository"):
            load_manifest(self.root, outside)


if __name__ == "__main__":
    unittest.main()
