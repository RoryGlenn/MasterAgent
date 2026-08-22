"""Release metadata and safe-default validation tests."""

from __future__ import annotations

import stat
import tomllib
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.validate_release import (
    _PUBLIC_READ_DOCUMENT_REQUIREMENTS,
    _RETENTION_PRUNE_DOCUMENT_REQUIREMENTS,
    _validate_copilot_agent,
    _validate_demo_powerpoint,
    _validate_demo_readiness,
    _validate_file_hygiene,
    _validate_first_run_contract,
    _validate_public_read_contract,
    _validate_retention_prune_contract,
    _validate_supply_chain,
    validate_archive,
    validate_project,
)


class ReleaseMetadataTests(unittest.TestCase):
    """Keep the v1 source tree packageable and fail-closed."""

    def test_repository_passes_release_validation(self) -> None:
        """The checked-in source tree should pass offline release checks."""

        root = Path(__file__).resolve().parents[1]
        report = validate_project(root)
        self.assertEqual(report.errors, ())
        self.assertTrue(report.valid)

    def test_release_rejects_a_world_writable_capsule_worker(self) -> None:
        with TemporaryDirectory() as directory:
            archive_path = Path(directory) / "unsafe.whl"
            worker = zipfile.ZipInfo("master_agent/capsule_worker.py")
            worker.create_system = 3
            worker.external_attr = (stat.S_IFREG | 0o666) << 16
            with zipfile.ZipFile(archive_path, mode="w") as archive:
                archive.writestr(worker, "pass\n")

            report = validate_archive(archive_path)

            self.assertTrue(
                any("writable by group or others" in error for error in report.errors)
            )

    def test_release_rejects_a_symlinked_capsule_worker(self) -> None:
        with TemporaryDirectory() as directory:
            archive_path = Path(directory) / "unsafe.whl"
            worker = zipfile.ZipInfo("master_agent/capsule_worker.py")
            worker.create_system = 3
            worker.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive_path, mode="w") as archive:
                archive.writestr(worker, "../attacker.py")

            report = validate_archive(archive_path)

            self.assertTrue(any("link entry" in error for error in report.errors))
            self.assertTrue(any("is not regular" in error for error in report.errors))

    def test_ci_installs_the_runtime_only_in_private_virtual_environments(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertEqual(workflow.count("umask 077"), 7)
        self.assertEqual(workflow.count('python -m venv "$'), 7)
        self.assertEqual(workflow.count("name: Seal hosted Python runtime"), 5)
        self.assertEqual(workflow.count('sudo chmod -R go-w -- "$pythonLocation"'), 5)
        self.assertEqual(workflow.count("apparmor-profiles bubblewrap"), 3)
        self.assertEqual(workflow.count("sudo apparmor_parser -r"), 3)
        self.assertNotIn("apparmor_restrict_unprivileged_userns=0", workflow)
        self.assertNotIn("run: python -m pip install", workflow)
        self.assertNotIn("\n          python -m pip install", workflow)

    def test_supply_chain_rejects_a_denied_runtime_license(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        relative_paths = (
            Path("LICENSE"),
            Path("THIRD_PARTY_NOTICES.md"),
            Path("requirements-runtime.lock"),
            Path("sbom.cdx.json"),
            Path("pyproject.toml"),
            Path("config/dependency-licenses.toml"),
            Path("supply-chain/runtime-dependencies.toml"),
            Path("scripts/generate_sbom.py"),
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in relative_paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source_root / relative).read_bytes())
            inventory = root / "supply-chain/runtime-dependencies.toml"
            inventory.write_text(
                inventory.read_text(encoding="utf-8").replace(
                    'license = "MIT"',
                    'license = "AGPL-3.0-only"',
                    1,
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_supply_chain(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("license is denied" in error for error in errors))

    def test_core_install_keeps_draft_rendering_dependencies_optional(self) -> None:
        root = Path(__file__).resolve().parents[1]
        pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        project = pyproject["project"]

        self.assertEqual(project["dependencies"], [])
        self.assertEqual(
            project["optional-dependencies"]["drafts"],
            [
                "Pillow==12.3.0",
                "XlsxWriter==3.2.9",
                "lxml==6.1.1",
                "python-pptx==1.0.2",
                "typing_extensions==4.16.0",
            ],
        )

    def test_runtime_directory_is_rejected_even_when_contents_are_ignored(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / ".master-agent" / "tokens"
            runtime.mkdir(parents=True)
            (runtime / "microsoft.json").write_text(
                '{"access_token":"TOP-SECRET"}\n',
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_file_hygiene(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("runtime directory" in error for error in errors))

    def test_copilot_agent_rejects_unsafe_tool_expansion(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".github/agents/MasterAgent.agent.md"
            agent.parent.mkdir(parents=True)
            source = (
                Path(__file__).resolve().parents[1]
                / ".github/agents/MasterAgent.agent.md"
            ).read_text(encoding="utf-8")
            agent.write_text(
                source.replace("  - execute\n", "  - execute\n  - web\n"),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("tools must be exactly" in error for error in errors))

    def test_copilot_agent_profile_is_required(self) -> None:
        with TemporaryDirectory() as directory:
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(Path(directory), checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("missing or unreadable" in error for error in errors))

    def test_copilot_agent_rejects_malformed_frontmatter(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".github/agents/MasterAgent.agent.md"
            agent.parent.mkdir(parents=True)
            agent.write_text("# Missing frontmatter\n", encoding="utf-8")
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("frontmatter" in error for error in errors))

    def test_copilot_agent_requires_policy_references(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".github/agents/MasterAgent.agent.md"
            agent.parent.mkdir(parents=True)
            source = (
                Path(__file__).resolve().parents[1]
                / ".github/agents/MasterAgent.agent.md"
            ).read_text(encoding="utf-8")
            agent.write_text(
                source.replace(
                    "[AGENTS.md](../../AGENTS.md)",
                    "AGENTS.md",
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any("missing required policy reference" in error for error in errors)
            )

    def test_copilot_agent_requires_bounded_runtime_bootstrap(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".github/agents/MasterAgent.agent.md"
            agent.parent.mkdir(parents=True)
            source = (
                Path(__file__).resolve().parents[1]
                / ".github/agents/MasterAgent.agent.md"
            ).read_text(encoding="utf-8")
            agent.write_text(
                source.replace(
                    ".venv/bin/python -m pip install -e .",
                    "python -m pip install --user -e .",
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any("missing required boundary" in error for error in errors)
            )

    def test_copilot_agent_requires_no_local_change_bootstrap_guard(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".github/agents/MasterAgent.agent.md"
            agent.parent.mkdir(parents=True)
            source = (
                Path(__file__).resolve().parents[1]
                / ".github/agents/MasterAgent.agent.md"
            ).read_text(encoding="utf-8")
            agent.write_text(
                source.replace(
                    "Repository-inspection, diagnosis-only, or explicit no-local-change",
                    "Local setup may always proceed",
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any("missing required boundary" in error for error in errors)
            )

    def test_copilot_agent_requires_automatic_atlassian_connection_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".github/agents/MasterAgent.agent.md"
            agent.parent.mkdir(parents=True)
            source = (
                Path(__file__).resolve().parents[1]
                / ".github/agents/MasterAgent.agent.md"
            ).read_text(encoding="utf-8")
            agent.write_text(
                source.replace(
                    "--connector-url SYSTEM=URL",
                    "use a manually configured URL",
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_copilot_agent(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any(
                    "missing required boundary" in error
                    and "--connector-url SYSTEM=URL" in error
                    for error in errors
                )
            )

    def test_first_run_contract_rejects_inconsistent_onboarding_markdown(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        relative_paths = (
            Path(".ai/MASTER_AGENT.md"),
            Path(".ai/FIRST_RUN.md"),
            Path(".ai/AUTONOMY.md"),
            Path("AGENTS.md"),
            Path("CHANGELOG.md"),
            Path("README.md"),
            Path("docs/copilot-custom-agent.md"),
            Path("docs/release-validation.md"),
            Path("docs/semantic-index.md"),
            Path("scripts/bootstrap_agent.py"),
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in relative_paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source_root / relative).read_bytes())
            guide = root / "docs/copilot-custom-agent.md"
            guide.write_text(
                guide.read_text(encoding="utf-8").replace(
                    "MasterAgent is ready locally",
                    "Setup probably worked",
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_first_run_contract(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any(
                    "docs/copilot-custom-agent.md" in error
                    and "MasterAgent is ready locally" in error
                    for error in errors
                )
            )

    def test_first_run_contract_rejects_capability_gap_as_final_answer(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        relative_paths = (
            Path(".ai/MASTER_AGENT.md"),
            Path(".ai/FIRST_RUN.md"),
            Path(".ai/AUTONOMY.md"),
            Path("AGENTS.md"),
            Path("CHANGELOG.md"),
            Path("README.md"),
            Path("docs/copilot-custom-agent.md"),
            Path("docs/release-validation.md"),
            Path("docs/semantic-index.md"),
            Path("scripts/bootstrap_agent.py"),
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in relative_paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source_root / relative).read_bytes())
            autonomy = root / ".ai/AUTONOMY.md"
            autonomy.write_text(
                autonomy.read_text(encoding="utf-8").replace(
                    "Never end an actionable request",
                    "You may end an actionable request",
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_first_run_contract(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any(
                    ".ai/AUTONOMY.md" in error
                    and "Never end an actionable request" in error
                    for error in errors
                )
            )

    def test_public_read_contract_rejects_blanket_credential_guidance(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in _PUBLIC_READ_DOCUMENT_REQUIREMENTS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source_root / relative).read_bytes())
            readme = root / "README.md"
            checks: list[str] = []
            errors: list[str] = []

            _validate_public_read_contract(root, checks, errors)

            self.assertEqual(errors, [])
            self.assertEqual(len(checks), 1)

            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\nOrganization-approved HTTPS API endpoints and credentials "
                "for live use.\n",
                encoding="utf-8",
            )
            checks = []
            errors = []

            _validate_public_read_contract(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any("blanket credential requirement" in error for error in errors)
            )

    def test_retention_prune_contract_rejects_preview_only_drift(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in _RETENTION_PRUNE_DOCUMENT_REQUIREMENTS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source_root / relative).read_bytes())
            checks: list[str] = []
            errors: list[str] = []

            _validate_retention_prune_contract(root, checks, errors)

            self.assertEqual(errors, [])
            self.assertEqual(len(checks), 1)

            operations = root / "docs/operations.md"
            operations.write_text(
                operations.read_text(encoding="utf-8")
                + "\nEvidence expiry deletion remains preview-only.\n",
                encoding="utf-8",
            )
            checks = []
            errors = []

            _validate_retention_prune_contract(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any("stale preview-only claim" in error for error in errors)
            )

    def test_demo_readiness_count_must_match_capability_catalog(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            demo = root / "examples/v1-demo"
            config = root / "config"
            demo.mkdir(parents=True)
            config.mkdir()
            (demo / "readiness.json").write_text(
                '{"checks":[{"name":"governance_coverage",'
                '"covered_capabilities":71}]}\n',
                encoding="utf-8",
            )
            (config / "capabilities.toml").write_text(
                '[capabilities."one"]\nenabled=true\n',
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_demo_readiness(root, demo, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(any("does not match" in error for error in errors))

    def test_demo_powerpoint_reports_missing_dependency_cleanly(self) -> None:
        """A minimal package-job environment must yield a release error, not crash."""

        checks: list[str] = []
        errors: list[str] = []

        with patch.dict("sys.modules", {"pptx": None}):
            _validate_demo_powerpoint(Path("unused"), checks, errors)

        self.assertEqual(checks, [])
        self.assertEqual(
            errors,
            [
                "v1 demonstration PowerPoint validation requires the optional drafts extra"
            ],
        )


if __name__ == "__main__":
    unittest.main()
