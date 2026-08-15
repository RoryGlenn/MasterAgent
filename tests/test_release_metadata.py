"""Release metadata and safe-default validation tests."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.validate_release import (
    _validate_copilot_agent,
    _validate_demo_powerpoint,
    _validate_demo_readiness,
    _validate_file_hygiene,
    _validate_first_run_contract,
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

    def test_copilot_agent_requires_read_only_bootstrap_guard(self) -> None:
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
                    "Explicit read-only, diagnosis-only, or no-change instructions take",
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

    def test_first_run_contract_rejects_inconsistent_onboarding_markdown(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        relative_paths = (
            Path(".ai/MASTER_AGENT.md"),
            Path(".ai/FIRST_RUN.md"),
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
                "v1 demonstration PowerPoint validation requires the python-pptx dependency"
            ],
        )


if __name__ == "__main__":
    unittest.main()
