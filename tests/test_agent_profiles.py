"""Focused checks for the fail-closed GitHub Copilot advisory profiles."""

from __future__ import annotations

import unittest
from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.advisory import (
    EXPECTED_PROFILE_PATHS,
    PARENT_PROFILE_PATH,
    RESEARCHER_PROFILE_PATH,
    validate_profile_inventory,
)
from scripts.validate_release import (
    _ADVISORY_DOCUMENT_REQUIREMENTS,
    _validate_advisory_agents,
    _validate_advisory_contract,
    _validate_copilot_agent,
)


class AdvisoryAgentProfileTests(unittest.TestCase):
    """Keep direct host delegation disabled and child tools read/search-only."""

    def setUp(self) -> None:
        self.source_root = Path(__file__).resolve().parents[1]

    def test_checked_in_profiles_pass_semantic_and_release_contracts(self) -> None:
        """Both validators must accept the exact checked-in inventory."""

        checks: list[str] = []
        errors: list[str] = []

        self.assertEqual(validate_profile_inventory(self.source_root), ())
        _validate_advisory_agents(self.source_root, checks, errors)
        _validate_advisory_contract(self.source_root, checks, errors)

        self.assertEqual(errors, [])
        self.assertEqual(len(checks), 2)

    def test_parent_cannot_regain_direct_host_delegation(self) -> None:
        """Adding the agent tool fails semantic and release validation."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy(EXPECTED_PROFILE_PATHS, root)
            parent = root / PARENT_PROFILE_PATH
            parent.write_text(
                parent.read_text(encoding="utf-8").replace(
                    "  - execute\n",
                    "  - execute\n  - agent\n",
                    1,
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            semantic_errors = validate_profile_inventory(root)
            _validate_copilot_agent(root, checks, errors)

            self.assertTrue(semantic_errors)
            self.assertEqual(checks, [])
            self.assertTrue(any("tools must be exactly" in item for item in errors))

    def test_researcher_cannot_gain_execute_edit_agent_or_broad_mcp(self) -> None:
        """Every widened child tool surface is rejected."""

        for tool in ("execute", "edit", "agent", "mcp.github"):
            with self.subTest(tool=tool), TemporaryDirectory() as directory:
                root = Path(directory)
                self._copy(EXPECTED_PROFILE_PATHS, root)
                researcher = root / RESEARCHER_PROFILE_PATH
                researcher.write_text(
                    researcher.read_text(encoding="utf-8").replace(
                        "  - search\n",
                        f"  - search\n  - {tool}\n",
                        1,
                    ),
                    encoding="utf-8",
                )
                checks: list[str] = []
                errors: list[str] = []

                semantic_errors = validate_profile_inventory(root)
                _validate_advisory_agents(root, checks, errors)

                self.assertTrue(semantic_errors)
                self.assertEqual(checks, [])
                self.assertTrue(any("tools must be exactly" in item for item in errors))

    def test_child_cannot_become_user_or_model_invocable(self) -> None:
        """Both direct invocation flags remain fail-closed."""

        mutations = (
            ("user-invocable: false", "user-invocable: true"),
            ("disable-model-invocation: true", "disable-model-invocation: false"),
        )
        for old, new in mutations:
            with self.subTest(new=new), TemporaryDirectory() as directory:
                root = Path(directory)
                self._copy(EXPECTED_PROFILE_PATHS, root)
                researcher = root / RESEARCHER_PROFILE_PATH
                researcher.write_text(
                    researcher.read_text(encoding="utf-8").replace(old, new, 1),
                    encoding="utf-8",
                )
                checks: list[str] = []
                errors: list[str] = []

                semantic_errors = validate_profile_inventory(root)
                _validate_advisory_agents(root, checks, errors)

                self.assertTrue(semantic_errors)
                self.assertEqual(checks, [])
                self.assertTrue(any("invocation" in item for item in errors))

    def test_contradictory_permission_text_is_rejected(self) -> None:
        """Prompt wording cannot reintroduce denied technical capabilities."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy(EXPECTED_PROFILE_PATHS, root)
            researcher = root / RESEARCHER_PROFILE_PATH
            researcher.write_text(
                researcher.read_text(encoding="utf-8")
                + "\nYou may use execute and provider tools are allowed.\n",
                encoding="utf-8",
            )

            errors = validate_profile_inventory(root)

            self.assertTrue(
                any("contradictory permission text" in item for item in errors)
            )

    def test_unreviewed_agent_profile_is_rejected(self) -> None:
        """A fourth profile cannot silently widen the host inventory."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy(EXPECTED_PROFILE_PATHS, root)
            extra = root / ".github/agents/Unreviewed.agent.md"
            extra.write_text(
                "---\nname: Unreviewed\ndescription: Unsafe\ntools:\n"
                "  - execute\nuser-invocable: false\n"
                "disable-model-invocation: false\n---\nUnsafe.\n",
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            semantic_errors = validate_profile_inventory(root)
            _validate_advisory_agents(root, checks, errors)

            self.assertTrue(semantic_errors)
            self.assertEqual(checks, [])
            self.assertTrue(any("unreviewed profiles" in item for item in errors))

    def test_durable_guidance_cannot_drop_parent_fallback(self) -> None:
        """Release guidance must keep the unsupported-host fallback explicit."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy(_ADVISORY_DOCUMENT_REQUIREMENTS, root)
            policy = root / ".ai/MASTER_AGENT.md"
            policy.write_text(
                policy.read_text(encoding="utf-8").replace(
                    "complete the same work directly",
                    "wait for an advisory child",
                    1,
                ),
                encoding="utf-8",
            )
            checks: list[str] = []
            errors: list[str] = []

            _validate_advisory_contract(root, checks, errors)

            self.assertEqual(checks, [])
            self.assertTrue(
                any(
                    "advisory sub-agent contract document is inconsistent" in item
                    and ".ai/MASTER_AGENT.md" in item
                    for item in errors
                )
            )

    def _copy(self, relatives: Iterable[Path], root: Path) -> None:
        for relative in relatives:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((self.source_root / relative).read_bytes())


if __name__ == "__main__":
    unittest.main()
