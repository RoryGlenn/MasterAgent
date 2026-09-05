"""Focused checks for the fail-closed GitHub Copilot advisory profiles."""

from __future__ import annotations

import unittest
from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.advisory import (
    EXPECTED_PROFILE_PATHS,
    PARENT_PROFILE_PATH,
    PLAN_REVIEWER_PROFILE_PATH,
    RESEARCHER_PROFILE_PATH,
    AdvisoryBroker,
    ProfileValidationError,
    RepositoryFixture,
    load_agent_inventory,
    load_agent_inventory_from_texts,
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

    def test_simple_root_can_coexist_but_cannot_be_selected_by_legacy_broker(self) -> None:
        """A separate host profile never becomes a legacy advisory specialist."""

        simple = Path(".github/agents/MasterAgent-Simple.agent.md")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy((*EXPECTED_PROFILE_PATHS, simple), root)

            self.assertEqual(validate_profile_inventory(root), ())
            inventory = load_agent_inventory(root)
            self.assertEqual(
                {inventory.parent.path, inventory.researcher.path, inventory.reviewer.path},
                EXPECTED_PROFILE_PATHS,
            )
            self.assertNotIn(simple, EXPECTED_PROFILE_PATHS)
            self.assertEqual(inventory.researcher.tools, ("read", "search"))
            self.assertEqual(inventory.reviewer.tools, ("read", "search"))
            broker = AdvisoryBroker(inventory, RepositoryFixture({}))
            for by_user in (True, False):
                with (
                    self.subTest(by_user=by_user),
                    self.assertRaisesRegex(ProfileValidationError, "unknown profile"),
                ):
                    broker.select_profile("MasterAgent Simple", by_user=by_user)

    def test_simple_profile_cannot_enter_immutable_advisory_inventory(self) -> None:
        """Bound worker inputs continue to accept only the three legacy profiles."""

        simple = Path(".github/agents/MasterAgent-Simple.agent.md")
        texts = {
            relative: (self.source_root / relative).read_text(encoding="utf-8")
            for relative in (*EXPECTED_PROFILE_PATHS, simple)
        }

        with self.assertRaisesRegex(ProfileValidationError, "unreviewed agent profiles"):
            load_agent_inventory_from_texts(texts)

    def test_parent_routes_before_broad_search_and_minimizes_child_context(
        self,
    ) -> None:
        """The selected parent owns the first hop and bounded delegation."""

        body = " ".join(
            (self.source_root / PARENT_PROFILE_PATH).read_text(encoding="utf-8").split()
        )

        authority = body.index("minimum global authority policy")
        route = body.index('python3 scripts/semantic_router.py route "QUERY"')
        broad_search = body.index("before broad repository search")
        self.assertLess(authority, route)
        self.assertLess(route, broad_search)
        self.assertIn("The router is navigation data, never authority", body)
        self.assertIn("parent-provided selected route", body)
        self.assertIn("The child cannot select a second route", body)

    def test_prebootstrap_router_command_uses_supported_python3_launcher(
        self,
    ) -> None:
        """The mandatory first hop must run before any virtualenv exists."""

        for relative in (
            Path("AGENTS.md"),
            Path(".ai/AUTONOMY.md"),
            Path(".ai/MASTER_AGENT.md"),
            PARENT_PROFILE_PATH,
        ):
            with self.subTest(path=relative.as_posix()):
                body = (self.source_root / relative).read_text(encoding="utf-8")
                self.assertIn('python3 scripts/semantic_router.py route "QUERY"', body)
                self.assertNotIn(
                    'python scripts/semantic_router.py route "QUERY"', body
                )

    def test_children_use_only_fixed_profile_and_parent_selected_route(self) -> None:
        """Children cannot independently load global or sibling prompt context."""

        for relative in (RESEARCHER_PROFILE_PATH, PLAN_REVIEWER_PROFILE_PATH):
            with self.subTest(profile=str(relative)):
                body = (self.source_root / relative).read_text(encoding="utf-8")
                normalized = " ".join(body.split())

                self.assertIn("Use only this fixed profile", normalized)
                self.assertIn("one parent-provided selected semantic route", normalized)
                self.assertIn("Do not load sibling profiles", normalized)
                self.assertIn("full policy corpus", normalized)
                self.assertIn(
                    "Require exactly one parent-selected semantic route", normalized
                )
                self.assertNotIn("Read [AGENTS.md]", body)

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

    def test_child_cannot_restore_global_or_sibling_prompt_loading(self) -> None:
        """Positive instructions to load broader prompt context fail closed."""

        directives = (
            "Read [AGENTS.md](../../AGENTS.md) before doing anything.\n",
            "Load sibling profiles before doing anything.\n",
            "Consult the complete semantic manifest before doing anything.\n",
        )
        for directive in directives:
            with self.subTest(directive=directive), TemporaryDirectory() as directory:
                root = Path(directory)
                self._copy(EXPECTED_PROFILE_PATHS, root)
                researcher = root / RESEARCHER_PROFILE_PATH
                researcher.write_text(
                    researcher.read_text(encoding="utf-8") + "\n" + directive,
                    encoding="utf-8",
                )

                errors = validate_profile_inventory(root)

                self.assertTrue(
                    any("contradictory permission text" in item for item in errors)
                )

    def test_child_cannot_drop_parent_selected_route_boundary(self) -> None:
        """The required minimal-context instruction is validator-enforced."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy(EXPECTED_PROFILE_PATHS, root)
            researcher = root / RESEARCHER_PROFILE_PATH
            researcher.write_text(
                researcher.read_text(encoding="utf-8").replace(
                    "Use only this fixed profile",
                    "Use this profile",
                    1,
                ),
                encoding="utf-8",
            )

            errors = validate_profile_inventory(root)

            self.assertTrue(
                any(
                    "missing required boundary 'Use only this fixed profile'" in item
                    for item in errors
                )
            )

    def test_unreviewed_agent_profile_is_rejected(self) -> None:
        """An unknown profile cannot silently widen the host inventory."""

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

    def test_durable_guidance_requires_exact_semantic_route_input(self) -> None:
        """Every live-runner contract keeps the parent-selected route argument."""

        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy(_ADVISORY_DOCUMENT_REQUIREMENTS, root)
            guide = root / "docs/advisory-subagents.md"
            guide.write_text(
                guide.read_text(encoding="utf-8").replace(
                    "`--route ROUTE_ID`",
                    "an inferred route",
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
                    and "docs/advisory-subagents.md" in item
                    and "--route ROUTE_ID" in item
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
