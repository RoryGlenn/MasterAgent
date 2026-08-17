"""Focused checks for the repository-owned Docs Agent contract."""

from __future__ import annotations

import unittest
from pathlib import Path


class DocsAgentContractTests(unittest.TestCase):
    """Prevent the documentation completion contract from drifting silently."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.contract = (self.root / ".ai/DOCS_AGENT.md").read_text(
            encoding="utf-8"
        )

    def test_contract_pins_methodology_modes_and_audiences(self) -> None:
        """The contract must retain its explicit audience-aware methodology."""

        required = (
            "Docs for Developers",
            "2nd edition (2026)",
            "maintenance",
            "authoring",
            "audit",
            "least technical member",
            "non-technical user",
            "mixed audience",
            "developer",
            "maintainer",
            "decision-maker",
            "Simplify the language, not the truth",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.contract)

    def test_contract_pins_analogy_accuracy_and_conflict_rules(self) -> None:
        """Accessibility must not weaken technical accuracy or hide defects."""

        required = (
            "Use an analogy only",
            "literal technical explanation",
            "Do not automatically treat the implementation as intended behavior",
            "do not rewrite documentation to make an apparent defect look intentional",
            "return `needs_review`",
            "current-state",
            "historical",
            "planned",
            "generated",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.contract)

    def test_contract_pins_scope_no_change_and_output_shape(self) -> None:
        """The specialist must remain narrow and may report a real no-change."""

        required = (
            "README",
            "do not edit production source",
            "`no_change` is a successful result",
            "status: updated | no_change | needs_review",
            "mode: maintenance | authoring | audit",
            "validation:",
            "issues:",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.contract)

    def test_parent_instructions_apply_the_contract_directly(self) -> None:
        """Every durable parent instruction must include the completion gate."""

        requirements = {
            Path("AGENTS.md"): (
                ".ai/DOCS_AGENT.md",
                "documentation completion gate",
                "complete the same documentation review directly",
            ),
            Path(".ai/MASTER_AGENT.md"): (
                "[`DOCS_AGENT.md`](DOCS_AGENT.md)",
                "documentation completion gate",
                "complete the same documentation review directly",
            ),
            Path(".github/agents/MasterAgent.agent.md"): (
                "[Docs Agent contract](../../.ai/DOCS_AGENT.md)",
                "## Documentation completion gate",
                "Complete the same documentation review directly",
            ),
        }

        for relative, markers in requirements.items():
            text = (self.root / relative).read_text(encoding="utf-8")
            for marker in markers:
                with self.subTest(relative=str(relative), marker=marker):
                    self.assertIn(marker, text)

    def test_indexed_subagent_guide_explains_the_direct_parent_model(self) -> None:
        """Public guidance must not imply that an unsafe child is active."""

        guide = (self.root / "docs/advisory-subagents.md").read_text(
            encoding="utf-8"
        )
        for marker in (
            "Think of the Docs Agent as the person who checks an instruction manual",
            "selected MasterAgent parent applies the contract's `maintenance` mode",
            "`updated`",
            "`no_change`",
            "`needs_review`",
            "The implementation is evidence, but it is not automatically",
            "[`.ai/DOCS_AGENT.md`](../.ai/DOCS_AGENT.md)",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, guide)

    def test_no_misleading_live_docs_profile_is_checked_in(self) -> None:
        """A contract file must not masquerade as a supported host child."""

        self.assertFalse(
            (self.root / ".github/agents/MasterAgent-Docs.agent.md").exists()
        )


if __name__ == "__main__":
    unittest.main()
