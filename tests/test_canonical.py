"""Source-of-truth tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from master_agent.canonical import SourceOfTruthRegistry
from master_agent.errors import ConfigurationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)

ROOT = Path(__file__).resolve().parents[1]


class SourceOfTruthTests(unittest.TestCase):
    """Verify projections cannot silently become canonical."""

    def test_projection_write_without_canonical_write_is_rejected(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        projection = AgentAction(
            capability="teams.message.draft",
            target=ResourceRef(
                system="teams",
                resource_type="message",
                resource_id="weekly-status-draft",
            ),
            parameters={
                "body": "changed status",
                "source_bindings": {"project_status_narrative": "a" * 64},
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:test:projection",
            justification="Test projection write.",
        )
        plan = ChangePlan(goal="Test", actions=(projection,), created_by="test")
        valid, reason = registry.validate(plan, projection)
        self.assertFalse(valid)
        self.assertIn("canonical source", reason)

    def test_projection_capability_cannot_bypass_rule_with_read_only_label(
        self,
    ) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        projection = AgentAction(
            capability="teams.message.draft",
            target=ResourceRef("teams", "message", "weekly-status-draft"),
            parameters={"body": "unbound projection"},
            risk=RiskLevel.READ_ONLY,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="canonical:forged-read-risk",
            justification="attempt to bypass canonical checks",
        )
        plan = ChangePlan(goal="Test", actions=(projection,), created_by="test")

        valid, reason = registry.validate(plan, projection)

        self.assertFalse(valid)
        self.assertIn("canonical source", reason)

    def test_projection_must_depend_on_the_canonical_write(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        canonical = AgentAction(
            capability="confluence.page.update",
            target=ResourceRef(
                "confluence",
                "page",
                "project-status",
                expected_version="1",
            ),
            parameters={
                "body": "canonical",
                "source_bindings": {"project_status_narrative": "a" * 64},
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:update",
            justification="update canonical source",
        )
        unordered = AgentAction(
            capability="teams.message.draft",
            target=ResourceRef("teams", "message", "weekly-status-draft"),
            parameters={
                "body": "projection",
                "source_bindings": {"project_status_narrative": "a" * 64},
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:projection:unordered",
            justification="update projection",
        )
        unordered_plan = ChangePlan(
            goal="unordered projection",
            actions=(unordered, canonical),
            created_by="test",
        )
        valid, reason = registry.validate(unordered_plan, unordered)
        self.assertFalse(valid)
        self.assertIn("must depend", reason)

        ordered = AgentAction(
            capability=unordered.capability,
            target=unordered.target,
            parameters=unordered.parameters,
            risk=unordered.risk,
            authority_source=unordered.authority_source,
            requires_approval=True,
            idempotency_key="canonical:projection:ordered",
            justification="update projection after canonical source",
            dependencies=(canonical.action_id,),
        )
        ordered_plan = ChangePlan(
            goal="ordered projection",
            actions=(ordered, canonical),
            created_by="test",
        )
        valid, reason = registry.validate(ordered_plan, ordered)
        self.assertFalse(valid)
        self.assertIn("matching field-value", reason)

        matching = AgentAction(
            capability=unordered.capability,
            target=unordered.target,
            parameters={
                "body": "canonical",
                "source_bindings": {"project_status_narrative": "b" * 64},
            },
            risk=unordered.risk,
            authority_source=unordered.authority_source,
            requires_approval=False,
            idempotency_key="canonical:projection:matching",
            justification="project the exact canonical value",
            dependencies=(canonical.action_id,),
        )
        matching_plan = ChangePlan(
            goal="matching projection",
            actions=(matching, canonical),
            created_by="test",
        )
        valid, _ = registry.validate(matching_plan, matching)
        self.assertTrue(valid)

    def test_unrelated_canonical_field_cannot_authorize_projection(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        forged_digest = "a" * 64
        canonical = AgentAction(
            capability="confluence.page.update",
            target=ResourceRef("confluence", "page", "project-status", "1"),
            parameters={
                "body": "unrelated title update",
                "source_bindings": {"page_title": forged_digest},
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:unrelated",
            justification="update a different field",
        )
        projection = AgentAction(
            capability="teams.message.draft",
            target=ResourceRef("teams", "message", "weekly-status-draft"),
            parameters={
                "body": "fabricated status",
                "source_bindings": {
                    "project_status_narrative": forged_digest,
                },
            },
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="projection:fabricated",
            justification="project an unrelated write",
            dependencies=(canonical.action_id,),
        )
        plan = ChangePlan(
            goal="reject field laundering",
            actions=(canonical, projection),
            created_by="test",
        )

        valid, reason = registry.validate(plan, projection)

        self.assertFalse(valid)
        self.assertIn("field-value", reason)

    def test_forged_equal_digest_cannot_hide_divergent_projection_values(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        forged_digest = "f" * 64
        canonical = AgentAction(
            capability="confluence.page.update",
            target=ResourceRef("confluence", "page", "project-status", "1"),
            parameters={
                "title": "Status",
                "body": "canonical narrative",
                "source_bindings": {
                    "project_status_narrative": forged_digest,
                },
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:forged-token",
            justification="update the canonical narrative",
        )
        projection_cases = (
            (
                "teams.message.draft",
                ResourceRef("teams", "message", "weekly-status-draft"),
                {"body": "divergent Teams narrative"},
            ),
            (
                "outlook.email.draft",
                ResourceRef("outlook", "draft", "weekly-status-draft"),
                {"body": "divergent Outlook narrative"},
            ),
            (
                "powerpoint.presentation.generate",
                ResourceRef("powerpoint", "presentation", "weekly-status"),
                {
                    "title": "Weekly status",
                    "slides": [
                        {
                            "title": "Narrative",
                            "bullets": ["divergent PowerPoint narrative"],
                        }
                    ],
                },
            ),
            (
                "powerpoint.presentation.generate",
                ResourceRef("powerpoint", "presentation", "weekly-status"),
                {
                    "title": "Weekly status",
                    "sections": ["canonical narrative"],
                    "slides": [
                        {
                            "title": "Narrative",
                            "bullets": ["rendered divergent narrative"],
                        }
                    ],
                },
            ),
            (
                "powerpoint.presentation.generate",
                ResourceRef("powerpoint", "presentation", "weekly-status"),
                {
                    "title": "Weekly status",
                    "slides": [
                        {
                            "title": "Narrative",
                            "bullets": ["rendered divergent narrative"] * 12
                            + ["canonical narrative"],
                        }
                    ],
                },
            ),
        )
        for index, (capability, target, parameters) in enumerate(projection_cases):
            with self.subTest(capability=capability):
                projection = AgentAction(
                    capability=capability,
                    target=target,
                    parameters={
                        **parameters,
                        "source_bindings": {
                            "project_status_narrative": forged_digest,
                        },
                    },
                    risk=RiskLevel.LOCAL_GENERATION,
                    authority_source=AuthoritySource.DIRECT_USER,
                    requires_approval=False,
                    idempotency_key=f"projection:forged-token:{index}",
                    justification="attempt to project divergent content",
                    dependencies=(canonical.action_id,),
                )
                plan = ChangePlan(
                    goal="reject a forged source binding",
                    actions=(canonical, projection),
                    created_by="test",
                )

                valid, reason = registry.validate(plan, projection)

                self.assertFalse(valid)
                self.assertIn("matching field-value", reason)

    def test_powerpoint_requires_values_from_both_canonical_rules(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        confluence = AgentAction(
            capability="confluence.page.update",
            target=ResourceRef("confluence", "page", "project-status", "1"),
            parameters={"body": "On track", "title": "Status"},
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:ppt:confluence",
            justification="update canonical narrative",
        )
        for index, jira_parameters in enumerate(
            (
                {"fields": {"status": {"name": "In Progress"}}},
                {"transition_id": "31", "target_status": "In Progress"},
            )
        ):
            capability = (
                "jira.issue.update"
                if "fields" in jira_parameters
                else "jira.issue.transition"
            )
            with self.subTest(capability=capability):
                jira = AgentAction(
                    capability=capability,
                    target=ResourceRef("jira", "issue", "PROJECT-SPRINT", "2"),
                    parameters=jira_parameters,
                    risk=RiskLevel.REVERSIBLE_WRITE,
                    authority_source=AuthoritySource.DIRECT_USER,
                    requires_approval=True,
                    idempotency_key=f"canonical:ppt:jira:{index}",
                    justification="update canonical work-item status",
                )
                powerpoint = AgentAction(
                    capability="powerpoint.presentation.generate",
                    target=ResourceRef(
                        "powerpoint",
                        "presentation",
                        "weekly-status",
                    ),
                    parameters={
                        "title": "Weekly status",
                        "slides": [
                            {
                                "title": "In Progress",
                                "bullets": ["On track"],
                            }
                        ],
                    },
                    risk=RiskLevel.LOCAL_GENERATION,
                    authority_source=AuthoritySource.DIRECT_USER,
                    requires_approval=False,
                    idempotency_key=f"projection:ppt:matching:{index}",
                    justification="project exact canonical values",
                    dependencies=(confluence.action_id, jira.action_id),
                )
                plan = ChangePlan(
                    goal="generate a bound PowerPoint",
                    actions=(confluence, jira, powerpoint),
                    created_by="test",
                )

                valid, reason = registry.validate(plan, powerpoint)

                self.assertTrue(valid, reason)

    def test_capability_without_a_parameter_verifier_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sources.toml"
            path.write_text(
                "[[rules]]\nfield='status'\ncanonical_system='jira'\n"
                "canonical_resource_id='X'\nprojections=['teams:X']\n"
                "direction='outbound_only'\n"
                "canonical_extractors={'jira.issue.update'=['fields.status']}\n"
                "projection_extractors={'teams.message.update'=['body']}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "no parameter verifier"):
                SourceOfTruthRegistry.from_toml(path)

    def test_unknown_source_direction_is_rejected_at_load(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sources.toml"
            path.write_text(
                "[[rules]]\nfield='status'\ncanonical_system='jira'\n"
                "canonical_resource_id='X'\nprojections=['teams:X']\n"
                "direction='bidirectional'\ncanonical_capabilities=['jira.issue.update']\n"
                "projection_capabilities=['teams.message.update']\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "direction"):
                SourceOfTruthRegistry.from_toml(path)


if __name__ == "__main__":
    unittest.main()
