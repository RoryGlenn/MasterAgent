"""Source-of-truth tests."""

import hashlib
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
            capability="teams.message.update",
            target=ResourceRef(
                system="teams",
                resource_type="message",
                resource_id="weekly-status-draft",
            ),
            parameters={
                "body": "changed status",
                "source_bindings": {"project_status_narrative": "a" * 64},
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:test:projection",
            justification="Test projection write.",
        )
        plan = ChangePlan(goal="Test", actions=(projection,), created_by="test")
        valid, reason = registry.validate(plan, projection)
        self.assertFalse(valid)
        self.assertIn("canonical source", reason)

    def test_projection_must_depend_on_the_canonical_write(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        digest = hashlib.sha256(b"canonical").hexdigest()
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
                "source_bindings": {"project_status_narrative": digest},
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:update",
            justification="update canonical source",
        )
        unordered = AgentAction(
            capability="teams.message.update",
            target=ResourceRef("teams", "message", "weekly-status-draft"),
            parameters={
                "body": "projection",
                "source_bindings": {"project_status_narrative": digest},
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
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
        valid, _ = registry.validate(ordered_plan, ordered)
        self.assertTrue(valid)

    def test_unrelated_canonical_field_cannot_authorize_projection(self) -> None:
        registry = SourceOfTruthRegistry.from_toml(
            ROOT / "config/sources_of_truth.toml"
        )
        projection_digest = "a" * 64
        canonical = AgentAction(
            capability="confluence.page.update",
            target=ResourceRef("confluence", "page", "project-status", "1"),
            parameters={
                "body": "unrelated title update",
                "source_bindings": {"page_title": projection_digest},
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=True,
            idempotency_key="canonical:unrelated",
            justification="update a different field",
        )
        projection = AgentAction(
            capability="teams.message.update",
            target=ResourceRef("teams", "message", "weekly-status-draft"),
            parameters={
                "body": "fabricated status",
                "source_bindings": {
                    "project_status_narrative": projection_digest,
                },
            },
            risk=RiskLevel.REVERSIBLE_WRITE,
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
        self.assertIn("field-bound", reason)

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
