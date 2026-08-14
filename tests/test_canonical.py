"""Source-of-truth tests."""

from pathlib import Path
import unittest

from master_agent.canonical import SourceOfTruthRegistry
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
            parameters={"body": "changed status"},
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


if __name__ == "__main__":
    unittest.main()
