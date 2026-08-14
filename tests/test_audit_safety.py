"""Audit-content minimization tests."""

from __future__ import annotations

from pathlib import Path
from contextlib import closing
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.connectors.mock import MockConnector
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry


ROOT = Path(__file__).resolve().parents[1]


class AuditSafetyTests(unittest.TestCase):
    """Verify retrieved bodies do not enter durable audit metadata."""

    def test_sensitive_read_content_is_not_written_to_audit_database(self) -> None:
        secret_text = "CONFIDENTIAL-CUSTOMER-DATA-DO-NOT-AUDIT"
        action = AgentAction(
            capability="jira.issue.read",
            target=ResourceRef(
                system="jira",
                resource_type="issue",
                resource_id="SENSITIVE-1",
            ),
            parameters={},
            risk=RiskLevel.READ_ONLY,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="audit-safety-read",
            justification="Verify audit minimization.",
        )
        plan = ChangePlan(
            goal="Read sensitive issue without persisting its body to audit.",
            actions=(action,),
            created_by="test",
        )
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            registry = ConnectorRegistry()
            registry.register(
                MockConnector(
                    "jira",
                    {"SENSITIVE-1": {"version": "1", "body": secret_text}},
                )
            )
            orchestrator = WorkflowOrchestrator(
                policy=PolicyEngine(
                    PolicyConfig.from_toml(ROOT / "config/policy.toml")
                ),
                sources=SourceOfTruthRegistry.from_toml(
                    ROOT / "config/sources_of_truth.toml"
                ),
                connectors=registry,
                audit=AuditLog(database),
            )
            report = orchestrator.run(plan, dry_run=False)
            self.assertTrue(report.successful)
            self.assertIn(secret_text, str(report.to_dict()))

            with closing(sqlite3.connect(database)) as connection:
                audit_payloads = "\n".join(
                    row[0]
                    for row in connection.execute(
                        "SELECT payload_json FROM audit_events"
                    ).fetchall()
                )
                completed_payloads = "\n".join(
                    row[0]
                    for row in connection.execute(
                        "SELECT result_json FROM completed_actions"
                    ).fetchall()
                )
            self.assertNotIn(secret_text, audit_payloads)
            self.assertNotIn(secret_text, completed_payloads)


if __name__ == "__main__":
    unittest.main()
