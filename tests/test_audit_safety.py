"""Audit-content minimization tests."""

from __future__ import annotations

import os
import sqlite3
import threading
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConnectorError
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

    def test_free_form_connector_error_is_digested_not_persisted(self) -> None:
        secret_text = "TOP-SECRET-PROVIDER-ERROR-BODY"

        class ExplodingConnector:
            system = "jira"
            capabilities = frozenset({"jira.issue.read"})

            def execute(self, action: AgentAction) -> object:
                raise ConnectorError(f"provider rejected request: {secret_text}")

            def read(self, resource: ResourceRef) -> None:
                return None

            def verify(self, action: AgentAction, result: object) -> object:
                raise AssertionError("verification must not run")

        action = AgentAction(
            capability="jira.issue.read",
            target=ResourceRef(
                system="jira",
                resource_type="issue",
                resource_id="ERROR-1",
            ),
            parameters={},
            risk=RiskLevel.READ_ONLY,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="audit-error-safety",
            justification="Verify provider error minimization.",
        )
        plan = ChangePlan(
            goal="Fail without persisting provider content.",
            actions=(action,),
            created_by="test",
        )
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            registry = ConnectorRegistry()
            registry.register(ExplodingConnector())  # type: ignore[arg-type]
            report = WorkflowOrchestrator(
                policy=PolicyEngine(
                    PolicyConfig.from_toml(ROOT / "config/policy.toml")
                ),
                sources=SourceOfTruthRegistry.from_toml(
                    ROOT / "config/sources_of_truth.toml"
                ),
                connectors=registry,
                audit=AuditLog(database),
            ).run(plan, dry_run=False)

            self.assertFalse(report.successful)
            self.assertIn(secret_text, report.actions[0].message)
            raw_database = database.read_bytes()

        self.assertNotIn(secret_text.encode("utf-8"), raw_database)
        self.assertIn(b"message_digest", raw_database)

    def test_verification_does_not_create_or_accept_an_empty_database(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "missing.sqlite3"

            valid, message = AuditLog.verify_existing(database)

            self.assertFalse(valid)
            self.assertIn("does not exist", message)
            self.assertFalse(database.exists())

            AuditLog(database)
            valid, message = AuditLog.verify_existing(database)
            self.assertFalse(valid)
            self.assertIn("contains no events", message)
            self.assertEqual(os.stat(database).st_mode & 0o777, 0o600)

    def test_checkpoint_detects_tail_truncation(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            audit = AuditLog(database)
            run_id = uuid4()
            plan_id = uuid4()
            for index in range(2):
                audit.record(
                    run_id=run_id,
                    plan_id=plan_id,
                    action_id=None,
                    event_type="test",
                    payload={"index": index},
                )
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "DELETE FROM audit_events WHERE id = "
                    "(SELECT MAX(id) FROM audit_events)"
                )
                connection.commit()

            valid, message = AuditLog.verify_existing(database)

            self.assertFalse(valid)
            self.assertIn("checkpoint", message)

    def test_concurrent_appends_preserve_one_linear_chain(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            audit = AuditLog(database)
            run_id = uuid4()
            plan_id = uuid4()
            barrier = threading.Barrier(8)
            errors: list[BaseException] = []

            def append(index: int) -> None:
                try:
                    barrier.wait()
                    audit.record(
                        run_id=run_id,
                        plan_id=plan_id,
                        action_id=None,
                        event_type="concurrent-test",
                        payload={"index": index},
                    )
                except (
                    OSError,
                    RuntimeError,
                    sqlite3.Error,
                    TypeError,
                    ValueError,
                ) as error:
                    # Preserve expected worker failures for the main assertion.
                    errors.append(error)

            threads = [
                threading.Thread(target=append, args=(index,)) for index in range(8)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(errors, [])
            self.assertEqual(
                AuditLog.verify_existing(database),
                (True, "verified 8 audit events"),
            )


if __name__ == "__main__":
    unittest.main()
