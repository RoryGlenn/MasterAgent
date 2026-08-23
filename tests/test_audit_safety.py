"""Audit-content minimization tests."""

from __future__ import annotations

import os
import sqlite3
import threading
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from master_agent import sqlite_safety
from master_agent.audit import AuditLog
from master_agent.canonical import SourceOfTruthRegistry
from master_agent.capabilities import CapabilityCatalog
from master_agent.connectors.mock import MockConnector
from master_agent.errors import ConfigurationError, ConnectorError
from master_agent.governance import GovernanceProfile
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ConnectorExecutionBinding,
    ExecutionContext,
    ResourceRef,
    RiskLevel,
)
from master_agent.orchestrator import WorkflowOrchestrator
from master_agent.policy import PolicyConfig, PolicyEngine
from master_agent.registry import ConnectorRegistry
from tests.helpers import govern_test_plan

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
        plan = govern_test_plan(plan)
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
            execution_context=ExecutionContext(
                integrations_sha256="b" * 64,
                connectors=(
                    ConnectorExecutionBinding(
                        system="jira",
                        deployment="cloud",
                        config_identity_sha256="a" * 64,
                        resolved_base_url="https://jira.example.test/rest/api/3",
                        resolved_origin="https://jira.example.test",
                        authentication_mode="bearer",
                        credential_identity="jira:user:42",
                    ),
                ),
            ),
        )
        plan = govern_test_plan(plan)
        with TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            registry = ConnectorRegistry()
            connector = ExplodingConnector()
            connector._config = SimpleNamespace(  # type: ignore[attr-defined]
                auth=SimpleNamespace(mode="bearer"),
                config_identity="a" * 64,
                base_url="https://jira.example.test/rest/api/3",
                ca_bundle=None,
                ca_bundle_sha256=None,
                max_pages=1,
                max_response_bytes=4096,
            )
            registry.register(connector)  # type: ignore[arg-type]
            report = WorkflowOrchestrator(
                policy=PolicyEngine(
                    PolicyConfig.from_toml(ROOT / "config/policy.toml")
                ),
                sources=SourceOfTruthRegistry.from_toml(
                    ROOT / "config/sources_of_truth.toml"
                ),
                connectors=registry,
                audit=AuditLog(database),
                capabilities=CapabilityCatalog.from_toml(
                    ROOT / "config/capabilities.toml"
                ),
                governance=GovernanceProfile.from_toml(ROOT / "config/governance.toml"),
            ).run(plan, dry_run=False)

            self.assertFalse(report.successful)
            self.assertNotIn(secret_text, report.actions[0].message)
            self.assertIn(
                "provider read failed after egress authorization",
                report.actions[0].message,
            )
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

    def test_verification_rejects_torn_ledger_without_mutating_state(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "audit.sqlite3"
            ledger = root / ".audit.sqlite3.master-agent.lock"
            audit = AuditLog(database)
            audit.record(
                run_id=uuid4(),
                plan_id=uuid4(),
                action_id=None,
                event_type="test",
                payload={"safe": True},
            )
            audit.close()
            with ledger.open("ab") as stream:
                stream.write(b"P deliberately-torn")
                stream.flush()
                os.fsync(stream.fileno())
            before_database = (database.read_bytes(), database.stat().st_mtime_ns)
            before_ledger = (ledger.read_bytes(), ledger.stat().st_mtime_ns)

            valid, message = AuditLog.verify_existing(database)

            self.assertFalse(valid)
            self.assertIn("torn", message)
            self.assertEqual(
                (database.read_bytes(), database.stat().st_mtime_ns),
                before_database,
            )
            self.assertEqual(
                (ledger.read_bytes(), ledger.stat().st_mtime_ns),
                before_ledger,
            )

    def test_successful_verification_does_not_mutate_snapshot_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "audit.sqlite3"
            ledger = root / ".audit.sqlite3.master-agent.lock"
            lock = root / ".audit.sqlite3.master-agent.flock"
            audit = AuditLog(database)
            audit.record(
                run_id=uuid4(),
                plan_id=uuid4(),
                action_id=None,
                event_type="test",
                payload={"safe": True},
            )
            audit.close()
            paths = (database, ledger, lock)
            before = {
                path.name: (
                    path.read_bytes(),
                    path.stat().st_mode & 0o777,
                    path.stat().st_mtime_ns,
                    path.stat().st_ctime_ns,
                )
                for path in paths
            }

            valid, message = AuditLog.verify_existing(database)

            after = {
                path.name: (
                    path.read_bytes(),
                    path.stat().st_mode & 0o777,
                    path.stat().st_mtime_ns,
                    path.stat().st_ctime_ns,
                )
                for path in paths
            }
            self.assertTrue(valid, message)
            self.assertEqual(after, before)

    def test_verification_does_not_recreate_a_missing_lock_ledger(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "audit.sqlite3"
            ledger = root / ".audit.sqlite3.master-agent.lock"
            audit = AuditLog(database)
            audit.record(
                run_id=uuid4(),
                plan_id=uuid4(),
                action_id=None,
                event_type="test",
                payload={"safe": True},
            )
            audit.close()
            ledger.unlink()
            before = (database.read_bytes(), database.stat().st_mtime_ns)

            valid, message = AuditLog.verify_existing(database)

            self.assertFalse(valid)
            self.assertIn("no trusted lock ledger", message)
            self.assertEqual(
                (database.read_bytes(), database.stat().st_mtime_ns),
                before,
            )
            self.assertFalse(ledger.exists())

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
            self.assertTrue(
                "checkpoint" in message or "content identity changed" in message
            )

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

    def test_post_construction_symlink_rebinding_is_rejected_without_write(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "audit.sqlite3"
            replacement = root / "replacement.sqlite3"
            displaced = root / "displaced.sqlite3"
            audit = AuditLog(database)
            replacement_audit = AuditLog(replacement)
            replacement_audit.close()

            database.rename(displaced)
            database.symlink_to(replacement.name)

            with self.assertRaisesRegex(ConfigurationError, "no-follow"):
                audit.record(
                    run_id=uuid4(),
                    plan_id=uuid4(),
                    action_id=None,
                    event_type="must-not-be-redirected",
                    payload={"unexpected": True},
                )

            self.assertEqual(_audit_event_count(replacement), 0)
            self.assertEqual(_audit_event_count(displaced), 0)
            audit.close()

    def test_post_construction_regular_file_rebinding_is_rejected_without_write(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "audit.sqlite3"
            replacement = root / "replacement.sqlite3"
            displaced = root / "displaced.sqlite3"
            audit = AuditLog(database)
            replacement_audit = AuditLog(replacement)
            replacement_audit.close()

            database.rename(displaced)
            replacement.rename(database)

            with self.assertRaisesRegex(ConfigurationError, "identity changed"):
                audit.record(
                    run_id=uuid4(),
                    plan_id=uuid4(),
                    action_id=None,
                    event_type="must-not-be-redirected",
                    payload={"unexpected": True},
                )

            self.assertEqual(_audit_event_count(database), 0)
            self.assertEqual(_audit_event_count(displaced), 0)
            audit.close()

    def test_constructor_swap_and_decoy_fd_cannot_redirect_schema_creation(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "audit.sqlite3"
            displaced = root / "displaced.sqlite3"
            attacker = root / "attacker.sqlite3"
            attacker.write_bytes(b"")
            attacker.chmod(0o600)
            real_connect = sqlite_safety.sqlite3.connect
            decoy_descriptors: list[int] = []

            def connect_while_redirected(
                *args: object,
                **kwargs: object,
            ) -> sqlite3.Connection:
                database.rename(displaced)
                attacker.rename(database)
                try:
                    connection = real_connect(*args, **kwargs)
                finally:
                    database.rename(attacker)
                    displaced.rename(database)
                decoy_descriptors.append(os.open(database, os.O_RDWR | os.O_NOFOLLOW))
                return connection

            try:
                with patch.object(
                    sqlite_safety.sqlite3,
                    "connect",
                    side_effect=connect_while_redirected,
                ):
                    audit = AuditLog(database)
                audit.close()
                self.assertTrue(
                    all(os.fstat(descriptor).st_ino for descriptor in decoy_descriptors)
                )
            finally:
                for descriptor in decoy_descriptors:
                    os.close(descriptor)

            self.assertEqual(attacker.read_bytes(), b"")
            self.assertEqual(
                _audit_table_names(database),
                [
                    "audit_events",
                    "audit_state",
                    "completed_actions",
                    "run_checkpoints",
                ],
            )


def _audit_event_count(database: Path) -> int:
    """Return the number of events without mutating the test database."""

    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    assert row is not None
    return int(row[0])


def _audit_table_names(database: Path) -> list[str]:
    """Return application table names from one stable audit generation."""

    with closing(sqlite3.connect(database)) as connection:
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]


if __name__ == "__main__":
    unittest.main()
