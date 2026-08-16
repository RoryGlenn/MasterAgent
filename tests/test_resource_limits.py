"""Resource-exhaustion boundaries for plans and local artifacts."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from master_agent import cli
from master_agent.capabilities import CapabilityCatalog, CapabilityDefinition
from master_agent.connectors import drafts
from master_agent.connectors.drafts import (
    ArtifactBudget,
    RepositoryDraftConnector,
    write_artifact_bundle,
)
from master_agent.directory_safety import PinnedDirectory
from master_agent.errors import ConnectorError, ValidationError
from master_agent.models import (
    AgentAction,
    AuthoritySource,
    ChangePlan,
    ResourceRef,
    RiskLevel,
)
from master_agent.resource_limits import (
    MAX_JSON_COLLECTION_ITEMS,
    MAX_JSON_DEPTH,
    MAX_JSON_STRING_CHARACTERS,
    MAX_PLAN_ACTIONS,
)

ROOT = Path(__file__).resolve().parents[1]


class PlanResourceLimitTests(unittest.TestCase):
    """Reject hostile plan shapes before recursive model or policy work."""

    def test_plan_byte_limit_fails_before_json_parser(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "oversized.json"
            plan_path.write_bytes(b" " * 65)

            with (
                patch.object(cli, "MAX_PLAN_BYTES", 64),
                patch.object(cli.json, "loads") as loads,
                self.assertRaisesRegex(ValidationError, "file limit"),
            ):
                cli._load_plan(plan_path)

            loads.assert_not_called()

    def test_pathological_json_integer_is_a_controlled_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "integer.json"
            plan_path.write_bytes(b'{"value":' + (b"9" * 5_000) + b"}")

            with self.assertRaisesRegex(ValidationError, "bounded valid"):
                cli._load_plan(plan_path)

    def test_deep_parameters_are_rejected_before_recursive_freezing(self) -> None:
        value: object = "leaf"
        for _index in range(MAX_JSON_DEPTH + 1):
            value = {"nested": value}

        with self.assertRaisesRegex(ValidationError, "nesting limit"):
            _action(parameters={"value": value})

    def test_oversized_strings_and_collections_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "character limit"):
            _action(parameters={"value": "x" * (MAX_JSON_STRING_CHARACTERS + 1)})

        with self.assertRaisesRegex(ValidationError, "item limit"):
            _action(
                parameters={
                    "value": list(range(MAX_JSON_COLLECTION_ITEMS + 1)),
                }
            )

    def test_many_actions_are_rejected_before_graph_validation(self) -> None:
        action = _action(parameters={"value": "bounded"})

        with self.assertRaisesRegex(ValidationError, "action limit"):
            ChangePlan(
                goal="bounded plan",
                actions=(action,) * (MAX_PLAN_ACTIONS + 1),
                created_by="test",
            )

    def test_aggregate_plan_parameter_bytes_are_bounded(self) -> None:
        large_value = "x" * 1_000_000
        actions = tuple(
            _action(parameters={"value": large_value}) for _index in range(9)
        )

        with self.assertRaisesRegex(ValidationError, "aggregate parameter-byte"):
            ChangePlan(
                goal="bounded aggregate parameters",
                actions=actions,
                created_by="test",
            )

    def test_every_local_capability_declares_safe_input_and_output_quotas(self) -> None:
        catalog = CapabilityCatalog.from_toml(ROOT / "config/capabilities.toml")
        local = tuple(
            item
            for item in catalog.definitions.values()
            if item.risk is RiskLevel.LOCAL_GENERATION
        )

        self.assertTrue(local)
        self.assertTrue(all(item.max_input_bytes for item in local))
        self.assertTrue(all(item.max_output_bytes for item in local))

    def test_capability_input_quota_is_enforced_before_connector_execution(
        self,
    ) -> None:
        definition = CapabilityDefinition(
            name="example.summary.generate",
            enabled=True,
            authentication="local",
            risk=RiskLevel.LOCAL_GENERATION,
            target_resource_types=("summary",),
            parameter_schema={"body": "string"},
            max_input_bytes=14,
            max_output_bytes=1024,
        )
        catalog = CapabilityCatalog({definition.name: definition})
        action = AgentAction(
            capability=definition.name,
            target=ResourceRef("example", "summary", "1"),
            parameters={"body": "x" * 11},
            risk=RiskLevel.LOCAL_GENERATION,
            authority_source=AuthoritySource.DIRECT_USER,
            requires_approval=False,
            idempotency_key="input-quota",
            justification="exercise local input quota",
        )

        allowed, reason = catalog.validate_action(action)

        self.assertFalse(allowed)
        self.assertIn("input quota", reason)


class ArtifactResourceLimitTests(unittest.TestCase):
    """Enforce per-capability and whole-run storage before final publication."""

    def test_artifact_budgets_cannot_expand_the_hard_run_ceiling(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1"):
            ArtifactBudget(max_bytes=65 * 1024 * 1024)

    def test_output_quota_cannot_expand_the_hard_artifact_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "artifact.bin"

            with self.assertRaisesRegex(ConnectorError, "quota is invalid"):
                write_artifact_bundle(
                    root,
                    ((path, b"bounded", "application/octet-stream"),),
                    max_output_bytes=17 * 1024 * 1024,
                )

            self.assertFalse(path.exists())

    def test_output_quota_fails_before_final_artifact_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connector = RepositoryDraftConnector(
                root,
                output_limits={
                    "repository.branch.plan": 1,
                    "repository.patch.generate": 1,
                },
            )
            try:
                with self.assertRaisesRegex(ConnectorError, "output quota"):
                    connector.execute(_branch_action())
            finally:
                connector.close()

            self.assertEqual(tuple(root.iterdir()), ())

    def test_aggregate_budget_is_shared_across_artifact_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = ArtifactBudget(max_bytes=5)
            first = root / "first.bin"
            second = root / "second.bin"

            write_artifact_bundle(
                root,
                ((first, b"abc", "application/octet-stream"),),
                artifact_budget=budget,
                max_output_bytes=4,
            )
            with self.assertRaisesRegex(ConnectorError, "aggregate"):
                write_artifact_bundle(
                    root,
                    ((second, b"def", "application/octet-stream"),),
                    artifact_budget=budget,
                    max_output_bytes=4,
                )

            self.assertEqual(budget.used_bytes, 3)
            self.assertEqual(first.read_bytes(), b"abc")
            self.assertFalse(second.exists())

    def test_large_artifact_verification_hashes_in_bounded_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "large.bin"
            payload = b"x" * (2 * 1024 * 1024 + 17)
            write_artifact_bundle(
                root,
                ((path, payload, "application/octet-stream"),),
            )
            requested_sizes: list[int] = []
            real_read = drafts.os.read

            def bounded_read(descriptor: int, size: int) -> bytes:
                requested_sizes.append(size)
                return real_read(descriptor, size)

            with (
                PinnedDirectory.open(root) as pinned,
                patch.object(drafts.os, "read", side_effect=bounded_read),
            ):
                digest, size = drafts._inspect_artifact(
                    pinned,
                    path,
                    max_bytes=len(payload),
                )

            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual(size, len(payload))
            self.assertTrue(requested_sizes)
            self.assertLessEqual(max(requested_sizes), 1024 * 1024)


def _action(*, parameters: dict[str, object]) -> AgentAction:
    return AgentAction(
        capability="example.resource.read",
        target=ResourceRef("example", "resource", str(uuid4())),
        parameters=parameters,
        risk=RiskLevel.READ_ONLY,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key=f"resource-limit-{uuid4()}",
        justification="exercise resource limits",
    )


def _branch_action() -> AgentAction:
    return AgentAction(
        capability="repository.branch.plan",
        target=ResourceRef("repository", "branch_plan", "bounded"),
        parameters={
            "branch": "feature/bounded",
            "base": "main",
            "output_name": "branch-plan.json",
        },
        risk=RiskLevel.LOCAL_GENERATION,
        authority_source=AuthoritySource.DIRECT_USER,
        requires_approval=False,
        idempotency_key="bounded-branch-plan",
        justification="exercise output quota",
    )
